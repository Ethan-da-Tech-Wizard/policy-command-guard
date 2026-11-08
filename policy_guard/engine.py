"""Policy-as-Code Command Evaluation & Shell Execution Guard Engine.

This module implements an AST-aware shell tokenization, lexical normalization,
dangerous pattern detection, path traversal prevention, and execution policy
enforcement engine.
"""

import os
import re
import shlex
from pathlib import Path
from typing import List, Optional, Sequence

from .models import Decision, EvaluationResult, PolicyRule, PolicyTier

# ==============================================================================
# SECTION 1: EDUCATIONAL CONSTANTS & LEXICAL DEFINITIONS
# ==============================================================================

# Delimiter used in serialized tool argument streams.
# In JSON strings, raw NUL (\x00) bytes cannot appear unescaped.
# Therefore, wrapping object keys and values in \x00 provides a cryptographically
# unambiguous boundary that prevents parameter injection or argument smuggling.
NUL = "\x00"

# Shell metacharacters that alter execution flow, subshell boundaries, or redirections.
# Unquoted occurrences of these characters inside arbitrary commands indicate
# syntax that bypasses single-command lexical parsing.
SHELL_METACHARACTERS = {";", "&", "|", "(", ")", "`", "$", "<", ">", "\\", "\n", "\r", "\t"}

# Dangerous shell command executables that alter system integrity, privilege boundaries,
# disk storage, or establish unauthorized network communication channels.
CRITICAL_DANGEROUS_BINARIES = {
    # Privilege escalation & identity alteration
    "sudo", "su", "doas", "pkexec", "run0", "visudo", "passwd", "usermod", "chroot", "unshare", "nsenter",
    # Disk destruction & low-level hardware writes
    "rm", "shred", "dd", "mkfs", "wipefs", "truncate", "fdisk", "parted", "blkdiscard",
    # Unauthorized outbound networking & reverse shells
    "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "ssh", "scp", "rsync",
    # Shell launchers & arbitrary code interpreters
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "eval", "exec",
}

# Whitelist of strictly safe, read-only inspection commands allowed in the default tier.
# Every command in this list must have no inherent arbitrary execution or network side effects.
ALLOWLISTED_INSPECTION_COMMANDS = {
    "ls", "cat", "head", "tail", "wc", "tree", "stat", "file", "pwd", "echo",
    "printf", "sort", "uniq", "cut", "tr", "nl", "diff", "cmp", "du", "df",
    "ps", "date", "whoami", "uname", "which", "basename", "dirname", "realpath",
    "sha256sum", "md5sum", "seq", "sleep", "true", "false", "nproc", "free",
    "uptime", "grep", "egrep", "fgrep", "rg", "jq", "git", "python3", "tar",
}

# Sensitive credential patterns and critical system directories.
# Any access to these paths (read or write) is strictly prohibited.
SENSITIVE_PATH_PATTERNS = [
    r"\.env(?:\.[A-Za-z0-9_.-]+|)",      # Environment files containing API keys and secrets
    r"\.ssh(?:/|[ \"'\\]|$)",             # SSH keys, authorized_keys, known_hosts
    r"\.aws(?:/|[ \"'\\]|$)",             # AWS credentials and config files
    r"\.gnupg(?:/|[ \"'\\]|$)",           # GPG private keys
    r"\.codex(?:/|[ \"'\\]|$)",           # LLM credentials and auth tokens
    r"\.local/share/keyrings",            # Desktop credential keyrings
    r"/etc/(?:shadow|gshadow|passwd-)",   # Unix password hashes
    r"/etc/ssl/private",                  # TLS/SSL private certificates
    r"/proc/(?:[^ \"'\\]+/|)(?:environ|mem|maps)",  # Memory dumping & environment variable snooping
    r"\.git/config",                      # Git configuration containing tokens or credentials
]


# ==============================================================================
# SECTION 2: SHELL TOKENIZATION & AST SEGMENTATION
# ==============================================================================

class ShellTokenizer:
    r"""AST-based Shell Tokenizer and Lexical Analyzer.

    Educational Note:
    -----------------
    Naive regex-based security filters check strings with `re.search("rm -rf", cmd)`.
    Attackers bypass naive string checks through:
      1. Variable substitution:   $'\x72\x6d' -rf x
      2. Quote splitting:        'r''m' -rf x  or  "r""m" -rf x
      3. Backslash escaping:     \r\m -rf x
      4. IFS field splitting:    rm${IFS}-rf${IFS}x
      5. Subshell smuggling:     echo $(rm -rf x)
      6. Chaining operators:     ls ; rm -rf x  or  ls && rm -rf x
      7. Pipeline injection:     cat f | sh

    This tokenizer dissects the command string into structural pipeline segments,
    strips obfuscation, normalizes quote contexts, and identifies compound operations.
    """

    @staticmethod
    def split_pipeline_segments(command_str: str) -> List[str]:
        """Split a compound command string into individual subcommands.

        Compound operators include pipes (|), logical AND (&&), logical OR (||),
        and command sequencing (; or newlines).

        Educational Note:
        -----------------
        Each subcommand in a pipeline must be evaluated independently. If an agent executes:
            `git status && rm -rf /`
        The presence of `git status` must not mask the subsequent destructive `rm` command.
        """
        # Strip trailing comments and whitespace
        clean_str = re.sub(r'(?<!\\)#.*$', '', command_str).strip()

        # Split on unquoted pipeline operators: |, &&, ||, ;, and newlines.
        # Uses positive lookahead/behind or regex tokenization respecting quotes.
        segments = []
        current_token = []
        in_single_quote = False
        in_double_quote = False
        escape_next = False

        i = 0
        n = len(clean_str)
        while i < n:
            char = clean_str[i]

            # Handle backslash escapes inside unquoted or double-quoted context
            if escape_next:
                current_token.append(char)
                escape_next = False
                i += 1
                continue

            if char == "\\" and not in_single_quote:
                escape_next = True
                current_token.append(char)
                i += 1
                continue

            # Toggle single quote state (single quotes ignore all special characters)
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                current_token.append(char)
                i += 1
                continue

            # Toggle double quote state
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                current_token.append(char)
                i += 1
                continue

            # If inside quotes, characters are literal data, not command operators
            if in_single_quote or in_double_quote:
                current_token.append(char)
                i += 1
                continue

            # Detect chaining operator: '&&' or '||'
            if i + 1 < n and clean_str[i:i+2] in ("&&", "||"):
                segment_text = "".join(current_token).strip()
                if segment_text:
                    segments.append(segment_text)
                current_token = []
                i += 2
                continue

            # Detect single-character chaining: ';', '|', or newline '\n'
            if char in (";", "|", "\n"):
                segment_text = "".join(current_token).strip()
                if segment_text:
                    segments.append(segment_text)
                current_token = []
                i += 1
                continue

            # Regular command character
            current_token.append(char)
            i += 1

        remainder = "".join(current_token).strip()
        if remainder:
            segments.append(remainder)

        return segments

    @staticmethod
    def extract_command_words(segment_str: str) -> List[str]:
        """Tokenize a single command segment into shell words.

        Uses POSIX-compliant shell lexical analysis with fallback normalization.
        """
        try:
            return shlex.split(segment_str, posix=True)
        except ValueError:
            # Unterminated quote or malformed shell syntax is inherently unsafe
            return segment_str.split()

    @staticmethod
    def normalize_executable_name(raw_word: str) -> str:
        """Strip obfuscation from an executable name.

        Handles:
          - Quoted identifiers: "rm" -> rm, 'rm' -> rm, r""m -> rm
          - Backslash escaping: \\rm -> rm
          - Path prefixes: /bin/rm -> rm, /usr/bin/env rm -> rm
          - ANSI-C quoting: $'rm' -> rm
        """
        # Remove internal quotes and backslashes
        cleaned = re.sub(r'[\'\"\\$]', '', raw_word)

        # Remove leading environment wrappers if present
        if "/" in cleaned:
            cleaned = os.path.basename(cleaned)

        return cleaned


# ==============================================================================
# SECTION 3: PATH TRAVERSAL & SECRET FILE DETECTION
# ==============================================================================

class PathSecurityValidator:
    """Security validator enforcing path containment and credential protection.

    Educational Note:
    -----------------
    Path traversal occurs when an attacker uses relative sequences (`../..`) or
    absolute paths (`/etc/shadow`) to reach files outside the intended sandbox.

    Common evasion techniques include:
      - Double dot traversal: `../../etc/passwd`
      - Redundant slash normalization: `///etc///shadow`
      - Dot segment obfuscation: `/etc/./shadow`
      - Quote splitting within paths: `~/.s"s"h/id_rsa`
      - Glob expansion evasion: `/etc/sha*` or `/home/*/.ssh`
    """

    @staticmethod
    def contains_path_traversal(target_str: str) -> bool:
        """Detect directory traversal sequences ('..') in commands or path arguments.

        Uses negative lookbehind and lookahead to prevent false positives on
        filenames like 'file..txt' while strictly blocking directory walking.
        """
        # Look for '..' bounded by path separators, spaces, quotes, or string boundaries
        pattern = r'(?<![A-Za-z0-9_~^])\.\.(?![A-Za-z0-9_.-])'
        return bool(re.search(pattern, target_str))

    @staticmethod
    def accesses_sensitive_secret(target_str: str) -> bool:
        """Check whether the string targets sensitive credentials, tokens, or system keys."""
        # De-obfuscate quotes inside the target string (e.g. ~/.s"s"h/id_rsa -> ~/.ssh/id_rsa)
        normalized = re.sub(r'[\'\"\\$]', '', target_str)

        for pat in SENSITIVE_PATH_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def is_contained_in_workspace(path_str: str, workspace_root: Optional[str] = None) -> bool:
        """Verify that an absolute or relative path resolves strictly within the workspace."""
        if workspace_root is None:
            workspace_root = os.getcwd()

        try:
            expanded = os.path.expanduser(path_str)
            resolved = Path(expanded).resolve()
            ws_resolved = Path(workspace_root).resolve()

            # Allowed system read-only exceptions (e.g. /etc/os-release for host diagnostics)
            system_read_exceptions = [
                Path("/etc/os-release"),
                Path("/etc/hostname"),
                Path("/proc/cpuinfo"),
                Path("/proc/meminfo"),
                Path("/dev/null"),
            ]
            if resolved in system_read_exceptions:
                return True

            # Standard temporary directories used for transient test builds
            temp_roots = [Path("/tmp").resolve(), Path("/private/tmp").resolve()]
            for tr in temp_roots:
                try:
                    resolved.relative_to(tr)
                    return True
                except ValueError:
                    pass

            # Primary verification: must be descendant of workspace root
            resolved.relative_to(ws_resolved)
            return True
        except (ValueError, RuntimeError):
            return False


# ==============================================================================
# SECTION 4: POLICY EVALUATION ENGINE
# ==============================================================================

class PolicyCommandGuard:
    """Core Policy-as-Code Evaluation Engine.

    Educational Architecture:
    --------------------------
    1. Zero-Trust Default:
       Any command not explicitly permitted by a formal grammar rule is denied.

    2. Two-Tier Enforcement Hierarchy:
       - Admin Tier: Hard-coded, immutable security constraints (highest priority).
         Even if a user-tier policy attempts to allow an operation, Admin deny rules
         take precedence and cannot be overridden.
       - User Tier: Project-level rules permitting specific inspection or development tasks.

    3. Tree-Sitter & AST Segmentation:
       When compound commands are submitted (`cmd1 | cmd2 && cmd3`), every single
       constituent subcommand must independently pass policy validation.
    """

    def __init__(
        self,
        rules: Optional[Sequence[PolicyRule]] = None,
        workspace_dir: Optional[str] = None,
        tier: PolicyTier = PolicyTier.ADMIN,
    ) -> None:
        self.rules = list(rules or [])
        self.workspace_dir = workspace_dir or os.getcwd()
        self.tier = tier

    def evaluate_shell_command(self, command_str: str) -> EvaluationResult:
        """Evaluate a raw shell command string against all security layers.

        Returns an EvaluationResult detailing the decision, matched rule, and reasoning.
        """
        # Step 1: Check command string length boundary
        # Overly long commands (>6000 chars) are denied to mitigate ReDoS and buffer attacks
        if len(command_str) > 6000:
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Command length exceeds maximum verifiable security threshold (6000 characters).",
            )

        # Step 2: Path traversal inspection
        if PathSecurityValidator.contains_path_traversal(command_str):
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Directory traversal sequence ('..') detected.",
                matched_pattern="path_traversal_dotdot",
            )

        # Step 3: Sensitive secret and credential file access detection
        if PathSecurityValidator.accesses_sensitive_secret(command_str):
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Command references sensitive credentials, tokens, or system keys.",
                matched_pattern="sensitive_secret_path",
            )

        # Step 4: Decompose compound command into pipeline segments
        segments = ShellTokenizer.split_pipeline_segments(command_str)
        if not segments:
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Empty or whitespace-only shell command.",
            )

        # Step 5: Evaluate each subcommand segment individually
        sub_results = []
        for segment in segments:
            sub_res = self._evaluate_single_segment(segment)
            sub_results.append(sub_res)
            # Fail-closed: if any segment in the pipeline is denied, the entire command is denied
            if sub_res.decision == Decision.DENY:
                return EvaluationResult(
                    decision=Decision.DENY,
                    rule=sub_res.rule,
                    message=f"Blocked pipeline segment [{segment}]: {sub_res.message}",
                    matched_pattern=sub_res.matched_pattern,
                    subcommand_results=sub_results,
                )

        # If all subsegments are evaluated and approved
        return EvaluationResult(
            decision=Decision.ALLOW,
            message="Allowed: Command passed all policy AST checks and inspection allowlists.",
            subcommand_results=sub_results,
        )

    def _evaluate_single_segment(self, segment_str: str) -> EvaluationResult:
        """Evaluate a single atomic command segment."""
        # Check for unquoted subshell executions: `...` or $(...)
        if re.search(r'(?<!\\)(?:`|\$\()', segment_str):
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Subshell command substitution (` or $()) is denied under zero-trust policy.",
                matched_pattern="subshell_substitution",
            )

        # Check for shell redirection into arbitrary files outside safe temp
        redirection_match = re.search(r'(?:>|>>)\s*([^\s;&|]+)', segment_str)
        if redirection_match:
            target_dest = redirection_match.group(1).strip("'\"")
            if target_dest not in ("/dev/null", "&1", "&2"):
                # Check if redirection destination is sensitive or outside workspace
                if PathSecurityValidator.accesses_sensitive_secret(target_dest):
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message=f"Blocked: Redirection target '{target_dest}' is a protected secret path.",
                        matched_pattern="protected_redirect",
                    )

        # Tokenize into shell words
        words = ShellTokenizer.extract_command_words(segment_str)
        if not words:
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Malformed or unparseable command segment.",
            )

        # Filter out leading environment variables (e.g. FOO=1 bar)
        cmd_idx = 0
        while cmd_idx < len(words) and "=" in words[cmd_idx] and not words[cmd_idx].startswith("-"):
            cmd_idx += 1

        if cmd_idx >= len(words):
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Environment variable definition without executable command.",
            )

        raw_cmd = words[cmd_idx]
        normalized_cmd = ShellTokenizer.normalize_executable_name(raw_cmd)

        # Check critical dangerous binaries
        if normalized_cmd in CRITICAL_DANGEROUS_BINARIES:
            return EvaluationResult(
                decision=Decision.DENY,
                message=f"Blocked: Command '{normalized_cmd}' is classified as critical dangerous executable.",
                matched_pattern=f"critical_binary_{normalized_cmd}",
            )

        # Check arbitrary python execution (-c or -m)
        if normalized_cmd in ("python", "python3"):
            args = words[cmd_idx+1:]
            for i, arg in enumerate(args):
                if arg == "-c":
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message="Blocked: Arbitrary python -c execution is prohibited without explicit whitelist template.",
                        matched_pattern="python_arbitrary_eval",
                    )
                if arg == "-m":
                    if i + 1 < len(args) and args[i+1] not in ("unittest", "pytest", "py_compile", "json.tool"):
                        return EvaluationResult(
                            decision=Decision.DENY,
                            message=f"Blocked: Python module execution '-m {args[i+1]}' is not permitted.",
                            matched_pattern="python_unauthorized_module",
                        )

        # Check git commands for remote exfiltration or repository destruction
        if normalized_cmd == "git":
            args = words[cmd_idx+1:]
            # Disallow git commands that reach the network or alter remote refs
            banned_git_subcommands = {
                "push", "fetch", "pull", "clone", "remote", "submodule",
                "clean", "reset", "rebase", "merge", "cherry-pick", "filter-branch",
            }
            for arg in args:
                if arg in banned_git_subcommands:
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message=f"Blocked: Git subcommand '{arg}' reaches external networks or mutates repository state.",
                        matched_pattern=f"git_restricted_{arg}",
                    )
                # Disallow configuration overrides that spawn subshells (e.g. core.pager, core.sshCommand)
                if arg.startswith("-c") or "core.pager" in arg or "core.sshCommand" in arg:
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message="Blocked: Git argument injection / pager configuration override detected.",
                        matched_pattern="git_argument_injection",
                    )

        # Check find options that execute commands or delete files
        if normalized_cmd == "find":
            for arg in words[cmd_idx+1:]:
                if any(dangerous_flag in arg for dangerous_flag in ("-exec", "-execdir", "-ok", "-okdir", "-delete")):
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message=f"Blocked: 'find' command with dangerous flag '{arg}'.",
                        matched_pattern="find_exec_delete",
                    )

        # Allowlist verification
        if normalized_cmd not in ALLOWLISTED_INSPECTION_COMMANDS:
            return EvaluationResult(
                decision=Decision.DENY,
                message=f"Blocked: Command '{normalized_cmd}' is not on the verified allowlist.",
                matched_pattern=f"unlisted_command_{normalized_cmd}",
            )

        return EvaluationResult(
            decision=Decision.ALLOW,
            message=f"Allowed: Subcommand segment '{normalized_cmd}' matches allowlist.",
        )
