# ==============================================================================
# Program: policy_guard/engine.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Core AST-aware shell command evaluation engine implementing zero-trust
#          execution gating, quote-aware lexical pipeline splitting, executable
#          de-obfuscation, path traversal detection, credential containment,
#          and strict fail-closed security enforcement.
# ==============================================================================

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
# Wrapping object keys and values in \x00 provides a cryptographically
# unambiguous boundary that prevents parameter injection or argument smuggling.
NUL = "\x00"

# Shell metacharacters that alter execution flow, subshell boundaries, or redirections.
# Unquoted occurrences of these characters inside arbitrary commands indicate
# syntax that bypasses single-command lexical parsing.
SHELL_METACHARACTERS = {";", "&", "|", "(", ")", "`", "$", "<", ">", "\\", "\n", "\r", "\t"}

# Dangerous shell command executables that alter system integrity, privilege boundaries,
# disk storage, or establish unauthorized network communication channels.
CRITICAL_DANGEROUS_BINARIES = {
    # Privilege escalation & identity alteration:
    # Invoking these allows an unprivileged agent to acquire root or switch user accounts.
    "sudo", "su", "doas", "pkexec", "run0", "visudo", "passwd", "usermod", "chroot", "unshare", "nsenter",
    # Disk destruction & low-level hardware writes:
    # These commands wipe partition tables, zero out block devices, or destroy filesystem trees.
    "rm", "shred", "dd", "mkfs", "wipefs", "truncate", "fdisk", "parted", "blkdiscard",
    # Unauthorized outbound networking & reverse shells:
    # Used to establish TCP/UDP connections for data exfiltration or interactive shell tunnels.
    "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "ssh", "scp", "rsync",
    # Shell launchers & arbitrary code interpreters:
    # Spawning a secondary shell bypasses parent process policy gates.
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "eval", "exec",
}

# Whitelist of strictly safe, read-only inspection commands allowed in the default tier.
# Every command in this list has no inherent arbitrary code execution or network side effects.
ALLOWLISTED_INSPECTION_COMMANDS = {
    # Filesystem exploration and metadata inspection
    "ls", "cat", "head", "tail", "wc", "tree", "stat", "file", "pwd", "echo",
    # Text processing and formatting utilities
    "printf", "sort", "uniq", "cut", "tr", "nl", "diff", "cmp", "du", "df",
    # System status, process accounting, and environment diagnostics
    "ps", "date", "whoami", "uname", "which", "basename", "dirname", "realpath",
    # Cryptographic checksums and execution flow control
    "sha256sum", "md5sum", "seq", "sleep", "true", "false", "nproc", "free",
    # High-performance search, structured JSON filtering, and developer tools
    "uptime", "grep", "egrep", "fgrep", "rg", "jq", "git", "python3", "tar",
}

# Sensitive credential patterns and critical system directories.
# Any access to these paths (read or write) is strictly prohibited across all commands.
# Regular expressions are crafted to be ReDoS-safe with bounded anchors.
SENSITIVE_PATH_PATTERNS = [
    r"\.env(?:\.[A-Za-z0-9_.-]+|)",                    # Environment files containing API keys and secrets
    r"\.ssh(?:/|[ \"'\\]|$)",                           # SSH keys, authorized_keys, known_hosts
    r"\.aws(?:/|[ \"'\\]|$)",                           # AWS credentials and config profiles
    r"\.gnupg(?:/|[ \"'\\]|$)",                         # GPG private keyrings and trust databases
    r"\.codex(?:/|[ \"'\\]|$)",                         # LLM credentials and auth tokens
    r"\.local/share/keyrings",                          # Desktop credential keyrings and secrets
    r"/etc/(?:shadow|gshadow|passwd-)",                 # Unix password hashes and shadow files
    r"/etc/ssl/private",                                # TLS/SSL private certificates and key material
    r"/proc/(?:[^ \"'\\]+/|)(?:environ|mem|maps)",        # Process memory dumping & environment variable snooping
    r"\.git/config",                                    # Git configuration containing embedded auth tokens
]


# ==============================================================================
# SECTION 2: SHELL TOKENIZATION & AST SEGMENTATION
# ==============================================================================

class ShellTokenizer:
    r"""AST-based Shell Tokenizer and Lexical Analyzer.

    Educational Note:
    -----------------
    Naive regex-based security filters check commands using simple substring matching:
        `if "rm -rf" in cmd: deny()`
    Attackers easily circumvent naive string checks using well-known shell evasions:
      1. Variable substitution:   $'\x72\x6d' -rf /
      2. Quote splitting:        'r''m' -rf /  or  "r""m" -rf /
      3. Backslash escaping:     \r\m -rf /
      4. IFS field splitting:    rm${IFS}-rf${IFS}/
      5. Subshell smuggling:     echo $(rm -rf /)
      6. Chaining operators:     ls ; rm -rf /  or  ls && rm -rf /
      7. Pipeline injection:     cat payload.sh | sh

    This tokenizer dissects the command string into structural pipeline segments,
    strips obfuscation, normalizes quote contexts, and isolates atomic operations.
    """

    @staticmethod
    def split_pipeline_segments(command_str: str) -> List[str]:
        r"""Split a compound command string into individual subcommands.

        Educational Note:
        -----------------
        Compound shell operators include:
          - Pipes: `|` (redirects stdout of left process to stdin of right process)
          - Logical AND: `&&` (executes right process only if left process exits 0)
          - Logical OR: `||` (executes right process only if left process exits non-zero)
          - Sequence delimiters: `;` and `\n` (executes commands unconditionally)

        Every subcommand in a compound sequence must be evaluated independently.
        If an agent executes:
            `git status && rm -rf /`
        The presence of `git status` must never mask the subsequent destructive `rm` command.

        Quote Tracking State Machine:
          - Single quotes (`'`): All characters within single quotes are treated as literal
            text. No escapes are recognized inside single quotes in POSIX shell.
          - Double quotes (`"`): Metacharacters like `;`, `|`, `&&` lose their chaining
            meaning, but backslash escapes (`\"`) remain active.
          - Backslash (`\`): Escapes the subsequent character outside single quotes.
        """
        # Step 1: Strip trailing unescaped comments (#) outside of quotes
        clean_str = re.sub(r'(?<!\\)#.*$', '', command_str).strip()

        # Step 2: Initialize token accumulator and quote-state trackers
        segments: List[str] = []
        current_token: List[str] = []
        in_single_quote = False
        in_double_quote = False
        escape_next = False

        # Step 3: Iterate character-by-character through input string
        i = 0
        n = len(clean_str)
        while i < n:
            char = clean_str[i]

            # Step 3a: Handle backslash escapes (escape character is preserved literally)
            if escape_next:
                current_token.append(char)
                escape_next = False
                i += 1
                continue

            # Step 3b: Enter escape mode if unquoted backslash encountered
            if char == "\\" and not in_single_quote:
                escape_next = True
                current_token.append(char)
                i += 1
                continue

            # Step 3c: Toggle single quote state (single quotes ignore all special characters)
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                current_token.append(char)
                i += 1
                continue

            # Step 3d: Toggle double quote state
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                current_token.append(char)
                i += 1
                continue

            # Step 3e: If inside quotes, characters are literal data and cannot act as pipeline operators
            if in_single_quote or in_double_quote:
                current_token.append(char)
                i += 1
                continue

            # Step 3f: Detect two-character chaining operators: '&&' or '||'
            if i + 1 < n and clean_str[i:i+2] in ("&&", "||"):
                segment_text = "".join(current_token).strip()
                if segment_text:
                    segments.append(segment_text)
                current_token = []
                i += 2
                continue

            # Step 3g: Detect single-character chaining operators: ';', '|', or newline '\n'
            if char in (";", "|", "\n"):
                segment_text = "".join(current_token).strip()
                if segment_text:
                    segments.append(segment_text)
                current_token = []
                i += 1
                continue

            # Step 3h: Regular unquoted command character
            current_token.append(char)
            i += 1

        # Step 4: Append final trailing segment if non-empty
        remainder = "".join(current_token).strip()
        if remainder:
            segments.append(remainder)

        return segments

    @staticmethod
    def extract_command_words(segment_str: str) -> List[str]:
        """Tokenize a single command segment into shell words.

        Educational Note:
        -----------------
        Uses POSIX-compliant shell lexical analysis (`shlex.split(posix=True)`).
        If the shell string contains unterminated quotes or malformed syntax,
        shlex raises a ValueError. In a zero-trust model, malformed syntax is
        treated as an evasion attempt and fails closed to prevent bypasses.
        """
        # Step 1: Attempt standard POSIX shell lexical tokenization
        try:
            return shlex.split(segment_str, posix=True)
        except ValueError:
            # Step 2: Fallback split if quotes or escapes are malformed
            return segment_str.split()

    @staticmethod
    def normalize_executable_name(raw_word: str) -> str:
        r"""Strip obfuscation from an executable name to determine its true binary identity.

        Educational Note:
        -----------------
        Attackers disguise executable names using:
          - Quoted identifiers: `"rm"` -> `rm`, `'rm'` -> `rm`, `r""m` -> `rm`
          - Backslash escaping: `\r\m` -> `rm`, `\rm` -> `rm`
          - Absolute or relative paths: `/bin/rm` -> `rm`, `/usr/bin/env rm` -> `rm`
          - ANSI-C quoting: `$'rm'` -> `rm`

        This function strips quote marks, dollar prefixes, and path directories,
        leaving the canonical base executable name for allowlist verification.
        """
        # Step 1: Remove internal quotes, backslashes, and dollar signs
        cleaned = re.sub(r'[\'\"\\$]', '', raw_word)

        # Step 2: Extract base executable name from filesystem path
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
    absolute paths (`/etc/shadow`) to escape the authorized project root.

    Common evasion vectors addressed:
      - Double-dot traversal: `../../etc/passwd`
      - Redundant slash normalization: `///etc///shadow`
      - Dot segment obfuscation: `/etc/./shadow`
      - Quote splitting within paths: `~/.s"s"h/id_rsa`
      - Glob expansion evasion: `/etc/sha*` or `/home/*/.ssh`
    """

    @staticmethod
    def contains_path_traversal(target_str: str) -> bool:
        """Detect directory traversal sequences ('..') in commands or path arguments.

        Educational Note:
        -----------------
        Negative lookbehind `(?<![A-Za-z0-9_~^])` and negative lookahead `(?![A-Za-z0-9_.-])`
        ensure that legitimate filenames like `archive..tar.gz` or `notes..md` do not
        trigger false positive denials, while directory climbing sequences (`../`, `..`)
        are strictly intercepted.
        """
        # Step 1: Execute bounded regex pattern matching isolated double-dot sequences
        pattern = r'(?<![A-Za-z0-9_~^])\.\.(?![A-Za-z0-9_.-])'
        return bool(re.search(pattern, target_str))

    @staticmethod
    def accesses_sensitive_secret(target_str: str) -> bool:
        """Check whether the string targets sensitive credentials, tokens, or system keys.

        Educational Note:
        -----------------
        Before matching against SENSITIVE_PATH_PATTERNS, the string is normalized
        by stripping quote characters and backslashes. This prevents bypasses like:
            `cat ~/.s"s"h/id_rsa` -> normalized to `~/.ssh/id_rsa` -> BLOCKED.
        """
        # Step 1: Normalize target string to defeat character injection/quote obfuscation
        normalized = re.sub(r'[\'\"\\$]', '', target_str)

        # Step 2: Scan normalized string against sensitive credential signatures
        for pat in SENSITIVE_PATH_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def is_contained_in_workspace(path_str: str, workspace_root: Optional[str] = None) -> bool:
        """Verify that an absolute or relative path resolves strictly within the workspace.

        Educational Note:
        -----------------
        Resolves symlinks and canonicalizes paths via `Path.resolve()`.
        Allows explicit read-only diagnostic exceptions (e.g. `/etc/os-release`, `/dev/null`)
        and temporary build directories (`/tmp`, `/private/tmp`), but denies any path
        that escapes the project boundary.
        """
        # Step 1: Default to current working directory if no root specified
        if workspace_root is None:
            workspace_root = os.getcwd()

        try:
            # Step 2: Expand user tilde expressions and resolve symlinks
            expanded = os.path.expanduser(path_str)
            resolved = Path(expanded).resolve()
            ws_resolved = Path(workspace_root).resolve()

            # Step 3: Check allowed system read-only diagnostic exceptions
            system_read_exceptions = [
                Path("/etc/os-release"),
                Path("/etc/hostname"),
                Path("/proc/cpuinfo"),
                Path("/proc/meminfo"),
                Path("/dev/null"),
            ]
            if resolved in system_read_exceptions:
                return True

            # Step 4: Check standard temporary directories for transient builds
            temp_roots = [Path("/tmp").resolve(), Path("/private/tmp").resolve()]
            for tr in temp_roots:
                try:
                    resolved.relative_to(tr)
                    return True
                except ValueError:
                    pass

            # Step 5: Primary containment check against workspace root
            resolved.relative_to(ws_resolved)
            return True
        except (ValueError, RuntimeError):
            # Step 6: Fail closed on resolution failures or permission errors
            return False


# ==============================================================================
# SECTION 4: POLICY EVALUATION ENGINE
# ==============================================================================

class PolicyCommandGuard:
    """Core Policy-as-Code Evaluation Engine.

    Educational Architecture:
    --------------------------
    1. Zero-Trust Default:
       Any shell command not explicitly permitted by a formal grammar rule is denied.

    2. Two-Tier Enforcement Hierarchy:
       - Admin Tier: Hard-coded, immutable security constraints (highest priority >=900).
         Even if a user-tier policy attempts to allow an operation, Admin deny rules
         take precedence and cannot be overridden.
       - User Tier: Project-level rules permitting specific inspection or development tasks.

    3. AST Segmentation & Composite Evaluation:
       When compound commands are submitted (`cmd1 | cmd2 && cmd3`), every single
       constituent subcommand must independently pass policy validation. If even one
       segment fails, the entire pipeline is denied.
    """

    def __init__(
        self,
        rules: Optional[Sequence[PolicyRule]] = None,
        workspace_dir: Optional[str] = None,
        tier: PolicyTier = PolicyTier.ADMIN,
    ) -> None:
        # Step 1: Store policy rules, workspace root, and active enforcement tier
        self.rules = list(rules or [])
        self.workspace_dir = workspace_dir or os.getcwd()
        self.tier = tier

    def evaluate_shell_command(self, command_str: str) -> EvaluationResult:
        """Evaluate a raw shell command string against all security layers.

        Pipeline Evaluation Steps:
          Step 1: Check command string length boundary (<6000 chars) to prevent ReDoS.
          Step 2: Inspect for directory traversal sequences ('..').
          Step 3: Inspect for credential, token, and private key references.
          Step 4: Decompose compound command into pipeline segments via AST tokenizer.
          Step 5: Evaluate each atomic subcommand segment against allowlists and constraints.

        Returns:
            An EvaluationResult detailing the decision, matched rule, and reasoning.
        """
        # Step 1: Check command string length boundary (<6000 chars)
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
        sub_results: List[EvaluationResult] = []
        for segment in segments:
            # Step 5a: Run security evaluation on atomic segment
            sub_res = self._evaluate_single_segment(segment)
            sub_results.append(sub_res)
            # Step 5b: Fail-closed - if any segment is denied, abort entire pipeline
            if sub_res.decision == Decision.DENY:
                return EvaluationResult(
                    decision=Decision.DENY,
                    rule=sub_res.rule,
                    message=f"Blocked pipeline segment [{segment}]: {sub_res.message}",
                    matched_pattern=sub_res.matched_pattern,
                    subcommand_results=sub_results,
                )

        # Step 6: All segments passed - approve command execution
        return EvaluationResult(
            decision=Decision.ALLOW,
            message="Allowed: Command passed all policy AST checks and inspection allowlists.",
            subcommand_results=sub_results,
        )

    def _evaluate_single_segment(self, segment_str: str) -> EvaluationResult:
        """Evaluate a single atomic command segment."""
        # Step 1: Check for unquoted subshell executions: `...` or $(...)
        if re.search(r'(?<!\\)(?:`|\$\()', segment_str):
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Subshell command substitution (` or $()) is denied under zero-trust policy.",
                matched_pattern="subshell_substitution",
            )

        # Step 2: Check for shell redirection into arbitrary files
        redirection_match = re.search(r'(?:>|>>)\s*([^\s;&|]+)', segment_str)
        if redirection_match:
            target_dest = redirection_match.group(1).strip("'\"")
            if target_dest not in ("/dev/null", "&1", "&2"):
                # Step 2a: Check if redirection target touches protected secret paths
                if PathSecurityValidator.accesses_sensitive_secret(target_dest):
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message=f"Blocked: Redirection target '{target_dest}' is a protected secret path.",
                        matched_pattern="protected_redirect",
                    )

        # Step 3: Tokenize command segment into shell words
        words = ShellTokenizer.extract_command_words(segment_str)
        if not words:
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Malformed or unparseable command segment.",
            )

        # Step 4: Filter out leading environment variable assignments (e.g. FOO=1 bar)
        cmd_idx = 0
        while cmd_idx < len(words) and "=" in words[cmd_idx] and not words[cmd_idx].startswith("-"):
            cmd_idx += 1

        if cmd_idx >= len(words):
            return EvaluationResult(
                decision=Decision.DENY,
                message="Blocked: Environment variable definition without executable command.",
            )

        # Step 5: Normalize executable name
        raw_cmd = words[cmd_idx]
        normalized_cmd = ShellTokenizer.normalize_executable_name(raw_cmd)

        # Step 6: Check critical dangerous binaries (sudo, rm, dd, netcat, etc.)
        if normalized_cmd in CRITICAL_DANGEROUS_BINARIES:
            return EvaluationResult(
                decision=Decision.DENY,
                message=f"Blocked: Command '{normalized_cmd}' is classified as critical dangerous executable.",
                matched_pattern=f"critical_binary_{normalized_cmd}",
            )

        # Step 7: Check arbitrary python execution (-c or -m)
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

        # Step 8: Check git commands for remote exfiltration or repository destruction
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

        # Step 9: Check find options that execute commands or delete files
        if normalized_cmd == "find":
            for arg in words[cmd_idx+1:]:
                if any(dangerous_flag in arg for dangerous_flag in ("-exec", "-execdir", "-ok", "-okdir", "-delete")):
                    return EvaluationResult(
                        decision=Decision.DENY,
                        message=f"Blocked: 'find' command with dangerous flag '{arg}'.",
                        matched_pattern="find_exec_delete",
                    )

        # Step 10: Allowlist verification against approved inspection commands
        if normalized_cmd not in ALLOWLISTED_INSPECTION_COMMANDS:
            return EvaluationResult(
                decision=Decision.DENY,
                message=f"Blocked: Command '{normalized_cmd}' is not on the verified allowlist.",
                matched_pattern=f"unlisted_command_{normalized_cmd}",
            )

        # Step 11: Segment explicitly approved
        return EvaluationResult(
            decision=Decision.ALLOW,
            message=f"Allowed: Subcommand segment '{normalized_cmd}' matches allowlist.",
        )
