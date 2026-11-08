#!/usr/bin/env python3
# ==============================================================================
# Policy-as-Code Shell Guard: Policy Specification Generator
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
r"""Generator for the allowlist section of scripts/ethan_gemini_policy.toml.

Why a generator: Gemini CLI 0.65.0 compiles every argsPattern with JS RegExp and rejects any pattern that
matches /\([^)]*[*+?{].*\)[*+?{]/ (isSafeRegExp) or is longer than 2048 chars, so a quantified group such as
(...)* or (?:...)? is impossible.  The allowlist is therefore written as DENY-ONLY rules ("deny unless the
command is inside the grammar", i.e. a negative lookahead) built from unrolled optional groups with empty
alternatives.  The `ethan` launcher (scripts/ethan: ethan_guard_snapshot) copies only `deny` rules into the
admin tier, so an allowlist expressed as deny rules is the only form that survives that snapshot.

What the engine shows the rules (checked in gemini-cli 0.65.0 policy-engine):
  stableStringify(args) = {\0"command":"<JSON text>"\0[,\0"dir_path":"..."\0]}   (keys sorted, each top-level
  pair wrapped in NUL).  A raw NUL can never occur inside a JSON string value, so  "\0  is the unambiguous end
  of the command value.  Quotes inside the command show up as  \"  (backslash + quote), a literal backslash
  as  \\ , newline as  \n .
  An `allow` rule that carries an argsPattern makes checkShellCommand() split the command with the bundled
  tree-sitter bash parser and re-check every sub-command against ALL rules (and a parse error becomes DENY in
  yolo mode).  That allow-all rule (allowRedirection = true) is emitted last.

Run:  python3 scripts/ethan_policy_gen.py --write     (splice into the toml)   |   --check   (CI: toml is current)
"""
import re
import sys
from pathlib import Path

TOML = Path(__file__).resolve().parent / "ethan_gemini_policy.toml"
BEGIN = "# BEGIN GENERATED ALLOWLIST (scripts/ethan_policy_gen.py) - do not edit by hand"
END = "# END GENERATED ALLOWLIST"

SH = '["run_shell_command", "ShellTool"]'
SQ = r"\x27"
DQ = r'\\"'                      # JSON text of a double quote inside the command
NUL = r"\x00"
START = r'^\{\x00"command":"'
WEND = r'(?: |")'                # a command word ends at a space or at the end of the command value
CMDEND = r'"\x00'

# ---------------------------------------------------------------- command names
NAMES = ["ls", "cat", "head", "tail", "wc", "tree", "stat", "file", "pwd", "echo", "printf", "sort", "uniq", "cut", "tr",
         "nl", "diff", "cmp", "du", "df", "ps", "date", "whoami", "uname", "which", "basename", "dirname", "realpath",
         "sha256sum", "md5sum", "seq", "sleep", "true", "false", "nproc", "free", "uptime", "grep", "egrep", "fgrep", "rg",
         "find", "jq", "tar", "git", "python3", "pip", "pip3", "node", "ethan", "sed", "awk", "xargs", "cd", "mkdir",
         "touch", "cp", "mv", "chmod", "pytest", "make", "npm", "nvidia-smi", r"scripts/ethan_capped_run\.sh"]
NAME_ALT = "|".join(NAMES)
ENVNAMES = "FOO|BAR|BAZ|LC_ALL|LANG|TZ|NO_COLOR|CI|PYTHONDONTWRITEBYTECODE|PYTHONUNBUFFERED"
ENVP = r"(?:(?:env |)(?:%s)=[A-Za-z0-9_.-]* |)" % ENVNAMES
CP = r'(?:^\{\x00"command":"|\| |&& )' + ENVP      # a command position (start of the value or after a pipe / &&)

# ---------------------------------------------------------------- paths
WS = r"(?:home/[^/ \"\x27\\]+/workspace|Users/[^/ \"\x27\\]+/workspace)"
ABS_OK = (r"(?:" + WS + r"|tmp|private/tmp|var/folders|private/var/folders|mnt/GameDrive/twu_scratch)(?:[/ \"\x27\\]|$)"
          r"|etc(?:/(?:os-release|hostname|lsb-release)|)[ \"\x27\\]"
          r"|proc/(?:cpuinfo|meminfo|loadavg|version|uptime)[ \"\x27\\]|dev/null[ \"\x27\\]")
ROOTD = r"(?:etc|root|home|var|usr|proc|sys|dev|opt|mnt|boot|bin|sbin|lib|lib64|srv|media|run|Users|Library|System|private|Volumes)(?:/|[ \"\x27\\])"
TMPD = r"(?:tmp|private/tmp|var/folders|private/var/folders)"
DOTDOT = r"(?<![A-Za-z0-9_~^])\.\.(?![A-Za-z0-9_.])"
SECRET_NAMES = (r"\.env(?:\.(?:local|production|prod|development|staging|secret|secrets)|)(?![A-Za-z0-9_.])|\.codex|\.pgpass|/etc/ssl/private|/etc/(?:passwd-|shadow|gshadow|sudoers|polkit-1|crypttab|ssh|wireguard|openvpn|"
                r"NetworkManager/system-connections)|/proc/(?:[^ \"\x27\\]*/|)(?:environ|mem|maps|cmdline|root|cwd|fd|exe|stack|syscall|mountinfo)|"
                r"\.mozilla|google-chrome|chromium|BraveSoftware|\.password-store|\.vault-token|\.local/share/keyrings|\.pypirc|"
                r"\.terraform\.d|\.azure|\.boto|\.s3cfg|\.config/rclone|\.huggingface|\.cache/huggingface|\.ollama|\.openai|\.anthropic|"
                r"\.git/config|\.git/credentials|(?<![A-Za-z0-9_.-])credentials(?:\.json|)[ \"\x27\\]|(?<![A-Za-z0-9_])tokens?\.(?:json|txt|yaml|yml)|"
                r"(?<![A-Za-z0-9_])secrets?\.(?:json|ya?ml|toml|env)|\.ppk|\.pfx|\.kdbx|private[_-]?key|Login Data|"
                r"(?<![A-Za-z0-9_])Cookies[ \"\x27\\]|\.config/[^ \"\x27\\]*(?:token|secret|credential|auth)|\.local/share/[^ \"\x27\\]*(?:token|secret|credential)")
def ci(word):
    """Case-insensitive literal (macOS volumes are case-insensitive by default)."""
    return "".join("[%s%s]" % (c.upper(), c.lower()) if c.isalpha() else re.escape(c) for c in word)


_END = r"[ \"\x27\\]"
PROT = ("(?:(?<![A-Za-z0-9_.-])(?:" + ci("AGENTS.md") + "|" + ci("CLAUDE.md") + "|" + ci("GEMINI.md") + "|" + ci(".gemini") + "(?:/|" + _END + ")|"
        + ci(".git") + "(?:/|" + _END + ")|" + ci(".codex") + "|" + ci(".claude") + "|"
        r"\.ssh|\.aws|\.gnupg|\.config|\.bashrc|\.bash_profile|\.profile|\.zshrc|\.zprofile|\.zshenv|\.pam_environment|\.xinitrc|"
        r"\.local/share|ethan(?:" + _END + r"|$)|archive/[^ \"\x27\\]*policy)"
        r"|" + ci("ethan_") + r"[A-Za-z_]*(?:gemini_policy|policy|guard|alarm|capped_run|sandbox|admin)[A-Za-z_.]*"
        r"|" + ci("ethan_know") + r"\.py"
        r"|policy_(?:bypass_suite|heldout)\.json|check_all_(?:latest\.json|history[A-Za-z._-]*\.jsonl)"
        r"|[A-Za-z0-9_@-]+\.(?:service|timer|socket|path|mount|plist)(?:" + _END + r"|$)|systemd|LaunchAgents|LaunchDaemons)")


def lone(*alts):
    return "(?:" + "|".join(alts) + ")"


def opt(*alts):
    """An optional group with an empty alternative (no quantifier, so Gemini's isSafeRegExp accepts it)."""
    return "(?:" + "|".join(alts) + "|)"


RULES = []   # (comment, toolName_toml, pattern, message)


def rule(comment, pattern, message, tool=SH):
    # `.*` must not run past the command value into description/dir_path text (false denies); NUL ends every value.
    RULES.append((comment, tool, pattern.replace(".*", r"[^\x00]*"), message))


# ======================================================================= 0. shape + name allowlist
rule("args must start with the command key (extra keys sorted before it would hide it from the anchored rules)",
     r'^(?!\{\x00"command":")', "Blocked: malformed shell call.")
rule("first word must be an allowlisted read-only/workspace command",
     START + r"(?!" + ENVP + "(?:" + NAME_ALT + ")" + WEND + ")",
     "Blocked: this command is not on the Ethan allowlist (read-only inspection, git read commands, workspace build/test). Use read_file/write_file/replace, or ask Ethan to run it himself.")
rule("every command after a pipe or && must also be allowlisted",
     r"(?:\| |&& )(?!" + ENVP + "(?:" + NAME_ALT + ")" + WEND + ")",
     "Blocked: this command is not on the Ethan allowlist (read-only inspection, git read commands, workspace build/test). Use read_file/write_file/replace, or ask Ethan to run it himself.")
rule("dir_path (working directory) must be inside the workspace",
     r'\x00"dir_path":"(?!(?:/(?:' + WS + "|" + TMPD + r')(?:/|")|[A-Za-z0-9_.][^"\\]*"))',
     "Blocked: the working directory must be inside the workspace.")
rule("dir_path traversal", r'\x00"dir_path":"[^\x00]*' + DOTDOT, "Blocked: '..' path traversal. Use paths inside the workspace.")
rule("command longer than 6000 characters", START + r"[^\x00]{6000}", "Blocked: command too long to check. Put the work in a script file in the workspace.")

# ======================================================================= 1. quote-aware lexical gate
PL = r"[^\x27\"\\\x00]*"
SEG = r"(?:\x27[^\x27\x00]*\x27" + PL + r"|\\\"[^\\\"\x00]*\\\"" + PL + r"|)"
SCAN = START + r"(?!python3 -c )" + PL + SEG * 6
F = lone(
    r"[;{}()`!<\x7f]",
    r"\\(?!\")",
    r"\$(?!HOME(?:/workspace|[ \"])|(?:USER|PWD)[ \"/])",
    r"\>(?!&[12]|/dev/null|>? ?[A-Za-z0-9_][A-Za-z0-9_./+-]*\"\x00)",
    r"(?<! )\||\|(?! )",
    r"(?<![ &>])&|(?<![&>])&(?!& )",
    r"(?<![A-Za-z0-9_)\]])~(?!/workspace[/ \"])",
    r"(?<![^ ])#",
    r"[?\[\]]",
    r"\*(?!\.(?:py|md|txt|json|jsonl|toml|csv|tsv|log|sh|js|ts|html|css|yaml|yml|cfg|ini|c|h|cpp|rs|go|java|rb|xml|rst|ipynb)(?:[ \"]|\x27))",
    r"\x27(?![^\x27\x00]*\x27)",
    r"\\\"(?![^\\\"\x00]*\\\")",
    r"\\\"[^\\\"\x00]*[$`]",
    r"(?<=[ =])(?:\x27(?=/" + ROOTD + r")|\\\"(?=/" + ROOTD + r")|)/(?!" + ABS_OK + ")",
)
rule("shell metacharacters outside quotes (substitution, redirection, chaining, globs, unbalanced quotes) are denied; only ' | ', ' && ', 2>&1, >/dev/null and a final '> relative-file' are structural",
     SCAN + F,
     "Blocked: shell syntax that cannot be checked (substitution, subshell, redirection, ';', glob, unbalanced quote, etc.). Use one plain command, optionally joined with ' | ' or ' && '.")
SEGF = r"(?:\x27[^\x27\x00]*\x27" + PL + r"|\\\"[^\\\"\x00]*\\\"" + PL + r")"
rule("more than six quoted pieces cannot be scanned",
     START + r"(?!python3 -c )" + PL + SEGF * 6 + r"(?:\x27|\\\")",
     "Blocked: too many quoted pieces to check. Simplify the command.")

# ======================================================================= 2. paths: absolute, parent, secrets, protected
rule("parent-directory traversal", START + r".*" + DOTDOT,
     "Blocked: '..' path traversal. Use paths inside the workspace.")
rule("credential and secret paths (shell)", START + r".*(?:" + SECRET_NAMES + ")",
     "Blocked: this path holds credentials or secrets. Ask Ethan to run this himself if it is really needed.")
# 2026-11-02 (locate/read-my-files work): private data dirs are unreadable to the CLI by shell as well as file tools.
# A directory component at the start of a value / after a space, quote, '=' , './' or the workspace root.
PRIVN = (r"(?:profile|business|grants|apply|backups|\.evidence|private|Company_Documents|receipts|invoices|clients|"
         r"\.stversions|exports|data/sessions|data/session_archive|data/malakopia)")
PRIV = r"(?:^|[ \"=]|\./|workspace/)" + PRIVN + r"(?:/|\"|$)"
PRIV_CD = r"(?:cd|pushd) +(?:\./|)" + PRIVN + r"(?: |/|\"|$)"
rule("private data directories (shell)", START + r".*(?:" + PRIV + "|" + PRIV_CD + ")",
     "Blocked: this folder holds private data (profile, business, grants, backups, evidence). Ask Ethan to run this himself if it is really needed.")
rule("globbing hidden names", START + r"(?!python3 -c ).*(?<=[ /])\.[^ \x27\"]*\*",
     "Blocked: glob over hidden names can reach secrets.")
rule("bare /etc and bare $HOME may only be listed (ls/stat/df/tree/file/echo), not read recursively",
     CP + r"(?:grep|egrep|fgrep|rg|find|cat|head|tail|diff|cmp|tar|sed|awk|jq|sort|wc|nl|cut|xargs|du|sha256sum|md5sum|git|python3|uniq|tr|cp|mv|pytest|make|npm) .*(?:(?<=[ =])/etc|\$HOME)(?:[ \"\x27\\]|$)",
     "Blocked: path outside the workspace. Only workspace paths, /tmp and a few read-only system files are available.")
rule("mutating commands may only touch unprotected workspace paths",
     CP + r"(?:cp|mv|touch|mkdir|chmod|pytest) .*" + PROT,
     "Blocked: this path is protected (policy, guards, instruction files, .gemini, .git, startup files, service units).")
rule("mutating commands take no glob (a glob could name a protected file)",
     CP + r"(?:cp|mv|touch|mkdir|chmod|pytest) .*\*", "Blocked: no globs in commands that change files. List the file names.")
rule("sed -i takes no glob", CP + r"sed .*(?<= )-[A-Za-z]*i[A-Za-z]* .*\*", "Blocked: no globs in commands that change files. List the file names.")
rule("sed -i on protected files", CP + r"sed .*(?<= )-[A-Za-z]*i[A-Za-z]* .*" + PROT,
     "Blocked: this path is protected (policy, guards, instruction files, .gemini, .git, startup files, service units).")
rule("redirect target protected", r">>? ?[^ \"]*" + PROT,
     "Blocked: this path is protected (policy, guards, instruction files, .gemini, .git, startup files, service units).")
rule("mutating commands and redirects stay inside the workspace (no /tmp, no absolute outside)",
     CP + r"(?:cp|mv|touch|mkdir|chmod|pytest) .*(?:(?<=[ =])|(?<=[ =]\x27)|(?<=[ =]\\\"))/(?!(?:" + WS + "|" + TMPD + ")/)",
     "Blocked: writes are limited to the workspace.")

# ======================================================================= 3. per-command argument rules
FLAGW = r"(?: |\"|=|$)"
rule("find: no -exec/-delete/-fprint family", CP + r"find .*(?<= )-(?:exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)" + WEND,
     "Blocked: find with -delete/-exec or file output. Ask Ethan to run this himself if it is really needed.")
rule("sort: no output file / external program", CP + r"sort .*(?<= )(?:-[A-Za-z]*[oT][A-Za-z]*|--output|--compress-program|--temporary-directory|--files0-from|--random-source)" + FLAGW,
     "Blocked: sort option that writes files or runs programs.")
rule("tree: no output file", CP + r"tree .*(?<= )(?:-[A-Za-z]*o[A-Za-z]*|--output)" + FLAGW, "Blocked: tree option that writes a file.")
rule("tail: no follow", CP + r"tail .*(?<= )(?:-[A-Za-z0-9]*[fF][A-Za-z0-9]*|--follow|--retry)" + FLAGW, "Blocked: tail -f never returns.")
rule("file: no magic compile", CP + r"file .*(?<= )(?:-C|--compile)" + FLAGW, "Blocked: file option that writes a file.")
rule("rg: no preprocessor", CP + r"rg .*(?<= )--(?:pre|pre-glob|hostname-bin)" + FLAGW, "Blocked: rg option that runs a program.")
rule("date: no clock setting", CP + r"date .*(?<= )(?:-s|--set)" + FLAGW, "Blocked: date option that changes the clock.")
rule("sleep takes only seconds", CP + r"sleep(?! [0-9.]+" + WEND + ")", "Blocked: sleep takes only a number.")
UF = r"(?: -[A-Za-z]+| -[fsw] [0-9]+|)"
rule("uniq: at most one input operand, no output file",
     CP + r"uniq(?!" + UF * 3 + r"(?: [A-Za-z0-9_./-]+|)(?:\"| \| | && ))", "Blocked: uniq with an output file.")
rule("mkdir only -p", CP + r"mkdir .*(?<= )-(?!p" + WEND + ")", "Blocked: unsupported mkdir option.")
rule("touch takes only file names", CP + r"touch .*(?<= )-", "Blocked: unsupported touch option.")
CPFL = r"-(?:[rRapnvfu]+|T|-)"
rule("cp options", CP + r"cp .*(?<= )-(?!(?:[rRapnvfu]+|T|-)" + WEND + ")", "Blocked: unsupported cp option.")
rule("mv options", CP + r"mv .*(?<= )-(?!(?:[nvfu]+|T|-)" + WEND + ")", "Blocked: unsupported mv option.")
rule("chmod only executable bit / ordinary file modes, no options",
     CP + r"chmod(?! (?:\+x|u\+x|a\+x|755|644|700|600|750|640|555|444)" + WEND + ")", "Blocked: chmod is limited to +x and ordinary file modes.")
rule("chmod no options", CP + r"chmod .*(?<= )-", "Blocked: unsupported chmod option.")
rule("cd takes one workspace-relative directory",
     CP + r"cd(?! [A-Za-z0-9_@+.][A-Za-z0-9_@+./-]*(?:\"| \| | && ))", "Blocked: cd takes one relative directory.")
rule("hostname/tar/pip/node/npm/make/pytest/ethan forms",
     CP + r"tar(?! -?[tvzjJf]*t[tvzjJf]*" + WEND + ")", "Blocked: tar is limited to listing (tf).")
rule("tar: no extra options", CP + r"tar [^ ]+ .*(?<= )-", "Blocked: tar is limited to listing (tf).")
rule("pip: read-only subcommands", CP + r"pip3?(?! (?:list|show|freeze|check|--version)" + WEND + ")", "Blocked: pip is limited to list/show/freeze/check.")
rule("pip list: no index queries", CP + r"pip3? .*(?<= )-(?:-outdated|o|-uptodate|u|-index-url|i|-extra-index-url|-find-links|f)" + FLAGW,
     "Blocked: that pip option contacts a package index.")
rule("node: version only", CP + r"node(?! (?:--version|-v)" + WEND + ")", "Blocked: node is limited to --version.")
rule("npm: fixed scripts", CP + r"npm(?! (?:run (?:build|test|lint|check|typecheck)|test)" + WEND + ")", "Blocked: npm is limited to run build/test/lint.")
rule("make: fixed targets", CP + r"make(?! (?:test|check|lint|build|all)" + WEND + ")", "Blocked: make is limited to test/check/lint/build.")
rule("ethan: health and guarded git only",
     CP + r"ethan(?! (?:health|--version|git (?:status|begin|stage|verify|finish|undo-last))" + WEND + ")", "Blocked: ethan is limited to health and the guarded git commands.")
rule("capped run: only unit tests", CP + r"scripts/ethan_capped_run\.sh(?! python3 (?:-B |)-m (?:unittest|pytest)" + WEND + ")",
     "Blocked: the capped runner is limited to unittest/pytest.")
rule("nvidia-smi: query only",
     CP + r"nvidia-smi(?!" + opt(r" --query-gpu=[a-z._,]+", r" --query-compute-apps=[a-z._,]+", r" --format=csv[a-z,]*", r" -q", r" -L") * 4 + r"(?:\"| \| | && ))",
     "Blocked: nvidia-smi is limited to read-only queries.")
rule("xargs: only read-only helpers",
     CP + r"xargs(?!" + opt(r" -0", r" -r", r" -n [0-9]+") * 3 + r" (?:echo|cat|head|tail|wc|grep|egrep|fgrep|rg|ls|stat|file|sha256sum|md5sum|sort|basename|dirname)" + WEND + ")",
     "Blocked: xargs may only run read-only helper commands.")

# ---- sed: fixed safe script grammar
SEDOPT = r"(?:-[nEri]+ |)"
SED_SCRIPT = (r"(?:\x27(?:[0-9]+(?:,(?:[0-9]+|\$)|)[pd]|\$p|/[^/\x27;\\]*/[pd]|s/[^/\x27;\\]*/[^/\x27;\\]*/[gpIi0-9]*)\x27|s/[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*/[gpIi0-9]*|[0-9]+(?:,[0-9]+|)[pd])")
rule("sed: options and script must match the safe grammar (no e/w/r commands)",
     CP + r"sed(?! " + SEDOPT * 3 + SED_SCRIPT + r"(?: [A-Za-z0-9_./ -]+|)(?:\"| \| | && ))",
     "Blocked: sed is limited to simple p/d/s scripts on files.")
rule("sed: only known flags after the script", CP + r"sed .*(?<= )-(?![nEri]+" + WEND + ")", "Blocked: unsupported sed option.")

# ---- awk: print-style programs only
AWKBODY = r"[A-Za-z0-9_ $.,+*/%=!{}()\[\];:-]*"
rule("awk: simple programs only (no system/getline/pipes/redirection/dq strings)",
     CP + r"awk(?! (?:-F(?: ?\x27[^\x27\x00]*\x27| ?[^ \x27\"\\-]+) |)\x27" + AWKBODY + r"\x27(?: [A-Za-z0-9_./ -]+|)(?:\"| \| | && ))",
     "Blocked: awk is limited to simple print programs.")
rule("awk: banned functions", CP + r"awk .*(?:system|getline|ENVIRON|close|fflush|PROCINFO|@include|RS=)",
     "Blocked: awk program can run commands or read the environment.")

# ---- jq
rule("jq: read-only filters", CP + r"jq(?!" + opt(r" -[rcSeMCnsR]+") * 3 + r" (?:\x27[^\x27\x00$@]*\x27|[A-Za-z0-9_.\[\]-]+)(?: [A-Za-z0-9_./-]+|)(?:\"| \| | && ))",
     "Blocked: jq is limited to simple filters on files.")
rule("jq: no environment/input functions", CP + r"jq .*(?<![A-Za-z0-9_])(?:env|ENV|input|inputs|input_filename|import|include|debug|stderr|halt|halt_error|getpath|\$__)(?![A-Za-z0-9_])",
     "Blocked: jq function can read the environment or other files.")

# ======================================================================= 4. git: fixed read-only subcommands and flags
GIT_SUB = (r"(?:status|diff|log|show|blame|ls-files|rev-parse|rev-list|describe|shortlog|cat-file|ls-tree|diff-tree|name-rev|"
           r"show-ref|count-objects|merge-base|grep)")
GIT_BR = r"branch" + opt(r" -a", r" -r", r" -v", r" -vv", r" --show-current", r" --list") * 3 + r"(?:\"| \| | && )"
GIT_TAG = r"tag(?: -l| --list|)(?:\"| \| | && )"
rule("git: only read-only subcommands (no global options except '-C .')",
     CP + r"git(?! (?:-C \. |--no-pager |)(?:-C \. |--no-pager |)(?:" + GIT_SUB + WEND + "|" + GIT_BR + "|" + GIT_TAG + "))",
     "Blocked: this git command changes the repository or reaches the network. Use the ethan git guard commands instead.")
GIT_SHORT = (r"[0-9]+|C \.|[pslarvuhbzwiImtne]+|u(?:no|all|normal)|U[0-9]+|M|L|S[^ ]*|G[^ ]*")
GIT_LONG = (r"no-pager|oneline|stat(?:=[0-9,]+|)|name-only|name-status|short|porcelain(?:=v[12]|)|branch|shortstat|numstat|summary|no-color|color|graph|"
            r"decorate|all|follow|cached|staged|no-merges|merges|reverse|abbrev-commit|abbrev=[0-9]+|relative|first-parent|topo-order|date-order|"
            r"since|until|after|before|author|committer|grep|format|pretty|max-count=[0-9]+|diff-filter=[A-Za-z]+|date=[a-z0-9:-]+|show-current|"
            r"list|ignored|untracked-files(?:=[a-z]+|)|count|no-patch|root|cc|skip=[0-9]+|max-parents=[0-9]+|min-parents=[0-9]+|no-abbrev|"
            r"full-history|simplify-by-decoration|exit-code|quiet|no-renames|find-renames|word-diff|ignore-all-space|ignore-space-change|"
            r"unified=[0-9]+|tags|heads|remotes|verify|short=[0-9]+|show-toplevel|abbrev-ref|is-inside-work-tree|contains|always|line-number|"
            r"files-with-matches|ignore-case|word-regexp|fixed-strings|extended-regexp|invert-match|")
GIT_FLAG = r"(?:" + GIT_SHORT + r"|-(?:" + GIT_LONG + r"))"
rule("git: only whitelisted flags (no -c, --output, --exec-path, --no-index, --ext-diff, -O, URLs)",
     CP + r"git .*(?<= )-(?!" + GIT_FLAG + r"(?: |\"|=|$))", "Blocked: git option not on the read-only whitelist.")
rule("git: arguments must not be URLs or remotes", CP + r"git .*(?::\/\/|git@|ssh:)", "Blocked: git network access.")

# ======================================================================= 5. python
PYPATH = r"[A-Za-z0-9_\u00a1-\uffff][A-Za-z0-9_./\u00a1-\uffff-]*"
PYKEY = r"[A-Za-z0-9_ \u00a1-\uffff-]+"


def pygroups(q, nl):
    """Python-source regex groups {selector: alternatives}; q is the regex for ONE python quote character, nl for a python '\\n'.
    One deny rule per group keeps every pattern under Gemini's 2048-character limit."""
    P = q + PYPATH + q
    K = q + PYKEY + q
    S = q + r"[A-Za-z0-9_ .,:/\u00a1-\uffff-]*" + q
    OP = r"open\(" + P + opt(r", " + q + "(?:r|rb)" + q) + r"\)"
    return {
        r"import csv; ": [
            r"import csv; print\((?:sum|max|min)\((?:int|float)\(x\[" + K + r"\]\) for x in csv\.DictReader\(" + OP + r"\)\)\)",
            r"import csv; print\(len\(list\(csv\.DictReader\(" + OP + r"\)\)\)\)"],
        r"import json; ": [
            r"import json; print\(json\.load\(" + OP + r"\)" + opt(r"\[" + K + r"\]", r"\[[0-9]+\]") * 3 + r"\)",
            r"import json; print\(json\.dumps\(\{\}\)\)"],
        r"print\(": [
            r"print\(max\(len\(l\) for l in " + OP + r"\.read\(\)\.splitlines\(\)\)\)",
            r"print\(max\(len\(l\.rstrip\(" + q + nl + q + r"\)\) for l in " + OP + r"\)\)",
            r"print\(sum\(int\(x\) for x in " + OP + r"\.read\(\)\.split\(\)\)\)",
            r"print\(sum\(1 for l in " + OP + r"\)\)",
            r"print\(len\(" + OP + r"\.read\(\)\.splitlines\(\)\)\)",
            r"print\(" + OP[:-2] + opt(r", encoding=" + q + r"utf-8" + q) + r"\)\.read\(\)\)",
            r"print\((?:[0-9 +*/()-]+|" + S + r")\)"],
        r"import (?:re|ast); ": [
            r"import re; print\(re\.compile\(" + S + r"\)\.pattern\)",
            r"import ast; print\(ast\.literal_eval\(" + q + r"[0-9,\[\] ]*" + q + r"\)\)"],
    }


Q_A = r"\x27"                                  # python quote inside a dq-wrapped body
Q_B = r"(?:\x27\\\"\x27\\\"\x27)"              # python quote inside a sq-wrapped body:  '"'"'
NL = r"\\\\n"                                  # python \n (backslash n) as JSON text (backslash is doubled)
rule("python3: allowed forms (script file, -m unittest|pytest|py_compile|json.tool, --version, or one strict -c template)",
     CP + r"python3(?! (?:--version|-V)" + WEND + r"| (?:-B |-u |)(?:-B |)(?:-m (?:unittest|pytest|py_compile)" + WEND +
     r"|(?:\./|)[A-Za-z0-9_][A-Za-z0-9_./-]*\.py" + WEND + r")| -c )",
     "Blocked: python3 is limited to workspace scripts, unittest/pytest/py_compile, --version and a few strict one-liners. Put code in a script file in the workspace.")
PYMSG = ("Blocked: python -c is limited to a few strict read-only one-liners (print/sum/max/len over open('<file>'), csv.DictReader, json.load). "
         "Put code in a script file in the workspace.")
for _wrap_open, _wrap_close, _q, _lead in ((r"\\\"", r"\\\"", Q_A, r"(?=\\\")"), (r"\x27", r"\x27", Q_B, r"(?=\x27)")):
    for _sel, _alts in pygroups(_q, NL).items():
        rule("python3 -c strict template group %s (%s wrapper)" % (_sel, "dq" if _q == Q_A else "sq"),
             START + r"python3 -c " + _lead + r"(?=" + _wrap_open + _sel + r")(?!" + _wrap_open + "(?:" + "|".join(_alts) + ")" + _wrap_close + CMDEND + ")",
             PYMSG)
    rule("python3 -c: unknown program shape (%s wrapper)" % ("dq" if _q == Q_A else "sq"),
         START + r"python3 -c " + _lead + r"(?!" + _wrap_open + r"(?:import (?:csv|json|re|ast); |print\())", PYMSG)
rule("python3 -c only as the first plain command (not after a pipe, not behind an env prefix)",
     r"(?:\| |&& )" + ENVP + r"python3 .*-c |" + START.replace("^", "^") + r"(?:env |)[A-Z_]+=[^ ]* python3 .*-c ",
     "Blocked: python -c is only allowed as a single plain command.")
rule("python3 -c: neither quote style", START + r"python3 -c (?!\\\"|\x27)", "Blocked: python -c needs a quoted program.")
rule("running guard scripts: only the guarded git subcommands",
     CP + r"python3 .*ethan_(?!git_guard\.py (?:status|begin|stage|verify|finish|undo-last)" + WEND + r")[A-Za-z_]*(?:policy|guard|alarm|sandbox|capped_run|admin)[A-Za-z_]*\.py",
     "Blocked: guard and policy scripts cannot be run from the model.")

# ---- knowledge index (scripts/ethan_know.py): read-only subcommands only; build (writes data/knowledge/) is never reachable.
KQ = r"(?:\x27[^\x27\x00]*\x27|\\\"[^\\\"\x00]*\\\"|[A-Za-z0-9_.-]+)"
KOPT = opt(r" --class (?:code|docs|research|policy|lesson|failure|license)", r" --k [0-9]+", r" --json") * 3
rule("ethan_know.py: only read-only search/answer-pack/stats/verify/freshness (build and any other mention of the file are denied)",
     r"ethan_know(?!\.py (?:(?:search|answer-pack) " + KQ + KOPT + r"|(?:stats|verify|freshness)" + opt(r" --json") + r")(?:\"| \| | && ))",
     "Blocked: the knowledge tool may only be run as 'python3 scripts/ethan_know.py search|answer-pack \"QUERY\" [--class C] [--k N]' or stats/verify/freshness. Building the index is done by Magi, not the CLI.")

# ---- wiring sheet (scripts/enki_wiring_sheet.py): read-only show/find/gaps/summary only; build (writes data/tools/) is never reachable.
rule("enki_wiring_sheet.py: only show/find/gaps/summary (build, --check and any other mention of the file are denied)",
     r"enki_wiring_sheet(?!\.py (?:(?:show|find) " + KQ + r"|summary|gaps" + opt(r" --limit [0-9]+", r" --status (?:FLOATING|PARTIAL)", r" --missing [a-z_]+") * 3 + r")(?:\"| \| | && ))",
     "Blocked: the wiring sheet may only be run as 'python3 scripts/enki_wiring_sheet.py show ID|NAME', 'find TEXT', 'gaps [--limit N] [--status S] [--missing M]' or 'summary'. Rebuilding it is done by Magi, not the CLI.")

# ---- split tool (scripts/ethan_split.py): a closed chain of single-step subcommands. Safe by construction: it reads the project, writes only
# under the split_work scratch folder, copies and never moves or deletes. Anything but these subcommands (or any extra argument) is denied.
rule("ethan_split.py: only status/plan/copy-code/copy-vault/verify/report and classify [one relative path]",
     r"ethan_split(?!_plan)(?!\.py (?:(?:status|plan|copy-code|copy-vault|verify|report)|classify(?: [A-Za-z0-9_@+][A-Za-z0-9_./@+-]*|))(?:\"| \| | && ))",
     "Blocked: the split tool may only be run as 'python3 scripts/ethan_split.py status|classify [PATH]|plan|copy-code|copy-vault|verify|report'. It copies; it never moves or deletes.")

# ======================================================================= 6. file tools
FT = '["read_file", "read_many_files", "list_directory", "glob", "search_file_content", "grep_search", "write_file", "replace"]'
READ_T = '["read_file", "read_many_files", "list_directory", "glob", "search_file_content", "grep_search"]'
WRITE_T = '["write_file", "replace"]'
FT_ABS = (r"/(?:" + WS + r"|" + TMPD + r"|mnt/GameDrive/twu_scratch)(?:/|\")|/etc/(?:os-release|hostname|lsb-release)\"|/proc/(?:cpuinfo|meminfo|loadavg|version|uptime)\"")
rule("read tools: path keys must be workspace-relative or an allowed absolute path",
     r'\x00"(?:file_path|dir_path|path)":"(?!' + FT_ABS + r")[/~$\\]", "Blocked: path outside the workspace.", READ_T)
rule("glob: absolute patterns", r'\x00"pattern":"(?!' + FT_ABS + r")[/~$\\]", "Blocked: path outside the workspace.", '["glob"]')
rule("read_many_files: path arrays", r'\x00"(?:include|paths|exclude)":\[[^\x00]*?(?:\[|,)"(?!' + FT_ABS + r")[/~$\\]", "Blocked: path outside the workspace.", READ_T)
rule("file tools: '..' in a path key", r'\x00"(?:file_path|dir_path|path|paths|include|pattern|directory)":[^\x00]*' + DOTDOT, "Blocked: '..' path traversal. Use paths inside the workspace.", FT)
rule("file tools: more secret paths (read side and path keys)", r'\x00"(?:file_path|dir_path|path|paths|include|pattern|exclude|directory)":[^\x00]*(?:' + SECRET_NAMES + ")",
     "Blocked: this path holds credentials or secrets. Ask Ethan to run this himself if it is really needed.", FT)
rule("file tools: private data directories", r'\x00"(?:file_path|dir_path|path|paths|include|exclude|directory)":[^\x00]*' + PRIV.replace("(?:^|", '(?:"|'),
     "Blocked: this folder holds private data (profile, business, grants, backups, evidence). Ask Ethan to run this himself if it is really needed.", FT)
rule("file tools: private data directories in a glob pattern (slash form only; a bare word is a search term)",
     r'\x00"pattern":"(?:[^\x00]*(?:[ =]|\./|\*/|workspace/|)|)' + PRIVN + "/",
     "Blocked: this folder holds private data (profile, business, grants, backups, evidence). Ask Ethan to run this himself if it is really needed.", FT)
rule("write tools: target must be an unprotected workspace file",
     r'\x00"file_path":"(?!(?:/(?:' + WS + "|" + TMPD + r")/|(?:\./|)[A-Za-z0-9_@+.-]))", "Blocked: writing outside the workspace. Write only inside the workspace.", WRITE_T)
rule("write tools: protected targets", r'\x00"file_path":"[^"\x00]*' + PROT,
     "Blocked: this path is protected (policy, guards, instruction files, .gemini, .git, startup files, service units).", WRITE_T)
rule("model memory persistence", r"", "Blocked: persistent memory writes are not allowed from the local model.", '["save_memory"]')


def build_block():
    out = [BEGIN, "# Primary control: deny-only negative lookaheads (see scripts/ethan_policy_gen.py docstring).",
           '# Guarded git commands the grammar allows: "ethan git status" "ethan git begin" "ethan git stage" "ethan git verify" "ethan git finish" "ethan git undo-last"', ""]
    for comment, tool, pat, msg in RULES:
        assert "'" not in pat, pat[:80]
        assert len(pat) < 2048, (len(pat), comment)
        assert not re.search(r"\([^)]*[*+?{].*\)[*+?{]", pat), "isSafeRegExp would reject: " + comment
        out.append("# " + comment)
        out.append("[[rule]]")
        out.append("toolName = " + tool)
        if pat:
            out.append("argsPattern = '" + pat + "'")
        out.append('decision = "deny"')
        out.append("priority = 900")
        out.append('denyMessage = "' + msg.replace('"', "'") + '"')
        out.append("")
    out += [
        "# --- allow-all shell (user tier): makes the engine split the command with its tree-sitter bash parser and re-check",
        "# every sub-command against all deny rules above; a parse error is DENY.  Everything dangerous was denied above.",
        "[[rule]]",
        "toolName = " + SH,
        "argsPattern = '^\\{\\x00\"command\":\"'",
        'decision = "allow"',
        "priority = 800",
        "allowRedirection = true",
        "",
        END,
    ]
    return "\n".join(out) + "\n"


def main(argv):
    block = build_block()
    text = TOML.read_text(encoding="utf-8")
    if BEGIN in text and END in text:
        pre = text[:text.index(BEGIN)]
        post = text[text.index(END) + len(END):].lstrip("\n")
        new = pre + block + ("\n" + post if post else "")
    else:
        new = None
    if "--check" in argv:
        sys.exit(0 if new == text else 1)
    if "--write" in argv:
        if new is None:
            sys.exit("markers missing in toml")
        TOML.write_text(new, encoding="utf-8")
        print("written", len(RULES), "rules")
    else:
        print(block)


if __name__ == "__main__":
    main(sys.argv[1:])
