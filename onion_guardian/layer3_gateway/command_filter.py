"""
onion_guardian.layer3_gateway.command_filter - command filtering engine.

Layer 3 command filtering is the last defense line before actual execution.

Protection goals:
- prevent raw shell passthrough
- block proxy and tunnel installation plus reverse shells
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any


@dataclass
class FilterResult:
    """Filtering result."""
    allowed: bool
    original: str
    filtered: str
    blocked_segments: list[str]
    reason: str


class CommandFilter:
    """
    Command filtering engine.

    Filtering pipeline: whitelist commands -> inspect arguments -> enforce
    policy-specific output constraints. Supports both shell-command filtering
    and Python code safety checks.

    Additional whitelist or blacklist entries can be injected through the
    constructor for environment-specific adaptation.
    """

    def __init__(
        self,
        extra_whitelist: set[str] | None = None,
        remove_from_whitelist: set[str] | None = None,
        extra_global_blacklist: list[tuple[re.Pattern, str]] | None = None,
    ):
        # Command allowlist.
        # Only these commands may execute directly.
        self.command_whitelist: set[str] = {
            # File operations.
            "ls", "cat", "head", "tail", "wc", "sort", "uniq",
            "find", "grep", "egrep", "fgrep", "awk", "sed",
            "cp", "mv", "rm", "mkdir", "rmdir", "touch",
            "chmod", "file", "stat", "du", "df",
            "tar", "gzip", "gunzip", "zip", "unzip",

            # Text processing.
            "echo", "printf", "tr", "cut", "paste", "tee",
            "diff", "patch", "jq", "yq",

            # Developer tools.
            "python3", "python", "pip", "pip3",
            "node", "npm", "npx",
            "rustc", "cargo",
            "go",
            "gcc", "g++", "make", "cmake",
            "git",

            # Safe subset of system information commands.
            "date", "cal", "uname", "whoami", "pwd", "env",
            "which", "type", "basename", "dirname", "realpath",
            "true", "false", "test",
        }

        # Command-specific denylist.
        self._dangerous_arg_patterns: list[tuple[str, re.Pattern, str]] = [
            # rm: do not allow deleting the filesystem root.
            ("rm", re.compile(r'-[a-zA-Z]*r[a-zA-Z]*f.*\s+/($|\s)'), "rm -rf / is not allowed"),
            ("rm", re.compile(r'-[a-zA-Z]*f[a-zA-Z]*r.*\s+/($|\s)'), "rm -fr / is not allowed"),

            # chmod: block 777 and SUID.
            ("chmod", re.compile(r'\b777\b'), "Setting 777 permissions is not allowed"),
            ("chmod", re.compile(r'\+s\b'), "Setting SUID is not allowed"),

            # git: do not allow force pushes.
            ("git", re.compile(r'push\s+.*--force'), "Force pushes are not allowed"),

            # pip: block insecure package sources.
            ("pip", re.compile(r'install\s+.*--index-url\s+http://'), "Installing from HTTP package indexes is not allowed"),
            ("pip3", re.compile(r'install\s+.*--index-url\s+http://'), "Installing from HTTP package indexes is not allowed"),

            # curl/wget piped into a shell.
            ("curl", re.compile(r'\|\s*(ba)?sh'), "curl | sh is not allowed"),
            ("wget", re.compile(r'-O\s*-\s*\|\s*(ba)?sh'), "wget | sh is not allowed"),
        ]

        # Global denylist patterns.
        self._global_blacklist: list[tuple[re.Pattern, str]] = [
            # Reverse shells.
            (re.compile(r'/dev/tcp/'), "Reverse shell pattern: /dev/tcp"),
            (re.compile(r'/dev/udp/'), "Reverse shell pattern: /dev/udp"),
            (re.compile(r'bash\s+-i\s+>&'), "Reverse shell pattern: bash -i"),
            (re.compile(r'nc\s+.*-e\s+/bin/'), "Reverse shell pattern: nc -e"),

            # Fork bombs.
            (re.compile(r':\(\)\{\s*:\|:'), "Fork bomb"),

            # Internal network reconnaissance.
            (re.compile(r'\bnmap\b'), "Network scan: nmap"),
            (re.compile(r'\bnetstat\b'), "Network information: netstat"),
            (re.compile(r'\bss\s+-[a-z]*[tl]'), "Network information: ss"),
            (re.compile(r'\barp\s+-a'), "Network information: arp"),
            (re.compile(r'\btraceroute\b'), "Network reconnaissance: traceroute"),

            # Proxy and tunnel tooling.
            (re.compile(r'\b(v2ray|xray|clash|trojan)\b', re.I), "Proxy tool"),
            (re.compile(r'\b(wireguard|openvpn|wg)\b', re.I), "VPN tool"),
            (re.compile(r'\b(frp|frpc|frps|ngrok|nps)\b', re.I), "Tunnel tool"),
            (re.compile(r'\bsocat\b.*\bexec\b', re.I), "Socat exec"),

            # Privilege escalation.
            (re.compile(r'\bsudo\b'), "Privilege escalation: sudo"),
            (re.compile(r'\bsu\s+-'), "Privilege escalation: su"),
            (re.compile(r'\bnsenter\b'), "Container escape: nsenter"),
            (re.compile(r'\bchroot\b'), "Privilege escalation: chroot"),

            # Destructive system operations.
            (re.compile(r'\bmkfs\b'), "Filesystem formatting"),
            (re.compile(r'\bdd\s+if='), "Block device write"),
            (re.compile(r'\b(shutdown|reboot|halt|poweroff)\b'), "System shutdown"),

            # Key and certificate access.
            (re.compile(r'cat\s+.*\.(key|pem|cert|crt)'), "Key file read"),
            (re.compile(r'cat\s+.*/\.ssh/'), "SSH key read"),
            (re.compile(r'cat\s+.*/etc/shadow'), "/etc/shadow read"),

            # Environment leakage.
            (re.compile(r'\bprintenv\b'), "Environment variable disclosure"),
            (re.compile(r'cat\s+/proc/\d+/environ'), "Process environment disclosure"),
        ]

        # Merge user customizations.
        if extra_whitelist:
            self.command_whitelist |= extra_whitelist
        if remove_from_whitelist:
            self.command_whitelist -= remove_from_whitelist
        if extra_global_blacklist:
            self._global_blacklist.extend(extra_global_blacklist)

    def filter_command(self, command: str) -> FilterResult:
        """
        Filter a single command.

        Processing flow:
        1. global denylist check
        2. command parsing and primary-command extraction
        3. allowlist check
        4. command-specific argument checks
        """
        blocked = []

        # Step 1: global denylist.
        for pattern, reason in self._global_blacklist:
            if pattern.search(command):
                blocked.append(reason)

        if blocked:
            return FilterResult(
                allowed=False,
                original=command,
                filtered="",
                blocked_segments=blocked,
                reason=f"Command blocked by global security policy: {', '.join(blocked)}",
            )

        # Step 2: parse commands.
        try:
            # Handle pipelines by checking each segment independently.
            pipe_segments = self._split_pipes(command)
        except ValueError:
            return FilterResult(
                allowed=False,
                original=command,
                filtered="",
                blocked_segments=["Command parsing failed"],
                reason="Invalid command syntax",
            )

        filtered_segments = []
        for segment in pipe_segments:
            result = self._filter_single_command(segment.strip())
            if not result.allowed:
                return result
            filtered_segments.append(result.filtered)

        filtered_command = " | ".join(filtered_segments)

        return FilterResult(
            allowed=True,
            original=command,
            filtered=filtered_command,
            blocked_segments=[],
            reason="Command filtering passed",
        )

    def filter_script(self, script: str) -> FilterResult:
        """Filter a multi-line shell script."""
        lines = script.split("\n")
        filtered_lines = []
        all_blocked = []

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines and comments.
            if not stripped or stripped.startswith("#"):
                filtered_lines.append(line)
                continue

            # Handle line continuations.
            if stripped.endswith("\\"):
                # Skip for now; proper multi-line merging can be added later.
                filtered_lines.append(line)
                continue

            result = self.filter_command(stripped)
            if not result.allowed:
                all_blocked.extend(
                    f"Line {i+1}: {b}" for b in result.blocked_segments
                )
                # Replace dangerous lines with a blocked marker.
                filtered_lines.append(f"# [GUARDIAN BLOCKED] {stripped}")
                filtered_lines.append(
                    f'echo "[GUARDIAN] Command blocked by security policy (line {i+1})"'
                )
            else:
                filtered_lines.append(result.filtered)

        return FilterResult(
            allowed=len(all_blocked) == 0,
            original=script,
            filtered="\n".join(filtered_lines),
            blocked_segments=all_blocked,
            reason="Script filtering completed" + (
                f" ({len(all_blocked)} commands blocked)" if all_blocked else ""
            ),
        )

    # Internal helpers.

    # Python code filtering (defense against system-call bypasses).

    # High-confidence dangerous Python call patterns.
    _PYTHON_DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
        # Process and shell execution.
        (re.compile(r'\bos\s*\.\s*system\s*\('),              "os.system() - direct shell execution"),
        (re.compile(r'\bos\s*\.\s*popen\s*\('),               "os.popen() - shell pipeline"),
        (re.compile(r'\bos\s*\.\s*exec[lv]p?e?\s*\('),        "os.exec*() - process replacement"),
        (re.compile(r'\bsubprocess\s*\.\s*(run|call|Popen|check_output|check_call|getstatusoutput|getoutput)\s*\('),
         "subprocess call - process creation"),

        # Native library loading.
        (re.compile(r'\bctypes\s*\.\s*(CDLL|cdll|WinDLL|windll|OleDLL|oledll)\b'),
         "ctypes native library load"),
        (re.compile(r'\bctypes\s*\.\s*util\s*\.\s*find_library\b'),
         "ctypes library lookup"),

        # Raw sockets and direct network operations.
        (re.compile(r'\bsocket\s*\.\s*socket\s*\('),           "Raw socket creation"),
        (re.compile(r'\.connect\s*\(\s*\(\s*["\']'),           "socket connect call"),

        # Dynamic import plus eval patterns.
        (re.compile(r'__import__\s*\(\s*["\'](?:os|subprocess|socket|shutil|ctypes)'),
         "__import__ dynamic import of a dangerous module"),
        (re.compile(r'\beval\s*\(\s*.*\bcompile\s*\('),        "eval(compile(...)) - dynamic code execution"),

        # Sensitive filesystem access.
        (re.compile(r'open\s*\(\s*[\'"]\s*/etc/'),             "Write to /etc/ system path"),
        (re.compile(r'open\s*\(\s*[\'"]\s*/proc/'),            "Access to /proc/ pseudo-filesystem"),
        (re.compile(r'open\s*\(\s*[\'"]\s*/sys/'),             "Access to /sys/ kernel interface"),
        (re.compile(r'open\s*\(\s*[\'"].*\.ssh/'),             "Access to SSH key directory"),
    ]

    def filter_python_code(self, code: str) -> FilterResult:
        """
        Filter Python code for security risks.

        This detects dangerous system-call patterns as an additional defense
        layer behind Guardian and Layer 2. It intentionally focuses on
        high-confidence patterns to avoid false positives on normal code.
        """
        blocked: list[str] = []

        for pattern, reason in self._PYTHON_DANGEROUS_PATTERNS:
            if pattern.search(code):
                blocked.append(reason)

        if blocked:
            return FilterResult(
                allowed=False,
                original=code,
                filtered="",
                blocked_segments=blocked,
                reason=f"Python security check blocked the request: {', '.join(blocked)}",
            )

        return FilterResult(
            allowed=True,
            original=code,
            filtered=code,
            blocked_segments=[],
            reason="Python security check passed",
        )

    # Shell command helpers.

    def _filter_single_command(self, command: str) -> FilterResult:
        """Filter one command segment without pipelines."""
        # Extract the primary command name.
        parts = command.split()
        if not parts:
            return FilterResult(True, command, command, [], "Empty command")

        # Handle `env VAR=val command` prefixes.
        cmd_name = parts[0]
        if cmd_name == "env" and len(parts) > 1:
            # Find the real command token.
            for i, p in enumerate(parts[1:], 1):
                if "=" not in p:
                    cmd_name = p
                    break

        # Allowlist check.
        if cmd_name not in self.command_whitelist:
            return FilterResult(
                allowed=False,
                original=command,
                filtered="",
                blocked_segments=[f"Command is not allowlisted: {cmd_name}"],
                reason=f"Unauthorized command: {cmd_name}",
            )

        # Command-specific argument checks.
        for check_cmd, pattern, reason in self._dangerous_arg_patterns:
            if cmd_name == check_cmd and pattern.search(command):
                return FilterResult(
                    allowed=False,
                    original=command,
                    filtered="",
                    blocked_segments=[reason],
                    reason=reason,
                )

        return FilterResult(
            allowed=True,
            original=command,
            filtered=command,
            blocked_segments=[],
            reason="OK",
        )

    def _split_pipes(self, command: str) -> list[str]:
        """Split a pipeline into command segments."""
        # Simple splitter that does not fully parse quoted shell syntax.
        segments = []
        current = []
        in_quotes = False
        quote_char = ""

        for char in command:
            if char in ('"', "'") and not in_quotes:
                in_quotes = True
                quote_char = char
                current.append(char)
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = ""
                current.append(char)
            elif char == "|" and not in_quotes:
                segments.append("".join(current))
                current = []
            else:
                current.append(char)

        if current:
            segments.append("".join(current))

        return segments
