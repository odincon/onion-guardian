"""
onion_guardian.layer2_router.validator - parameter validator.

Deterministic Layer 2 validation with no LLM dependency.
This is a key defense against prompt-injection bypasses: even if the model is
tricked, Layer 2's code-based checks still stand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from onion_guardian.defaults import DEFAULT_MAX_LENGTHS, DEFAULT_MAX_STRING_LENGTH


@dataclass
class ValidationError:
    param_name: str
    message: str
    severity: str = "ERROR"  # "ERROR" / "WARNING"


class ParamValidator:
    """
    Deterministic parameter validator.

    All validation rules are implemented in code and do not depend on model
    output.
    """

    def __init__(self, sandbox_base: str = "/workspace"):
        self.sandbox_base = sandbox_base

    def validate(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
    ) -> list[ValidationError]:
        """Run the full validation suite."""
        errors = []

        # Common validation.
        errors.extend(self._validate_no_null_bytes(params))
        errors.extend(self._validate_no_path_traversal(params))
        errors.extend(self._validate_string_lengths(params))

        # Action-specific validation.
        validator = self._action_validators.get(action)
        if validator:
            errors.extend(validator(params, session_id))

        return errors

    # Common validation.

    def _validate_no_null_bytes(self, params: dict[str, Any]) -> list[ValidationError]:
        """Detect null-byte injection attempts."""
        errors = []
        for key, value in params.items():
            if isinstance(value, str) and "\x00" in value:
                errors.append(ValidationError(
                    param_name=key,
                    message="Parameter contains a null byte and may be part of an injection attempt",
                    severity="ERROR",
                ))
        return errors

    def _validate_no_path_traversal(self, params: dict[str, Any]) -> list[ValidationError]:
        """
        Path traversal protection.

        This defends against cross-session data access such as
        `../../../user_data/sessions/other_session/`.
        """
        errors = []
        path_keys = {"path", "file_path", "dir_path", "working_dir", "cwd"}

        for key, value in params.items():
            if key.startswith("_obf_"):
                continue
            if key in path_keys and isinstance(value, str):
                # Normalize the path.
                normalized = _normalize_path(value)

                # Detect path traversal markers.
                if ".." in normalized:
                    errors.append(ValidationError(
                        param_name=key,
                        message=f"Path contains '..' traversal markers: {value}",
                        severity="ERROR",
                    ))

                # Disallow absolute paths.
                if normalized.startswith("/"):
                    errors.append(ValidationError(
                        param_name=key,
                        message=f"Absolute paths are not allowed: {value}",
                        severity="ERROR",
                    ))

                # Disallow home-directory expansion.
                if "~" in normalized:
                    errors.append(ValidationError(
                        param_name=key,
                        message=f"'~' path expansion is not allowed: {value}",
                        severity="ERROR",
                    ))

        return errors

    def _validate_string_lengths(self, params: dict[str, Any]) -> list[ValidationError]:
        """Prevent overly large parameters from causing DoS issues."""
        errors = []

        for key, value in params.items():
            if isinstance(value, str):
                max_len = DEFAULT_MAX_LENGTHS.get(key, DEFAULT_MAX_STRING_LENGTH)
                if len(value) > max_len:
                    errors.append(ValidationError(
                        param_name=key,
                        message=f"Parameter length {len(value)} exceeds the limit {max_len}",
                        severity="ERROR",
                    ))
        return errors

    # Action-specific validation.

    @property
    def _action_validators(self) -> dict[str, callable]:
        return {
            "sandbox_executor.run": self._validate_code_execution,
            "sandbox_executor.run_shell": self._validate_shell_command,
            "file_manager.read": self._validate_file_read,
            "file_manager.write": self._validate_file_write,
            "network_proxy.request": self._validate_http_request,
            "package_manager.install": self._validate_package_install,
        }

    def _validate_code_execution(
        self, params: dict[str, Any], session_id: str
    ) -> list[ValidationError]:
        """Validate code-execution requests."""
        errors = []
        code = params.get("source", "") or params.get("code", "")

        # Scan for dangerous code patterns.
        dangerous_patterns = [
            (r'import\s+ctypes', "Importing ctypes is not allowed (may enable raw memory access)"),
            (r'import\s+resource', "Importing resource is not allowed (may alter system limits)"),
            (r'__import__\s*\(\s*["\']ctypes', "Dynamic ctypes imports are not allowed"),
            (r'exec\s*\(\s*compile', "exec(compile(...)) is not allowed"),
            (r'eval\s*\(\s*input', "eval(input(...)) is not allowed"),
        ]

        for pattern, message in dangerous_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                errors.append(ValidationError(
                    param_name="code",
                    message=message,
                    severity="WARNING",
                ))

        return errors

    def _validate_shell_command(
        self, params: dict[str, Any], session_id: str
    ) -> list[ValidationError]:
        """Validate shell command requests."""
        errors = []
        cmd = params.get("cmd", "") or params.get("command", "")

        # Check chained shell operators.
        if any(op in cmd for op in ["&&", "||", ";", "|", "`", "$("]):
            # Do not fully reject here; tag it for deeper Layer 3 inspection.
            # The pipe operator is common enough that it remains a warning.
            if any(op in cmd for op in ["&&", "||", ";", "`", "$("]):
                errors.append(ValidationError(
                    param_name="command",
                    message="Command contains chained operators and requires deeper Layer 3 inspection",
                    severity="WARNING",
                ))

        return errors

    def _validate_file_read(
        self, params: dict[str, Any], session_id: str
    ) -> list[ValidationError]:
        """Validate file-read requests."""
        errors = []
        path = params.get("file_path", "") or params.get("path", "")

        # Detect sensitive file patterns.
        sensitive_patterns = [
            (r'\.env$', "Reading .env files is not allowed (may expose secrets)"),
            (r'\.key$', "Reading key files is not allowed"),
            (r'\.pem$', "Reading certificate files is not allowed"),
            (r'id_rsa', "Reading SSH keys is not allowed"),
            (r'\.git/config', "Reading Git config is not allowed (may expose credentials)"),
            (r'\.[a-z0-9_-]*rc$', "Reading credential-bearing dot-rc files is not allowed"),
        ]

        for pattern, message in sensitive_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                errors.append(ValidationError(
                    param_name="path",
                    message=message,
                    severity="ERROR",
                ))

        return errors

    def _validate_file_write(
        self, params: dict[str, Any], session_id: str
    ) -> list[ValidationError]:
        """Validate file-write requests."""
        errors = []
        path = params.get("file_path", "") or params.get("path", "")
        content = params.get("data", "") or params.get("content", "")

        # Check the write target.
        dangerous_targets = [
            (r'\.bashrc$', "Modifying .bashrc is not allowed"),
            (r'\.profile$', "Modifying .profile is not allowed"),
            (r'\.ssh/', "Writing to the .ssh directory is not allowed"),
            (r'crontab', "Modifying crontab is not allowed"),
        ]

        for pattern, message in dangerous_targets:
            if re.search(pattern, path, re.IGNORECASE):
                errors.append(ValidationError(
                    param_name="path",
                    message=message,
                    severity="ERROR",
                ))

        # Detect dangerous content patterns such as SSH key injection.
        if re.search(r'ssh-rsa\s+AAAA', content):
            errors.append(ValidationError(
                param_name="content",
                message="Detected an SSH public-key injection attempt",
                severity="ERROR",
            ))

        return errors

    def _validate_http_request(
        self, params: dict[str, Any], session_id: str
    ) -> list[ValidationError]:
        """Validate HTTP requests."""
        errors = []
        url = params.get("target_url", "") or params.get("url", "")

        # Block internal targets to reduce SSRF risk.
        internal_patterns = [
            r'https?://127\.',
            r'https?://localhost',
            r'https?://0\.0\.0\.0',
            r'https?://10\.',
            r'https?://172\.(1[6-9]|2\d|3[01])\.',
            r'https?://192\.168\.',
            r'https?://169\.254\.',
            r'https?://\[::1\]',
            r'https?://(?:metadata|instance-data)(?:[.:/]|$)',
        ]

        for pattern in internal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                errors.append(ValidationError(
                    param_name="url",
                    message=f"Access to internal addresses is not allowed: {url}",
                    severity="ERROR",
                ))

        return errors

    def _validate_package_install(
        self, params: dict[str, Any], session_id: str
    ) -> list[ValidationError]:
        """Validate package-install requests."""
        errors = []
        packages = params.get("pkg_list", "") or params.get("packages", "")

        # Blacklisted packages.
        blacklist = {
            "v2ray", "xray", "clash", "trojan", "wireguard",
            "shadowsocks", "frp", "ngrok", "nps",
            "mitmproxy", "bettercap",  # Man-in-the-middle tools.
            "impacket",  # Offensive networking toolkit.
        }

        if isinstance(packages, str):
            pkg_list = [p.strip() for p in packages.split(",")]
        elif isinstance(packages, list):
            pkg_list = packages
        else:
            return errors

        for pkg in pkg_list:
            pkg_name = pkg.split("==")[0].split(">=")[0].split("<=")[0].strip().lower()
            if pkg_name in blacklist:
                errors.append(ValidationError(
                    param_name="packages",
                    message=f"Installing blacklisted package is not allowed: {pkg_name}",
                    severity="ERROR",
                ))

        return errors


def _normalize_path(path: str) -> str:
    """Normalize paths without depending on `os.path` semantics."""
    # Replace backslashes.
    path = path.replace("\\", "/")
    # Collapse repeated slashes.
    while "//" in path:
        path = path.replace("//", "/")
    return path
