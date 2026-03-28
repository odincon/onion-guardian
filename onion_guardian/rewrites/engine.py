"""
Structured rewrite planning and application.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from onion_guardian.kernel.types import RewriteOp
from onion_guardian.rewrites.types import RewritePlan


class RewriteEngine:
    """
    Two-phase rewrite engine.

    1. `plan()` produces structured `RewriteOp` instances
    2. `apply()` applies those operations to request parameters
    """

    def __init__(self, sandbox_base: str = "/workspace"):
        self.sandbox_base = sandbox_base
        self._rule_planners: dict[str, Callable[[dict[str, Any], str], tuple[RewriteOp, ...]]] = {
            "PKG_BLACKLIST_PROXY": self._plan_proxy_install,
            "CMD_BLACKLIST_HOST_RECON": self._plan_host_recon,
            "PATH_RESTRICT_SESSION": self._plan_session_path,
            "PKG_INSTALL_AUDIT": self._plan_package_audit,
        }
        self._op_handlers: dict[str, Callable[[dict[str, Any], RewriteOp], dict[str, Any]]] = {
            "set_param": self._apply_set_param,
            "rewrite_code": self._apply_rewrite_code,
            "sanitize_params": self._apply_sanitize_params,
        }

    def plan(
        self,
        action: str,
        params: dict[str, Any],
        matched_rules: list[str],
        session_id: str = "",
    ) -> RewritePlan:
        ops: list[RewriteOp] = []

        for rule_id in matched_rules:
            planner = self._rule_planners.get(rule_id)
            if planner is not None:
                ops.extend(planner(dict(params), session_id))

        code_key = self._code_target(params)
        if code_key is not None and isinstance(params.get(code_key), str):
            ops.append(
                RewriteOp(
                    op="rewrite_code",
                    target=code_key,
                    value={
                        "language": self._language_for(action, params, code_key),
                        "session_id": session_id,
                    },
                    reason="language_specific_rewrite",
                )
            )

        ops.append(
            RewriteOp(
                op="sanitize_params",
                target="*",
                value={"session_id": session_id},
                reason="generic_sanitization",
            )
        )

        return RewritePlan(ops=tuple(ops))

    def apply(self, params: dict[str, Any], ops: tuple[RewriteOp, ...]) -> dict[str, Any]:
        result = dict(params)
        for op in ops:
            handler = self._op_handlers.get(op.op)
            if handler is None:
                continue
            result = handler(result, op)
        return result

    def rewrite(
        self,
        action: str,
        params: dict[str, Any],
        matched_rules: list[str],
        session_id: str = "",
    ) -> dict[str, Any]:
        return self.apply(
            params=params,
            ops=self.plan(
                action=action,
                params=params,
                matched_rules=matched_rules,
                session_id=session_id,
            ).ops,
        )

    def rewrite_code(self, code: str, language: str, session_id: str = "") -> str:
        if language in ("bash", "sh", "shell"):
            return self._rewrite_bash(code, session_id)
        if language in ("python", "python3", "py"):
            return self._rewrite_python(code, session_id)
        return code

    def _apply_set_param(self, params: dict[str, Any], op: RewriteOp) -> dict[str, Any]:
        result = dict(params)
        result[op.target] = op.value
        return result

    def _apply_rewrite_code(self, params: dict[str, Any], op: RewriteOp) -> dict[str, Any]:
        result = dict(params)
        value = result.get(op.target)
        if not isinstance(value, str):
            return result

        metadata = op.value if isinstance(op.value, dict) else {}
        language = str(metadata.get("language", "bash"))
        session_id = str(metadata.get("session_id", ""))
        result[op.target] = self.rewrite_code(value, language, session_id=session_id)
        return result

    def _apply_sanitize_params(self, params: dict[str, Any], op: RewriteOp) -> dict[str, Any]:
        metadata = op.value if isinstance(op.value, dict) else {}
        session_id = str(metadata.get("session_id", ""))
        return self._sanitize_mapping(params, session_id)

    def _sanitize_mapping(self, params: dict[str, Any], session_id: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in params.items():
            if isinstance(value, str):
                result[key] = self._sanitize_string(value, session_id)
            elif isinstance(value, dict):
                result[key] = self._sanitize_mapping(value, session_id)
            elif isinstance(value, list):
                result[key] = [
                    self._sanitize_string(item, session_id) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    def _plan_proxy_install(
        self, params: dict[str, Any], session_id: str
    ) -> tuple[RewriteOp, ...]:
        code_key = self._code_target(params)
        if code_key is None:
            return ()
        return (
            RewriteOp(
                op="set_param",
                target=code_key,
                value='echo "[GUARDIAN] Network proxy and tunnel installation is blocked by policy"',
                reason="proxy_install_blocked",
            ),
        )

    def _plan_host_recon(
        self, params: dict[str, Any], session_id: str
    ) -> tuple[RewriteOp, ...]:
        code_key = self._code_target(params)
        if code_key is None:
            return ()
        return (
            RewriteOp(
                op="set_param",
                target=code_key,
                value=(
                    '# [GUARDIAN] Network reconnaissance command replaced by policy\n'
                    'echo "Current environment: restricted sandbox"\n'
                    'echo "Network mode: outbound access is limited to allowlisted domains"\n'
                    'python3 -c "import platform; print(f\'OS: {platform.system()} {platform.release()}\')"'
                ),
                reason="host_recon_rewritten",
            ),
        )

    def _plan_session_path(
        self, params: dict[str, Any], session_id: str
    ) -> tuple[RewriteOp, ...]:
        path = params.get("path")
        if not isinstance(path, str):
            return ()
        return (
            RewriteOp(
                op="set_param",
                target="path",
                value=f"{self.sandbox_base}/{session_id}/",
                reason="session_path_rewritten",
            ),
        )

    def _plan_package_audit(
        self, params: dict[str, Any], session_id: str
    ) -> tuple[RewriteOp, ...]:
        code_key = self._code_target(params)
        code = params.get(code_key) if code_key is not None else None
        if code_key is None or not isinstance(code, str):
            return ()

        rewritten = re.sub(
            r"\bpip\s+install\b",
            "pip install --user --no-warn-script-location",
            code,
        )
        rewritten = re.sub(
            r"\bnpm\s+install\b",
            "npm install --ignore-scripts",
            rewritten,
        )
        return (
            RewriteOp(
                op="set_param",
                target=code_key,
                value=rewritten,
                reason="package_install_hardened",
            ),
        )

    def _language_for(self, action: str, params: dict[str, Any], code_key: str) -> str:
        language = params.get("language") or params.get("lang")
        if isinstance(language, str) and language:
            return language
        if code_key == "cmd":
            return "bash"
        if action in ("sandbox_executor.run_shell", "run_command"):
            return "bash"
        return "python"

    def _code_target(self, params: dict[str, Any]) -> str | None:
        for key in ("code", "source", "cmd"):
            if key in params:
                return key
        return None

    def _rewrite_bash(self, code: str, session_id: str) -> str:
        lines = code.split("\n")
        rewritten_lines: list[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                rewritten_lines.append(line)
                continue

            line = re.sub(
                r"\brm\s+-rf\s+/",
                f"rm -rf {self.sandbox_base}/{session_id}/",
                line,
            )
            line = re.sub(
                r"\bpip\s+install\b(?!.*--user)",
                "pip install --user --no-warn-script-location",
                line,
            )

            if re.search(r"\b(apt|apt-get)\s+(install|add)\b", line):
                rewritten_lines.append(f"# [GUARDIAN] System package installation requires review: {stripped}")
                rewritten_lines.append('echo "[GUARDIAN] Package installation request recorded and pending review"')
                continue

            line = re.sub(r">\s*/dev/(sda|zero|null|tcp|udp)", "> /dev/null", line)
            line = re.sub(
                r"\bcurl\s+.*\b(ifconfig|public-ip|myip|ip-check|checkip)\b",
                'echo "[GUARDIAN] External IP lookups are disabled"',
                line,
            )
            rewritten_lines.append(line)

        return "\n".join(rewritten_lines)

    def _rewrite_python(self, code: str, session_id: str) -> str:
        lines = code.split("\n")
        rewritten_lines: list[str] = []

        for line in lines:
            if re.search(r"os\.system\s*\(", line) or re.search(
                r"subprocess\.(run|Popen|call)", line
            ):
                rewritten_lines.append("# [GUARDIAN] System calls require security review")
                rewritten_lines.append(f"# Original code: {line.strip()}")
                rewritten_lines.append(
                    'raise PermissionError("[GUARDIAN] Direct system calls are disabled. Use the provided safe API instead.")'
                )
                continue

            match = re.search(r'open\s*\(\s*["\'](/[^"\']+)["\']', line)
            if match:
                original_path = match.group(1)
                if not original_path.startswith(self.sandbox_base):
                    safe_path = f"{self.sandbox_base}/{session_id}/{original_path.lstrip('/')}"
                    line = line.replace(original_path, safe_path)

            if re.search(r"\.connect\s*\(\s*\(", line):
                rewritten_lines.append("# [GUARDIAN] Direct socket connections are disabled")
                rewritten_lines.append(
                    'raise PermissionError("[GUARDIAN] Use the requests library through the security gateway for network access.")'
                )
                continue

            rewritten_lines.append(line)

        return "\n".join(rewritten_lines)

    def _sanitize_string(self, value: str, session_id: str) -> str:
        value = re.sub(r"\x1b\[[0-9;]*m", "", value)
        value = value.replace("\x00", "")
        value = re.sub(r"\.\./", "", value)
        return value
