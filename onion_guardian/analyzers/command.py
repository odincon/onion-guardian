"""
Command/code analyzer for Layer 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from onion_guardian.kernel.types import Signal
from onion_guardian.layer3_gateway.command_filter import CommandFilter
from onion_guardian.utils.types import ActionVerdict, RiskLevel


_EXECUTION_ACTIONS = frozenset({"sandbox_executor.run", "sandbox_executor.run_shell"})


@dataclass(frozen=True)
class CommandAnalysis:
    params: dict[str, Any]
    signals: tuple[Signal, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class CommandAnalyzer:
    def __init__(self, command_filter: CommandFilter):
        self.command_filter = command_filter
        self._filter_dispatch = {
            "bash": self.command_filter.filter_script,
            "sh": self.command_filter.filter_script,
            "shell": self.command_filter.filter_script,
            "python": self.command_filter.filter_python_code,
            "python3": self.command_filter.filter_python_code,
            "py": self.command_filter.filter_python_code,
        }

    def analyze(self, action: str, params: dict[str, Any]) -> CommandAnalysis:
        if action not in _EXECUTION_ACTIONS:
            return CommandAnalysis(params=dict(params))

        code_key = self._code_key(params)
        if code_key is None:
            return CommandAnalysis(params=dict(params))

        code = params.get(code_key)
        if not isinstance(code, str):
            return CommandAnalysis(params=dict(params))

        lang = str(
            params.get("lang")
            or params.get("language")
            or ("bash" if code_key == "cmd" else "bash")
        )
        filter_fn = self._filter_dispatch.get(lang)
        if filter_fn is None:
            return CommandAnalysis(params=dict(params))

        filter_result = filter_fn(code)
        next_params = dict(params)
        if filter_result.allowed:
            if filter_result.filtered != code:
                next_params[code_key] = filter_result.filtered
            return CommandAnalysis(params=next_params)

        return CommandAnalysis(
            params=next_params,
            signals=(
                Signal(
                    source="layer3.command_filter",
                    code="COMMAND_FILTER_BLOCK",
                    effect=ActionVerdict.BLOCK,
                    severity=RiskLevel.CRITICAL,
                    reason=filter_result.reason,
                    tags=("layer3", "command_filter"),
                ),
            ),
            metadata={"blocked_commands": filter_result.blocked_segments},
        )

    def _code_key(self, params: dict[str, Any]) -> str | None:
        for key in ("source", "cmd", "code"):
            if key in params:
                return key
        return None
