"""
Typed runtime configuration objects for Onion Guardian.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from onion_guardian.contracts.common import ActionVerdict, RiskLevel


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                key: _freeze_value(item)
                for key, item in value.items()
            }
        )
    if isinstance(value, list):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_value(item) for item in value)
    return value


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(
        {
            key: _freeze_value(item)
            for key, item in value.items()
        }
    )


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _thaw_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    return value


@dataclass(frozen=True)
class GuardianRuntimeConfig:
    backend: str
    model_name: str
    temperature: float
    max_tokens: int
    enable_llm_analysis: bool


@dataclass(frozen=True)
class SandboxRuntimeConfig:
    base_path: str
    session_isolation: bool
    max_file_size_mb: int
    disk_quota_mb: int
    max_processes: int
    max_open_files: int
    max_memory_mb: int
    max_execution_time_sec: int


@dataclass(frozen=True)
class NetworkRuntimeConfig:
    mode: str
    allowed_domains: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    blocked_ports: tuple[int, ...]


@dataclass(frozen=True)
class AuditRuntimeConfig:
    log_path: str | None
    level: str


@dataclass(frozen=True)
class EffectiveConfig:
    """
    Fully resolved runtime configuration.

    This is the single runtime truth used to construct the middleware graph.
    """

    rules_path: str
    prompts_path: str | None
    rules: tuple[Any, ...]
    prompts: Mapping[str, Any]
    guardian: GuardianRuntimeConfig
    sandbox: SandboxRuntimeConfig
    network: NetworkRuntimeConfig
    audit: AuditRuntimeConfig
    rate_limit: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "prompts", _freeze_mapping(self.prompts))


@dataclass(frozen=True)
class RewriteOp:
    op: str
    target: str
    value: Any
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _freeze_value(self.value))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RewriteOp":
        return cls(
            op=str(data["op"]),
            target=str(data["target"]),
            value=data.get("value"),
            reason=str(data.get("reason", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "op": self.op,
            "target": self.target,
            "value": _thaw_value(self.value),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Signal:
    source: str
    code: str
    effect: ActionVerdict
    severity: RiskLevel
    reason: str
    rule_id: str | None = None
    confidence: float = 1.0
    matched_text: str = ""
    rewrite_ops: tuple[RewriteOp, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    effect: ActionVerdict
    severity: RiskLevel
    reasons: tuple[str, ...]
    matched_rules: tuple[str, ...]
    signals: tuple[Signal, ...]
    rewrite_ops: tuple[RewriteOp, ...]
    audit_tags: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionPlan:
    action: str
    params: Mapping[str, Any]
    session_id: str
    user_id: str
    constraints: Mapping[str, Any]
    rewrite_ops: tuple[RewriteOp, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", _freeze_mapping(self.params))
        object.__setattr__(self, "constraints", _freeze_mapping(self.constraints))
        object.__setattr__(self, "rewrite_ops", tuple(self.rewrite_ops))

    def as_execution_output(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "params": _thaw_value(self.params),
            "session_id": self.session_id,
            "user_id": self.user_id,
            "constraints": _thaw_value(self.constraints),
            "rewrite_ops": [op.as_dict() for op in self.rewrite_ops],
        }
