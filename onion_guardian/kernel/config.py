"""
Compile effective runtime configuration from raw config + explicit overrides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from onion_guardian.kernel.types import (
    AuditRuntimeConfig,
    EffectiveConfig,
    GuardianRuntimeConfig,
    NetworkRuntimeConfig,
    SandboxRuntimeConfig,
)
from onion_guardian.utils.types import SecurityConfig


def _override(value: Any, fallback: Any) -> Any:
    return fallback if value is None else value


def compile_effective_config(
    *,
    rules_path: str | Path,
    prompts_path: str | Path | None,
    raw_config: SecurityConfig,
    prompts: dict[str, Any] | None,
    guardian_backend: str | None = None,
    guardian_model: str | None = None,
    guardian_temperature: float | None = None,
    guardian_max_tokens: int | None = None,
    sandbox_root: str | Path | None = None,
    audit_log_path: str | None = None,
    audit_level: str | None = None,
    network_mode: str | None = None,
    enable_llm: bool | None = None,
    session_isolation: bool | None = None,
    max_file_size_mb: int | None = None,
    disk_quota_mb: int | None = None,
    max_processes: int | None = None,
    max_open_files: int | None = None,
    max_memory_mb: int | None = None,
    max_execution_time_sec: int | None = None,
    rate_limit: int | None = None,
) -> EffectiveConfig:
    """
    Compile a frozen runtime config.

    Explicit keyword overrides always win over YAML-derived values.
    """

    sandbox_base = str(_override(sandbox_root, raw_config.sandbox_base_path))

    return EffectiveConfig(
        rules_path=str(rules_path),
        prompts_path=str(prompts_path) if prompts_path else None,
        rules=tuple(raw_config.rules),
        prompts=dict(prompts or {}),
        guardian=GuardianRuntimeConfig(
            backend=_override(guardian_backend, raw_config.guardian_model),
            model_name=_override(guardian_model, raw_config.guardian_model_name),
            temperature=float(_override(guardian_temperature, raw_config.guardian_temperature)),
            max_tokens=int(_override(guardian_max_tokens, raw_config.guardian_max_tokens)),
            enable_llm_analysis=bool(
                _override(enable_llm, raw_config.guardian_enable_llm_analysis)
            ),
        ),
        sandbox=SandboxRuntimeConfig(
            base_path=sandbox_base,
            session_isolation=bool(
                _override(session_isolation, raw_config.session_isolation)
            ),
            max_file_size_mb=int(_override(max_file_size_mb, raw_config.max_file_size_mb)),
            disk_quota_mb=int(_override(disk_quota_mb, raw_config.disk_quota_mb)),
            max_processes=int(_override(max_processes, raw_config.max_processes)),
            max_open_files=int(_override(max_open_files, raw_config.max_open_files)),
            max_memory_mb=int(_override(max_memory_mb, raw_config.max_memory_mb)),
            max_execution_time_sec=int(
                _override(max_execution_time_sec, raw_config.max_execution_time_sec)
            ),
        ),
        network=NetworkRuntimeConfig(
            mode=_override(network_mode, raw_config.network_mode),
            allowed_domains=tuple(raw_config.allowed_domains),
            allowed_ports=tuple(raw_config.allowed_ports),
            blocked_ports=tuple(raw_config.blocked_ports),
        ),
        audit=AuditRuntimeConfig(
            log_path=_override(audit_log_path, raw_config.audit_log_path),
            level=_override(audit_level, raw_config.audit_level),
        ),
        rate_limit=int(_override(rate_limit, raw_config.rate_limit)),
    )
