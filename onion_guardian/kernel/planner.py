"""
Pure helpers for building execution-time constraint payloads.
"""

from __future__ import annotations

from typing import Any, Mapping

from onion_guardian.defaults import (
    DEFAULT_CPU_PERCENT,
    DEFAULT_CPU_PERIOD,
    DEFAULT_DNS_SERVERS,
    DEFAULT_MAX_EXECUTION_TIME_SEC,
    DEFAULT_MAX_MEMORY_MB,
    DEFAULT_MAX_PROCESSES,
    DEFAULT_NOBODY_GID,
    DEFAULT_NOBODY_UID,
    DEFAULT_TMPFS_SIZE_MB,
)
from onion_guardian.kernel.types import ExecutionPlan, RewriteOp


_EXECUTION_ACTIONS = frozenset({"sandbox_executor.run", "sandbox_executor.run_shell"})
_CONSTRAINT_KEYS = {
    "__sandbox__": "sandbox",
    "__execution_env__": "execution_env",
}


def build_sandbox_metadata(
    *,
    action: str,
    params: Mapping[str, Any],
    session_id: str,
    user_id: str,
    session_root: str,
    resource_limits: Mapping[str, Any],
    max_execution_time_sec: int,
    max_memory_mb: int,
    max_processes: int,
    network_mode: str = "restricted",
) -> dict[str, Any]:
    metadata = {
        "session_id": session_id,
        "user_id": user_id,
        "session_root": session_root,
        "resource_limits": dict(resource_limits),
    }

    if action in _EXECUTION_ACTIONS:
        metadata["execution"] = {
            "timeout_sec": min(
                params.get("timeout_sec", DEFAULT_MAX_EXECUTION_TIME_SEC),
                max_execution_time_sec,
            ),
            "network_mode": network_mode,
            "user": f"sandbox_{user_id[:8]}",
            "cgroup_limits": {
                "memory_mb": max_memory_mb,
                "cpu_percent": DEFAULT_CPU_PERCENT,
                "pids_max": max_processes,
            },
        }

    return metadata


def build_execution_env(
    *,
    params: Mapping[str, Any] | None = None,
    sandbox_metadata: Mapping[str, Any] | None = None,
    user_id: str,
    network_mode: str,
) -> dict[str, Any]:
    sandbox_meta = dict(sandbox_metadata or {})
    if not sandbox_meta and params is not None:
        sandbox_meta = dict(params.get("__sandbox__", {}))
    resource_limits = sandbox_meta.get("resource_limits", {})
    execution = sandbox_meta.get("execution", {})

    return {
        "run_as_user": execution.get("user", f"sandbox_{user_id[:8]}"),
        "run_as_uid": DEFAULT_NOBODY_UID,
        "run_as_gid": DEFAULT_NOBODY_GID,
        "cgroup": {
            "memory_limit_bytes": resource_limits.get(
                "max_memory_bytes", DEFAULT_MAX_MEMORY_MB * 1024 * 1024
            ),
            "cpu_period": DEFAULT_CPU_PERIOD,
            "cpu_quota": execution.get("cgroup_limits", {}).get(
                "cpu_percent", DEFAULT_CPU_PERCENT
            ) * 1000,
            "pids_max": resource_limits.get("max_processes", DEFAULT_MAX_PROCESSES),
        },
        "timeout_sec": execution.get("timeout_sec", DEFAULT_MAX_EXECUTION_TIME_SEC),
        "seccomp_profile": "default",
        "blocked_syscalls": [
            "mount",
            "umount",
            "umount2",
            "ptrace",
            "kexec_load",
            "kexec_file_load",
            "open_by_handle_at",
            "init_module",
            "finit_module",
            "delete_module",
            "acct",
            "unshare",
            "setns",
            "pivot_root",
        ],
        "network": {
            "mode": network_mode,
            "dns_servers": list(DEFAULT_DNS_SERVERS),
        },
        "filesystem": {
            "readonly_root": False,
            "tmpfs_size_mb": DEFAULT_TMPFS_SIZE_MB,
            "no_new_privileges": True,
        },
    }


def build_execution_plan(
    *,
    action: str,
    params: Mapping[str, Any],
    session_id: str,
    user_id: str,
    constraints: Mapping[str, Any] | None = None,
    rewrite_ops: tuple[RewriteOp, ...] | None = None,
) -> ExecutionPlan:
    runtime_params: dict[str, Any] = {}
    resolved_constraints: dict[str, Any] = (
        {key: dict(value) if isinstance(value, dict) else value for key, value in constraints.items()}
        if constraints is not None
        else {}
    )

    for key, value in params.items():
        constraint_key = _CONSTRAINT_KEYS.get(key)
        if constraint_key is None:
            runtime_params[key] = value
            continue
        if constraint_key not in resolved_constraints:
            resolved_constraints[constraint_key] = (
                dict(value) if isinstance(value, dict) else value
            )

    return ExecutionPlan(
        action=action,
        params=runtime_params,
        session_id=session_id,
        user_id=user_id,
        constraints=resolved_constraints,
        rewrite_ops=rewrite_ops or (),
    )
