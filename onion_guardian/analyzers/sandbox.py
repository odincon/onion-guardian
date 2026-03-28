"""
Sandbox/path and resource analyzers for Layer 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from onion_guardian.kernel.types import Signal
from onion_guardian.layer2_router.sandbox import PathSandbox, ResourceQuota
from onion_guardian.utils.types import ActionVerdict, RiskLevel


@dataclass(frozen=True)
class PathSandboxAnalysis:
    params: dict[str, Any] | None = None
    signals: tuple[Signal, ...] = ()


@dataclass(frozen=True)
class ResourceQuotaAnalysis:
    signals: tuple[Signal, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class PathSandboxAnalyzer:
    def __init__(self, path_sandbox: PathSandbox):
        self.path_sandbox = path_sandbox
        self._path_keys = {"path", "file_path", "dir_path", "working_dir", "cwd"}

    def analyze(
        self,
        params: dict[str, Any],
        session_id: str,
        user_id: str,
    ) -> PathSandboxAnalysis:
        result = dict(params)
        signals: list[Signal] = []

        for key in self._path_keys:
            if key not in result or not isinstance(result[key], str):
                continue

            resolved, allowed, reason = self.path_sandbox.resolve_path(
                result[key], session_id, user_id
            )
            if not allowed:
                signals.append(
                    Signal(
                        source="layer2.path_sandbox",
                        code="PATH_SANDBOX_BLOCK",
                        effect=ActionVerdict.BLOCK,
                        severity=RiskLevel.CRITICAL,
                        reason=reason,
                        tags=("layer2", "path_sandbox"),
                    )
                )
                return PathSandboxAnalysis(params=None, signals=tuple(signals))

            result[key] = resolved

        return PathSandboxAnalysis(params=result, signals=tuple(signals))


class ResourceQuotaAnalyzer:
    def __init__(self, resource_quota: ResourceQuota):
        self.resource_quota = resource_quota

    def analyze(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
    ) -> ResourceQuotaAnalysis:
        request = self._resource_request(action, params)
        if request is None:
            return ResourceQuotaAnalysis()

        resource, amount, _ttl_sec = request
        allowed, reason = self.resource_quota.check_quota(session_id, resource, amount)
        if allowed:
            return ResourceQuotaAnalysis()

        return ResourceQuotaAnalysis(
            signals=(
                Signal(
                    source="layer2.resource_quota",
                    code="RESOURCE_QUOTA_BLOCK",
                    effect=ActionVerdict.BLOCK,
                    severity=RiskLevel.HIGH,
                    reason=reason,
                    tags=("layer2", "resource_quota"),
                ),
            )
        )

    def commit(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
    ) -> tuple[bool, str]:
        request = self._resource_request(action, params)
        if request is None:
            return True, "OK"

        resource, amount, ttl_sec = request
        allowed, reason = self.resource_quota.check_quota(session_id, resource, amount)
        if not allowed:
            return False, reason

        self.resource_quota.consume(
            session_id,
            resource,
            amount,
            ttl_sec=ttl_sec,
        )
        return True, "OK"

    def _resource_request(
        self,
        action: str,
        params: dict[str, Any],
    ) -> tuple[str, int, int | None] | None:
        if action in ("file_manager.write",):
            content = params.get("data", "") or params.get("content", "")
            size = len(content.encode("utf-8")) if isinstance(content, str) else 0
            return ("disk", size, None) if size > 0 else None

        if action in ("sandbox_executor.run", "sandbox_executor.run_shell"):
            return ("processes", 1, self._execution_timeout(params))

        return None

    def _execution_timeout(self, params: dict[str, Any]) -> int:
        raw_timeout = (
            params.get("timeout_sec")
            or params.get("timeout")
            or self.resource_quota.config.max_execution_time_sec
        )
        try:
            timeout = int(raw_timeout)
        except (TypeError, ValueError):
            timeout = self.resource_quota.config.max_execution_time_sec

        return max(1, min(timeout, self.resource_quota.config.max_execution_time_sec))
