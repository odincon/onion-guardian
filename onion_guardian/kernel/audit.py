"""
Pure audit event modeling and sanitization helpers.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from onion_guardian.utils.crypto import hash_path, sanitize_for_log


class AuditLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ALERT = "ALERT"


@dataclass(frozen=True)
class AuditEvent:
    timestamp: float = field(default_factory=time.time)
    level: AuditLevel = AuditLevel.INFO
    event_type: str = ""
    request_id: str = ""
    session_id: str = ""
    user_id: str = ""
    action: str = ""
    verdict: str = ""
    risk_level: str = ""
    matched_rules: list[str] = field(default_factory=list)
    reason: str = ""
    layer: str = ""
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


def build_allow_event(
    *,
    request_id: str,
    session_id: str,
    user_id: str,
    action: str,
    layer: str,
    duration_ms: float = 0.0,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        level=AuditLevel.INFO,
        event_type="allow",
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        action=action,
        verdict="ALLOW",
        layer=layer,
        duration_ms=duration_ms,
        metadata=metadata or {},
    )


def build_block_event(
    *,
    request_id: str,
    session_id: str,
    user_id: str,
    action: str,
    reason: str,
    layer: str,
    matched_rules: list[str] | None = None,
    risk_level: str = "HIGH",
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        level=AuditLevel.ALERT,
        event_type="block",
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        action=action,
        verdict="BLOCK",
        risk_level=risk_level,
        matched_rules=matched_rules or [],
        reason=reason,
        layer=layer,
        metadata=metadata or {},
    )


def build_rewrite_event(
    *,
    request_id: str,
    session_id: str,
    user_id: str,
    action: str,
    reason: str,
    layer: str,
    matched_rules: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        level=AuditLevel.WARN,
        event_type="rewrite",
        request_id=request_id,
        session_id=session_id,
        user_id=user_id,
        action=action,
        verdict="REWRITE",
        matched_rules=matched_rules or [],
        reason=reason,
        layer=layer,
        metadata=metadata or {},
    )


def build_error_event(
    *,
    request_id: str,
    error: str,
    layer: str,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        level=AuditLevel.ALERT,
        event_type="error",
        request_id=request_id,
        reason=error,
        layer=layer,
        metadata=metadata or {},
    )


def sanitize_audit_event(event: AuditEvent) -> dict[str, Any]:
    record = asdict(event)
    record["metadata"] = sanitize_for_log(record.get("metadata", {}))
    if record.get("session_id"):
        record["session_id_hash"] = hash_path(record["session_id"])
    return record
