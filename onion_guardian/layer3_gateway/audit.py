"""
onion_guardian.layer3_gateway.audit - audit logging compatibility layer.

Records security events for later analysis and alerting.

Design goals:
- structured JSONL records
- sensitive-data redaction (no real paths or IP addresses)
- event severity levels (DEBUG/INFO/WARN/ALERT)
- support for both streaming and file persistence
"""

from __future__ import annotations

import sys
from typing import Any, TextIO

from onion_guardian.adapters.audit_sink import (
    AuditSink,
    build_default_audit_sink,
    read_audit_stats,
)
from onion_guardian.kernel.audit import (
    AuditEvent,
    AuditLevel,
    build_allow_event,
    build_block_event,
    build_error_event,
    build_rewrite_event,
    sanitize_audit_event,
)


class AuditLogger:
    """
    Audit logger.

    Usage:
        logger = AuditLogger(log_path="/var/log/onion-guardian/audit.jsonl")
        logger.log_block(request_id="abc", reason="v2ray installation blocked", ...)
    """

    def __init__(
        self,
        log_path: str | None = None,
        level: AuditLevel = AuditLevel.INFO,
        stream: TextIO | None = None,
        capture_blocked_requests: bool = True,
        sink: AuditSink | None = None,
    ):
        self.log_path = log_path
        self.level = level
        self.stream = stream or sys.stderr
        self.capture_blocked_requests = capture_blocked_requests

        self._level_order = {
            AuditLevel.DEBUG: 0,
            AuditLevel.INFO: 1,
            AuditLevel.WARN: 2,
            AuditLevel.ALERT: 3,
        }
        self.sink = sink or build_default_audit_sink(
            log_path=self.log_path,
            stream=self.stream,
            stream_level=AuditLevel.WARN.value,
        )

    def log(self, event: AuditEvent) -> None:
        """Record one audit event."""
        # Severity filter.
        if self._level_order.get(event.level, 0) < self._level_order.get(self.level, 0):
            return

        record = sanitize_audit_event(event)

        try:
            self.sink.emit(record, level=event.level.value, reason=event.reason)
        except OSError:
            pass

    def emit_events(self, events: tuple[AuditEvent, ...]) -> None:
        """Record a batch of audit events."""
        for event in events:
            self.log(event)

    def log_allow(
        self,
        request_id: str,
        session_id: str,
        user_id: str,
        action: str,
        layer: str,
        duration_ms: float = 0.0,
        **kwargs,
    ) -> None:
        """Record an allow event."""
        self.log(build_allow_event(
            request_id=request_id,
            session_id=session_id,
            user_id=user_id,
            action=action,
            layer=layer,
            duration_ms=duration_ms,
            metadata=dict(kwargs),
        ))

    def log_block(
        self,
        request_id: str,
        session_id: str,
        user_id: str,
        action: str,
        reason: str,
        layer: str,
        matched_rules: list[str] | None = None,
        risk_level: str = "HIGH",
        **kwargs,
    ) -> None:
        """Record a block event."""
        self.log(build_block_event(
            request_id=request_id,
            session_id=session_id,
            user_id=user_id,
            action=action,
            reason=reason,
            layer=layer,
            matched_rules=matched_rules,
            risk_level=risk_level,
            metadata=dict(kwargs),
        ))

    def log_rewrite(
        self,
        request_id: str,
        session_id: str,
        user_id: str,
        action: str,
        reason: str,
        layer: str,
        matched_rules: list[str] | None = None,
        **kwargs,
    ) -> None:
        """Record a rewrite event."""
        self.log(build_rewrite_event(
            request_id=request_id,
            session_id=session_id,
            user_id=user_id,
            action=action,
            reason=reason,
            layer=layer,
            matched_rules=matched_rules,
            metadata=dict(kwargs),
        ))

    def log_error(
        self,
        request_id: str,
        error: str,
        layer: str,
        **kwargs,
    ) -> None:
        """Record an error event."""
        self.log(build_error_event(
            request_id=request_id,
            error=error,
            layer=layer,
            metadata=dict(kwargs),
        ))

    # Statistics.

    def get_stats(self, since: float | None = None) -> dict[str, Any]:
        """Return audit statistics by reading the log file."""
        return read_audit_stats(self.log_path, since=since)
