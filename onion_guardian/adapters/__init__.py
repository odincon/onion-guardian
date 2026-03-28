"""
Adapters for IO-facing integration points.
"""

from onion_guardian.adapters.audit_sink import (
    AuditSink,
    build_default_audit_sink,
    CompositeAuditSink,
    JsonlAuditSink,
    NullAuditSink,
    read_audit_stats,
    StreamAuditSink,
)

__all__ = [
    "AuditSink",
    "build_default_audit_sink",
    "CompositeAuditSink",
    "JsonlAuditSink",
    "NullAuditSink",
    "read_audit_stats",
    "StreamAuditSink",
]
