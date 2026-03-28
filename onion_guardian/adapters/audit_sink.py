"""
IO adapters for audit event persistence and streaming.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence, TextIO


_LEVEL_ORDER = {
    "DEBUG": 0,
    "INFO": 1,
    "WARN": 2,
    "ALERT": 3,
}


class AuditSink(Protocol):
    def emit(self, record: Mapping[str, Any], *, level: str, reason: str) -> None:
        """Persist or stream a sanitized audit record."""


@dataclass(frozen=True)
class NullAuditSink:
    def emit(self, record: Mapping[str, Any], *, level: str, reason: str) -> None:
        return None


@dataclass(frozen=True)
class JsonlAuditSink:
    path: str

    def __post_init__(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def emit(self, record: Mapping[str, Any], *, level: str, reason: str) -> None:
        line = json.dumps(dict(record), ensure_ascii=False, default=str)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


@dataclass(frozen=True)
class StreamAuditSink:
    stream: TextIO
    min_level: str = "WARN"
    prefix: str = "GUARDIAN"

    def emit(self, record: Mapping[str, Any], *, level: str, reason: str) -> None:
        if _LEVEL_ORDER.get(level, 0) < _LEVEL_ORDER.get(self.min_level, 0):
            return
        self.stream.write(f"[{self.prefix} {level}] {reason}\n")
        self.stream.flush()


@dataclass(frozen=True)
class CompositeAuditSink:
    sinks: Sequence[AuditSink] = field(default_factory=tuple)

    def emit(self, record: Mapping[str, Any], *, level: str, reason: str) -> None:
        for sink in self.sinks:
            sink.emit(record, level=level, reason=reason)


def build_default_audit_sink(
    *,
    log_path: str | None = None,
    stream: TextIO | None = None,
    stream_level: str = "WARN",
) -> AuditSink:
    sinks: list[AuditSink] = []
    if log_path:
        sinks.append(JsonlAuditSink(log_path))
    if stream is not None:
        sinks.append(StreamAuditSink(stream=stream, min_level=stream_level))
    if not sinks:
        return NullAuditSink()
    return CompositeAuditSink(tuple(sinks))


def read_audit_stats(log_path: str | None, since: float | None = None) -> dict[str, Any]:
    if not log_path or not os.path.exists(log_path):
        return {"error": "Audit log file does not exist"}

    stats = {
        "total_events": 0,
        "by_verdict": {"ALLOW": 0, "BLOCK": 0, "REWRITE": 0, "ESCALATE": 0},
        "by_layer": {},
        "by_risk_level": {},
        "top_blocked_rules": {},
    }

    try:
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if since and record.get("timestamp", 0) < since:
                    continue

                stats["total_events"] += 1
                verdict = record.get("verdict", "")
                if verdict in stats["by_verdict"]:
                    stats["by_verdict"][verdict] += 1

                layer = record.get("layer", "unknown")
                stats["by_layer"][layer] = stats["by_layer"].get(layer, 0) + 1

                risk = record.get("risk_level", "")
                if risk:
                    stats["by_risk_level"][risk] = stats["by_risk_level"].get(risk, 0) + 1

                for rule in record.get("matched_rules", []):
                    stats["top_blocked_rules"][rule] = (
                        stats["top_blocked_rules"].get(rule, 0) + 1
                    )
    except OSError:
        return {"error": "Unable to read the audit log file"}

    return stats
