"""
Neutral shared enums for public and kernel code.
"""

from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    """Risk levels emitted by Guardian and policy checks."""

    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionVerdict(str, Enum):
    """Executable policy effects returned by the middleware."""

    ALLOW = "ALLOW"
    REWRITE = "REWRITE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
