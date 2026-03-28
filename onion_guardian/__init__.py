"""
onion-guardian: AI IDE tool-call security middleware.

It inspects abstract tool requests and returns an execution plan for an
external executor.

Quick Start:
    from onion_guardian import OnionGuardian

    og = OnionGuardian.from_config()
    result = og.quick_check(
        action="execute_code",
        params={"code": "ls -la", "language": "bash"},
        session_id="s1",
        user_id="u1",
    )
    print(result.verdict)
"""

__version__ = "0.1.0"

from onion_guardian.core import OnionGuardian
from onion_guardian.utils.types import (
    ActionVerdict,
    ExecutionResult,
    GuardianVerdict,
    LayerResult,
    RiskLevel,
    SecurityConfig,
    SecurityRule,
    ToolRequest,
)
from onion_guardian import defaults  # noqa: F401 - re-export convenience

__all__ = [
    "OnionGuardian",
    "ActionVerdict",
    "ExecutionResult",
    "GuardianVerdict",
    "LayerResult",
    "RiskLevel",
    "SecurityConfig",
    "SecurityRule",
    "ToolRequest",
    "defaults",
]
