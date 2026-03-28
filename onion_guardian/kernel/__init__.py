"""
Kernel primitives for Onion Guardian.

This package holds runtime configuration and core types that the middleware
can pass around without depending on IO-heavy adapters.
"""

from onion_guardian.kernel.audit import (
    AuditEvent,
    AuditLevel,
    build_allow_event,
    build_block_event,
    build_error_event,
    build_rewrite_event,
    sanitize_audit_event,
)
from onion_guardian.kernel.config import compile_effective_config
from onion_guardian.kernel.planner import (
    build_execution_env,
    build_execution_plan,
    build_sandbox_metadata,
)
from onion_guardian.kernel.pipeline import PipelineState, run_pipeline
from onion_guardian.kernel.reducer import reduce_signals
from onion_guardian.kernel.types import (
    AuditRuntimeConfig,
    Decision,
    ExecutionPlan,
    EffectiveConfig,
    GuardianRuntimeConfig,
    NetworkRuntimeConfig,
    SandboxRuntimeConfig,
    Signal,
    RewriteOp,
)

__all__ = [
    "AuditRuntimeConfig",
    "AuditEvent",
    "AuditLevel",
    "Decision",
    "ExecutionPlan",
    "EffectiveConfig",
    "GuardianRuntimeConfig",
    "NetworkRuntimeConfig",
    "PipelineState",
    "SandboxRuntimeConfig",
    "Signal",
    "RewriteOp",
    "build_allow_event",
    "build_block_event",
    "build_error_event",
    "build_execution_env",
    "build_execution_plan",
    "build_rewrite_event",
    "build_sandbox_metadata",
    "compile_effective_config",
    "run_pipeline",
    "reduce_signals",
    "sanitize_audit_event",
]
