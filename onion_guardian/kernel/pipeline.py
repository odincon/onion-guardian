"""
Pipeline orchestration helpers for the security middleware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from onion_guardian.contracts.common import ActionVerdict
from onion_guardian.kernel.audit import (
    AuditEvent,
    build_allow_event,
    build_block_event,
    build_rewrite_event,
)
from onion_guardian.kernel.types import ExecutionPlan, RewriteOp
from onion_guardian.utils.types import LayerResult


PipelineStep = Callable[["PipelineState"], LayerResult]


@dataclass(frozen=True)
class PipelineState:
    request_id: str
    session_id: str
    user_id: str
    action: str
    params: Mapping[str, Any]
    constraints: Mapping[str, Any] = field(default_factory=dict)
    rewrite_ops: tuple[RewriteOp, ...] = ()
    layer_trace: tuple[LayerResult, ...] = ()
    audit_events: tuple[AuditEvent, ...] = ()
    halted: bool = False
    final_verdict: ActionVerdict | None = None
    failure_reason: str = ""
    execution_plan: ExecutionPlan | None = None

    def apply(self, result: LayerResult) -> "PipelineState":
        next_action = result.transformed_action or self.action
        next_params = result.transformed_params or self.params
        next_constraints = dict(self.constraints)
        if result.constraints:
            next_constraints.update(result.constraints)
        next_rewrite_ops = self.rewrite_ops + tuple(
            op if isinstance(op, RewriteOp) else RewriteOp.from_mapping(op)
            for op in result.rewrite_ops
        )
        next_audit_events = self.audit_events + (self._build_audit_event(result),)

        return PipelineState(
            request_id=self.request_id,
            session_id=self.session_id,
            user_id=self.user_id,
            action=next_action,
            params=next_params,
            constraints=next_constraints,
            rewrite_ops=next_rewrite_ops,
            layer_trace=self.layer_trace + (result,),
            audit_events=next_audit_events,
            halted=not result.passed,
            final_verdict=result.verdict if not result.passed else self.final_verdict,
            failure_reason=result.reason if not result.passed else self.failure_reason,
            execution_plan=self.execution_plan,
        )

    def attach_execution_plan(self, execution_plan: ExecutionPlan) -> "PipelineState":
        return PipelineState(
            request_id=self.request_id,
            session_id=self.session_id,
            user_id=self.user_id,
            action=self.action,
            params=self.params,
            constraints=self.constraints,
            rewrite_ops=self.rewrite_ops,
            layer_trace=self.layer_trace,
            audit_events=self.audit_events,
            halted=self.halted,
            final_verdict=self.final_verdict,
            failure_reason=self.failure_reason,
            execution_plan=execution_plan,
        )

    def _build_audit_event(self, result: LayerResult) -> AuditEvent:
        if not result.passed:
            return build_block_event(
                request_id=self.request_id,
                session_id=self.session_id,
                user_id=self.user_id,
                action=self.action,
                reason=result.reason,
                layer=result.layer,
            )
        if result.verdict == ActionVerdict.REWRITE:
            return build_rewrite_event(
                request_id=self.request_id,
                session_id=self.session_id,
                user_id=self.user_id,
                action=self.action,
                reason=result.reason,
                layer=result.layer,
            )
        return build_allow_event(
            request_id=self.request_id,
            session_id=self.session_id,
            user_id=self.user_id,
            action=self.action,
            layer=result.layer,
            duration_ms=result.duration_ms,
        )


def run_pipeline(
    initial_state: PipelineState,
    steps: Sequence[PipelineStep],
) -> PipelineState:
    state = initial_state
    for step in steps:
        if state.halted:
            break
        state = state.apply(step(state))
    return state
