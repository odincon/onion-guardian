"""
Deterministic router for Layer 2.

Layer 2 routes normalized requests from Layer 1 toward Layer 3.

Key properties:
- purely deterministic logic, with no LLM dependency
- prompt injection against the primary model should not bypass Layer 2
- parameter validation, path sandboxing, and resource quota checks remain local
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
import time
from typing import Any, Callable

from onion_guardian.analyzers.rate_limit import RateLimitAnalyzer
from onion_guardian.analyzers.sandbox import PathSandboxAnalyzer, ResourceQuotaAnalyzer
from onion_guardian.analyzers.schema import SchemaAnalyzer
from onion_guardian.kernel.planner import build_sandbox_metadata
from onion_guardian.kernel.reducer import reduce_signals
from onion_guardian.kernel.types import Decision, Signal
from onion_guardian.layer2_router.validator import ParamValidator
from onion_guardian.layer2_router.sandbox import PathSandbox, ResourceQuota, SandboxConfig
from onion_guardian.utils.types import (
    ActionVerdict,
    LayerResult,
)
from onion_guardian.defaults import (
    DEFAULT_RATE_LIMIT_PER_MINUTE,
)


@dataclass(frozen=True)
class _RouterStepResult:
    params: dict[str, Any] | None
    signals: tuple[Signal, ...] = ()


@dataclass(frozen=True)
class _RouterStep:
    run: Callable[[dict[str, Any]], _RouterStepResult]
    stop_when: Callable[["_RouterStepResult", Decision], bool]


class DeterministicRouter:
    """
    Deterministic policy router for Layer 2.

    Layer 1 ──(normalized request)──→ Layer 2 ──(validated request)──→ Layer 3

    Responsibilities:
    1. validate parameters and format constraints
    2. enforce path sandboxing for file operations
    3. check quota-related limits
    4. apply per-session rate limiting
    """

    def __init__(
        self,
        sandbox_config: SandboxConfig | None = None,
        default_rate_limit: int = DEFAULT_RATE_LIMIT_PER_MINUTE,
    ):
        self.sandbox_config = sandbox_config or SandboxConfig()
        self.default_rate_limit = default_rate_limit
        self.validator = ParamValidator(sandbox_base=self.sandbox_config.base_path)
        self.path_sandbox = PathSandbox(config=self.sandbox_config)
        self.resource_quota = ResourceQuota(config=self.sandbox_config)
        self.rate_limit_analyzer = RateLimitAnalyzer()
        self.schema_analyzer = SchemaAnalyzer(self.validator)
        self.path_analyzer = PathSandboxAnalyzer(self.path_sandbox)
        self.resource_analyzer = ResourceQuotaAnalyzer(self.resource_quota)

    def process(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
        user_id: str,
        max_calls_per_minute: int | None = None,
    ) -> LayerResult:
        """
        Process a request through Layer 2.

        All checks here are deterministic and do not depend on an LLM.
        """
        start = time.monotonic()
        rate_limit = (
            self.default_rate_limit if max_calls_per_minute is None else max_calls_per_minute
        )
        working_params = dict(params)
        signals: list[Signal] = []
        for step in self._build_steps(
            action=action,
            session_id=session_id,
            user_id=user_id,
            rate_limit=rate_limit,
        ):
            outcome = step.run(working_params)
            signals.extend(outcome.signals)
            decision = reduce_signals(signals)

            if outcome.params is not None:
                working_params = outcome.params

            if step.stop_when(outcome, decision):
                return self._result_from_decision(
                    decision=decision,
                    start=start,
                )

        # Step 5: build executor-facing constraints.
        sandbox_constraints = self._build_constraints(
            action, working_params, session_id, user_id
        )
        decision = reduce_signals(signals)
        warning_text = "; ".join(decision.reasons)

        return LayerResult(
            layer="layer2",
            passed=True,
            verdict=ActionVerdict.ALLOW,
            transformed_action=action,
            transformed_params=working_params,
            constraints={"sandbox": sandbox_constraints},
            reason=f"Layer 2 passed{f' (warnings: {warning_text})' if warning_text else ''}",
            duration_ms=(time.monotonic() - start) * 1000,
        )

    # Constraint planning.

    def _build_constraints(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
        user_id: str,
    ) -> dict[str, Any]:
        """
        Build execution constraints for downstream enforcement.

        These constraints are intended to be enforced by Layer 3 and by the
        external executor.
        """
        return build_sandbox_metadata(
            action=action,
            params=params,
            session_id=session_id,
            user_id=user_id,
            session_root=self.path_sandbox._get_session_root(session_id, user_id),
            resource_limits=self.path_sandbox.get_resource_limits(session_id, user_id),
            max_execution_time_sec=self.sandbox_config.max_execution_time_sec,
            max_memory_mb=self.sandbox_config.max_memory_mb,
            max_processes=self.sandbox_config.max_processes,
        )

    def _result_from_decision(
        self,
        decision: Decision,
        start: float,
    ) -> LayerResult:
        return LayerResult(
            layer="layer2",
            passed=False,
            verdict=decision.effect,
            reason="; ".join(decision.reasons) if decision.reasons else "Layer 2 blocked the request",
            duration_ms=(time.monotonic() - start) * 1000,
        )

    def _build_steps(
        self,
        *,
        action: str,
        session_id: str,
        user_id: str,
        rate_limit: int,
    ) -> tuple[_RouterStep, ...]:
        return (
            _RouterStep(
                run=partial(
                    self._run_rate_limit_step,
                    session_id=session_id,
                    rate_limit=rate_limit,
                ),
                stop_when=self._stop_on_any_signal,
            ),
            _RouterStep(
                run=partial(
                    self._run_schema_step,
                    action=action,
                    session_id=session_id,
                ),
                stop_when=self._stop_on_block,
            ),
            _RouterStep(
                run=partial(
                    self._run_path_sandbox_step,
                    session_id=session_id,
                    user_id=user_id,
                ),
                stop_when=self._stop_on_missing_params_or_block,
            ),
            _RouterStep(
                run=partial(
                    self._run_resource_quota_step,
                    action=action,
                    session_id=session_id,
                ),
                stop_when=self._stop_on_block,
            ),
        )

    def _run_rate_limit_step(
        self,
        params: dict[str, Any],
        *,
        session_id: str,
        rate_limit: int,
    ) -> _RouterStepResult:
        analysis = self.rate_limit_analyzer.analyze(session_id, rate_limit)
        return _RouterStepResult(params=dict(params), signals=analysis.signals)

    def _run_schema_step(
        self,
        params: dict[str, Any],
        *,
        action: str,
        session_id: str,
    ) -> _RouterStepResult:
        analysis = self.schema_analyzer.analyze(action, params, session_id)
        return _RouterStepResult(params=dict(params), signals=analysis.signals)

    def _run_path_sandbox_step(
        self,
        params: dict[str, Any],
        *,
        session_id: str,
        user_id: str,
    ) -> _RouterStepResult:
        analysis = self.path_analyzer.analyze(params, session_id, user_id)
        return _RouterStepResult(params=analysis.params, signals=analysis.signals)

    def _run_resource_quota_step(
        self,
        params: dict[str, Any],
        *,
        action: str,
        session_id: str,
    ) -> _RouterStepResult:
        analysis = self.resource_analyzer.analyze(action, params, session_id)
        return _RouterStepResult(params=dict(params), signals=analysis.signals)

    @staticmethod
    def _stop_on_any_signal(outcome: _RouterStepResult, decision: Decision) -> bool:
        return bool(outcome.signals)

    @staticmethod
    def _stop_on_block(outcome: _RouterStepResult, decision: Decision) -> bool:
        return decision.effect == ActionVerdict.BLOCK

    @staticmethod
    def _stop_on_missing_params_or_block(outcome: _RouterStepResult, decision: Decision) -> bool:
        return outcome.params is None or decision.effect == ActionVerdict.BLOCK

    def cleanup_session(self, session_id: str) -> None:
        """Release Layer 2 state associated with a session."""
        self.rate_limit_analyzer.cleanup_session(session_id)
        self.resource_quota.cleanup_session(session_id)

    def commit_resources(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
    ) -> tuple[bool, str]:
        """Commit resource usage after the full request is allowed."""
        return self.resource_analyzer.commit(action, params, session_id)
