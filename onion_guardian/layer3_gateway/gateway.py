"""
Security gateway for Layer 3.

Layer 3 is the innermost middleware layer and performs the final
pre-execution checks.

Layer 2 ──(validated request)──→ Layer 3 ──(safe execution plan)──→ sandbox / container

Responsibilities:
1. perform final command and code filtering
2. enforce network policy checks
3. inject execution-environment constraints
4. emit audit events
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
import time
from typing import Any, Callable

from onion_guardian.analyzers.command import CommandAnalyzer
from onion_guardian.analyzers.network import NetworkAnalyzer
from onion_guardian.kernel.planner import build_execution_env
from onion_guardian.kernel.reducer import reduce_signals
from onion_guardian.kernel.types import Decision, Signal
from onion_guardian.layer3_gateway.command_filter import CommandFilter
from onion_guardian.layer3_gateway.network_policy import NetworkPolicy, NetworkPolicyConfig
from onion_guardian.layer3_gateway.audit import AuditLogger, AuditLevel
from onion_guardian.utils.types import ActionVerdict, LayerResult


@dataclass(frozen=True)
class _GatewayStepResult:
    params: dict[str, Any]
    signals: tuple[Signal, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _GatewayStep:
    run: Callable[[dict[str, Any]], _GatewayStepResult]
    stop_when: Callable[["_GatewayStepResult", Decision], bool]


class SecurityGateway:
    """
    Final policy gateway for Layer 3.

    This is the last middleware checkpoint before a request reaches the
    external executor.
    """

    def __init__(
        self,
        network_config: NetworkPolicyConfig | None = None,
        audit_log_path: str | None = None,
        audit_level: str = "INFO",
        command_filter: CommandFilter | None = None,
    ):
        self.command_filter = command_filter or CommandFilter()
        self.network_policy = NetworkPolicy(config=network_config)
        self.command_analyzer = CommandAnalyzer(self.command_filter)
        self.network_analyzer = NetworkAnalyzer(self.network_policy)
        self.audit = AuditLogger(
            log_path=audit_log_path,
            level=AuditLevel(audit_level),
        )

    def process(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
        user_id: str,
        constraints: dict[str, Any] | None = None,
        request_id: str = "",
        emit_audit: bool = True,
    ) -> LayerResult:
        """
        Process a request through Layer 3.

        Final checks performed here:
        1. filter code or shell execution paths
        2. enforce network policy where relevant
        3. attach execution-environment constraints
        4. emit audit records when enabled
        """
        start = time.monotonic()
        working_params = dict(params)
        working_constraints = dict(constraints or {})
        signals: list[Signal] = []
        block_metadata: dict[str, Any] = {}
        for step in self._build_steps(action=action, session_id=session_id):
            outcome = step.run(working_params)
            working_params = outcome.params
            signals.extend(outcome.signals)
            block_metadata.update(outcome.metadata)
            decision = reduce_signals(signals)

            if step.stop_when(outcome, decision):
                if emit_audit:
                    self._emit_block_audit(
                        action=action,
                        session_id=session_id,
                        user_id=user_id,
                        request_id=request_id,
                        reason="; ".join(decision.reasons),
                        metadata=block_metadata,
                    )
                return self._result_from_decision(decision, start)

        # Step 3: attach execution-environment constraints.
        execution_env = self._build_execution_env(working_constraints, user_id)
        working_constraints["execution_env"] = execution_env

        # Step 4: audit emission.
        if emit_audit:
            self.audit.log_allow(
                request_id=request_id,
                session_id=session_id,
                user_id=user_id,
                action=action,
                layer="layer3",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        return LayerResult(
            layer="layer3",
            passed=True,
            verdict=ActionVerdict.ALLOW,
            transformed_action=action,
            transformed_params=working_params,
            constraints=working_constraints,
            reason="Layer 3 passed: security gateway checks completed",
            duration_ms=(time.monotonic() - start) * 1000,
        )

    def _build_execution_env(self, constraints: dict[str, Any], user_id: str) -> dict:
        """
        Build the execution-environment contract for the external executor.

        These parameters are expected to be enforced outside the Python process,
        for example through containers, VMs, or another runtime boundary.
        """
        return build_execution_env(
            sandbox_metadata=constraints.get("sandbox"),
            user_id=user_id,
            network_mode=self.network_policy.config.mode,
        )

    def _build_steps(
        self,
        *,
        action: str,
        session_id: str,
    ) -> tuple[_GatewayStep, ...]:
        return (
            _GatewayStep(
                run=partial(self._run_command_step, action=action),
                stop_when=self._stop_on_block,
            ),
            _GatewayStep(
                run=partial(
                    self._run_network_step,
                    action=action,
                    session_id=session_id,
                ),
                stop_when=self._stop_on_block,
            ),
        )

    def _run_command_step(
        self,
        params: dict[str, Any],
        *,
        action: str,
    ) -> _GatewayStepResult:
        analysis = self.command_analyzer.analyze(action=action, params=params)
        return _GatewayStepResult(
            params=analysis.params,
            signals=analysis.signals,
            metadata=analysis.metadata,
        )

    def _run_network_step(
        self,
        params: dict[str, Any],
        *,
        action: str,
        session_id: str,
    ) -> _GatewayStepResult:
        analysis = self.network_analyzer.analyze(
            action=action,
            params=params,
            session_id=session_id,
        )
        return _GatewayStepResult(
            params=dict(params),
            signals=analysis.signals,
            metadata=analysis.metadata,
        )

    def _emit_block_audit(
        self,
        *,
        action: str,
        session_id: str,
        user_id: str,
        request_id: str,
        reason: str,
        metadata: dict[str, Any],
    ) -> None:
        self.audit.log_block(
            request_id=request_id,
            session_id=session_id,
            user_id=user_id,
            action=action,
            reason=reason,
            layer="layer3",
            **metadata,
        )

    def _result_from_decision(self, decision: Decision, start: float) -> LayerResult:
        return LayerResult(
            layer="layer3",
            passed=False,
            verdict=decision.effect,
            reason="; ".join(decision.reasons) if decision.reasons else "Layer 3 blocked the request",
            duration_ms=(time.monotonic() - start) * 1000,
        )

    @staticmethod
    def _stop_on_block(outcome: _GatewayStepResult, decision: Decision) -> bool:
        return decision.effect == ActionVerdict.BLOCK
