"""
Primary middleware orchestrator for Onion Guardian.

Typical usage:

    from onion_guardian import OnionGuardian

    guardian = OnionGuardian.from_config()
    result = guardian.process(request, session_id="s1", user_id="u1")

Internal flow:

    Request ──→ Guardian Model (intent analysis / rewrite)
       │
       ├── BLOCK ──→ return immediately
       │
       ▼
    Layer 1 — semantic abstraction (hide real executor names)
       │
       ├── BLOCK ──→ return
       │
       ▼
    Layer 2 — deterministic routing (validation / sandbox / rate limit)
       │
       ├── BLOCK ──→ return
       │
       ▼
    Layer 3 — security gateway (command filter / network policy / audit)
       │
       ├── BLOCK ──→ return
       │
       ▼
    ExecutionPlan ←── external executor
"""

from __future__ import annotations

import importlib.resources
import time
from pathlib import Path
from typing import Any

import yaml

from onion_guardian.kernel.config import compile_effective_config
from onion_guardian.kernel.planner import build_execution_plan
from onion_guardian.kernel.pipeline import PipelineState, run_pipeline
from onion_guardian.kernel.types import EffectiveConfig
from onion_guardian.kernel.audit import AuditEvent
from onion_guardian.utils.types import (
    ActionVerdict,
    ExecutionResult,
    GuardianVerdict,
    LayerResult,
    SecurityConfig,
    ToolRequest,
)
from onion_guardian.utils.crypto import generate_token

# Guardian Model
from onion_guardian.guardian.model import GuardianModel

# Layer 1: semantic abstraction
from onion_guardian.layer1_semantic.abstraction import SemanticAbstraction

# Layer 2: deterministic routing
from onion_guardian.layer2_router.router import DeterministicRouter

# Layer 3: security gateway
from onion_guardian.layer3_gateway.gateway import SecurityGateway
from onion_guardian.layer3_gateway.network_policy import NetworkPolicyConfig


def _default_config_path(filename: str) -> Path:
    """Return the path to a packaged default config resource."""
    ref = importlib.resources.files("onion_guardian.config").joinpath(filename)
    # `importlib.resources.files()` returns a Traversable. In the supported
    # packaging modes here it resolves cleanly to a filesystem path.
    return Path(str(ref))


def _load_yaml_file(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class OnionGuardian:
    """
    Main orchestrator for the onion-style middleware stack.

    Design principles:
    - each layer can be tested independently
    - the Guardian model analyzes intent and suggests rewrites, but is not the
      sole decision-maker
    - explicit critical policy matches can block without consulting an LLM
    - every request carries a full `layer_trace` for audit and debugging
    """

    def __init__(
        self,
        guardian: GuardianModel,
        layer1: SemanticAbstraction,
        layer2: DeterministicRouter,
        layer3: SecurityGateway,
        config: SecurityConfig,
        effective_config: EffectiveConfig,
    ):
        self.guardian = guardian
        self.layer1 = layer1
        self.layer2 = layer2
        self.layer3 = layer3
        self.config = config
        self.effective_config = effective_config

    @classmethod
    def from_config(
        cls,
        rules_path: str | Path | None = None,
        prompts_path: str | Path | None = None,
        guardian_backend: str | None = None,
        guardian_model: str | None = None,
        sandbox_root: str | Path | None = None,
        audit_log_path: str | None = None,
        network_mode: str | None = None,
        enable_llm: bool | None = None,
        **kwargs: Any,
    ) -> OnionGuardian:
        """
        Build a fully wired OnionGuardian instance from config.

        When ``rules_path`` or ``prompts_path`` is *None*, packaged defaults are
        used automatically. Explicit paths override the packaged defaults.

        Args:
            rules_path: Path to the security rules YAML file.
            prompts_path: Path to the Guardian prompt YAML file.
            guardian_backend: Guardian backend ("local" / "custom").
            guardian_model: Local model identifier or custom backend import target.
            sandbox_root: Sandbox root directory.
            audit_log_path: Audit log destination. ``None`` disables file writes.
            network_mode: Network policy mode ("none" / "restricted" / "open").
            enable_llm: Enable semantic LLM analysis. ``False`` keeps Guardian
                on deterministic policy evaluation only.
            **kwargs: Additional runtime overrides forwarded into config
                compilation.
        """
        rules_path = Path(rules_path) if rules_path else _default_config_path("default_rules.yaml")
        prompts_path = Path(prompts_path) if prompts_path else _default_config_path("guardian_prompts.yaml")

        # Load and compile runtime configuration.
        config = SecurityConfig.from_yaml(rules_path) if rules_path.exists() else SecurityConfig()
        prompts = _load_yaml_file(prompts_path if prompts_path.exists() else None)
        effective_config = compile_effective_config(
            rules_path=rules_path,
            prompts_path=prompts_path if prompts_path.exists() else None,
            raw_config=config,
            prompts=prompts,
            guardian_backend=guardian_backend,
            guardian_model=guardian_model,
            sandbox_root=sandbox_root,
            audit_log_path=audit_log_path,
            audit_level=kwargs.get("audit_level"),
            network_mode=network_mode,
            enable_llm=enable_llm,
            guardian_temperature=kwargs.get("guardian_temperature"),
            guardian_max_tokens=kwargs.get("guardian_max_tokens"),
            session_isolation=kwargs.get("session_isolation"),
            max_file_size_mb=kwargs.get("max_file_size_mb"),
            disk_quota_mb=kwargs.get("disk_quota_mb"),
            max_processes=kwargs.get("max_processes"),
            max_open_files=kwargs.get("max_open_files"),
            max_memory_mb=kwargs.get("max_memory_mb"),
            max_execution_time_sec=kwargs.get("max_execution_time_sec"),
            rate_limit=kwargs.get("rate_limit"),
        )

        # Build Guardian.
        guardian = GuardianModel(
            rules=list(effective_config.rules),
            prompts=effective_config.prompts,
            backend=effective_config.guardian.backend,
            model_name=effective_config.guardian.model_name,
            temperature=effective_config.guardian.temperature,
            max_tokens=effective_config.guardian.max_tokens,
            sandbox_base=effective_config.sandbox.base_path,
            enable_llm_analysis=effective_config.guardian.enable_llm_analysis,
        )

        # Build Layer 1.
        layer1 = SemanticAbstraction()

        # Build Layer 2.
        from onion_guardian.layer2_router.sandbox import SandboxConfig
        sandbox_cfg = SandboxConfig(
            base_path=effective_config.sandbox.base_path,
            session_isolation=effective_config.sandbox.session_isolation,
            max_file_size_mb=effective_config.sandbox.max_file_size_mb,
            disk_quota_mb=effective_config.sandbox.disk_quota_mb,
            max_processes=effective_config.sandbox.max_processes,
            max_open_files=effective_config.sandbox.max_open_files,
            max_memory_mb=effective_config.sandbox.max_memory_mb,
            max_execution_time_sec=effective_config.sandbox.max_execution_time_sec,
        )
        layer2 = DeterministicRouter(
            sandbox_config=sandbox_cfg,
            default_rate_limit=effective_config.rate_limit,
        )

        # Build Layer 3.
        net_config = NetworkPolicyConfig(
            mode=effective_config.network.mode,
            allowed_domains=list(effective_config.network.allowed_domains),
            allowed_ports=list(effective_config.network.allowed_ports),
        )
        layer3 = SecurityGateway(
            network_config=net_config,
            audit_log_path=effective_config.audit.log_path,
            audit_level=effective_config.audit.level,
        )

        return cls(
            guardian=guardian,
            layer1=layer1,
            layer2=layer2,
            layer3=layer3,
            config=config,
            effective_config=effective_config,
        )

    def process(
        self,
        request: ToolRequest,
        session_id: str,
        user_id: str,
    ) -> ExecutionResult:
        """
        Process a tool-call request through the full middleware pipeline.

        Args:
            request: The input tool request.
            session_id: Session identifier used for isolation.
            user_id: User identifier used for multi-tenant enforcement.

        Returns:
            An ``ExecutionResult`` containing the final verdict, the per-layer
            trace, and an ``execution_output`` plan when the request is allowed.
        """
        request_id = generate_token(16)
        start = time.monotonic()
        state = run_pipeline(
            PipelineState(
                request_id=request_id,
                session_id=session_id,
                user_id=user_id,
                action=request.action,
                params=dict(request.params),
            ),
            (
                lambda current: self._run_guardian(
                    request=request,
                    session_id=current.session_id,
                    user_id=current.user_id,
                    request_id=current.request_id,
                ),
                lambda current: self._run_layer1(
                    action=current.action,
                    params=dict(current.params),
                    session_id=current.session_id,
                ),
                lambda current: self._run_layer2(
                    action=current.action,
                    params=dict(current.params),
                    session_id=current.session_id,
                    user_id=current.user_id,
                ),
                lambda current: self._run_layer3(
                    action=current.action,
                    params=dict(current.params),
                    constraints=dict(current.constraints),
                    session_id=current.session_id,
                    user_id=current.user_id,
                    request_id=current.request_id,
                ),
            ),
        )

        if state.halted:
            self._emit_audit_events(state.audit_events)
            return ExecutionResult(
                request_id=request_id,
                verdict=state.final_verdict or ActionVerdict.BLOCK,
                layer_trace=list(state.layer_trace),
                reason=state.failure_reason,
                total_duration_ms=(time.monotonic() - start) * 1000,
            )

        committed, reason = self.layer2.commit_resources(
            action=state.action,
            params=dict(state.params),
            session_id=session_id,
        )
        if not committed:
            self._emit_audit_events(state.audit_events)
            return ExecutionResult(
                request_id=request_id,
                verdict=ActionVerdict.BLOCK,
                layer_trace=list(state.layer_trace),
                reason=reason,
                total_duration_ms=(time.monotonic() - start) * 1000,
            )

        # Phase 4: build the final execution plan for the external executor.
        execution_plan = build_execution_plan(
            action=state.action,
            params=state.params,
            session_id=session_id,
            user_id=user_id,
            constraints=state.constraints,
            rewrite_ops=state.rewrite_ops,
        )
        state = state.attach_execution_plan(execution_plan)
        self._emit_audit_events(state.audit_events)

        return ExecutionResult(
            request_id=request_id,
            verdict=ActionVerdict.ALLOW,
            layer_trace=list(state.layer_trace),
            reason="All security layers passed",
            total_duration_ms=(time.monotonic() - start) * 1000,
            execution_output=state.execution_plan.as_execution_output(),
        )

    # Internal helpers.

    def _run_guardian(
        self,
        request: ToolRequest,
        session_id: str,
        user_id: str,
        request_id: str,
    ) -> LayerResult:
        """Run Guardian evaluation."""
        start = time.monotonic()

        try:
            # Ensure the request carries the runtime session and user identity.
            request_copy = request.model_copy(
                update={"session_id": session_id, "user_id": user_id}
            )
            verdict: GuardianVerdict = self.guardian.evaluate(request_copy)

            if verdict.action == ActionVerdict.BLOCK:
                return LayerResult(
                    layer="guardian",
                    passed=False,
                    verdict=ActionVerdict.BLOCK,
                    reason=f"Guardian blocked the request: {verdict.reason}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            if verdict.action == ActionVerdict.ESCALATE:
                return LayerResult(
                    layer="guardian",
                    passed=False,
                    verdict=ActionVerdict.ESCALATE,
                    reason=f"Guardian escalated the request: {verdict.reason}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            if verdict.action == ActionVerdict.REWRITE:
                return LayerResult(
                    layer="guardian",
                    passed=True,
                    verdict=ActionVerdict.REWRITE,
                    reason=f"Guardian rewrote the request: {verdict.reason}",
                    transformed_action=verdict.rewritten_action,
                    transformed_params=verdict.rewritten_params,
                    rewrite_ops=verdict.rewrite_ops,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            return LayerResult(
                layer="guardian",
                passed=True,
                verdict=ActionVerdict.ALLOW,
                reason="Guardian allowed the request",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        except Exception:
            # Guardian failures are fail-closed because this layer carries
            # semantic protections that do not exist downstream.
            return LayerResult(
                layer="guardian",
                passed=False,
                verdict=ActionVerdict.BLOCK,
                reason="Guardian evaluation failed",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    def _run_layer1(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
    ) -> LayerResult:
        """Run Layer 1 semantic abstraction."""
        start = time.monotonic()

        try:
            request = ToolRequest(
                action=action,
                params=params,
                session_id=session_id,
                user_id="",  # Layer 1 does not need a user id.
            )
            return self.layer1.process(request)

        except Exception as e:
            return LayerResult(
                layer="layer1",
                passed=False,
                verdict=ActionVerdict.BLOCK,
                reason=f"Layer 1 error: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    def _run_layer2(
        self,
        action: str,
        params: dict[str, Any],
        session_id: str,
        user_id: str,
    ) -> LayerResult:
        """Run Layer 2 deterministic routing."""
        start = time.monotonic()

        try:
            result = self.layer2.process(
                action=action,
                params=params,
                session_id=session_id,
                user_id=user_id,
            )
            return result

        except Exception as e:
            return LayerResult(
                layer="layer2",
                passed=False,
                verdict=ActionVerdict.BLOCK,
                reason=f"Layer 2 error: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    def _run_layer3(
        self,
        action: str,
        params: dict[str, Any],
        constraints: dict[str, Any],
        session_id: str,
        user_id: str,
        request_id: str,
    ) -> LayerResult:
        """Run Layer 3 security gateway checks."""
        try:
            return self.layer3.process(
                action=action,
                params=params,
                constraints=constraints,
                session_id=session_id,
                user_id=user_id,
                request_id=request_id,
                emit_audit=False,
            )
        except Exception as e:
            return LayerResult(
                layer="layer3",
                passed=False,
                verdict=ActionVerdict.BLOCK,
                reason=f"Layer 3 error: {e}",
                duration_ms=0,
            )

    # Convenience helpers.

    def quick_check(
        self,
        action: str,
        params: dict[str, Any] | None = None,
        session_id: str = "default",
        user_id: str = "anonymous",
    ) -> ExecutionResult:
        """
        Run a quick policy check without manually constructing ``ToolRequest``.

        Example:
            result = guardian.quick_check(
                action="execute_code",
                params={"code": "curl http://10.6.96.3:8080", "language": "bash"},
                session_id="s1",
                user_id="u1",
            )
            print(result.verdict)  # ActionVerdict.BLOCK
        """
        request = ToolRequest(
            action=action,
            params=params or {},
            session_id=session_id,
            user_id=user_id,
        )
        return self.process(request, session_id=session_id, user_id=user_id)

    def get_llm_tools(self) -> list[dict[str, Any]]:
        """
        Export the LLM-visible tool list for function calling.

        Tool names are already abstracted, so the model does not see the real
        executor identifiers.
        """
        return self.layer1.get_tools_for_llm()

    def get_audit_stats(self) -> dict[str, Any]:
        """Return audit statistics from the configured audit sink."""
        return self.layer3.audit.get_stats()

    def get_effective_config(self) -> EffectiveConfig:
        """Return the compiled runtime configuration."""
        return self.effective_config

    def _emit_audit_events(self, events: tuple[AuditEvent, ...]) -> None:
        if not events:
            return
        self.layer3.audit.emit_events(events)
