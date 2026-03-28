"""
Guardian model implementation for Onion Guardian.

The Guardian model is the outer policy sentinel in the onion-style stack.
It is intended to be a small local model (roughly 1-3B parameters) focused on
intent analysis and security review.

Core design ideas:
- do not trust the protected primary LLM to enforce security policy
- prefer local execution with low latency and no external dependency
- prefer rewrite-or-restrict behavior over unnecessary hard rejection

Supported backends:
1. `local`: local transformers model, preferred for isolation
2. `openai`: OpenAI API fallback
3. `anthropic`: Anthropic API fallback
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import replace
from typing import Any, Optional

import yaml

from onion_guardian.guardian.intent_analyzer import IntentAnalyzer, IntentAnalysis
from onion_guardian.kernel.reducer import reduce_signals
from onion_guardian.kernel.types import Decision, Signal
from onion_guardian.rewrites.engine import RewriteEngine
from onion_guardian.utils.types import (
    ActionVerdict,
    GuardianVerdict,
    RiskLevel,
    SecurityRule,
    ToolRequest,
)
from onion_guardian.defaults import (
    DEFAULT_GUARDIAN_BACKEND,
    DEFAULT_GUARDIAN_MAX_TOKENS,
    DEFAULT_GUARDIAN_TEMPERATURE,
    DEFAULT_LOCAL_MODEL,
    DEFAULT_OPENAI_MODEL,
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_SANDBOX_BASE_PATH,
)

logger = logging.getLogger("onion_guardian.guardian")


class GuardianModel:
    """
    AI policy sentinel for the outermost middleware layer.

    Workflow:
    1. run deterministic intent analysis first
    2. if needed, fall back to an LLM backend for semantic review
    3. derive `ALLOW` / `REWRITE` / `BLOCK` / `ESCALATE`
    4. if the decision is `REWRITE`, produce structured rewrite operations

    Usage:
        guardian = GuardianModel.from_config("config/default_rules.yaml")
        verdict = guardian.evaluate(request)
    """

    def __init__(
        self,
        rules: list[SecurityRule],
        prompts: dict[str, str],
        backend: str = DEFAULT_GUARDIAN_BACKEND,
        model_name: str = DEFAULT_LOCAL_MODEL,
        temperature: float = DEFAULT_GUARDIAN_TEMPERATURE,
        max_tokens: int = DEFAULT_GUARDIAN_MAX_TOKENS,
        sandbox_base: str = DEFAULT_SANDBOX_BASE_PATH,
        enable_llm_analysis: bool = True,
    ):
        self.rules = rules
        self.prompts = prompts
        self.backend = backend
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.enable_llm_analysis = enable_llm_analysis

        # Core collaborators.
        self.intent_analyzer = IntentAnalyzer(rules)
        self.rewriter = RewriteEngine(sandbox_base=sandbox_base)

        # Lazily initialized LLM backend.
        self._llm = None

    @classmethod
    def from_config(
        cls,
        rules_path: str,
        prompts_path: str | None = None,
        enable_llm_analysis: bool | None = None,
    ) -> "GuardianModel":
        """Construct a Guardian model from YAML config files."""
        with open(rules_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        # Parse rule definitions.
        rules = []
        for rule_data in config.get("rules", []):
            rules.append(SecurityRule(**rule_data))

        # Parse prompt templates.
        prompts = {}
        if prompts_path:
            with open(prompts_path, "r", encoding="utf-8") as f:
                prompts = yaml.safe_load(f)

        guardian_cfg = config.get("guardian", {})
        sandbox_cfg = config.get("sandbox", {})

        return cls(
            rules=rules,
            prompts=prompts,
            backend=guardian_cfg.get("backend", DEFAULT_GUARDIAN_BACKEND),
            model_name=guardian_cfg.get("model_name", DEFAULT_LOCAL_MODEL),
            temperature=guardian_cfg.get("temperature", DEFAULT_GUARDIAN_TEMPERATURE),
            max_tokens=guardian_cfg.get("max_tokens", DEFAULT_GUARDIAN_MAX_TOKENS),
            sandbox_base=sandbox_cfg.get("base_path", DEFAULT_SANDBOX_BASE_PATH),
            enable_llm_analysis=enable_llm_analysis if enable_llm_analysis is not None
                               else guardian_cfg.get("enable_llm_analysis", True),
        )

    def evaluate(self, request: ToolRequest) -> GuardianVerdict:
        """
        Evaluate the security risk of a request.

        This is the main Guardian entrypoint.

        Processing flow:
        1. run deterministic rule matching first
        2. block immediately on explicit critical policy hits
        3. use an LLM only when additional semantic analysis is needed
        4. combine rule-based and LLM signals into the final verdict
        """
        start = time.monotonic()

        # Step 1: deterministic rule analysis.
        intent = self.intent_analyzer.analyze(
            action=request.action,
            params=request.params,
            session_id=request.session_id,
            context_history=request.context_history,
        )
        has_rule_match = any(signal.source == "rule_match" for signal in intent.signals)

        # Explicit rules take precedence over LLM outputs so YAML policy remains
        # the authority.
        if has_rule_match:
            return self._build_verdict_from_intent(intent, request)

        fallback_verdict = self._build_verdict_from_intent(intent, request)

        # Step 3: allow SAFE / LOW paths unless they merit deeper analysis.
        if intent.highest_risk in (RiskLevel.SAFE, RiskLevel.LOW):
            # Optionally call the LLM when the request still looks complex.
            if self.enable_llm_analysis and self._needs_llm_analysis(request):
                llm_verdict = self._llm_analyze(request, intent)
                if llm_verdict:
                    return llm_verdict

            return fallback_verdict

        # Step 4: MEDIUM / HIGH requests may require deeper semantic review.
        if self.enable_llm_analysis:
            llm_verdict = self._llm_analyze(request, intent)
            if llm_verdict:
                return llm_verdict

        # Fall back to rule-derived behavior when the LLM is disabled or
        # unavailable.
        return fallback_verdict

    def _needs_llm_analysis(self, request: ToolRequest) -> bool:
        """Return whether the request warrants deeper LLM analysis."""
        # Multi-turn conversations may indicate dependency-chain escalation.
        has_conversation_depth = len(request.context_history) >= 3
        if has_conversation_depth:
            return True
        # Code-execution requests above a trivial length benefit from semantic
        # review.  The cutoff is intentionally generous: anything much longer
        # than a short snippet is worth a look.
        if request.action in ("execute_code", "run_command"):
            code = request.params.get("code", "")
            is_nontrivial = len(code) > 200
            if is_nontrivial:
                return True
        return False

    def _build_verdict_from_intent(
        self, intent: IntentAnalysis, request: ToolRequest
    ) -> GuardianVerdict:
        """Build a Guardian verdict from analyzed intent signals."""
        decision = self._build_decision_from_intent(intent, request)
        matched_rules = list(decision.matched_rules)

        # Materialize rewritten params only for rewrite decisions.
        rewritten_params = None
        if decision.effect == ActionVerdict.REWRITE:
            rewritten_params = self.rewriter.apply(request.params, decision.rewrite_ops)

        reason = "; ".join(decision.reasons) if decision.reasons else "Security checks passed"

        return GuardianVerdict(
            risk_level=decision.severity,
            action=decision.effect,
            confidence=max((s.confidence for s in intent.signals), default=0.5),
            reason=reason,
            matched_rules=matched_rules,
            rewritten_params=rewritten_params,
            rewrite_ops=[
                {
                    "op": op.op,
                    "target": op.target,
                    "value": op.value,
                    "reason": op.reason,
                }
                for op in decision.rewrite_ops
            ],
            detected_intent=intent.chain_stage if intent.is_chain_attack else "normal",
            intent_chain=[intent.chain_stage] if intent.is_chain_attack else [],
        )

    def _build_decision_from_intent(
        self, intent: IntentAnalysis, request: ToolRequest
    ) -> Decision:
        """Convert intent analysis into an effect-first decision."""
        decision = reduce_signals(self._build_policy_signals(intent))
        if decision.effect != ActionVerdict.REWRITE:
            return decision

        rewrite_plan = self.rewriter.plan(
            action=request.action,
            params=request.params,
            matched_rules=list(decision.matched_rules),
            session_id=request.session_id,
        )
        return replace(decision, rewrite_ops=rewrite_plan.ops)

    def _build_policy_signals(self, intent: IntentAnalysis) -> tuple[Signal, ...]:
        rule_map = {rule.rule_id: rule for rule in self.rules}
        signals: list[Signal] = []

        for intent_signal in intent.signals:
            rule = rule_map.get(intent_signal.rule_id)
            effect = (
                rule.action
                if intent_signal.source == "rule_match" and rule is not None
                else self._fallback_verdict_from_risk(intent_signal.risk_level)
            )
            signals.append(
                Signal(
                    source=intent_signal.source,
                    code=intent_signal.rule_id or intent_signal.source,
                    effect=effect,
                    severity=intent_signal.risk_level,
                    reason=intent_signal.description or "Security signal",
                    rule_id=intent_signal.rule_id or None,
                    confidence=intent_signal.confidence,
                    matched_text=intent_signal.matched_text,
                    tags=(intent_signal.source,),
                )
            )

        return tuple(signals)

    def _fallback_verdict_from_risk(self, risk_level: RiskLevel) -> ActionVerdict:
        """Fallback policy semantics when no explicit rule effect exists."""
        if risk_level == RiskLevel.CRITICAL:
            return ActionVerdict.BLOCK
        if risk_level == RiskLevel.HIGH:
            return ActionVerdict.BLOCK
        if risk_level == RiskLevel.MEDIUM:
            return ActionVerdict.REWRITE
        return ActionVerdict.ALLOW

    # LLM analysis helpers.

    def _llm_analyze(
        self, request: ToolRequest, intent: IntentAnalysis
    ) -> GuardianVerdict | None:
        """Run semantic analysis through the configured LLM backend."""
        try:
            llm = self._get_llm()
            if llm is None:
                return None

            # Build the prompt payload.
            analysis_prompt = self._build_analysis_prompt(request)

            # Call the LLM backend.
            response = llm.generate(
                system_prompt=self.prompts.get("system_prompt", ""),
                user_prompt=analysis_prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )

            # Parse the model response back into a verdict.
            return self._parse_llm_response(response, intent)

        except Exception as e:
            logger.warning(f"Guardian LLM analysis failed: {e}")
            return None

    def _build_analysis_prompt(self, request: ToolRequest) -> str:
        """Build the analysis prompt sent to the Guardian LLM."""
        template = self.prompts.get("analysis_template", "")

        context = "\n".join(
            f"[{i+1}] {msg[:200]}"
            for i, msg in enumerate(request.context_history[-5:])
        )

        return template.format(
            action=request.action,
            params=json.dumps(request.params, ensure_ascii=False, indent=2)[:500],
            context_window=min(len(request.context_history), 5),
            context=context or "(no prior context)",
        )

    def _parse_llm_response(
        self, response: str, rule_intent: IntentAnalysis
    ) -> GuardianVerdict | None:
        """Parse the LLM JSON response into a Guardian verdict."""
        try:
            # Extract the JSON payload from the raw model output.
            json_match = _extract_json(response)
            if not json_match:
                return None

            data = json.loads(json_match)

            risk_level = RiskLevel(data.get("risk_level", "SAFE"))
            verdict = ActionVerdict(data.get("verdict", "ALLOW"))

            # If deterministic rules detected a higher risk, keep the stronger
            # policy result. The LLM must not downgrade explicit rule matches.
            if _risk_order(rule_intent.highest_risk) > _risk_order(risk_level):
                risk_level = rule_intent.highest_risk
                # Explicit block semantics cannot be downgraded by the LLM.
                if rule_intent.highest_risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    verdict = ActionVerdict.BLOCK

            return GuardianVerdict(
                risk_level=risk_level,
                action=verdict,
                confidence=float(data.get("confidence", 0.7)),
                reason=data.get("reason", "LLM analysis result"),
                detected_intent=data.get("detected_intent", ""),
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse Guardian LLM response: {e}")
            return None

    def _get_llm(self) -> Optional["GuardianLLMBackend"]:
        """Lazily initialize the configured LLM backend."""
        if self._llm is not None:
            return self._llm

        if self.backend == "local":
            self._llm = LocalGuardianLLM(self.model_name)
        elif self.backend == "openai":
            self._llm = OpenAIGuardianLLM(self.model_name)
        elif self.backend == "anthropic":
            self._llm = AnthropicGuardianLLM(self.model_name)
        else:
            logger.warning(f"Unknown Guardian backend: {self.backend}")
            return None

        return self._llm


# LLM backend abstractions.

class GuardianLLMBackend:
    """Abstract base class for Guardian LLM backends."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = DEFAULT_GUARDIAN_TEMPERATURE,
        max_tokens: int = DEFAULT_GUARDIAN_MAX_TOKENS,
    ) -> str:
        raise NotImplementedError


class LocalGuardianLLM(GuardianLLMBackend):
    """
    Local transformers backend.

    Recommended small-model options:
    - Qwen/Qwen2.5-1.5B-Instruct
    - microsoft/Phi-3-mini-4k-instruct
    - another compact instruct-tuned local model
    """

    def __init__(self, model_name: str):
        self.model_name = model_name
        self._pipeline = None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = DEFAULT_GUARDIAN_TEMPERATURE,
        max_tokens: int = DEFAULT_GUARDIAN_MAX_TOKENS,
    ) -> str:
        pipeline = self._get_pipeline()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        outputs = pipeline(
            messages,
            max_new_tokens=max_tokens,
            temperature=temperature,
            do_sample=temperature > 0,
            return_full_text=False,
        )
        return outputs[0]["generated_text"]

    def _get_pipeline(self):
        if self._pipeline is None:
            try:
                from transformers import pipeline
                self._pipeline = pipeline(
                    "text-generation",
                    model=self.model_name,
                    device_map="auto",
                    torch_dtype="auto",
                )
            except ImportError:
                raise RuntimeError(
                    "transformers is not installed. Run: pip install onion-guardian[guardian-local]"
                )
        return self._pipeline


class OpenAIGuardianLLM(GuardianLLMBackend):
    """OpenAI API backend."""

    def __init__(self, model_name: str = DEFAULT_OPENAI_MODEL):
        self.model_name = model_name
        self._client = None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = DEFAULT_GUARDIAN_TEMPERATURE,
        max_tokens: int = DEFAULT_GUARDIAN_MAX_TOKENS,
    ) -> str:
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content

    def _get_client(self):
        if self._client is None:
            try:
                import openai
                self._client = openai.OpenAI()
            except ImportError:
                raise RuntimeError(
                    "openai is not installed. Run: pip install onion-guardian[guardian-api]"
                )
        return self._client


class AnthropicGuardianLLM(GuardianLLMBackend):
    """Anthropic API backend."""

    def __init__(self, model_name: str = DEFAULT_ANTHROPIC_MODEL):
        self.model_name = model_name
        self._client = None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = DEFAULT_GUARDIAN_TEMPERATURE,
        max_tokens: int = DEFAULT_GUARDIAN_MAX_TOKENS,
    ) -> str:
        client = self._get_client()
        response = client.messages.create(
            model=self.model_name,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.content[0].text

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic()
            except ImportError:
                raise RuntimeError(
                    "anthropic is not installed. Run: pip install onion-guardian[guardian-api]"
                )
        return self._client


# Helper functions.

def _extract_json(text: str) -> str | None:
    """Extract a JSON object or fenced JSON block from text."""
    import re
    # Try fenced ```json ... ``` output first.
    match = re.search(r'```json\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # Fall back to a direct `{ ... }` object.
    match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    return None


def _risk_order(level: RiskLevel) -> int:
    return {
        RiskLevel.SAFE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }[level]
