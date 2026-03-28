"""
onion_guardian.guardian.intent_analyzer - intent analysis engine.

Multi-strategy intent analysis:
1. rule matching as a fast path
2. dependency-chain detection for multi-turn escalation
3. context-drift detection when the topic shifts toward sensitive areas
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from onion_guardian.utils.types import RiskLevel, SecurityRule, RuleCategory
from onion_guardian.defaults import DEFAULT_SENSITIVE_KEYWORDS, DEFAULT_DRIFT_MIN_HITS


@dataclass
class IntentSignal:
    """One intent signal."""
    source: str          # "rule_match" / "chain_detect" / "drift_detect"
    rule_id: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    description: str = ""
    confidence: float = 0.0
    matched_text: str = ""


@dataclass
class IntentAnalysis:
    """Full intent-analysis result."""
    signals: list[IntentSignal] = field(default_factory=list)
    highest_risk: RiskLevel = RiskLevel.SAFE
    is_chain_attack: bool = False
    chain_stage: str = "none"  # none / setup / escalation / extraction

    @property
    def has_risk(self) -> bool:
        return self.highest_risk not in (RiskLevel.SAFE, RiskLevel.LOW)

    def add_signal(self, signal: IntentSignal) -> None:
        self.signals.append(signal)
        if _risk_order(signal.risk_level) > _risk_order(self.highest_risk):
            self.highest_risk = signal.risk_level


def _risk_order(level: RiskLevel) -> int:
    return {
        RiskLevel.SAFE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }[level]


class IntentAnalyzer:
    """
    Intent analyzer, the first defense line in the onion architecture.

    It applies deterministic screening before the Guardian model gets involved.
    This reduces LLM load and ensures known attack vectors are blocked without
    depending on model judgment.

    Extra knobs:
    - ``extra_sensitive_keywords``: add more sensitive keywords
    - ``drift_min_hits``: minimum sensitive-keyword hits in recent history
      to trigger a drift signal (default: 3)
    """

    def __init__(
        self,
        rules: list[SecurityRule],
        extra_sensitive_keywords: set[str] | None = None,
        drift_min_hits: int = DEFAULT_DRIFT_MIN_HITS,
    ):
        self._rules = [r for r in rules if r.enabled]
        self._extra_sensitive_keywords = extra_sensitive_keywords or set()
        self._drift_min_hits = drift_min_hits
        # Precompile regular expressions.
        self._compiled: dict[str, list[tuple[re.Pattern, SecurityRule]]] = {}
        for rule in self._rules:
            category = rule.category.value
            if category not in self._compiled:
                self._compiled[category] = []
            for pattern in rule.patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self._compiled[category].append((compiled, rule))
                except re.error:
                    pass  # Skip invalid regex patterns.

    def analyze(
        self,
        action: str,
        params: dict,
        session_id: str = "",
        context_history: list[str] | None = None,
    ) -> IntentAnalysis:
        """
        Run the full intent analysis.

        Args:
            action: action name
            params: request parameters
            session_id: current session ID, used for `{SESSION_ID}` placeholders
            context_history: recent conversation history
        """
        result = IntentAnalysis()

        # Build the text blob to scan.
        text_to_scan = self._build_scan_text(action, params)

        # 1. Rule matching.
        self._match_rules(text_to_scan, session_id, result)

        # 2. Dependency-chain detection.
        if context_history:
            self._detect_chain_attack(context_history, text_to_scan, result)

        # 3. Context-drift detection.
        if context_history:
            self._detect_context_drift(context_history, result)

        return result

    def _build_scan_text(self, action: str, params: dict) -> str:
        """Flatten action and params into scanable text."""
        parts = [action]
        for key, value in params.items():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(str(v) for v in value)
            elif isinstance(value, dict):
                parts.extend(str(v) for v in value.values())
        return "\n".join(parts)

    def _match_rules(
        self, text: str, session_id: str, result: IntentAnalysis
    ) -> None:
        """Run rule matching with precompiled regular expressions."""
        for category, patterns in self._compiled.items():
            for compiled_re, rule in patterns:
                # Replace the session-ID placeholder.
                if "{SESSION_ID}" in rule.patterns[0]:
                    try:
                        adjusted = re.compile(
                            compiled_re.pattern.replace("{SESSION_ID}", re.escape(session_id)),
                            re.IGNORECASE | re.MULTILINE,
                        )
                    except re.error:
                        continue
                else:
                    adjusted = compiled_re

                match = adjusted.search(text)
                if match:
                    result.add_signal(IntentSignal(
                        source="rule_match",
                        rule_id=rule.rule_id,
                        risk_level=RiskLevel(rule.severity),
                        description=rule.description,
                        confidence=0.9,  # discrete tier: deterministic match
                        matched_text=match.group()[:100],
                    ))

    def _detect_chain_attack(
        self, history: list[str], current: str, result: IntentAnalysis
    ) -> None:
        """
        Detect dependency-chain attacks.

        Typical pattern:
        - turn 1: an apparently benign technical question
        - turn 2: a premise like "we need to inspect X first"
        - turn 3: a request that extracts internal or sensitive information

        Detection focuses on gradual shifts from general knowledge to concrete
        implementation details and then to internal system data.
        """
        chain_patterns = [
            (
                r"(need|must|have to|first|before).*(understand|get|inspect|check|look at|read|access|fetch)",
                "setup",
            ),
            (
                r"(to|in order to).*(answer|solve|complete|understand).*(need|must|have to|first)",
                "setup",
            ),
            (
                r"(based on|according to).*(previous|above|earlier|last step).*(result|info|analysis|step).*(further|continue|next|get|fetch|read|inspect)",
                "escalation",
            ),
            (
                r"(just now|last step|previous analysis).*(found|saw|noticed).*(so|therefore|next|continue)",
                "escalation",
            ),
            (
                r"(get|read|inspect|check|access|show|fetch).*(config|key|cert|certificate|environment|system|network|ssl|tls)",
                "extraction",
            ),
            (r"(can you|please).*(show|read|get|fetch).*(config|key|cert|env|system)", "extraction"),
            (r"/(etc|proc|sys|root)/", "extraction"),
            (r"\.(pem|key|crt|env|yaml|yml|cnf)\b", "extraction"),
        ]

        # Track stage progression across history and the current request.
        stages_seen: dict[str, int] = {}  # stage -> first matching message index
        all_messages = list(history) + [current]

        for idx, msg in enumerate(all_messages):
            for pattern, stage in chain_patterns:
                if re.search(pattern, msg, re.IGNORECASE):
                    if stage not in stages_seen:
                        stages_seen[stage] = idx

        # Detection logic:
        # 1. setup + escalation in sequence strongly suggests extraction next
        # 2. setup followed by extraction also counts as a dependency chain
        is_chain = False
        chain_stage = "none"

        if "setup" in stages_seen and "escalation" in stages_seen:
            # setup before escalation indicates a classic dependency chain
            if stages_seen["setup"] <= stages_seen["escalation"]:
                is_chain = True
                chain_stage = "extraction"

        elif "setup" in stages_seen and "extraction" in stages_seen:
            if stages_seen["setup"] < stages_seen["extraction"]:
                is_chain = True
                chain_stage = "extraction"

        if is_chain:
            result.is_chain_attack = True
            result.chain_stage = chain_stage
            result.add_signal(IntentSignal(
                source="chain_detect",
                risk_level=RiskLevel.HIGH,
                description=f"Detected a dependency-chain attack (stage: {chain_stage})",
                confidence=0.8,  # discrete tier: heuristic match
            ))

    def _detect_context_drift(
        self, history: list[str], result: IntentAnalysis
    ) -> None:
        """
        Detect context drift.

        This checks whether the conversation gradually drifts from safe topics
        toward sensitive ones.  The detection is purely discrete: count how many
        distinct sensitive keywords appear in recent turns.  No density formula
        or continuous scoring is used — the threshold is a simple hit count that
        operators can tune via ``drift_min_hits``.
        """
        sensitive_keywords = set(DEFAULT_SENSITIVE_KEYWORDS) | self._extra_sensitive_keywords

        # Look at the last few turns only.
        recent = history[-3:] if len(history) >= 3 else history

        # Count distinct sensitive-keyword hits across recent messages.
        hits: set[str] = set()
        for msg in recent:
            msg_lower = msg.lower()
            for kw in sensitive_keywords:
                if kw.lower() in msg_lower:
                    hits.add(kw.lower())

        if len(hits) >= self._drift_min_hits:
            result.add_signal(IntentSignal(
                source="drift_detect",
                risk_level=RiskLevel.MEDIUM,
                description=(
                    f"Context drift detected: {len(hits)} sensitive keyword(s) "
                    f"in recent history (threshold: {self._drift_min_hits})"
                ),
                confidence=0.8,
                matched_text=", ".join(sorted(hits)[:5]),
            ))
