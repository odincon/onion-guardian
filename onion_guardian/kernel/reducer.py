"""
Signal reducer for effect-first policy decisions.
"""

from __future__ import annotations

from collections.abc import Iterable

from onion_guardian.contracts.common import ActionVerdict, RiskLevel
from onion_guardian.kernel.types import Decision, Signal


_EFFECT_PRIORITY = {
    ActionVerdict.ALLOW: 0,
    ActionVerdict.REWRITE: 1,
    ActionVerdict.ESCALATE: 2,
    ActionVerdict.BLOCK: 3,
}

_RISK_PRIORITY = {
    RiskLevel.SAFE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def reduce_signals(signals: Iterable[Signal]) -> Decision:
    """
    Reduce multiple policy signals into one deterministic decision.
    """
    materialized = tuple(signals)
    if not materialized:
        return Decision(
            effect=ActionVerdict.ALLOW,
            severity=RiskLevel.SAFE,
            reasons=(),
            matched_rules=(),
            signals=(),
            rewrite_ops=(),
            audit_tags=(),
        )

    effect = max(materialized, key=lambda signal: _EFFECT_PRIORITY[signal.effect]).effect
    severity = max(materialized, key=lambda signal: _RISK_PRIORITY[signal.severity]).severity

    reasons = _dedupe(signal.reason for signal in materialized if signal.reason)
    matched_rules = _dedupe(
        signal.rule_id for signal in materialized if signal.rule_id
    )
    audit_tags = _dedupe(
        tag
        for signal in materialized
        for tag in signal.tags
    )
    rewrite_ops = ()
    if effect == ActionVerdict.REWRITE:
        rewrite_ops = tuple(
            rewrite_op
            for signal in materialized
            if signal.effect == ActionVerdict.REWRITE
            for rewrite_op in signal.rewrite_ops
        )

    return Decision(
        effect=effect,
        severity=severity,
        reasons=reasons,
        matched_rules=matched_rules,
        signals=materialized,
        rewrite_ops=rewrite_ops,
        audit_tags=audit_tags,
    )


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)
