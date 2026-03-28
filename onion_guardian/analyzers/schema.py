"""
Schema/validation analyzer for Layer 2.
"""

from __future__ import annotations

from dataclasses import dataclass

from onion_guardian.kernel.types import Signal
from onion_guardian.layer2_router.validator import ParamValidator, ValidationError
from onion_guardian.utils.types import ActionVerdict, RiskLevel


@dataclass(frozen=True)
class SchemaAnalysis:
    signals: tuple[Signal, ...] = ()


class SchemaAnalyzer:
    def __init__(self, validator: ParamValidator):
        self.validator = validator

    def analyze(self, action: str, params: dict, session_id: str) -> SchemaAnalysis:
        errors = self.validator.validate(action, params, session_id)
        signals: list[Signal] = []
        for error in errors:
            signals.append(self._signal_from_error(error))
        return SchemaAnalysis(signals=tuple(signals))

    def _signal_from_error(self, error: ValidationError) -> Signal:
        return Signal(
            source="layer2.validator",
            code=f"VALIDATION_{error.severity}",
            effect=ActionVerdict.BLOCK if error.severity == "ERROR" else ActionVerdict.ALLOW,
            severity=RiskLevel.HIGH if error.severity == "ERROR" else RiskLevel.LOW,
            reason=error.message,
            tags=("layer2", "validator", error.severity.lower()),
        )
