"""
Rate-limit analyzer for Layer 2.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from onion_guardian.kernel.types import Signal
from onion_guardian.utils.types import ActionVerdict, RiskLevel


@dataclass(frozen=True)
class RateLimitAnalysis:
    signals: tuple[Signal, ...] = ()


class RateLimitAnalyzer:
    def __init__(self) -> None:
        self._rate_counters: dict[str, list[float]] = {}

    def analyze(
        self,
        session_id: str,
        rate_limit: int,
        now: float | None = None,
    ) -> RateLimitAnalysis:
        if self._allow(session_id, rate_limit, now=now):
            return RateLimitAnalysis()

        return RateLimitAnalysis(
            signals=(
                Signal(
                    source="layer2.rate_limit",
                    code="RATE_LIMIT_BLOCK",
                    effect=ActionVerdict.BLOCK,
                    severity=RiskLevel.HIGH,
                    reason=f"Rate limit exceeded: at most {rate_limit} calls per minute",
                    tags=("layer2", "rate_limit"),
                ),
            )
        )

    def cleanup_session(self, session_id: str) -> None:
        self._rate_counters.pop(session_id, None)

    def _allow(self, session_id: str, rate_limit: int, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        window = 60.0

        timestamps = self._rate_counters.setdefault(session_id, [])
        self._rate_counters[session_id] = [
            timestamp for timestamp in timestamps if current_time - timestamp < window
        ]

        if len(self._rate_counters[session_id]) >= rate_limit:
            return False

        self._rate_counters[session_id].append(current_time)
        return True
