"""
Network analyzer for Layer 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from onion_guardian.kernel.types import Signal
from onion_guardian.layer3_gateway.network_policy import NetworkPolicy
from onion_guardian.utils.types import ActionVerdict, RiskLevel


@dataclass(frozen=True)
class NetworkAnalysis:
    signals: tuple[Signal, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


class NetworkAnalyzer:
    def __init__(self, network_policy: NetworkPolicy):
        self.network_policy = network_policy

    def analyze(self, action: str, params: dict[str, str], session_id: str) -> NetworkAnalysis:
        if action != "network_proxy.request":
            return NetworkAnalysis()

        url = params.get("target_url", "") or params.get("url", "")
        allowed, reason = self.network_policy.check_url(url, session_id)
        if allowed:
            return NetworkAnalysis()

        return NetworkAnalysis(
            signals=(
                Signal(
                    source="layer3.network_policy",
                    code="NETWORK_POLICY_BLOCK",
                    effect=ActionVerdict.BLOCK,
                    severity=RiskLevel.HIGH,
                    reason=reason,
                    tags=("layer3", "network_policy"),
                ),
            ),
            metadata={"url": url},
        )
