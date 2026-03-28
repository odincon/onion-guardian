"""
Structured rewrite planning types.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from onion_guardian.kernel.types import RewriteOp


@dataclass(frozen=True)
class RewritePlan:
    ops: tuple[RewriteOp, ...] = field(default_factory=tuple)
