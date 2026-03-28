"""
Compatibility wrapper around the structured rewrite engine.
"""

from __future__ import annotations

from typing import Any, Iterable

from onion_guardian.rewrites.engine import RewriteEngine


class PromptRewriter:
    """
    Backward-compatible facade for legacy callers.

    New internal code should use ``onion_guardian.rewrites.engine.RewriteEngine``
    directly. This class intentionally stays thin and delegates all behavior to
    the structured rewrite engine.
    """

    def __init__(self, sandbox_base: str = "/workspace"):
        self.sandbox_base = sandbox_base
        self.engine = RewriteEngine(sandbox_base=sandbox_base)

    def rewrite(
        self,
        action: str,
        params: dict[str, Any],
        matched_rules: list[str],
        session_id: str = "",
    ) -> dict[str, Any]:
        return self.engine.rewrite(
            action=action,
            params=params,
            matched_rules=matched_rules,
            session_id=session_id,
        )

    def plan(
        self,
        action: str,
        params: dict[str, Any],
        matched_rules: list[str],
        session_id: str = "",
    ):
        return self.engine.plan(
            action=action,
            params=params,
            matched_rules=matched_rules,
            session_id=session_id,
        )

    def apply(self, params: dict[str, Any], ops: Iterable[Any]):
        return self.engine.apply(params=params, ops=tuple(ops))

    def rewrite_code(self, code: str, language: str, session_id: str = "") -> str:
        return self.engine.rewrite_code(code, language, session_id=session_id)
