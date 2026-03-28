"""
Layer 1 semantic abstraction.

Primary responsibilities:
1. map LLM tool-call requests to abstract actions
2. apply early type checks and parameter normalization
3. generate obfuscation tokens where needed
4. keep underlying implementation details hidden from the model

Key security properties:
- LLM-visible tool descriptions do not expose real paths, commands, or ports
- sensitive values can be tokenized so chain-of-thought leakage does not reveal
  raw executor details
"""

from __future__ import annotations

import time
from typing import Any

from onion_guardian.layer1_semantic.action_registry import ActionRegistry, AbstractAction, ParamSpec
from onion_guardian.utils.crypto import generate_session_key, obfuscate_param
from onion_guardian.utils.types import (
    ActionVerdict,
    LayerResult,
    ToolRequest,
)


class SemanticAbstraction:
    """
    Semantic abstraction layer for Layer 1.

    LLM ──(abstract action)──→ Layer 1 ──(normalized request)──→ Layer 2

    Responsibilities:
    1. resolve an incoming action against the abstract registry
    2. normalize parameters and fill defaults
    3. generate obfuscation tokens for sensitive values
    4. export the LLM-visible tool surface without implementation details
    """

    def __init__(self, registry: ActionRegistry | None = None):
        self.registry = registry or ActionRegistry()
        self._session_keys: dict[str, str] = {}  # session_id -> session_key
        self._obfuscation_maps: dict[str, dict[str, str]] = {}  # session_id -> {token: real_value}

    def process(self, request: ToolRequest) -> LayerResult:
        """
        Process a request through Layer 1.

        Returns:
            A ``LayerResult`` whose ``transformed_action`` and
            ``transformed_params`` represent the normalized request.
        """
        start = time.monotonic()

        # 1. Resolve the abstract action.
        action = self.registry.get(request.action)
        if action is None:
            return LayerResult(
                layer="layer1",
                passed=False,
                verdict=ActionVerdict.BLOCK,
                reason=f"Unknown action: {request.action}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # 2. Validate and normalize parameters.
        validated, errors = self._validate_params(action, request.params)
        if errors:
            return LayerResult(
                layer="layer1",
                passed=False,
                verdict=ActionVerdict.BLOCK,
                reason=f"Parameter validation failed: {'; '.join(errors)}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # 3. Obfuscate sensitive values while retaining runtime mappings.
        obfuscated = self._obfuscate_sensitive_params(
            action, validated, request.session_id
        )

        # 4. Resolve the executor-facing handler and parameter names.
        resolution = self.registry.resolve(request.action)
        if resolution:
            real_handler, params_map = resolution
            # Map abstract parameter names to executor-facing names.
            real_params = {}
            for abstract_name, real_name in params_map.items():
                if abstract_name in obfuscated:
                    real_params[real_name] = obfuscated[abstract_name]
            # Preserve values that are not explicitly remapped.
            for k, v in obfuscated.items():
                mapped = False
                for abstract_name in params_map:
                    if k == abstract_name:
                        mapped = True
                        break
                if not mapped:
                    real_params[k] = v
        else:
            real_handler = request.action
            real_params = obfuscated

        return LayerResult(
            layer="layer1",
            passed=True,
            verdict=ActionVerdict.ALLOW,
            transformed_action=real_handler,
            transformed_params=real_params,
            reason="Layer 1 passed: action resolved and parameters validated",
            duration_ms=(time.monotonic() - start) * 1000,
        )

    def get_tools_for_llm(self, categories: list[str] | None = None) -> list[dict]:
        """
        Return the tool list exposed to the LLM.

        This is the only tool interface the model should see. It does not
        include real paths, commands, or parameter remapping details.
        """
        return self.registry.export_for_llm(categories)

    def deobfuscate(self, session_id: str, token: str) -> str | None:
        """Resolve an obfuscation token back to its real value."""
        mapping = self._obfuscation_maps.get(session_id, {})
        return mapping.get(token, token)  # Return the original token if unresolved.

    # Internal helpers.

    def _validate_params(
        self, action: AbstractAction, params: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Validate and normalize parameters against the action schema."""
        validated = {}
        errors = []

        for spec in action.params:
            if spec.name in params:
                value = params[spec.name]

                # Type check.
                error = self._check_type(spec, value)
                if error:
                    errors.append(error)
                    continue

                # Length check.
                if isinstance(value, str) and len(value) > spec.max_length:
                    errors.append(
                        f"Parameter '{spec.name}' exceeds the maximum length ({len(value)} > {spec.max_length})"
                    )
                    continue

                # Path safety check.
                if spec.type == "path" and spec.path_must_be_relative:
                    if isinstance(value, str) and (value.startswith("/") or ".." in value):
                        errors.append(
                            f"Parameter '{spec.name}' must be a relative path and cannot contain '..' or start with '/'"
                        )
                        continue

                validated[spec.name] = value

            elif spec.required:
                errors.append(f"Missing required parameter: '{spec.name}'")

            elif spec.default is not None:
                validated[spec.name] = spec.default

        return validated, errors

    def _check_type(self, spec: ParamSpec, value: Any) -> str | None:
        """Run a basic type check for one parameter."""
        type_checks = {
            "string": lambda v: isinstance(v, str),
            "path": lambda v: isinstance(v, str),
            "integer": lambda v: isinstance(v, int),
            "boolean": lambda v: isinstance(v, bool),
            "enum": lambda v: isinstance(v, str) and v in spec.enum_values,
        }

        checker = type_checks.get(spec.type)
        if checker and not checker(value):
            if spec.type == "enum":
                return f"Parameter '{spec.name}' must be one of: {spec.enum_values}"
            return (
                f"Parameter '{spec.name}' has the wrong type: "
                f"expected {spec.type}, got {type(value).__name__}"
            )
        return None

    def _obfuscate_sensitive_params(
        self, action: AbstractAction, params: dict[str, Any], session_id: str
    ) -> dict[str, Any]:
        """
        Obfuscate sensitive parameters.

        At the moment this primarily targets path-like parameters so reasoning
        traces do not leak raw filesystem locations.
        """
        if session_id not in self._session_keys:
            self._session_keys[session_id] = generate_session_key()
            self._obfuscation_maps[session_id] = {}

        session_key = self._session_keys[session_id]
        obf_map = self._obfuscation_maps[session_id]
        result = dict(params)

        for spec in action.params:
            if spec.type == "path" and spec.name in result:
                real_value = result[spec.name]
                token = obfuscate_param(str(real_value), session_key)
                obf_map[token] = real_value
                # Keep the real runtime value while storing the obfuscation token
                # for downstream audit and debugging use.
                result[f"_obf_{spec.name}"] = token

        return result

    def cleanup_session(self, session_id: str) -> None:
        """Drop obfuscation state associated with a session."""
        self._session_keys.pop(session_id, None)
        self._obfuscation_maps.pop(session_id, None)
