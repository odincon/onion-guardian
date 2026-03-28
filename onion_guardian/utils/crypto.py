"""
onion_guardian.utils.crypto - security utilities.

Helpers for parameter obfuscation, hashing, token generation, and log
sanitization.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import base64
from typing import Any


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(length)


def generate_session_key() -> str:
    """Generate a one-time session key for parameter obfuscation."""
    return secrets.token_urlsafe(24)


def obfuscate_param(value: str, session_key: str) -> str:
    """
    Obfuscate a parameter value before it reaches the model.

    The LLM sees an obfuscated token rather than the raw value, which helps
    reduce chain-of-thought or memory leakage of executor details.
    """
    raw = hmac.new(
        session_key.encode(),
        value.encode(),
        hashlib.sha256,
    ).digest()
    return f"__OBF_{base64.urlsafe_b64encode(raw[:12]).decode()}__"


def deobfuscate_param(token: str, mapping: dict[str, str]) -> str | None:
    """Resolve an obfuscation token back to its original value."""
    return mapping.get(token)


def hash_path(path: str) -> str:
    """Hash a path so audit logs do not expose the real filesystem location."""
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def sanitize_for_log(data: dict[str, Any], sensitive_keys: set[str] | None = None) -> dict[str, Any]:
    """
    Redact sensitive fields before data reaches audit logs.

    This helps avoid exposing secrets such as credentials or host details in
    persisted records.
    """
    if sensitive_keys is None:
        sensitive_keys = {
            "password", "secret", "token", "key", "apikey",
            "api_key", "private_key", "certificate", "cert",
            "ip", "host", "addr", "address",
        }

    sanitized = {}
    for k, v in data.items():
        if any(sk in k.lower() for sk in sensitive_keys):
            sanitized[k] = "***REDACTED***"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_for_log(v, sensitive_keys)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_for_log(item, sensitive_keys) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized
