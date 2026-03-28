"""
Shared runtime types used across the middleware stack.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from onion_guardian.contracts.common import ActionVerdict, RiskLevel
from onion_guardian.defaults import (
    DEFAULT_ALLOWED_DOMAINS,
    DEFAULT_ALLOWED_PORTS,
    DEFAULT_AUDIT_LEVEL,
    DEFAULT_AUDIT_LOG_PATH,
    DEFAULT_BLOCKED_PORTS,
    DEFAULT_DISK_QUOTA_MB,
    DEFAULT_GUARDIAN_BACKEND,
    DEFAULT_GUARDIAN_MAX_TOKENS,
    DEFAULT_GUARDIAN_TEMPERATURE,
    DEFAULT_LOCAL_MODEL,
    DEFAULT_MAX_EXECUTION_TIME_SEC,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_MEMORY_MB,
    DEFAULT_MAX_OPEN_FILES,
    DEFAULT_MAX_PROCESSES,
    DEFAULT_NETWORK_MODE,
    DEFAULT_RATE_LIMIT_PER_MINUTE,
    DEFAULT_SANDBOX_BASE_PATH,
)

# Request and response contracts.

class ToolRequest(BaseModel):
    """Raw tool-call request issued by an LLM or a user."""
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = Field(default_factory=time.time)

    action: str                     # Abstract action name such as "execute_code".
    params: dict[str, Any]          # Action parameters.
    session_id: str                 # Session identifier for isolation.
    user_id: str                    # User identifier for policy enforcement.

    raw_prompt: Optional[str] = None   # Original model prompt for analysis.
    context_history: list[str] = Field(default_factory=list)  # Recent dialogue turns.


class GuardianVerdict(BaseModel):
    """Guardian review output before the full middleware pipeline completes."""
    risk_level: RiskLevel
    action: ActionVerdict              # ALLOW / REWRITE / BLOCK / ESCALATE
    confidence: float = Field(ge=0.0, le=1.0)

    reason: str                     # Human-readable explanation.
    matched_rules: list[str] = Field(default_factory=list)  # Matched rule ids.
    rewritten_action: Optional[str] = None   # Rewritten action for REWRITE.
    rewritten_params: Optional[dict[str, Any]] = None  # Rewritten params for REWRITE.
    rewrite_ops: list[dict[str, Any]] = Field(default_factory=list)

    # Intent analysis metadata.
    detected_intent: str = ""       # Detected intent label.
    intent_chain: list[str] = Field(default_factory=list)  # Dependency-chain metadata.


class LayerResult(BaseModel):
    """Result emitted by one middleware layer."""
    layer: str                      # "guardian" / "layer1" / "layer2" / "layer3"
    passed: bool
    verdict: ActionVerdict = ActionVerdict.ALLOW

    transformed_action: Optional[str] = None
    transformed_params: Optional[dict[str, Any]] = None
    constraints: Optional[dict[str, Any]] = None
    rewrite_ops: list[dict[str, Any]] = Field(default_factory=list)
    reason: str = ""
    duration_ms: float = 0.0


class ExecutionResult(BaseModel):
    """Final middleware result returned to the caller."""
    request_id: str
    verdict: ActionVerdict

    # Success path.
    output: Optional[str] = None
    execution_output: Optional[dict[str, Any]] = None  # Final safe execution plan.
    artifacts: list[str] = Field(default_factory=list)  # Produced artifact paths.

    # Failure / interception path.
    reason: Optional[str] = None
    suggestion: Optional[str] = None  # Optional user-facing alternative suggestion.

    # Audit trace.
    layer_trace: list[LayerResult] = Field(default_factory=list)
    total_duration_ms: float = 0.0


# Security rule models.

class RuleCategory(str, Enum):
    """Security rule category."""
    COMMAND_BLACKLIST = "COMMAND_BLACKLIST"
    PACKAGE_BLACKLIST = "PACKAGE_BLACKLIST"
    PATH_RESTRICTION = "PATH_RESTRICTION"
    NETWORK_POLICY = "NETWORK_POLICY"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INTENT_PATTERN = "INTENT_PATTERN"


class SecurityRule(BaseModel):
    """Single security rule entry."""
    rule_id: str
    category: RuleCategory
    severity: RiskLevel
    description: str

    # Match conditions.
    patterns: list[str]             # Regex list; any match triggers the rule.

    # Policy effect.
    action: ActionVerdict = ActionVerdict.BLOCK
    message: str = ""               # User-facing message.

    # Optional rewrite template.
    rewrite_template: Optional[str] = None

    enabled: bool = True


class SecurityConfig(BaseModel):
    """Top-level security configuration loaded from YAML or defaults."""
    # Guardian backend.
    guardian_model: str = DEFAULT_GUARDIAN_BACKEND
    guardian_model_name: str = DEFAULT_LOCAL_MODEL
    guardian_temperature: float = DEFAULT_GUARDIAN_TEMPERATURE
    guardian_max_tokens: int = DEFAULT_GUARDIAN_MAX_TOKENS
    guardian_enable_llm_analysis: bool = True

    # Sandbox.
    sandbox_base_path: str = DEFAULT_SANDBOX_BASE_PATH
    session_isolation: bool = True
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    disk_quota_mb: int = DEFAULT_DISK_QUOTA_MB
    max_processes: int = DEFAULT_MAX_PROCESSES
    max_open_files: int = DEFAULT_MAX_OPEN_FILES
    max_memory_mb: int = DEFAULT_MAX_MEMORY_MB
    max_execution_time_sec: int = DEFAULT_MAX_EXECUTION_TIME_SEC

    # Network.
    network_mode: str = DEFAULT_NETWORK_MODE
    allowed_domains: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_DOMAINS))
    allowed_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_PORTS))
    blocked_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_BLOCKED_PORTS))

    # Rate limit.
    rate_limit: int = DEFAULT_RATE_LIMIT_PER_MINUTE

    # Rules.
    rules: list[SecurityRule] = Field(default_factory=list)

    # Audit.
    audit_log_path: str = DEFAULT_AUDIT_LOG_PATH
    audit_level: str = DEFAULT_AUDIT_LEVEL

    @classmethod
    def from_yaml(cls, path: "str | Path") -> "SecurityConfig":
        """Load a ``SecurityConfig`` from YAML."""
        import yaml
        from pathlib import Path

        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Extract config sections.
        guardian_cfg = data.get("guardian", {})
        sandbox_cfg = data.get("sandbox", {})
        network_cfg = data.get("network", {})
        audit_cfg = data.get("audit", {})

        # Parse rules.
        rules = [SecurityRule(**r) for r in data.get("rules", [])]

        return cls(
            guardian_model=guardian_cfg.get(
                "backend",
                guardian_cfg.get("model", DEFAULT_GUARDIAN_BACKEND),
            ),
            guardian_model_name=guardian_cfg.get("model_name", DEFAULT_LOCAL_MODEL),
            guardian_temperature=guardian_cfg.get("temperature", DEFAULT_GUARDIAN_TEMPERATURE),
            guardian_max_tokens=guardian_cfg.get("max_tokens", DEFAULT_GUARDIAN_MAX_TOKENS),
            guardian_enable_llm_analysis=guardian_cfg.get("enable_llm_analysis", True),
            sandbox_base_path=sandbox_cfg.get("base_path", DEFAULT_SANDBOX_BASE_PATH),
            session_isolation=sandbox_cfg.get("session_isolation", True),
            max_file_size_mb=sandbox_cfg.get("max_file_size_mb", DEFAULT_MAX_FILE_SIZE_MB),
            disk_quota_mb=sandbox_cfg.get("disk_quota_mb", DEFAULT_DISK_QUOTA_MB),
            max_processes=sandbox_cfg.get("max_processes", DEFAULT_MAX_PROCESSES),
            max_open_files=sandbox_cfg.get("max_open_files", DEFAULT_MAX_OPEN_FILES),
            max_memory_mb=sandbox_cfg.get("max_memory_mb", DEFAULT_MAX_MEMORY_MB),
            max_execution_time_sec=sandbox_cfg.get("max_execution_time_sec", DEFAULT_MAX_EXECUTION_TIME_SEC),
            network_mode=network_cfg.get("mode", DEFAULT_NETWORK_MODE),
            allowed_domains=network_cfg.get("allowed_domains", list(DEFAULT_ALLOWED_DOMAINS)),
            allowed_ports=network_cfg.get("allowed_ports", list(DEFAULT_ALLOWED_PORTS)),
            blocked_ports=network_cfg.get("blocked_ports", list(DEFAULT_BLOCKED_PORTS)),
            rate_limit=data.get("rate_limit", DEFAULT_RATE_LIMIT_PER_MINUTE),
            rules=rules,
            audit_log_path=audit_cfg.get("log_path", DEFAULT_AUDIT_LOG_PATH),
            audit_level=audit_cfg.get("level", DEFAULT_AUDIT_LEVEL),
        )
