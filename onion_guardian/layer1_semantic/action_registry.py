"""
onion_guardian.layer1_semantic.action_registry - abstract action registry.

Core design idea:
the LLM should never see real tool names, paths, or raw executor parameters.
It only sees abstract actions.

Example:
  LLM-visible: "execute_code" -> params: {language, code}
  Actual executor call: RunBash(f"cd /workspace/{session_id} && timeout 30 {code}")

Even if chain-of-thought is leaked, the attacker still cannot recover the real
execution interface.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from onion_guardian.defaults import (
    DEFAULT_MAX_EXECUTION_TIME_SEC,
    DEFAULT_MAX_LENGTHS,
    DEFAULT_MAX_STRING_LENGTH,
    DEFAULT_RATE_LIMIT_PER_MINUTE,
)


@dataclass
class ParamSpec:
    """Parameter specification."""
    name: str
    type: str                    # "string" / "integer" / "boolean" / "enum" / "path"
    required: bool = True
    description: str = ""
    default: Any = None
    enum_values: list[str] = field(default_factory=list)

    # Security constraints.
    max_length: int = DEFAULT_MAX_STRING_LENGTH
    pattern: str = ""            # Regex validation.
    path_must_be_relative: bool = True  # Paths must be relative.

    def to_llm_property(self) -> dict[str, Any]:
        """Export one parameter using JSON-Schema-compatible types."""
        json_type = {
            "string": "string",
            "path": "string",
            "integer": "integer",
            "boolean": "boolean",
            "enum": "string",
        }.get(self.type, "string")

        schema = {
            "type": json_type,
            "description": self.description,
        }
        if self.enum_values:
            schema["enum"] = list(self.enum_values)
        if self.default is not None:
            schema["default"] = self.default
        if self.pattern:
            schema["pattern"] = self.pattern
        if json_type == "string" and self.max_length != DEFAULT_MAX_STRING_LENGTH:
            schema["maxLength"] = self.max_length
        return schema


@dataclass
class AbstractAction:
    """
    Abstract action definition.

    This is the smallest unit visible to the LLM. The model knows only the
    action name and parameter schema, not the underlying implementation.
    """
    action_id: str               # Unique identifier, e.g. "execute_code".
    display_name: str            # Name shown to the LLM.
    description: str             # Description shown to the LLM.
    category: str                # "code" / "file" / "network" / "system"
    params: list[ParamSpec]      # Parameter schema.

    # Security metadata.
    risk_base: str = "LOW"       # Base risk level.
    requires_confirmation: bool = False  # Whether user confirmation is required.
    max_calls_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE

    # Internal mappings that remain hidden from the LLM.
    _real_handler: str = ""      # Actual handler name.
    _real_params_map: dict = field(default_factory=dict)  # Parameter mapping.

    def to_llm_schema(self) -> dict:
        """Export the schema shown to the LLM without implementation details."""
        return {
            "name": self.display_name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    p.name: p.to_llm_property()
                    for p in self.params
                },
                "required": [p.name for p in self.params if p.required],
            },
        }


class ActionRegistry:
    """
    Action registry, the core of Layer 1.

    Manages abstract action registration, lookup, and export.
    """

    def __init__(self):
        self._actions: dict[str, AbstractAction] = {}
        self._register_defaults()

    def register(self, action: AbstractAction) -> None:
        """Register one abstract action."""
        self._actions[action.action_id] = action

    def get(self, action_id: str) -> AbstractAction | None:
        """Return the definition for one action."""
        return self._actions.get(action_id)

    def list_actions(self, category: str | None = None) -> list[AbstractAction]:
        """List all available actions."""
        actions = list(self._actions.values())
        if category:
            actions = [a for a in actions if a.category == category]
        return actions

    def export_for_llm(self, categories: list[str] | None = None) -> list[dict]:
        """
        Export the tool list shown to the LLM.

        This is an abstract view with no executor details. The model should not
        be able to infer the real underlying commands from it.
        """
        actions = self.list_actions()
        if categories:
            actions = [a for a in actions if a.category in categories]
        return [a.to_llm_schema() for a in actions]

    def resolve(self, action_id: str) -> tuple[str, dict] | None:
        """
        Resolve an abstract action to its real handler (internal use only).

        Returns:
            `(real_handler_name, params_mapping)` or `None`
        """
        action = self._actions.get(action_id)
        if action is None:
            return None
        return action._real_handler, copy.deepcopy(action._real_params_map)

    # Default action registration.

    def _register_defaults(self) -> None:
        """Register the default abstract action set."""

        # Code execution.
        self.register(AbstractAction(
            action_id="execute_code",
            display_name="Execute Code",
            description="Run a code snippet in the sandbox. Supports Python, JavaScript, Bash, and more.",
            category="code",
            params=[
                ParamSpec(name="language", type="enum", description="Programming language",
                         enum_values=["python", "javascript", "typescript", "bash", "ruby", "go", "rust"]),
                ParamSpec(name="code", type="string", description="Code to execute",
                         max_length=DEFAULT_MAX_LENGTHS["code"]),
                ParamSpec(name="timeout", type="integer", description="Execution timeout in seconds",
                         required=False, default=DEFAULT_MAX_EXECUTION_TIME_SEC),
            ],
            risk_base="MEDIUM",
            _real_handler="sandbox_executor.run",
            _real_params_map={"language": "lang", "code": "source", "timeout": "timeout_sec"},
        ))

        # File operations.
        self.register(AbstractAction(
            action_id="read_file",
            display_name="Read File",
            description="Read file contents from the working directory.",
            category="file",
            params=[
                ParamSpec(name="path", type="path", description="File path relative to the working directory",
                         path_must_be_relative=True),
                ParamSpec(name="start_line", type="integer", description="Start line",
                         required=False, default=1),
                ParamSpec(name="end_line", type="integer", description="End line",
                         required=False, default=-1),
            ],
            risk_base="LOW",
            _real_handler="file_manager.read",
            _real_params_map={"path": "file_path"},
        ))

        self.register(AbstractAction(
            action_id="write_file",
            display_name="Write File",
            description="Create or modify a file in the working directory.",
            category="file",
            params=[
                ParamSpec(name="path", type="path", description="File path relative to the working directory",
                         path_must_be_relative=True),
                ParamSpec(name="content", type="string", description="File contents",
                         max_length=DEFAULT_MAX_LENGTHS["content"]),
            ],
            risk_base="LOW",
            _real_handler="file_manager.write",
            _real_params_map={"path": "file_path", "content": "data"},
        ))

        self.register(AbstractAction(
            action_id="list_directory",
            display_name="List Directory",
            description="List files and subdirectories in the working directory.",
            category="file",
            params=[
                ParamSpec(name="path", type="path", description="Directory path relative to the working directory",
                         required=False, default=".", path_must_be_relative=True),
            ],
            risk_base="SAFE",
            _real_handler="file_manager.list_dir",
            _real_params_map={"path": "dir_path"},
        ))

        # Network access.
        self.register(AbstractAction(
            action_id="http_request",
            display_name="HTTP Request",
            description="Send an HTTP request to a domain in the allowlist.",
            category="network",
            params=[
                ParamSpec(name="url", type="string", description="Target URL"),
                ParamSpec(name="method", type="enum", description="HTTP method",
                         enum_values=["GET", "POST", "PUT", "DELETE"], default="GET"),
                ParamSpec(name="headers", type="string", description="Request headers as JSON",
                         required=False),
                ParamSpec(name="body", type="string", description="Request body",
                         required=False),
            ],
            risk_base="MEDIUM",
            requires_confirmation=True,
            _real_handler="network_proxy.request",
            _real_params_map={"url": "target_url"},
        ))

        # Package management.
        self.register(AbstractAction(
            action_id="install_package",
            display_name="Install Package",
            description="Install dependencies from approved package managers.",
            category="system",
            params=[
                ParamSpec(name="manager", type="enum", description="Package manager",
                         enum_values=["pip", "npm", "cargo"]),
                ParamSpec(name="packages", type="string", description="Comma-separated package list"),
            ],
            risk_base="MEDIUM",
            requires_confirmation=True,
            max_calls_per_minute=5,
            _real_handler="package_manager.install",
            _real_params_map={"manager": "pm_type", "packages": "pkg_list"},
        ))

        # Terminal execution.
        self.register(AbstractAction(
            action_id="run_command",
            display_name="Run Command",
            description="Run a terminal command inside the sandbox.",
            category="code",
            params=[
                ParamSpec(name="command", type="string", description="Command to execute",
                         max_length=DEFAULT_MAX_LENGTHS["command"]),
                ParamSpec(name="working_dir", type="path", description="Working directory",
                         required=False, default=".", path_must_be_relative=True),
            ],
            risk_base="HIGH",
            _real_handler="sandbox_executor.run_shell",
            _real_params_map={"command": "cmd", "working_dir": "cwd"},
        ))

        # Search.
        self.register(AbstractAction(
            action_id="search_files",
            display_name="Search Files",
            description="Search file contents in the working directory.",
            category="file",
            params=[
                ParamSpec(name="query", type="string", description="Search query or regular expression"),
                ParamSpec(name="path", type="path", description="Search directory",
                         required=False, default=".", path_must_be_relative=True),
                ParamSpec(name="file_pattern", type="string", description="Filename glob pattern",
                         required=False, default="*"),
            ],
            risk_base="SAFE",
            _real_handler="file_manager.search",
            _real_params_map={"query": "pattern"},
        ))
