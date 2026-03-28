# Onion Guardian

Pre-execution security middleware for AI-powered IDEs and coding agents.

Onion Guardian sits between an LLM tool call and the real executor. It reviews
intent, normalizes requests onto an abstract action surface, applies
deterministic policy checks, and returns an executor-facing `execution_output`
plan for an external sandbox or runner to enforce.

## What It Is

Onion Guardian is:

- a policy layer for tool calls
- a pre-execution inspection pipeline
- a library for producing constrained execution plans

Onion Guardian is not:

- a container runtime
- a VM or sandbox implementation
- a code executor

If a request is allowed, Onion Guardian returns a structured plan. Your own
executor, container, VM, or broker still performs the real execution.

## Why It Exists

When an LLM can read files, run commands, install packages, or access the
network, model-level safety alone is not enough. Prompt injection can try to
push the model into actions that should be blocked by deterministic policy.

This project separates:

- the tool surface shown to the LLM
- the executor-facing action that runs outside the model
- the security policy that decides whether the request is allowed

## Core Flow

```text
LLM / User Request
  -> intent analysis
  -> action normalization
  -> deterministic policy checks
  -> decision aggregation
  -> constraint compilation
  -> ExecutionPlan
  -> external executor
```

## Features

- Abstract tool surface for the model via `get_llm_tools()`
- Intent review and rule matching in the Guardian layer
- Parameter validation and path safety checks
- Deterministic routing for sandbox and quota constraints
- Command and network policy enforcement before execution
- Executor-facing `execution_output` contract
- Layer-by-layer audit trace for debugging and incident review

## Install

From source:

```bash
pip install -e .
```

Optional extras:

```bash
pip install -e '.[dev]'
pip install -e '.[guardian-local]'
pip install -e '.[guardian-api]'
```

Use `guardian-local` when you want a local Transformers-based Guardian model.
Use `guardian-api` when you want OpenAI or Anthropic as the semantic backend.

## Quick Start

For a deterministic first run, disable semantic LLM analysis:

```python
from onion_guardian import ActionVerdict, OnionGuardian

guardian = OnionGuardian.from_config(enable_llm=False)

result = guardian.quick_check(
    action="execute_code",
    params={
        "language": "python",
        "code": "print('hello from onion guardian')",
    },
    session_id="session_123",
    user_id="user_123",
)

if result.verdict == ActionVerdict.ALLOW:
    plan = result.execution_output
    print(plan["action"])
    print(plan["params"])
    print(plan["constraints"])
else:
    print(result.verdict)
    print(result.reason)
```

Typical `execution_output` shape:

```python
{
    "action": "sandbox_executor.run",
    "params": {
        "lang": "python",
        "source": "print('hello from onion guardian')",
        "timeout_sec": 30,
    },
    "session_id": "session_123",
    "user_id": "user_123",
    "constraints": {
        "sandbox": {...},
        "execution_env": {...},
    },
    "rewrite_ops": [],
}
```

## Using `process()`

Use `process()` when you already construct a `ToolRequest` or want richer
metadata such as `raw_prompt` and `context_history`.

```python
from onion_guardian import OnionGuardian, ToolRequest

guardian = OnionGuardian.from_config(enable_llm=False)

request = ToolRequest(
    action="run_command",
    params={"command": "echo hello", "working_dir": "."},
    session_id="session_123",
    user_id="user_123",
    context_history=[
        "User wants to inspect a project directory",
        "Assistant is preparing a safe command",
    ],
)

result = guardian.process(
    request,
    session_id=request.session_id,
    user_id=request.user_id,
)
```

## Abstract Actions

The default registry exposes a small action surface:

- `execute_code`
- `run_command`
- `read_file`
- `write_file`
- `list_directory`
- `search_files`
- `http_request`
- `install_package`

These abstract actions are mapped internally to executor-facing handlers. The
LLM should only see the abstract surface, not the real executor identifiers.

## Integration Pattern

Typical integration flow:

1. Give `guardian.get_llm_tools()` to the LLM.
2. Convert the model tool call into `ToolRequest` or `quick_check(...)`.
3. If the verdict is `ALLOW`, send `execution_output` to your real executor.
4. Enforce `constraints` outside the Python process.
5. Store `layer_trace` and audit output for investigation and regression tests.

The supported integration contract is `ExecutionResult` plus
`execution_output`:

- `execution_output["action"]`: executor-facing action identifier
- `execution_output["params"]`: runtime parameters for the executor
- `execution_output["constraints"]`: security envelope from the middleware
- `execution_output["rewrite_ops"]`: structured rewrite trace

Executors should fail closed on unknown actions.

## Configuration

The simplest entrypoint uses packaged defaults:

```python
guardian = OnionGuardian.from_config()
```

You can override packaged config:

```python
guardian = OnionGuardian.from_config(
    rules_path="config/default_rules.yaml",
    prompts_path="config/guardian_prompts.yaml",
    enable_llm=False,
    network_mode="restricted",
)
```

Useful runtime overrides include:

- `guardian_backend`
- `guardian_model`
- `sandbox_root`
- `network_mode`
- `audit_log_path`
- `enable_llm`
- `rate_limit`

Inspect the compiled runtime config with:

```python
effective = guardian.get_effective_config()
```

## Security Scope

Onion Guardian is designed around these assumptions:

- the LLM is not a trusted policy engine
- deterministic enforcement is required after model reasoning
- executor constraints must be enforced outside Python-process trust
- configuration and rules must be auditable

The package includes command filtering, network policy checks, path controls,
quota planning, and audit hooks. It does not claim to replace a real sandbox.

## Project Status

This project is suitable to publish as an alpha middleware package.

It is not a production-grade standalone sandbox. Before production use, you
still need:

- an external executor or sandbox
- environment-specific hardening
- deployment-specific logging and retention decisions
- your own threat-model validation

## Development

Common local commands:

```bash
python -m pytest -q
python -m build --sdist --wheel --no-isolation
python examples/user_smoke_suite.py
```

Project files:

- contributor guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- security policy: [`SECURITY.md`](./SECURITY.md)
- changelog: [`CHANGELOG.md`](./CHANGELOG.md)
- CI workflow: [`.github/workflows/package_checks.yml`](./.github/workflows/package_checks.yml)

## License

MIT. See [`LICENSE`](./LICENSE).
