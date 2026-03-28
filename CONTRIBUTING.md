# Contributing

Thanks for contributing to Onion Guardian.

## Scope

This project is a policy and planning layer for AI tool execution. It is not a
standalone sandbox or runtime.

Contributions are most useful when they improve one of these areas:

- security rule quality
- request normalization and executor planning
- command and network policy behavior
- auditability and traceability
- tests and packaging

## Development Setup

Install from source:

```bash
pip install -e '.[dev]'
```

Optional Guardian backends:

```bash
pip install -e '.[guardian-local]'
pip install -e '.[guardian-api]'
```

## Common Commands

Run tests:

```bash
python -m pytest -q
```

Build packages:

```bash
python -m build --sdist --wheel --no-isolation
```

## Contribution Guidelines

- Keep the public positioning accurate. Do not present this package as a full
  sandbox.
- Prefer deterministic enforcement over model-only judgment when the policy can
  be encoded directly.
- Keep changes auditable. If behavior changes, add or update tests.
- Preserve the separation between LLM-facing abstract actions and executor-facing
  actions.
- Update `README.md` if the public contract changes.

## Pull Requests

A good pull request usually includes:

- a focused change
- tests for the changed behavior
- a short explanation of the security or integration impact

## Reporting Security Issues

Please do not open a public issue for unpatched vulnerabilities. See
[`SECURITY.md`](./SECURITY.md).
