# Security Policy

## Supported Status

Onion Guardian is currently maintained as an alpha package.

It should be treated as a policy and planning layer, not as a complete security
boundary by itself.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately to the maintainer instead of
opening a public issue before a fix is available.

Include:

- affected version or commit
- reproduction steps
- impact summary
- whether the issue requires a specific executor or deployment setup

## Security Scope

This project aims to reduce risk in AI-driven tool execution by:

- constraining the model-visible tool surface
- applying deterministic policy checks before execution
- emitting executor-facing constraints and audit traces

This project does not guarantee complete isolation on its own. Real security
still depends on the external executor, sandbox, runtime policy, host hardening,
and deployment configuration.
