# Security policy

Debug Evidence processes material that may contain credentials, production identifiers and other sensitive runtime data. Treat logs, traces, environment metadata and diagnostic probes as security-sensitive inputs.

## Reporting a vulnerability

Use GitHub private vulnerability reporting when available. Do not publish live secrets, private logs, customer data or exploit details in a public issue.

If private reporting is unavailable, open a minimal issue requesting a private contact path without sensitive details.

## V0 boundary

The current V0:

- uses only synthetic offline incident fixtures;
- executes no shell commands;
- performs no network probes;
- mutates no source code or infrastructure;
- calls no model provider;
- redacts values for environment keys that look credential-sensitive;
- records unsupported probes as blocked rather than executing them.

## Future adapters

Real log, process, container, Kubernetes, observability and model adapters require separate threat-model updates before release. New probe authority must be explicit, read-only by default and covered by negative controls.

## Diagnostic claims

A `SUPPORTED` result is not a security certification or universal proof of root cause. It means the configured evidence inside one bounded incident contract supports the hypothesis without unresolved required evidence.
