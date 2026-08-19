# Debug Evidence V0 architecture

Debug Evidence separates **observation**, **hypothesis**, **probe policy** and **diagnostic result**.

```text
incident inputs
   ↓
normalisation / redaction boundary
   ↓
bounded hypotheses
   ↓
allowlisted read-only probes
   ↓
evidence graph
   ↓
SUPPORTED | CONTRADICTED | INDETERMINATE
   ↓
deterministic incident bundle
```

## Why diagnosis is separate from remediation

A debugger that can immediately rewrite source code can hide the distinction between an explanation and evidence for that explanation. V0 deliberately has no mutation layer.

Future remediation work must receive a separately authorised evidence bundle rather than inheriting implicit shell or repository authority from the diagnosis engine.

## Probe policy

V0 supports only deterministic fixture probes:

- `log_contains`;
- `stack_contains`;
- `diff_contains`;
- `env_present`;
- `env_equals`.

An unknown probe kind is recorded as blocked. It is not executed or silently skipped. A blocked required support path keeps a hypothesis `INDETERMINATE`.

## Contradictory evidence

Supporting evidence does not disappear when contradiction is found. The misleading-log control intentionally records a database-timeout log supporting one hypothesis while a configuration probe materially contradicts it.

This is important: the bundle is an evidence record, not only a final label.

## Privacy boundary

Raw inputs contribute to a source SHA-256 so the fixture identity is stable, but sensitive environment keys are redacted in the output bundle. V0 does not persist raw logs separately and probe summaries never include expected secret values.

Future real-runtime adapters require a deeper redaction model before any external model/provider integration.

## Claim semantics

- `SUPPORTED`: bounded support exists and no required evidence remains unresolved.
- `CONTRADICTED`: material configured evidence falsifies the hypothesis inside the tested boundary.
- `INDETERMINATE`: evidence is missing, blocked or insufficient.

These states are diagnostic evidence semantics, not probabilities of truth.
