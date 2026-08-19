# Debug Evidence

Evidence-driven incident diagnosis before code mutation.

Debug Evidence is an open-source CLI project for collecting runtime signals, testing bounded hypotheses and producing reproducible incident evidence bundles.

> Diagnose before you mutate.

The project treats logs, traces, environment metadata, recent code changes and safe diagnostic probes as evidence. It preserves contradictory signals and explicit uncertainty instead of turning a plausible explanation into a fabricated root-cause claim.

## Status

Early public foundation. V0 is being built around deterministic offline incident fixtures, policy-bounded probes and negative controls.

## Design principles

- Evidence before remediation.
- Read-only diagnosis before mutation.
- Contradictory evidence remains visible.
- Unsafe probes are blocked by policy.
- Sensitive data is redacted before persistence or model use.
- Optional model reasoning cannot certify the diagnosis.
- The core path must run without a paid model key.

## V0 target

```text
incident inputs
    ↓
normalised evidence
    ↓
bounded hypotheses
    ↓
safe probes
    ↓
support / contradiction / missing evidence
    ↓
reproducible debug bundle
    ↓
SUPPORTED | CONTRADICTED | INDETERMINATE
```

The repository will not claim autonomous repair, arbitrary shell authority, observability-platform replacement or production incident automation beyond mechanisms that are actually implemented and tested.

## Licence

Apache-2.0 planned for the public V0. Licence file will be added with the first implementation PR.
