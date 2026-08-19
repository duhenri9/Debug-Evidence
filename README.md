# Debug Evidence

Evidence-driven incident diagnosis before code mutation.

Debug Evidence is an open-source CLI for collecting runtime signals, testing bounded hypotheses and producing reproducible incident evidence bundles.

> Diagnose before you mutate.

## V0

The first executable slice runs entirely offline over synthetic incidents. It preserves supporting, contradicting and unresolved evidence instead of converting a plausible explanation into a root-cause claim.

```text
incident inputs
    ↓
normalisation / redaction
    ↓
bounded hypotheses
    ↓
allowlisted safe probes
    ↓
evidence graph
    ↓
SUPPORTED | CONTRADICTED | INDETERMINATE
    ↓
deterministic incident bundle
```

### What V0 proves

- deterministic incident/source identity;
- bounded hypothesis/result semantics;
- explicit contradictory evidence;
- policy-blocked unsupported probes;
- redaction of credential-shaped environment keys;
- a misleading-log control where the loudest error is contradicted by stronger evidence;
- a missing-evidence control that remains `INDETERMINATE`;
- an unsafe-probe control that is blocked before execution;
- deterministic evidence-bundle digest.

### What V0 does not prove

- universal root-cause correctness;
- production log/trace ingestion;
- arbitrary shell or network diagnostics;
- autonomous remediation;
- LLM reasoning quality;
- observability-platform replacement;
- production readiness.

## Run it

```bash
python -m pip install -e ".[dev]"
debug-evidence fixtures/misleading-log.json
```

Run the uncertainty/safety controls:

```bash
debug-evidence fixtures/missing-evidence.json
debug-evidence fixtures/unsafe-probe.json
```

## V0 probe policy

The offline runtime supports only:

- `log_contains`;
- `stack_contains`;
- `diff_contains`;
- `env_present`;
- `env_equals`.

Unknown probe kinds are recorded as blocked. They are not executed or silently ignored.

## Evidence model

Each bundle records:

- incident id and schema;
- SHA-256 identity of the source fixture;
- hypothesis statuses plus support/contradiction/unresolved probe ids;
- executed or blocked probe evidence;
- redacted environment metadata;
- explicit claim boundary;
- deterministic bundle SHA-256.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the diagnosis, probe-policy and privacy boundaries. The staged runtime/observability roadmap is tracked in issue #1.

## Development

```bash
python -m compileall src
python -m pytest -q
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
```

CI additionally executes all incident controls and uploads their evidence bundles.

## Security

See [`SECURITY.md`](SECURITY.md). V0 executes no shell commands, performs no network probes, mutates no code and calls no model provider.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New probes or diagnosis claims should arrive with a failure/indeterminate control.

## Licence

Apache-2.0.
