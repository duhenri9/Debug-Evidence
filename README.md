# Debug Evidence

Evidence-driven incident diagnosis before code mutation.

Debug Evidence is an open-source CLI for collecting runtime signals, testing bounded hypotheses and producing reproducible incident evidence bundles.

> Diagnose before you mutate.

## Current engineering baseline

Debug Evidence now has two executable evidence layers:

```text
V0 — deterministic offline diagnosis
incident fixture
    ↓
normalisation / redaction
    ↓
bounded hypotheses + allowlisted probes
    ↓
SUPPORTED | CONTRADICTED | INDETERMINATE
    ↓
deterministic evidence bundle

V0.2 — bounded local runtime collection
explicit local paths / env keys / metadata paths
    ↓
path + symlink safety checks
    ↓
log / stack / Git / runtime / filesystem evidence
    ↓
workspace tokenisation + redaction
    ↓
sanitised V0 analysis
    ↓
report + deterministic ZIP + archive receipt
```

Neither layer mutates source code, executes target application code, runs arbitrary shell probes or claims universal root-cause correctness.

## V0 — deterministic offline diagnosis

The first executable slice runs entirely offline over synthetic incidents. It preserves supporting, contradicting and unresolved evidence instead of converting a plausible explanation into a root-cause claim.

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

Run it:

```bash
python -m pip install -e ".[dev]"
debug-evidence fixtures/misleading-log.json
debug-evidence fixtures/missing-evidence.json
debug-evidence fixtures/unsafe-probe.json
```

The offline V0 runtime supports only:

- `log_contains`;
- `stack_contains`;
- `diff_contains`;
- `env_present`;
- `env_equals`.

Unknown probe kinds are recorded as blocked. They are not executed or silently ignored.

## V0.2 — bounded local runtime evidence collector

V0.2 adds a read-only local collection boundary without turning Debug Evidence into a shell agent or a generic observability collector.

It can collect only explicitly declared evidence from a caller-selected workspace:

- bounded local log and stack-trace files;
- allowlisted environment keys;
- Python traceback and Node stack frames;
- exact Git `HEAD`, branch, porcelain status and recent commit identities;
- changed paths plus tracked unified-diff digest/preview;
- privacy-bounded runtime fingerprint;
- filesystem metadata and full SHA-256 identities for explicitly requested bounded files.

The collector rejects absolute paths, parent traversal, `.git` paths and symlink inputs before content collection. Workspace paths are tokenised before persistence. Secret-like allowlisted environment values and high-signal credential patterns are redacted before the sanitised data reaches the existing V0 hypothesis engine.

A successful collection can emit:

- `debug-evidence.local-report.v0.2` JSON;
- a deterministic sanitised ZIP archive;
- an external archive receipt binding the exact ZIP bytes and members by SHA-256.

If required collection cannot be completed safely, the CLI emits an `INDETERMINATE` failure receipt and does not leave a partial archive behind.

Example:

```bash
debug-evidence-local fixtures/local-v02-python.json \
  --workspace /path/to/incident-workspace \
  --report artifacts/local-report.json \
  --archive artifacts/incident.zip \
  --archive-receipt artifacts/incident-archive-receipt.json
```

The checked fixtures and CI create their own temporary Git workspace; do not treat `fixtures/local-v02-python.json` as a promise that arbitrary paths on a user's machine are collected automatically.

## Evidence model

V0 bundles record:

- incident id and schema;
- SHA-256 identity of the source fixture;
- hypothesis statuses plus support/contradiction/unresolved probe ids;
- executed or blocked probe evidence;
- redacted environment metadata;
- explicit claim boundary;
- deterministic bundle SHA-256.

V0.2 local reports additionally bind the declared collection spec to the observed local snapshot, Git/runtime/filesystem evidence and deterministic archive identity without persisting raw secrets or unrestricted host data.

## Claim boundary

Debug Evidence does **not** claim:

- universal root-cause correctness;
- production log/trace ingestion coverage;
- arbitrary shell or network diagnostics;
- target-process sandboxing;
- autonomous remediation;
- LLM reasoning quality;
- universal DLP/redaction guarantees;
- complete logs when bounded previews are truncated;
- observability-platform replacement;
- production readiness.

V0.2 proves only the declared local snapshot/parse/correlation mechanisms over explicitly allowlisted inputs.

## Development

```bash
python -m compileall src
python -m pytest -q
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
```

CI executes V0 positive/negative controls plus V0.2 temporary-workspace controls for local evidence correlation, redaction, deterministic archive evidence and fail-closed path escape, then uploads only the generated evidence artifacts.

## Architecture and roadmap

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — diagnosis, probe-policy and privacy boundaries.
- [Issue #1](../../issues/1) — staged runtime/observability roadmap.

## Security

See [`SECURITY.md`](SECURITY.md). The shipped runtime does not mutate code, execute arbitrary shell commands or call a model provider.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New collection surfaces, probes or diagnosis claims should arrive with failure/indeterminate controls and explicit privacy/authority boundaries.

## Licence

Apache-2.0.
