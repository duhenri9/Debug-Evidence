# Contributing

Debug Evidence welcomes focused contributions that improve evidence quality, failure semantics or safe diagnostic coverage.

## Before opening a PR

Run:

```bash
python -m pip install -e ".[dev]"
python -m compileall src
python -m pytest -q
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
```

If your change adds a new probe or result state, add a fixture that proves how it fails or becomes indeterminate.

## Safety rules

- Do not submit production logs, private traces, customer data or live credentials.
- Do not add arbitrary shell/network execution as a convenience shortcut.
- Do not weaken redaction or blocked-probe behaviour to make a demo pass.
- Keep remediation/mutation outside the V0 diagnosis layer.

## Claims

A plausible explanation is not evidence. New diagnosis claims should name the exact inputs and probes that support or contradict them and should preserve unresolved alternatives where the mechanism cannot decide safely.
