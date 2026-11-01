# Debug-Evidence — Public Agent Acceptance and Completion Contract

**Repository profile:** Read-only incident diagnosis. Preserve consent/least-privilege, redaction, bounded probes, unresolved hypotheses and independently reproducible evidence.

This is a **public-safe operational subset** for contributor and coding-agent work. It does not reproduce or imply access to any private corporate playbook. It does not replace this repository's existing domain, security, ownership, license, CI or release rules.

## Evidence-first work cycle

- **A0 — scope before work:** record the approved problem and user/operator result, source revision, existing invariant, in/out of scope, risk level, expected artifact and a check that could disprove success. Avoid speculative refactors.
- **A1 — inspect before handoff:** compare the actual diff with the scope; validate applicable tests and negative cases for the touched boundary; record exact repository/branch/commit. Missing evidence is **UNKNOWN**, not PASS.
- **A2 — accept before COMPLETE:** give the versioned official artifact, observed check results, evidence or reproduction commands, failures, remaining risks and accountable next action. A passing build or a green fixture proves only what it actually exercised. Self-declared completion is not independent acceptance.
- **A3 — for operated services only:** observe user outcome, errors/recovery and value over time. Avoid unsupported market or production claims.

**Modes:** A read-only audit delivers a traceable report and does not modify product code unless separately authorized. An implementation/release retains all required CI, versioned proof and project-specific review. A small docs task need not execute browser/payment tests when genuinely irrelevant, but a software change cannot use that exception.

**Compact handoff:** approved task + target outcome; baseline/candidate SHA; changed artifact; PASS/FAIL/UNKNOWN/N/A_WITH_REASON checks; result and counterexample; pending risk/owner; **VERIFIED / BLOCKED / NOT_TESTED**. Use the existing PR or issue rather than creating redundant process documents.

**Limits:** Protect secrets, fixtures vs production, real customer data, existing worktrees, resource quota and source provenance. Do not weaken a deterministic guard to make a CI check pass. This file is a contributor instruction, **not evidence that repository release or product correctness has been certified**.
