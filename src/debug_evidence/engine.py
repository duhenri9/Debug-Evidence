"""Deterministic incident evidence engine for Debug Evidence V0."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from debug_evidence.models import Bundle, HypothesisResult, HypothesisStatus, ProbeEvidence

CLAIM_BOUNDARY = (
    "This bundle records only the supplied synthetic incident inputs and allowlisted V0 probes. "
    "It does not establish a universal root cause, production safety or remediation correctness."
)

SENSITIVE_KEY_PARTS = ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "PRIVATE_KEY", "CREDENTIAL")
ALLOWED_PROBES = {"log_contains", "stack_contains", "diff_contains", "env_equals", "env_present"}


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha256(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _redact_environment(environment: Mapping[str, Any]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in sorted(environment.items()):
        upper = str(key).upper()
        if any(part in upper for part in SENSITIVE_KEY_PARTS):
            redacted[str(key)] = "[REDACTED]"
        else:
            redacted[str(key)] = str(value)
    return redacted


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("logs must be a list of strings")
    return list(value)


def _run_probe(inputs: Mapping[str, Any], raw: Mapping[str, Any]) -> ProbeEvidence:
    probe_id = str(raw["id"])
    hypothesis_id = str(raw["hypothesis_id"])
    kind = str(raw["kind"])
    relation = str(raw["relation"])
    params = dict(raw.get("params", {}))

    if relation not in {"support", "contradict"}:
        return ProbeEvidence(
            probe_id=probe_id,
            hypothesis_id=hypothesis_id,
            kind=kind,
            executed=False,
            blocked=True,
            matched=None,
            relation=relation,
            summary="blocked: unsupported evidence relation",
        )

    if kind not in ALLOWED_PROBES:
        return ProbeEvidence(
            probe_id=probe_id,
            hypothesis_id=hypothesis_id,
            kind=kind,
            executed=False,
            blocked=True,
            matched=None,
            relation=relation,
            summary=f"blocked by probe policy: {kind}",
        )

    matched: bool | None
    summary: str

    if kind == "log_contains":
        logs = _strings(inputs.get("logs", []))
        needle = str(params["needle"])
        matched = any(needle in line for line in logs)
        summary = f"log_contains matched={matched}"
    elif kind == "stack_contains":
        stack = inputs.get("stack_trace")
        if stack is None:
            matched = None
            summary = "stack trace unavailable"
        else:
            matched = str(params["needle"]) in str(stack)
            summary = f"stack_contains matched={matched}"
    elif kind == "diff_contains":
        diff = inputs.get("recent_diff")
        if diff is None:
            matched = None
            summary = "recent diff unavailable"
        else:
            matched = str(params["needle"]) in str(diff)
            summary = f"diff_contains matched={matched}"
    elif kind == "env_present":
        environment = dict(inputs.get("environment", {}))
        key = str(params["key"])
        matched = key in environment
        summary = f"env_present key={key} matched={matched}"
    else:
        environment = dict(inputs.get("environment", {}))
        key = str(params["key"])
        if key not in environment:
            matched = None
            summary = f"env_equals key={key} unavailable"
        else:
            matched = str(environment[key]) == str(params["value"])
            summary = f"env_equals key={key} matched={matched}"

    return ProbeEvidence(
        probe_id=probe_id,
        hypothesis_id=hypothesis_id,
        kind=kind,
        executed=True,
        blocked=False,
        matched=matched,
        relation=relation,
        summary=summary,
    )


def _is_unresolved(probe: ProbeEvidence) -> bool:
    support_not_matched = probe.relation == "support" and probe.matched is False
    return probe.blocked or probe.matched is None or support_not_matched


def _classify_hypothesis(
    hypothesis: Mapping[str, Any], probes: Sequence[ProbeEvidence]
) -> HypothesisResult:
    hypothesis_id = str(hypothesis["id"])
    relevant = [probe for probe in probes if probe.hypothesis_id == hypothesis_id]
    support = sorted(
        probe.probe_id
        for probe in relevant
        if probe.relation == "support" and probe.matched is True
    )
    contradict = sorted(
        probe.probe_id
        for probe in relevant
        if probe.relation == "contradict" and probe.matched is True
    )
    unresolved = sorted(probe.probe_id for probe in relevant if _is_unresolved(probe))

    if contradict:
        status = HypothesisStatus.CONTRADICTED
    elif unresolved:
        status = HypothesisStatus.INDETERMINATE
    elif support:
        status = HypothesisStatus.SUPPORTED
    else:
        status = HypothesisStatus.INDETERMINATE

    return HypothesisResult(
        hypothesis_id=hypothesis_id,
        statement=str(hypothesis["statement"]),
        status=status,
        supporting_probe_ids=tuple(support),
        contradicting_probe_ids=tuple(contradict),
        unresolved_probe_ids=tuple(unresolved),
    )


def analyse_incident(fixture: Mapping[str, Any]) -> Bundle:
    """Analyse one deterministic offline incident fixture."""

    incident_id = str(fixture["incident_id"])
    inputs = dict(fixture["inputs"])
    raw_hypotheses = [dict(item) for item in list(fixture["hypotheses"])]
    raw_probes = [dict(item) for item in list(fixture["probes"])]

    probes = tuple(_run_probe(inputs, probe) for probe in raw_probes)
    hypotheses = tuple(_classify_hypothesis(hypothesis, probes) for hypothesis in raw_hypotheses)
    source_sha256 = _sha256(fixture)
    redacted_environment = _redact_environment(dict(inputs.get("environment", {})))

    unsigned: dict[str, Any] = {
        "schema": "debug-evidence.bundle.v0",
        "incident_id": incident_id,
        "source_sha256": source_sha256,
        "hypotheses": [
            {
                "hypothesis_id": item.hypothesis_id,
                "statement": item.statement,
                "status": item.status.value,
                "supporting_probe_ids": list(item.supporting_probe_ids),
                "contradicting_probe_ids": list(item.contradicting_probe_ids),
                "unresolved_probe_ids": list(item.unresolved_probe_ids),
            }
            for item in hypotheses
        ],
        "probes": [
            {
                "probe_id": item.probe_id,
                "hypothesis_id": item.hypothesis_id,
                "kind": item.kind,
                "executed": item.executed,
                "blocked": item.blocked,
                "matched": item.matched,
                "relation": item.relation,
                "summary": item.summary,
            }
            for item in probes
        ],
        "redacted_environment": redacted_environment,
        "claim_boundary": CLAIM_BOUNDARY,
    }

    return Bundle(
        schema="debug-evidence.bundle.v0",
        incident_id=incident_id,
        source_sha256=source_sha256,
        hypotheses=hypotheses,
        probes=probes,
        redacted_environment=redacted_environment,
        claim_boundary=CLAIM_BOUNDARY,
        bundle_sha256=_sha256(unsigned),
    )
