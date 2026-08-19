from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from debug_evidence.engine import analyse_incident
from debug_evidence.models import Bundle, HypothesisResult, HypothesisStatus

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def load(name: str) -> dict[str, Any]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def by_id(bundle: Bundle, hypothesis_id: str) -> HypothesisResult:
    return next(item for item in bundle.hypotheses if item.hypothesis_id == hypothesis_id)


def test_misleading_loud_log_is_preserved_but_contradicted() -> None:
    bundle = analyse_incident(load("misleading-log.json"))
    database = by_id(bundle, "database-misconfiguration")
    cache = by_id(bundle, "cache-thrash")
    assert database.status is HypothesisStatus.CONTRADICTED
    assert "p-db-log" in database.supporting_probe_ids
    assert "p-db-config-valid" in database.contradicting_probe_ids
    assert cache.status is HypothesisStatus.SUPPORTED


def test_sensitive_environment_value_is_redacted() -> None:
    bundle = analyse_incident(load("misleading-log.json"))
    assert bundle.redacted_environment["API_TOKEN"] == "[REDACTED]"
    assert "debug-evidence-demo-not-a-live-token" not in json.dumps(bundle.to_dict())


def test_missing_evidence_is_indeterminate() -> None:
    bundle = analyse_incident(load("missing-evidence.json"))
    result = bundle.hypotheses[0]
    assert result.status is HypothesisStatus.INDETERMINATE
    assert result.unresolved_probe_ids == ("p-endpoint",)


def test_unsafe_probe_is_blocked_and_indeterminate() -> None:
    bundle = analyse_incident(load("unsafe-probe.json"))
    assert bundle.hypotheses[0].status is HypothesisStatus.INDETERMINATE
    probe = bundle.probes[0]
    assert probe.blocked is True
    assert probe.executed is False
    assert probe.matched is None


def test_bundle_digest_is_deterministic() -> None:
    first = analyse_incident(load("misleading-log.json"))
    second = analyse_incident(load("misleading-log.json"))
    assert first.source_sha256 == second.source_sha256
    assert first.bundle_sha256 == second.bundle_sha256
