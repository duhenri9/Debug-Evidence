"""Stable public contracts for Debug Evidence V0."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class HypothesisStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class ProbeEvidence:
    probe_id: str
    hypothesis_id: str
    kind: str
    executed: bool
    blocked: bool
    matched: bool | None
    relation: str
    summary: str


@dataclass(frozen=True)
class HypothesisResult:
    hypothesis_id: str
    statement: str
    status: HypothesisStatus
    supporting_probe_ids: tuple[str, ...]
    contradicting_probe_ids: tuple[str, ...]
    unresolved_probe_ids: tuple[str, ...]


@dataclass(frozen=True)
class Bundle:
    schema: str
    incident_id: str
    source_sha256: str
    hypotheses: tuple[HypothesisResult, ...]
    probes: tuple[ProbeEvidence, ...]
    redacted_environment: dict[str, str]
    claim_boundary: str
    bundle_sha256: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for hypothesis in payload["hypotheses"]:
            hypothesis["status"] = hypothesis["status"].value
        return payload
