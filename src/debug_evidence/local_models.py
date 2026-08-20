"""Typed evidence contracts for Debug Evidence local-runtime V0.2."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from debug_evidence.models import Bundle


@dataclass(frozen=True)
class TextFileEvidence:
    path: str
    byte_count: int
    raw_sha256: str
    preview_byte_limit: int
    truncated: bool
    redacted_preview: str
    redacted_preview_sha256: str


@dataclass(frozen=True)
class TraceFrame:
    function: str
    file: str
    line: int
    column: int | None


@dataclass(frozen=True)
class TraceEvidence:
    runtime: str
    error_type: str | None
    error_message: str | None
    frames: tuple[TraceFrame, ...]
    parser_version: str
    source_path: str | None


@dataclass(frozen=True)
class GitEvidence:
    available: bool
    repository_root: str | None
    head_sha: str | None
    branch: str | None
    status_entries: tuple[str, ...]
    changed_paths: tuple[str, ...]
    diff_sha256: str
    diff_truncated: bool
    redacted_diff_preview: str
    recent_commits: tuple[str, ...]
    error: str | None


@dataclass(frozen=True)
class RuntimeFingerprint:
    runtime: str
    python_implementation: str
    python_version: str
    python_executable: str
    node_version: str | None
    platform_system: str
    platform_machine: str
    workspace: str


@dataclass(frozen=True)
class FilesystemEvidence:
    path: str
    kind: str
    size_bytes: int | None
    sha256: str | None
    mode: str | None


@dataclass(frozen=True)
class LocalIncidentReport:
    schema: str
    incident_id: str
    runtime: str
    spec_sha256: str
    log_files: tuple[TextFileEvidence, ...]
    stack_file: TextFileEvidence | None
    trace: TraceEvidence
    git: GitEvidence
    environment: tuple[tuple[str, str], ...]
    runtime_fingerprint: RuntimeFingerprint
    filesystem: tuple[FilesystemEvidence, ...]
    bundle: Bundle
    claim_boundary: str
    report_sha256: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["bundle"] = self.bundle.to_dict()
        return payload


@dataclass(frozen=True)
class ArchiveMember:
    path: str
    sha256: str
    byte_count: int


@dataclass(frozen=True)
class ArchiveReceipt:
    schema: str
    incident_id: str
    archive_sha256: str
    archive_byte_count: int
    members: tuple[ArchiveMember, ...]
    claim_boundary: str
    receipt_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LocalCollectionFailure:
    """Machine-readable fail-closed result when local evidence cannot be collected safely."""

    schema: str
    incident_id: str
    outcome: str
    error_code: str
    error: str
    claim_boundary: str
    receipt_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
