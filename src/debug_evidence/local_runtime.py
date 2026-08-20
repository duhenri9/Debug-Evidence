"""Bounded local-runtime evidence collection for Debug Evidence V0.2.

The collector is read-only with respect to the target workspace. It persists only
explicitly requested paths/environment keys, redacts before persistence, and feeds
only sanitised inputs into the deterministic V0 analysis engine.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from debug_evidence.engine import analyse_incident
from debug_evidence.local_models import (
    ArchiveMember,
    ArchiveReceipt,
    FilesystemEvidence,
    GitEvidence,
    LocalCollectionFailure,
    LocalIncidentReport,
    RuntimeFingerprint,
    TextFileEvidence,
    TraceEvidence,
    TraceFrame,
)

LOCAL_CLAIM_BOUNDARY = (
    "Debug Evidence V0.2 records only the explicitly allowlisted local files, environment "
    "keys, Git evidence and runtime metadata collected by this bounded snapshot. Redaction "
    "and previews are defence-in-depth evidence controls, not a general DLP guarantee. The "
    "report does not establish a universal root cause, complete logs when previews are "
    "truncated, production observability coverage or remediation correctness."
)
ARCHIVE_CLAIM_BOUNDARY = (
    "The V0.2 archive contains only the sanitised report, deterministic analysis bundle and "
    "redacted bounded previews emitted by the local collector. Its digest identifies archive "
    "bytes; it is not a signature or proof of complete incident capture."
)
FAILURE_CLAIM_BOUNDARY = (
    "INDETERMINATE means required local evidence could not be collected safely inside the "
    "V0.2 policy. No incident conclusion or archive is manufactured from missing evidence."
)
DEFAULT_PREVIEW_BYTES = 65_536
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_GIT_DIFF_BYTES = 64 * 1024 * 1024
RECENT_COMMIT_LIMIT = 5
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SENSITIVE_KEY = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)",
    re.IGNORECASE,
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?im)\b(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)\b"
    r"\s*[:=]\s*([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([^\s]+)")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_GITHUB_PAT = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_AWS_ACCESS = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_PYTHON_FRAME = re.compile(r'^\s*File "(?P<file>.+?)", line (?P<line>\d+), in (?P<fn>.+?)\s*$')
_NODE_FRAME_WITH_FN = re.compile(
    r"^\s*at\s+(?P<fn>.+?)\s+\((?P<file>.+?):(?P<line>\d+):(?P<column>\d+)\)\s*$"
)
_NODE_FRAME = re.compile(r"^\s*at\s+(?P<file>.+?):(?P<line>\d+):(?P<column>\d+)\s*$")


class CollectionError(RuntimeError):
    """Fail-closed local collection error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_json(payload: object) -> str:
    return _sha256_bytes(_canonical_json(payload))


def _normalise_relative(raw: object) -> str:
    rendered = str(raw).replace("\\", "/")
    path = PurePosixPath(rendered)
    if not rendered or path.is_absolute() or ".." in path.parts or ".git" in path.parts:
        raise CollectionError("UNSAFE_PATH", f"unsafe workspace-relative path: {rendered!r}")
    normalised = path.as_posix()
    if normalised in {"", "."}:
        raise CollectionError("UNSAFE_PATH", f"unsafe workspace-relative path: {rendered!r}")
    return normalised


def _safe_path(workspace: Path, relative: str) -> Path:
    root = workspace.resolve()
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise CollectionError(
                "SYMLINK_BLOCKED",
                f"symlink path is not collectable: {relative}",
            )
    try:
        resolved_parent = current.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise CollectionError(
            "PATH_MISSING",
            f"parent path is missing: {relative}",
        ) from error
    if not resolved_parent.is_relative_to(root):
        raise CollectionError("UNSAFE_PATH", f"path escapes workspace: {relative}")
    return current


def _workspace_tokenise(text: str, workspace: Path) -> str:
    root = str(workspace.resolve())
    tokenised = text.replace(root, "<WORKSPACE>")
    return tokenised.replace(root.replace("\\", "/"), "<WORKSPACE>")


def _redact(text: str, workspace: Path, exact_secrets: Sequence[str]) -> str:
    redacted = _workspace_tokenise(text, workspace)
    unique_secrets = {item for item in exact_secrets if item}
    for secret in sorted(unique_secrets, key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    redacted = _BEARER.sub(r"\1[REDACTED]", redacted)
    redacted = _ASSIGNMENT_SECRET.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        redacted,
    )
    redacted = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", redacted)
    redacted = _GITHUB_PAT.sub("[REDACTED_TOKEN]", redacted)
    redacted = _OPENAI_KEY.sub("[REDACTED_API_KEY]", redacted)
    return _AWS_ACCESS.sub("[REDACTED_ACCESS_KEY]", redacted)


def _bounded_file_preview(
    path: Path,
    relative: str,
    *,
    preview_bytes: int,
    workspace: Path,
    exact_secrets: Sequence[str],
) -> TextFileEvidence:
    if preview_bytes < 1:
        raise CollectionError("INVALID_SPEC", "preview_bytes must be positive")
    if not path.is_file():
        raise CollectionError("PATH_NOT_FILE", f"expected a regular file: {relative}")
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise CollectionError(
            "SOURCE_TOO_LARGE",
            f"source exceeds {MAX_SOURCE_BYTES} byte collection bound: {relative}",
        )

    digest = hashlib.sha256()
    tail: deque[bytes] = deque()
    tail_size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            digest.update(chunk)
            tail.append(chunk)
            tail_size += len(chunk)
            while tail and tail_size - len(tail[0]) >= preview_bytes:
                tail_size -= len(tail.popleft())

    preview_raw = b"".join(tail)[-preview_bytes:]
    preview = preview_raw.decode("utf-8", errors="replace")
    redacted = _redact(preview, workspace, exact_secrets)
    return TextFileEvidence(
        path=relative,
        byte_count=size,
        raw_sha256=digest.hexdigest(),
        preview_byte_limit=preview_bytes,
        truncated=size > preview_bytes,
        redacted_preview=redacted,
        redacted_preview_sha256=_sha256_bytes(redacted.encode()),
    )


def _parse_python_trace(text: str, source_path: str | None) -> TraceEvidence:
    frames: list[TraceFrame] = []
    lines = text.splitlines()
    for line in lines:
        match = _PYTHON_FRAME.match(line)
        if match:
            frames.append(
                TraceFrame(
                    function=match.group("fn"),
                    file=match.group("file"),
                    line=int(match.group("line")),
                    column=None,
                )
            )

    error_type: str | None = None
    error_message: str | None = None
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("File ", "Traceback")):
            continue
        if ":" not in stripped:
            continue
        candidate, message = stripped.split(":", 1)
        if candidate and " " not in candidate:
            error_type = candidate
            error_message = message.strip() or None
            break
    return TraceEvidence(
        runtime="python",
        error_type=error_type,
        error_message=error_message,
        frames=tuple(frames),
        parser_version="python-trace.v1",
        source_path=source_path,
    )


def _parse_node_trace(text: str, source_path: str | None) -> TraceEvidence:
    frames: list[TraceFrame] = []
    error_type: str | None = None
    error_message: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if error_type is None and not stripped.startswith("at "):
            if ":" in stripped:
                candidate, message = stripped.split(":", 1)
                error_type = candidate.strip() or None
                error_message = message.strip() or None
            else:
                error_message = stripped
        match = _NODE_FRAME_WITH_FN.match(line)
        if match:
            frames.append(
                TraceFrame(
                    function=match.group("fn"),
                    file=match.group("file"),
                    line=int(match.group("line")),
                    column=int(match.group("column")),
                )
            )
            continue
        match = _NODE_FRAME.match(line)
        if match:
            frames.append(
                TraceFrame(
                    function="<anonymous>",
                    file=match.group("file"),
                    line=int(match.group("line")),
                    column=int(match.group("column")),
                )
            )
    return TraceEvidence(
        runtime="node",
        error_type=error_type,
        error_message=error_message,
        frames=tuple(frames),
        parser_version="node-stack.v1",
        source_path=source_path,
    )


def parse_trace(runtime: str, text: str, source_path: str | None = None) -> TraceEvidence:
    """Parse a sanitised Python traceback or Node stack without executing target code."""

    if runtime == "python":
        return _parse_python_trace(text, source_path)
    if runtime == "node":
        return _parse_node_trace(text, source_path)
    raise CollectionError("UNSUPPORTED_RUNTIME", f"unsupported runtime: {runtime}")


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_git(root: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            env=_git_environment(),
        )
    except OSError as error:
        return subprocess.CompletedProcess(
            args=["git", *arguments],
            returncode=127,
            stdout="",
            stderr=str(error),
        )


def _git_required(root: Path, arguments: Sequence[str], context: str) -> str:
    completed = _run_git(root, arguments)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git command failed"
        detail = detail.replace(str(root.resolve()), "<WORKSPACE>")
        raise CollectionError("GIT_EVIDENCE_ERROR", f"{context}: {detail}")
    return completed.stdout


def _read_stream_evidence(
    stream: BinaryIO,
    *,
    preview_bytes: int,
    workspace: Path,
    exact_secrets: Sequence[str],
) -> tuple[str, int, bool, str]:
    stream.flush()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    if size > MAX_GIT_DIFF_BYTES:
        raise CollectionError(
            "GIT_DIFF_TOO_LARGE",
            f"git diff exceeds {MAX_GIT_DIFF_BYTES} byte collection bound",
        )
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(65_536):
        digest.update(chunk)
    stream.seek(0)
    preview_raw = stream.read(preview_bytes)
    preview = _redact(
        preview_raw.decode("utf-8", errors="replace"),
        workspace,
        exact_secrets,
    )
    truncated = size > preview_bytes
    if truncated:
        preview += "\n[TRUNCATED]"
    return digest.hexdigest(), size, truncated, preview


def _split_nul_paths(raw: str) -> set[str]:
    return {item for item in raw.split("\0") if item}


def _collect_git(
    workspace: Path,
    *,
    require_git: bool,
    preview_bytes: int,
    exact_secrets: Sequence[str],
) -> GitEvidence:
    probe = _run_git(workspace, ["rev-parse", "--show-toplevel"])
    if probe.returncode != 0:
        if require_git:
            raise CollectionError(
                "GIT_REQUIRED",
                "workspace is not inside a readable Git repository",
            )
        return GitEvidence(
            available=False,
            repository_root=None,
            head_sha=None,
            branch=None,
            status_entries=(),
            changed_paths=(),
            diff_sha256=_EMPTY_SHA256,
            diff_truncated=False,
            redacted_diff_preview="",
            recent_commits=(),
            error="Git repository unavailable",
        )

    repository_root = Path(probe.stdout.strip()).resolve()
    if repository_root != workspace.resolve():
        raise CollectionError(
            "GIT_ROOT_MISMATCH",
            "V0.2 requires the explicit workspace to equal the resolved Git root",
        )
    head = _git_required(repository_root, ["rev-parse", "HEAD"], "resolve HEAD").strip()

    branch_probe = _run_git(
        repository_root,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
    )
    if branch_probe.returncode == 0:
        branch = branch_probe.stdout.strip()
    elif branch_probe.returncode == 1:
        branch = "DETACHED"
    else:
        raise CollectionError("GIT_EVIDENCE_ERROR", "cannot resolve branch identity")

    status = _git_required(
        repository_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        "read status",
    )
    status_entries = tuple(line for line in status.splitlines() if line)
    tracked_raw = _git_required(
        repository_root,
        ["diff", "--name-only", "-z", "HEAD", "--"],
        "read changed tracked paths",
    )
    untracked_raw = _git_required(
        repository_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        "read untracked paths",
    )
    changed_paths = _split_nul_paths(tracked_raw) | _split_nul_paths(untracked_raw)

    with tempfile.TemporaryFile() as diff_stream:
        try:
            completed = subprocess.run(
                ["git", "diff", "--binary", "--no-color", "HEAD", "--"],
                cwd=repository_root,
                check=False,
                stdout=diff_stream,
                stderr=subprocess.PIPE,
                env=_git_environment(),
            )
        except OSError as error:
            raise CollectionError("GIT_EVIDENCE_ERROR", "cannot execute git diff") from error
        if completed.returncode != 0:
            raise CollectionError("GIT_EVIDENCE_ERROR", "git diff failed")
        diff_sha256, _size, diff_truncated, diff_preview = _read_stream_evidence(
            diff_stream,
            preview_bytes=preview_bytes,
            workspace=workspace,
            exact_secrets=exact_secrets,
        )

    log_format = "%H%x1f%P%x1f%cI%x1f%s"
    recent_raw = _git_required(
        repository_root,
        ["log", f"-{RECENT_COMMIT_LIMIT}", f"--pretty=format:{log_format}"],
        "read recent commits",
    )
    recent_commits = tuple(
        _redact(line, workspace, exact_secrets) for line in recent_raw.splitlines() if line
    )
    return GitEvidence(
        available=True,
        repository_root="<WORKSPACE>",
        head_sha=head,
        branch=branch,
        status_entries=tuple(_redact(item, workspace, exact_secrets) for item in status_entries),
        changed_paths=tuple(sorted(changed_paths)),
        diff_sha256=diff_sha256,
        diff_truncated=diff_truncated,
        redacted_diff_preview=diff_preview,
        recent_commits=recent_commits,
        error=None,
    )


def _node_version() -> str | None:
    try:
        completed = subprocess.run(
            ["node", "--version"],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _runtime_fingerprint(runtime: str) -> RuntimeFingerprint:
    return RuntimeFingerprint(
        runtime=runtime,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        python_executable=Path(sys.executable).name,
        node_version=_node_version() if runtime == "node" else None,
        platform_system=platform.system(),
        platform_machine=platform.machine(),
        workspace="<WORKSPACE>",
    )


def _environment_evidence(
    allowlist: Sequence[str],
    source: Mapping[str, str],
    workspace: Path,
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    evidence: list[tuple[str, str]] = []
    exact_secrets: list[str] = []
    for raw_key in allowlist:
        key = str(raw_key)
        if not key or "=" in key:
            raise CollectionError("INVALID_SPEC", f"invalid environment key: {key!r}")
        if key not in source:
            evidence.append((key, "<UNSET>"))
            continue
        value = str(source[key])
        if _SENSITIVE_KEY.search(key):
            evidence.append((key, "[REDACTED]"))
            if value:
                exact_secrets.append(value)
        else:
            evidence.append((key, _workspace_tokenise(value, workspace)))
    secrets = tuple(sorted(set(exact_secrets), key=len, reverse=True))
    return tuple(sorted(evidence)), secrets


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def _filesystem_evidence(
    workspace: Path,
    raw_paths: Sequence[object],
) -> tuple[FilesystemEvidence, ...]:
    evidence: list[FilesystemEvidence] = []
    for raw in raw_paths:
        relative = _normalise_relative(raw)
        path = _safe_path(workspace, relative)
        if not path.exists():
            evidence.append(
                FilesystemEvidence(
                    path=relative,
                    kind="missing",
                    size_bytes=None,
                    sha256=None,
                    mode=None,
                )
            )
            continue
        info = path.stat()
        mode = stat.filemode(info.st_mode)
        if path.is_dir():
            evidence.append(
                FilesystemEvidence(
                    path=relative,
                    kind="directory",
                    size_bytes=None,
                    sha256=None,
                    mode=mode,
                )
            )
            continue
        if not path.is_file():
            raise CollectionError(
                "UNSUPPORTED_FILE_TYPE",
                f"unsupported metadata target: {relative}",
            )
        if info.st_size > MAX_SOURCE_BYTES:
            raise CollectionError(
                "SOURCE_TOO_LARGE",
                f"metadata file exceeds bound: {relative}",
            )
        evidence.append(
            FilesystemEvidence(
                path=relative,
                kind="file",
                size_bytes=info.st_size,
                sha256=_file_sha256(path),
                mode=mode,
            )
        )
    return tuple(sorted(evidence, key=lambda item: item.path))


def _sanitised_fixture(
    spec: Mapping[str, Any],
    *,
    log_files: Sequence[TextFileEvidence],
    stack_file: TextFileEvidence | None,
    git: GitEvidence,
    environment: Sequence[tuple[str, str]],
) -> dict[str, Any]:
    logs: list[str] = []
    for evidence in log_files:
        logs.extend(evidence.redacted_preview.splitlines())
    return {
        "incident_id": str(spec["incident_id"]),
        "inputs": {
            "logs": logs,
            "stack_trace": stack_file.redacted_preview if stack_file else None,
            "recent_diff": git.redacted_diff_preview if git.available else None,
            "environment": dict(environment),
        },
        "hypotheses": list(spec.get("hypotheses", [])),
        "probes": list(spec.get("probes", [])),
    }


def collect_local_incident(
    spec: Mapping[str, Any],
    workspace: Path,
    *,
    environment_source: Mapping[str, str] | None = None,
) -> LocalIncidentReport:
    """Collect and analyse an explicitly allowlisted local incident snapshot."""

    root = workspace.resolve()
    if not root.is_dir():
        raise CollectionError("WORKSPACE_MISSING", "workspace path is not a directory")
    incident_id = str(spec.get("incident_id", "UNKNOWN"))
    runtime = str(spec.get("runtime", ""))
    if runtime not in {"python", "node"}:
        raise CollectionError(
            "UNSUPPORTED_RUNTIME",
            f"runtime must be python or node: {runtime!r}",
        )
    preview_bytes = int(spec.get("preview_bytes", DEFAULT_PREVIEW_BYTES))
    if preview_bytes < 1 or preview_bytes > MAX_SOURCE_BYTES:
        raise CollectionError(
            "INVALID_SPEC",
            "preview_bytes is outside the allowed bound",
        )

    source_environment = os.environ if environment_source is None else environment_source
    raw_env_allowlist = spec.get("env_allowlist", [])
    if not isinstance(raw_env_allowlist, list):
        raise CollectionError("INVALID_SPEC", "env_allowlist must be a JSON array")
    environment, exact_secrets = _environment_evidence(
        raw_env_allowlist,
        source_environment,
        root,
    )

    raw_log_paths = spec.get("log_files", [])
    if not isinstance(raw_log_paths, list) or not raw_log_paths:
        raise CollectionError(
            "INVALID_SPEC",
            "log_files must be a non-empty JSON array",
        )
    log_files: list[TextFileEvidence] = []
    for raw in raw_log_paths:
        relative = _normalise_relative(raw)
        log_files.append(
            _bounded_file_preview(
                _safe_path(root, relative),
                relative,
                preview_bytes=preview_bytes,
                workspace=root,
                exact_secrets=exact_secrets,
            )
        )

    stack_file: TextFileEvidence | None = None
    stack_raw = spec.get("stack_file")
    if stack_raw is not None:
        stack_relative = _normalise_relative(stack_raw)
        stack_file = _bounded_file_preview(
            _safe_path(root, stack_relative),
            stack_relative,
            preview_bytes=preview_bytes,
            workspace=root,
            exact_secrets=exact_secrets,
        )
    trace = parse_trace(
        runtime,
        stack_file.redacted_preview if stack_file else "",
        stack_file.path if stack_file else None,
    )

    git = _collect_git(
        root,
        require_git=bool(spec.get("require_git", True)),
        preview_bytes=preview_bytes,
        exact_secrets=exact_secrets,
    )

    raw_metadata_paths = spec.get("metadata_paths", [])
    if not isinstance(raw_metadata_paths, list):
        raise CollectionError("INVALID_SPEC", "metadata_paths must be a JSON array")
    filesystem = _filesystem_evidence(root, raw_metadata_paths)

    sanitised = _sanitised_fixture(
        spec,
        log_files=log_files,
        stack_file=stack_file,
        git=git,
        environment=environment,
    )
    bundle = analyse_incident(sanitised)
    runtime_fingerprint = _runtime_fingerprint(runtime)
    spec_sha256 = _sha256_json(spec)
    unsigned: dict[str, Any] = {
        "schema": "debug-evidence.local-report.v0.2",
        "incident_id": incident_id,
        "runtime": runtime,
        "spec_sha256": spec_sha256,
        "log_files": [asdict(item) for item in log_files],
        "stack_file": asdict(stack_file) if stack_file else None,
        "trace": asdict(trace),
        "git": asdict(git),
        "environment": [list(item) for item in environment],
        "runtime_fingerprint": asdict(runtime_fingerprint),
        "filesystem": [asdict(item) for item in filesystem],
        "bundle": bundle.to_dict(),
        "claim_boundary": LOCAL_CLAIM_BOUNDARY,
    }
    return LocalIncidentReport(
        schema="debug-evidence.local-report.v0.2",
        incident_id=incident_id,
        runtime=runtime,
        spec_sha256=spec_sha256,
        log_files=tuple(log_files),
        stack_file=stack_file,
        trace=trace,
        git=git,
        environment=environment,
        runtime_fingerprint=runtime_fingerprint,
        filesystem=filesystem,
        bundle=bundle,
        claim_boundary=LOCAL_CLAIM_BOUNDARY,
        report_sha256=_sha256_json(unsigned),
    )


def collection_failure(
    incident_id: str,
    error: CollectionError,
) -> LocalCollectionFailure:
    unsigned = {
        "schema": "debug-evidence.local-failure.v0.2",
        "incident_id": incident_id,
        "outcome": "INDETERMINATE",
        "error_code": error.code,
        "error": error.message,
        "claim_boundary": FAILURE_CLAIM_BOUNDARY,
    }
    return LocalCollectionFailure(
        schema="debug-evidence.local-failure.v0.2",
        incident_id=incident_id,
        outcome="INDETERMINATE",
        error_code=error.code,
        error=error.message,
        claim_boundary=FAILURE_CLAIM_BOUNDARY,
        receipt_sha256=_sha256_json(unsigned),
    )


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"


def _archive_payloads(report: LocalIncidentReport) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {
        "collection.json": _json_bytes(report.to_dict()),
        "bundle.json": _json_bytes(report.bundle.to_dict()),
        "git/diff.patch": report.git.redacted_diff_preview.encode(),
    }
    for index, evidence in enumerate(report.log_files, start=1):
        payloads[f"inputs/log-{index:02d}.txt"] = evidence.redacted_preview.encode()
    if report.stack_file is not None:
        payloads["inputs/stack.txt"] = report.stack_file.redacted_preview.encode()
    members = [
        {
            "path": path,
            "sha256": _sha256_bytes(payload),
            "byte_count": len(payload),
        }
        for path, payload in sorted(payloads.items())
    ]
    manifest = {
        "schema": "debug-evidence.archive-manifest.v0.2",
        "incident_id": report.incident_id,
        "members": members,
        "claim_boundary": ARCHIVE_CLAIM_BOUNDARY,
    }
    payloads["manifest.json"] = _json_bytes(manifest)
    return payloads


def build_incident_archive(
    report: LocalIncidentReport,
    destination: Path,
) -> ArchiveReceipt:
    """Write a deterministic, sanitised ZIP archive and return external byte evidence."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    payloads = _archive_payloads(report)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, payload in sorted(payloads.items()):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, payload)

    archive_bytes = destination.read_bytes()
    archive_sha256 = _sha256_bytes(archive_bytes)
    members = tuple(
        ArchiveMember(
            path=path,
            sha256=_sha256_bytes(payload),
            byte_count=len(payload),
        )
        for path, payload in sorted(payloads.items())
    )
    unsigned = {
        "schema": "debug-evidence.archive-receipt.v0.2",
        "incident_id": report.incident_id,
        "archive_sha256": archive_sha256,
        "archive_byte_count": len(archive_bytes),
        "members": [asdict(item) for item in members],
        "claim_boundary": ARCHIVE_CLAIM_BOUNDARY,
    }
    return ArchiveReceipt(
        schema="debug-evidence.archive-receipt.v0.2",
        incident_id=report.incident_id,
        archive_sha256=archive_sha256,
        archive_byte_count=len(archive_bytes),
        members=members,
        claim_boundary=ARCHIVE_CLAIM_BOUNDARY,
        receipt_sha256=_sha256_json(unsigned),
    )
