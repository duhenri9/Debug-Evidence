from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from debug_evidence.local_runtime import (
    CollectionError,
    build_incident_archive,
    collect_local_incident,
    parse_trace,
)

SYNTHETIC_SECRET = "synthetic-redaction-value-123"


def _git(root: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def make_repository(parent: Path, name: str = "repo") -> Path:
    root = parent / name
    root.mkdir()
    (root / "src").mkdir()
    (root / "logs").mkdir()
    (root / "src/service.py").write_text("CACHE_LIMIT = 32\n", encoding="utf-8")
    (root / "logs/app.log").write_text(
        "ERROR database unavailable while retrying request\n"
        f"WARN cache eviction storm detected token={SYNTHETIC_SECRET}\n",
        encoding="utf-8",
    )
    (root / "logs/trace.txt").write_text(
        "Traceback (most recent call last):\n"
        '  File "src/service.py", line 12, in handle\n'
        "    raise CacheOverflow('eviction budget exhausted')\n"
        "CacheOverflow: eviction budget exhausted\n",
        encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "debug-evidence@example.invalid")
    _git(root, "config", "user.name", "Debug Evidence Fixture")
    _git(root, "add", "-A")
    environment = os.environ.copy()
    environment["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:00+00:00"
    environment["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:00+00:00"
    _git(root, "commit", "-q", "-m", "fixture baseline", env=environment)
    (root / "src/service.py").write_text("CACHE_LIMIT = 1\n", encoding="utf-8")
    return root


def incident_spec() -> dict[str, Any]:
    return {
        "incident_id": "local-python-v02",
        "runtime": "python",
        "preview_bytes": 32768,
        "require_git": True,
        "log_files": ["logs/app.log"],
        "stack_file": "logs/trace.txt",
        "env_allowlist": ["APP_MODE", "WORKSPACE_HINT", "DEBUG_EVIDENCE_TEST_TOKEN"],
        "metadata_paths": ["src/service.py", "logs/app.log"],
        "hypotheses": [
            {"id": "database-outage", "statement": "Database outage."},
            {"id": "cache-regression", "statement": "Cache regression."},
        ],
        "probes": [
            {
                "id": "database-decoy-contradiction",
                "hypothesis_id": "database-outage",
                "kind": "stack_contains",
                "relation": "contradict",
                "params": {"needle": "CacheOverflow"},
            },
            {
                "id": "cache-log-support",
                "hypothesis_id": "cache-regression",
                "kind": "log_contains",
                "relation": "support",
                "params": {"needle": "cache eviction storm"},
            },
            {
                "id": "cache-diff-support",
                "hypothesis_id": "cache-regression",
                "kind": "diff_contains",
                "relation": "support",
                "params": {"needle": "CACHE_LIMIT = 1"},
            },
        ],
    }


def evidence_environment(root: Path) -> dict[str, str]:
    return {
        "APP_MODE": "production",
        "WORKSPACE_HINT": str(root),
        "DEBUG_EVIDENCE_TEST_TOKEN": SYNTHETIC_SECRET,
    }


def test_collects_python_trace_git_diff_env_and_sanitised_v0_analysis(tmp_path: Path) -> None:
    root = make_repository(tmp_path)
    status_before = _git(root, "status", "--porcelain=v1", "--untracked-files=all")

    report = collect_local_incident(
        incident_spec(),
        root,
        environment_source=evidence_environment(root),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    status_after = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    statuses = {item.hypothesis_id: item.status.value for item in report.bundle.hypotheses}

    assert report.schema == "debug-evidence.local-report.v0.2"
    assert report.trace.error_type == "CacheOverflow"
    assert report.trace.frames[0].function == "handle"
    assert report.git.available
    assert report.git.head_sha
    assert report.git.changed_paths == ("src/service.py",)
    assert "CACHE_LIMIT = 1" in report.git.redacted_diff_preview
    assert statuses == {
        "cache-regression": "SUPPORTED",
        "database-outage": "CONTRADICTED",
    }
    assert dict(report.environment) == {
        "APP_MODE": "production",
        "DEBUG_EVIDENCE_TEST_TOKEN": "[REDACTED]",
        "WORKSPACE_HINT": "<WORKSPACE>",
    }
    assert SYNTHETIC_SECRET not in rendered
    assert SYNTHETIC_SECRET not in report.log_files[0].redacted_preview
    assert status_before == status_after


def test_node_stack_parser_handles_named_and_anonymous_frames() -> None:
    trace = parse_trace(
        "node",
        "TypeError: boom\n"
        "    at run (/workspace/app.js:10:4)\n"
        "    at /workspace/index.js:2:1\n",
        "stack.txt",
    )

    assert trace.error_type == "TypeError"
    assert trace.error_message == "boom"
    assert trace.frames[0].function == "run"
    assert trace.frames[0].line == 10
    assert trace.frames[1].function == "<anonymous>"
    assert trace.frames[1].column == 1


def test_parent_escape_is_rejected_before_file_read(tmp_path: Path) -> None:
    root = make_repository(tmp_path)
    outside = tmp_path / "outside.log"
    outside.write_text("outside\n", encoding="utf-8")
    spec = incident_spec()
    spec["log_files"] = ["../outside.log"]

    with pytest.raises(CollectionError, match="unsafe workspace-relative path") as captured:
        collect_local_incident(spec, root, environment_source={})

    assert captured.value.code == "UNSAFE_PATH"
    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_symlink_input_is_blocked(tmp_path: Path) -> None:
    root = make_repository(tmp_path)
    outside = tmp_path / "outside.log"
    outside.write_text("outside\n", encoding="utf-8")
    (root / "logs/link.log").symlink_to(outside)
    spec = incident_spec()
    spec["log_files"] = ["logs/link.log"]

    with pytest.raises(CollectionError, match="symlink path") as captured:
        collect_local_incident(spec, root, environment_source={})

    assert captured.value.code == "SYMLINK_BLOCKED"


def test_required_git_repository_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "not-git"
    (root / "logs").mkdir(parents=True)
    (root / "logs/app.log").write_text("hello\n", encoding="utf-8")
    spec = {
        "incident_id": "missing-git",
        "runtime": "python",
        "require_git": True,
        "log_files": ["logs/app.log"],
        "env_allowlist": [],
        "metadata_paths": [],
        "hypotheses": [],
        "probes": [],
    }

    with pytest.raises(CollectionError, match="Git repository") as captured:
        collect_local_incident(spec, root, environment_source={})

    assert captured.value.code == "GIT_REQUIRED"


def test_large_log_has_complete_raw_digest_but_bounded_redacted_preview(tmp_path: Path) -> None:
    root = make_repository(tmp_path)
    payload = ("prefix\n" + ("x" * 4096) + f"\ntoken={SYNTHETIC_SECRET}\n").encode()
    (root / "logs/app.log").write_bytes(payload)
    spec = incident_spec()
    spec["preview_bytes"] = 64

    report = collect_local_incident(
        spec,
        root,
        environment_source=evidence_environment(root),
    )
    log = report.log_files[0]

    assert log.truncated
    assert log.preview_byte_limit == 64
    assert log.raw_sha256 == hashlib.sha256(payload).hexdigest()
    assert SYNTHETIC_SECRET not in log.redacted_preview
    assert len(log.redacted_preview.encode()) < 128


def test_archive_is_byte_reproducible_and_contains_no_raw_secret(tmp_path: Path) -> None:
    first_root = make_repository(tmp_path, "first")
    second_root = make_repository(tmp_path, "second")
    first = collect_local_incident(
        incident_spec(),
        first_root,
        environment_source=evidence_environment(first_root),
    )
    second = collect_local_incident(
        incident_spec(),
        second_root,
        environment_source=evidence_environment(second_root),
    )
    first_archive = tmp_path / "first.zip"
    second_archive = tmp_path / "second.zip"

    first_receipt = build_incident_archive(first, first_archive)
    second_receipt = build_incident_archive(second, second_archive)

    assert first.report_sha256 == second.report_sha256
    assert first_archive.read_bytes() == second_archive.read_bytes()
    assert first_receipt.archive_sha256 == second_receipt.archive_sha256
    assert first_receipt.receipt_sha256 == second_receipt.receipt_sha256
    assert SYNTHETIC_SECRET.encode() not in first_archive.read_bytes()

    with zipfile.ZipFile(first_archive) as archive:
        names = sorted(archive.namelist())
        assert names == [
            "bundle.json",
            "collection.json",
            "git/diff.patch",
            "inputs/log-01.txt",
            "inputs/stack.txt",
            "manifest.json",
        ]
        for name in names:
            assert SYNTHETIC_SECRET.encode() not in archive.read(name)


def test_non_git_collection_can_be_explicitly_allowed(tmp_path: Path) -> None:
    root = tmp_path / "standalone"
    (root / "logs").mkdir(parents=True)
    (root / "logs/app.log").write_text("standalone event\n", encoding="utf-8")
    spec = {
        "incident_id": "standalone",
        "runtime": "python",
        "require_git": False,
        "log_files": ["logs/app.log"],
        "env_allowlist": [],
        "metadata_paths": [],
        "hypotheses": [],
        "probes": [],
    }

    report = collect_local_incident(spec, root, environment_source={})

    assert not report.git.available
    assert report.git.error == "Git repository unavailable"
    assert report.bundle.hypotheses == ()


def test_missing_node_binary_does_not_break_node_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = make_repository(tmp_path)
    spec = incident_spec()
    spec["runtime"] = "node"
    monkeypatch.setenv("PATH", "")

    report = collect_local_incident(spec, root, environment_source={})

    assert report.runtime_fingerprint.node_version is None
