"""CLI for bounded local runtime evidence collection and deterministic incident archives."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from debug_evidence.local_runtime import (
    CollectionError,
    build_incident_archive,
    collect_local_incident,
    collection_failure,
)


def _load_spec(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("local incident spec must be a JSON object")
    return payload


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path, help="Local V0.2 incident collection spec")
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Explicit evidence workspace",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Write the local collection report/failure JSON",
    )
    parser.add_argument(
        "--archive",
        type=Path,
        help="Write a deterministic sanitised incident ZIP",
    )
    parser.add_argument(
        "--archive-receipt",
        type=Path,
        help="Write external SHA-256/member evidence for the archive bytes",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        spec = _load_spec(args.spec)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        failure = collection_failure(
            "UNKNOWN",
            CollectionError(
                "SPEC_READ_ERROR",
                f"cannot read incident spec ({type(error).__name__})",
            ),
        )
        payload = failure.to_dict()
        if args.report:
            _write_json(args.report, payload)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        return 3

    incident_id = str(spec.get("incident_id", "UNKNOWN"))
    try:
        report = collect_local_incident(spec, args.workspace)
        if args.archive_receipt and not args.archive:
            raise CollectionError("INVALID_SPEC", "--archive-receipt requires --archive")
        archive_receipt = None
        if args.archive:
            archive_receipt = build_incident_archive(report, args.archive)
        if args.report:
            _write_json(args.report, report.to_dict())
        if args.archive_receipt and archive_receipt is not None:
            _write_json(args.archive_receipt, archive_receipt.to_dict())
        print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except CollectionError as error:
        if args.archive and args.archive.exists():
            args.archive.unlink()
        if args.archive_receipt and args.archive_receipt.exists():
            args.archive_receipt.unlink()
        failure = collection_failure(incident_id, error)
        payload = failure.to_dict()
        if args.report:
            _write_json(args.report, payload)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
