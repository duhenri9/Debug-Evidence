from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SYNTHETIC_SECRET = "synthetic-redaction-value-123"


def git(root: Path, *arguments: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(["git", *arguments], cwd=root, env=env, check=True)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_local_fixture.py PATH")
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=False)
    (root / "src").mkdir()
    (root / "logs").mkdir()

    (root / "src/service.py").write_text("CACHE_LIMIT = 32\n", encoding="utf-8")
    (root / "logs/app.log").write_text(
        "ERROR database unavailable while retrying request\n"
        "WARN cache eviction storm detected token=" + SYNTHETIC_SECRET + "\n",
        encoding="utf-8",
    )
    (root / "logs/trace.txt").write_text(
        "Traceback (most recent call last):\n"
        '  File "src/service.py", line 12, in handle\n'
        "    raise CacheOverflow('eviction budget exhausted')\n"
        "CacheOverflow: eviction budget exhausted\n",
        encoding="utf-8",
    )

    git(root, "init", "-q")
    git(root, "config", "user.email", "debug-evidence@example.invalid")
    git(root, "config", "user.name", "Debug Evidence Fixture")
    git(root, "add", "-A")
    environment = os.environ.copy()
    environment["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:00+00:00"
    environment["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:00+00:00"
    git(root, "commit", "-q", "-m", "fixture baseline", env=environment)

    # The incident-correlated change happens after the baseline commit.
    (root / "src/service.py").write_text("CACHE_LIMIT = 1\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
