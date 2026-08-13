from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
EVIDENCE_DIR = ROOT / "evidence"
REPORT_PATH = EVIDENCE_DIR / "local-verification.json"
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "evidence",
}
EXCLUDED_SUFFIXES = {".db", ".log", ".pyc", ".sqlite", ".sqlite3", ".tmp", ".zip"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_manifest() -> list[dict[str, Any]]:
    files = sorted(
        (
            path
            for path in ROOT.rglob("*")
            if path.is_file()
            and not any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in path.parts)
            and path.suffix.lower() not in EXCLUDED_SUFFIXES
        ),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    return [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in files
    ]


def git_state() -> dict[str, Any]:
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    revision = run("rev-parse", "HEAD")
    status = run("status", "--porcelain", "--untracked-files=normal")
    return {
        "revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "revisionObserved": revision.returncode == 0,
        "workingTreeDirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
    }


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with tempfile.NamedTemporaryFile(
        mode="wb", delete=False, dir=path.parent, prefix=path.name + ".", suffix=".tmp"
    ) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    test_process = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    test_output = (test_process.stdout + test_process.stderr).strip()
    match = re.search(r"Ran (\d+) tests?", test_output)
    test_count = int(match.group(1)) if match else None

    demo: dict[str, Any] | None = None
    demo_exit: int | None = None
    demo_error: str | None = None
    if test_process.returncode == 0:
        demo_process = subprocess.run(
            [sys.executable, "-B", "-m", "defensive_control_plane", "demo"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        demo_exit = demo_process.returncode
        if demo_process.returncode == 0:
            try:
                demo = json.loads(demo_process.stdout)
            except json.JSONDecodeError:
                demo_error = "demo returned non-JSON output"
        else:
            demo_error = (demo_process.stderr or demo_process.stdout).strip()

    manifest = source_manifest()
    manifest_digest = hashlib.sha256(
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    repository = git_state()
    passed = (
        test_process.returncode == 0
        and demo_exit == 0
        and demo is not None
        and demo.get("caseExportVerified") is True
        and demo.get("connectorCalls") == 1
        and demo.get("dryRunMutationCalls") == 0
        and demo.get("restoreDrill", {}).get("state") == "VERIFIED_LOCAL"
    )
    report: dict[str, Any] = {
        "schema": "LocalDefensiveControlPlaneVerificationV2",
        "observedAt": observed_at,
        "state": "VERIFIED_LOCAL" if passed else "FAILED_CLOSED",
        "scope": "local-python-sqlite-fake-connector",
        "python": sys.version,
        "pythonExecutable": Path(sys.executable).name,
        "testCommand": "python -B -m unittest discover -s tests -v",
        "testExitCode": test_process.returncode,
        "testCount": test_count,
        "testOutput": test_output.splitlines(),
        "demoExitCode": demo_exit,
        "demo": demo,
        "demoError": demo_error,
        "sourceManifest": manifest,
        "sourceManifestDigest": manifest_digest,
        "repository": repository,
        "productionOperational": False,
        "externalConnectors": "UNAVAILABLE",
        "deployedRuntime": "UNAVAILABLE",
    }
    atomic_write_json(REPORT_PATH, report)
    print(
        json.dumps(
            {
                "report": str(REPORT_PATH.relative_to(ROOT)),
                "state": report["state"],
                "testCount": test_count,
                "sourceManifestDigest": manifest_digest,
                "sourceRevision": repository["revision"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
