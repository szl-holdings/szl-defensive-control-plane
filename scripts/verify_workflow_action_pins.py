#!/usr/bin/env python3
"""Fail closed when workflow action uses entries are not immutably pinned."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Sequence

BUILD_PUSH_ACTION = "docker/build-push-action"
VERIFIED_BUILD_PUSH_REVISIONS = {
    # Official lightweight tag verified from docker/build-push-action on 2026-08-26.
    "v7.3.0": "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
}
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})
USES_KEY = re.compile(
    r"""(?:["']uses["']|\buses\b)\s*:""",
    re.IGNORECASE,
)
EXTERNAL_REFERENCE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*"
    r"(?P<action>[a-z0-9_.-]+/[a-z0-9_.-]+(?:/[a-z0-9_.\-/]+)?)@"
    r"(?P<revision>[0-9a-f]{40})\s+#\s+"
    r"(?P<version>v\d+\.\d+\.\d+)\s*$"
)
LOCAL_REFERENCE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*\./[a-zA-Z0-9_.\-/]+\s*$"
)


def workflow_paths(workflow_directory: Path) -> list[Path]:
    """Return every YAML workflow, including nested reusable workflows."""
    return sorted(
        path
        for path in workflow_directory.rglob("*")
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def validation_errors(workflow_directory: Path) -> list[str]:
    """Return actionable errors for every executable workflow action reference."""
    if not workflow_directory.is_dir():
        return [f"{workflow_directory}: workflow directory does not exist"]

    errors: list[str] = []
    build_push_reference_count = 0
    for path in workflow_paths(workflow_directory):
        display_path = path.relative_to(workflow_directory)
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if line.lstrip().startswith("#"):
                continue
            if USES_KEY.search(line) is None:
                continue
            if LOCAL_REFERENCE.fullmatch(line) is not None:
                continue
            match = EXTERNAL_REFERENCE.fullmatch(line)
            if match is None:
                errors.append(
                    f"{display_path}:{line_number}: workflow action uses entries must "
                    "be unquoted standalone local actions or lowercase external "
                    "actions pinned to a 40-character commit SHA with an exact "
                    "semver comment"
                )
                continue

            action = match.group("action")
            if action != BUILD_PUSH_ACTION:
                continue
            build_push_reference_count += 1
            revision = match.group("revision")
            version = match.group("version")
            expected_revision = VERIFIED_BUILD_PUSH_REVISIONS.get(version)
            if expected_revision is None:
                errors.append(
                    f"{display_path}:{line_number}: unrecognized verified version "
                    f"{version!r} for {BUILD_PUSH_ACTION}"
                )
            elif revision != expected_revision:
                errors.append(
                    f"{display_path}:{line_number}: {version} must resolve to "
                    f"{expected_revision}, observed {revision}"
                )

    if build_push_reference_count == 0:
        errors.append(
            f"{workflow_directory}: no canonical {BUILD_PUSH_ACTION} references found"
        )
    return errors


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    default_directory = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "workflow_directory",
        nargs="?",
        type=Path,
        default=default_directory,
        help="workflow directory to verify (defaults to this repository)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    errors = validation_errors(args.workflow_directory)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Workflow action pins verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
