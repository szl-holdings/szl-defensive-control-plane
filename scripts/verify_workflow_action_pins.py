#!/usr/bin/env python3
"""Fail closed when workflow action uses entries are not immutably pinned."""

from __future__ import annotations

import argparse
import ast
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
QUOTED_YAML_KEY = re.compile(
    r"""(?P<double>"(?:\\.|[^"\\])*")\s*:|(?P<single>'(?:''|[^'])*')\s*:"""
)
EXTERNAL_REFERENCE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*"
    r"(?P<action>[a-z0-9_.-]+/[a-z0-9_.-]+(?:/[a-z0-9_.\-/]+)?)@"
    r"(?P<revision>[0-9a-f]{40})\s+#\s+"
    r"(?P<version>v\d+\.\d+\.\d+)\s*$"
)
LOCAL_REFERENCE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*(?P<path>\./[a-zA-Z0-9_.\-/]+)\s*$"
)


def workflow_paths(workflow_directory: Path) -> list[Path]:
    """Return every YAML workflow, including nested reusable workflows."""
    return sorted(
        path
        for path in workflow_directory.rglob("*")
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def _line_has_uses_key(line: str) -> bool:
    """Detect plain and YAML-decoded quoted representations of the uses key."""
    if USES_KEY.search(line) is not None:
        return True

    for match in QUOTED_YAML_KEY.finditer(line):
        token = match.group("double") or match.group("single")
        if token.startswith("'"):
            decoded = token[1:-1].replace("''", "'")
        else:
            try:
                decoded = ast.literal_eval(token)
            except (SyntaxError, ValueError):
                continue
        if isinstance(decoded, str) and decoded.casefold() == "uses":
            return True
    return False


def _repository_root(workflow_directory: Path) -> Path:
    if (
        workflow_directory.name == "workflows"
        and workflow_directory.parent.name == ".github"
    ):
        return workflow_directory.parents[1].resolve()
    return workflow_directory.resolve()


def _display_path(path: Path, repository_root: Path) -> Path:
    try:
        return path.relative_to(repository_root)
    except ValueError:
        return path


def _local_action_manifest(
    reference: str,
    source_path: Path,
    line_number: int,
    repository_root: Path,
    errors: list[str],
) -> Path | None:
    display_path = _display_path(source_path, repository_root)
    action_directory = (repository_root / reference[2:]).resolve()
    try:
        action_directory.relative_to(repository_root)
    except ValueError:
        errors.append(
            f"{display_path}:{line_number}: local action {reference!r} escapes "
            "the repository root"
        )
        return None

    manifests = [
        action_directory / name
        for name in ("action.yml", "action.yaml")
        if (action_directory / name).is_file()
    ]
    if len(manifests) != 1:
        errors.append(
            f"{display_path}:{line_number}: local action {reference!r} must "
            "resolve to exactly one action.yml or action.yaml manifest"
        )
        return None
    return manifests[0]


def validation_errors(workflow_directory: Path) -> list[str]:
    """Return actionable errors for workflows and referenced local actions."""
    if not workflow_directory.is_dir():
        return [f"{workflow_directory}: workflow directory does not exist"]

    errors: list[str] = []
    build_push_reference_count = 0
    repository_root = _repository_root(workflow_directory)
    pending_paths = workflow_paths(workflow_directory)
    scanned_paths: set[Path] = set()

    while pending_paths:
        path = pending_paths.pop(0).resolve()
        if path in scanned_paths:
            continue
        scanned_paths.add(path)
        display_path = _display_path(path, repository_root)

        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if line.lstrip().startswith("#"):
                continue
            if not _line_has_uses_key(line):
                continue

            local_match = LOCAL_REFERENCE.fullmatch(line)
            if local_match is not None:
                manifest = _local_action_manifest(
                    local_match.group("path"),
                    path,
                    line_number,
                    repository_root,
                    errors,
                )
                if manifest is not None and manifest not in scanned_paths:
                    pending_paths.append(manifest)
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
