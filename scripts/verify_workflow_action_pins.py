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
    # Official lightweight tag verified from docker/build-push-action on 2026-10-01.
    "v7.4.0": "c3c9e263c25d99ce0380d002d59b67737d91b0dc",
}
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})
BLOCK_SCALAR_INDICATOR = re.compile(
    r"[|>](?:(?P<indent_first>[1-9])(?P<chomp_after>[+-])?"
    r"|(?P<chomp_first>[+-])(?P<indent_after>[1-9])?)?"
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


def _quoted_scalar_end(text: str, position: int) -> tuple[int, bool]:
    quote = text[position]
    position += 1
    while position < len(text):
        character = text[position]
        if quote == "'" and character == "'":
            if position + 1 < len(text) and text[position + 1] == "'":
                position += 2
                continue
            return position + 1, True
        if quote == '"' and character == "\\":
            position += 2
            continue
        if character == quote:
            return position + 1, True
        position += 1
    return len(text), False


YamlToken = tuple[str, str, int, int]
PROPERTY_TOKEN_KINDS = frozenset({"anchor", "tag"})
FLOW_PUNCTUATION = frozenset("[]{},")


def _is_mapping_colon(text: str, position: int) -> bool:
    if text[position] != ":":
        return False
    next_position = position + 1
    return (
        next_position == len(text)
        or text[next_position].isspace()
        or text[next_position] in FLOW_PUNCTUATION
    )


def _yaml_tokens(text: str, position: int) -> list[YamlToken]:
    """Lex one physical YAML line at node boundaries, without parsing values."""
    tokens: list[YamlToken] = []
    initial_position = position
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text) or text[position] == "#":
            break

        start = position
        character = text[position]
        if character in FLOW_PUNCTUATION or character == ":":
            tokens.append((character, character, start, start + 1))
            position += 1
            continue
        previous = position - 1
        while previous >= initial_position and text[previous].isspace():
            previous -= 1
        quote_starts_node = (
            not tokens
            or previous < initial_position
            or text[previous] in "[{,:"
            or tokens[-1][0] in PROPERTY_TOKEN_KINDS
        )
        if character in {"'", '"'} and quote_starts_node:
            position, closed = _quoted_scalar_end(text, position)
            kind = "quoted" if closed else "unterminated-quoted"
            tokens.append((kind, text[start:position], start, position))
            continue
        if character == "?" and (
            position + 1 == len(text)
            or text[position + 1].isspace()
            or text[position + 1] in "[{"
        ):
            tokens.append(("explicit", character, start, start + 1))
            position += 1
            continue

        if character in "*&!":
            kind = {"*": "alias", "&": "anchor", "!": "tag"}[character]
            if (
                character == "!"
                and position + 1 < len(text)
                and text[position + 1] == "<"
            ):
                position += 2
                while position < len(text) and text[position] != ">":
                    position += 1
                if position < len(text):
                    position += 1
                tokens.append((kind, text[start:position], start, position))
                continue
            position += 1
            while position < len(text):
                if text[position].isspace() or text[position] in FLOW_PUNCTUATION:
                    break
                if _is_mapping_colon(text, position):
                    break
                position += 1
            tokens.append((kind, text[start:position], start, position))
            continue

        while position < len(text):
            if text[position].isspace() or text[position] in FLOW_PUNCTUATION:
                break
            if _is_mapping_colon(text, position):
                break
            position += 1
        tokens.append(("plain", text[start:position], start, position))
    return tokens


def _skip_properties(tokens: list[YamlToken], index: int) -> int:
    while index < len(tokens) and tokens[index][0] in PROPERTY_TOKEN_KINDS:
        index += 1
    return index


def _decoded_key(token: YamlToken) -> str | None:
    kind, raw, _, _ = token
    if kind == "plain":
        return raw
    if kind != "quoted":
        return None
    if raw.startswith("'"):
        return raw[1:-1].replace("''", "'")
    try:
        decoded = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return None
    return decoded if isinstance(decoded, str) else None


def _has_mapping_colon(tokens: list[YamlToken], index: int) -> bool:
    return index + 1 < len(tokens) and tokens[index + 1][0] == ":"


def _key_facts(tokens: list[YamlToken], index: int) -> tuple[bool, bool]:
    if index >= len(tokens):
        return False, False
    kind = tokens[index][0]
    if kind == "unterminated-quoted":
        return False, True
    if kind == "explicit":
        return False, True
    if kind == "alias" and _has_mapping_colon(tokens, index):
        return False, True
    if kind in "]}" and _has_mapping_colon(tokens, index):
        return False, True
    if kind not in {"plain", "quoted"} or not _has_mapping_colon(tokens, index):
        return False, False
    decoded = _decoded_key(tokens[index])
    if decoded is None:
        return False, True
    return decoded.casefold() == "uses", False


def _flow_candidate_facts(
    text: str,
    tokens: list[YamlToken],
    start: int,
    end: int,
) -> tuple[bool, bool]:
    """Classify one flow mapping key while preserving plain-scalar spaces."""
    candidate = tokens[start:end]
    index = _skip_properties(candidate, 0)
    scalar = candidate[index:]
    if not scalar:
        return False, False
    if any(token[0] in {"explicit", "alias", "unterminated-quoted"} for token in scalar):
        return False, True
    if len(scalar) == 1:
        decoded = _decoded_key(scalar[0])
        if decoded is None:
            return False, True
        return decoded.casefold() == "uses", False
    if all(token[0] == "plain" for token in scalar):
        decoded = text[scalar[0][2] : scalar[-1][3]].strip()
        return decoded.casefold() == "uses", False
    return False, True


def _flow_key_facts(
    text: str,
    tokens: list[YamlToken],
    start: int,
) -> tuple[bool, bool]:
    """Classify keys in nested flow collections without splitting plain keys."""
    has_uses = False
    has_unsupported = False
    contexts: list[dict[str, int | str | bool]] = []

    for index in range(start, len(tokens)):
        kind = tokens[index][0]
        if kind in "[{":
            contexts.append(
                {
                    "kind": kind,
                    "entry_start": index + 1,
                    "expecting_key": kind == "{",
                }
            )
            continue
        if kind in "]}":
            if contexts:
                contexts.pop()
            continue
        if not contexts:
            continue

        context = contexts[-1]
        if kind == ",":
            context["entry_start"] = index + 1
            context["expecting_key"] = context["kind"] == "{"
            continue
        if kind == ":":
            uses, unsupported = _flow_candidate_facts(
                text,
                tokens,
                int(context["entry_start"]),
                index,
            )
            has_uses = has_uses or uses
            has_unsupported = has_unsupported or unsupported
            context["entry_start"] = index + 1
            context["expecting_key"] = False
            continue
        if (
            kind == "unterminated-quoted"
            and context["kind"] == "{"
            and context["expecting_key"]
        ):
            has_unsupported = True

    return has_uses, has_unsupported


def _line_tokens(line: str) -> tuple[int, int, list[YamlToken]]:
    leading = len(line) - len(line.lstrip(" "))
    position = leading
    if position == 0 and line.startswith("\ufeff"):
        position = 1
    if (
        leading == 0
        and line.startswith("---", position)
        and (
            position + 3 == len(line)
            or line[position + 3].isspace()
        )
    ):
        position += 3
        while position < len(line) and line[position].isspace():
            position += 1
    if position < len(line) and line[position] == "-" and (
        position + 1 == len(line) or line[position + 1].isspace()
    ):
        position += 1
        while position < len(line) and line[position].isspace():
            position += 1
    return leading, position, _yaml_tokens(line, position)


def _line_key_facts(line: str) -> tuple[bool, bool]:
    """Classify structural mapping keys without scanning scalar values."""
    _, _, tokens = _line_tokens(line)
    key_index = _skip_properties(tokens, 0)
    if key_index >= len(tokens):
        return False, False
    if tokens[key_index][0] in "[{":
        return _flow_key_facts(line, tokens, key_index)

    has_uses, has_unsupported = _key_facts(tokens, key_index)
    if not _has_mapping_colon(tokens, key_index):
        return has_uses, has_unsupported
    value_index = _skip_properties(tokens, key_index + 2)
    if value_index < len(tokens) and tokens[value_index][0] in "[{":
        flow_uses, flow_unsupported = _flow_key_facts(
            line,
            tokens,
            value_index,
        )
        has_uses = has_uses or flow_uses
        has_unsupported = has_unsupported or flow_unsupported
    return has_uses, has_unsupported


def _multiline_value_start(line: str) -> int | None:
    """Return the opening quote for a continued value, never for a key."""
    _, _, tokens = _line_tokens(line)
    has_uses, has_unsupported = _line_key_facts(line)
    if has_uses or has_unsupported:
        return None
    for kind, _, start, _ in tokens:
        if kind == "unterminated-quoted":
            return start
    return None


def _block_scalar_header(line: str) -> tuple[int, int | None] | None:
    """Return base indentation and optional explicit content indentation."""
    leading, key_column, tokens = _line_tokens(line)
    index = _skip_properties(tokens, 0)
    base_indent = leading
    if index >= len(tokens):
        return None
    match = BLOCK_SCALAR_INDICATOR.fullmatch(tokens[index][1])
    if match is None:
        if not _has_mapping_colon(tokens, index):
            return None
        base_indent = key_column
        index = _skip_properties(tokens, index + 2)
        if index >= len(tokens):
            return None
        match = BLOCK_SCALAR_INDICATOR.fullmatch(tokens[index][1])
    if match is None:
        return None
    indent_text = match.group("indent_first") or match.group("indent_after")
    return base_indent, int(indent_text) if indent_text is not None else None


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
    manifest = manifests[0].resolve()
    try:
        manifest.relative_to(repository_root)
    except ValueError:
        errors.append(
            f"{display_path}:{line_number}: local action {reference!r} resolves "
            "to a manifest outside the repository root"
        )
        return None
    return manifest


def _local_action_cycles(
    graph: dict[Path, set[Path]],
) -> list[tuple[Path, ...]]:
    """Return deterministic directed cycles in the local-action graph."""
    visited: set[Path] = set()
    visiting: set[Path] = set()
    stack: list[Path] = []
    stack_positions: dict[Path, int] = {}
    cycles: list[tuple[Path, ...]] = []

    def visit(node: Path) -> None:
        visiting.add(node)
        stack_positions[node] = len(stack)
        stack.append(node)
        for target in sorted(graph.get(node, set()), key=lambda path: path.as_posix()):
            if target in visiting:
                cycles.append(tuple(stack[stack_positions[target] :] + [target]))
            elif target not in visited:
                visit(target)
        stack.pop()
        stack_positions.pop(node)
        visiting.remove(node)
        visited.add(node)

    nodes = set(graph)
    for targets in graph.values():
        nodes.update(targets)
    for node in sorted(nodes, key=lambda path: path.as_posix()):
        if node not in visited:
            visit(node)
    return cycles


def validation_errors(workflow_directory: Path) -> list[str]:
    """Return actionable errors for workflows and referenced local actions."""
    if not workflow_directory.is_dir():
        return [f"{workflow_directory}: workflow directory does not exist"]

    errors: list[str] = []
    build_push_reference_count = 0
    repository_root = _repository_root(workflow_directory)
    pending_paths = workflow_paths(workflow_directory)
    scanned_paths: set[Path] = set()
    local_action_graph: dict[Path, set[Path]] = {}

    while pending_paths:
        path = pending_paths.pop(0).resolve()
        if path in scanned_paths:
            continue
        scanned_paths.add(path)
        display_path = _display_path(path, repository_root)
        block_scalar_base: int | None = None
        block_scalar_content: int | None = None
        quoted_value: str | None = None
        quoted_value_line = 0
        quoted_value_start = 0

        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if quoted_value is not None:
                quoted_value += "\n" + line
                _, closed = _quoted_scalar_end(
                    quoted_value,
                    quoted_value_start,
                )
                if not closed:
                    continue
                line = quoted_value
                line_number = quoted_value_line
                quoted_value = None

            if block_scalar_base is not None:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                indentation = len(line) - len(line.lstrip(" "))
                if block_scalar_content is None:
                    if indentation > block_scalar_base:
                        block_scalar_content = indentation
                        continue
                elif indentation >= block_scalar_content:
                    continue
                block_scalar_base = None
                block_scalar_content = None

            if line.lstrip().startswith("#"):
                continue
            block_header = _block_scalar_header(line)
            if block_header is not None:
                block_scalar_base, explicit_indent = block_header
                if explicit_indent is not None:
                    block_scalar_content = block_scalar_base + explicit_indent

            has_uses_key, has_unsupported_key = _line_key_facts(line)
            if has_unsupported_key:
                errors.append(
                    f"{display_path}:{line_number}: unsupported YAML mapping "
                    "forms are forbidden (explicit, complex, alias-derived, "
                    "or multi-line quoted)"
                )
                continue
            if not has_uses_key:
                continued_value = _multiline_value_start(line)
                if continued_value is not None:
                    quoted_value = line
                    quoted_value_line = line_number
                    quoted_value_start = continued_value
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
                if manifest is not None:
                    local_action_graph.setdefault(path, set()).add(manifest)
                    if manifest not in scanned_paths and manifest not in pending_paths:
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

    for cycle in _local_action_cycles(local_action_graph):
        display_cycle = " -> ".join(
            str(_display_path(node, repository_root)) for node in cycle
        )
        errors.append(
            f"local action reference cycle detected: {display_cycle}"
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
