from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_workflow_action_pins import (
    BUILD_PUSH_ACTION,
    VERIFIED_BUILD_PUSH_REVISIONS,
    validation_errors,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VALID_VERSION = "v7.3.0"
VALID_REVISION = VERIFIED_BUILD_PUSH_REVISIONS[VALID_VERSION]


class WorkflowActionPinTests(unittest.TestCase):
    def _validate_line(self, filename: str, line: str) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workflow_directory = Path(temporary_directory)
            (workflow_directory / filename).write_text(
                "name: fixture\nsteps:\n  " + line + "\n",
                encoding="utf-8",
            )
            return validation_errors(workflow_directory)

    def test_repository_workflows_are_clean(self) -> None:
        self.assertEqual(
            validation_errors(REPO_ROOT / ".github" / "workflows"),
            [],
        )

    def test_yaml_suffix_is_discovered_and_valid_pin_passes(self) -> None:
        errors = self._validate_line(
            "fixture.yaml",
            f"- uses : {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}",
        )
        self.assertEqual(errors, [])

    def test_wrong_valid_looking_revision_is_rejected(self) -> None:
        wrong_revision = "53b7df96c91f9d12dcc8a07bcb9ccacbed38856a"
        errors = self._validate_line(
            "fixture.yml",
            f"- uses: {BUILD_PUSH_ACTION}@{wrong_revision} # {VALID_VERSION}",
        )
        self.assertTrue(any(VALID_REVISION in error for error in errors), errors)
        self.assertTrue(any(wrong_revision in error for error in errors), errors)

    def test_moving_tag_and_missing_version_comment_are_rejected(self) -> None:
        lines = (
            f"- uses: {BUILD_PUSH_ACTION}@v7",
            f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION}",
        )
        for line in lines:
            with self.subTest(line=line):
                errors = self._validate_line("fixture.yml", line)
                self.assertTrue(
                    any("workflow action uses entries must" in error for error in errors),
                    errors,
                )

    def test_unknown_version_comment_is_rejected(self) -> None:
        errors = self._validate_line(
            "fixture.yml",
            f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # v7.3.1",
        )
        self.assertTrue(
            any("unrecognized verified version" in error for error in errors),
            errors,
        )

    def test_other_external_action_requires_full_sha(self) -> None:
        canonical = (
            f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        )
        errors = self._validate_line(
            "fixture.yml",
            canonical + "\n  - uses: actions/checkout@v4",
        )
        self.assertTrue(
            any("workflow action uses entries must" in error for error in errors),
            errors,
        )

    def test_repository_local_action_is_allowed(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_line(
            "fixture.yml",
            canonical + "\n  - uses: ./local/action",
        )
        self.assertEqual(errors, [])

    def test_noncanonical_forms_cannot_hide_beside_a_valid_reference(self) -> None:
        canonical = (
            f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        )
        alternate_forms = {
            "quoted value": f'- uses: "{BUILD_PUSH_ACTION}@v7"',
            "quoted key": f'- "uses": {BUILD_PUSH_ACTION}@v7',
            "flow mapping": f"- {{uses: {BUILD_PUSH_ACTION}@v7}}",
            "case variant": (
                f"- uses: Docker/Build-Push-Action@{VALID_REVISION} "
                f"# {VALID_VERSION}"
            ),
            "block scalar": (
                "- uses: >\n"
                f"      {BUILD_PUSH_ACTION}@v7"
            ),
            "alias": (
                "- name: anchored\n"
                "    env:\n"
                f"      ACTION: &build_push {BUILD_PUSH_ACTION}@v7\n"
                "  - uses: *build_push"
            ),
        }
        for name, alternate in alternate_forms.items():
            with self.subTest(name=name):
                errors = self._validate_line(
                    "fixture.yaml",
                    canonical + "\n  " + alternate,
                )
                self.assertTrue(
                    any("unquoted standalone" in error for error in errors),
                    errors,
                )

    def test_commented_reference_is_not_executable_evidence(self) -> None:
        errors = self._validate_line(
            "fixture.yaml",
            f"# - uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}",
        )
        self.assertTrue(
            any("no canonical" in error for error in errors),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
