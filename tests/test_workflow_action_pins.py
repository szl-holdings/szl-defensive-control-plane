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

    def _validate_repository(
        self,
        workflow_body: str,
        manifests: dict[str, str],
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            workflow_directory = repository_root / ".github" / "workflows"
            workflow_directory.mkdir(parents=True)
            (workflow_directory / "fixture.yml").write_text(
                "name: fixture\nsteps:\n  " + workflow_body + "\n",
                encoding="utf-8",
            )
            for relative_path, manifest_body in manifests.items():
                manifest_path = repository_root / relative_path
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                manifest_path.write_text(manifest_body, encoding="utf-8")
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

    def test_repository_local_action_is_allowed_when_manifest_is_clean(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./local/action",
            {
                "local/action/action.yml": (
                    "name: local fixture\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - run: 'true'\n"
                    "      shell: bash\n"
                )
            },
        )
        self.assertEqual(errors, [])

    def test_local_action_manifest_is_required(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./local/missing",
            {},
        )
        self.assertTrue(any("exactly one action.yml" in error for error in errors), errors)

    def test_nested_local_action_moving_tag_is_rejected(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./actions/outer",
            {
                "actions/outer/action.yaml": (
                    "name: outer\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - uses: ./actions/inner\n"
                ),
                "actions/inner/action.yml": (
                    "name: inner\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - uses: actions/checkout@v4\n"
                ),
            },
        )
        self.assertTrue(
            any("workflow action uses entries must" in error for error in errors),
            errors,
        )

    def test_local_action_manifest_must_be_unambiguous(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./actions/ambiguous",
            {
                "actions/ambiguous/action.yml": "name: first\n",
                "actions/ambiguous/action.yaml": "name: second\n",
            },
        )
        self.assertTrue(any("exactly one action.yml" in error for error in errors), errors)

    def test_local_action_path_cannot_escape_repository_root(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./actions/../../outside",
            {},
        )
        self.assertTrue(
            any("escapes the repository root" in error for error in errors),
            errors,
        )

    def test_nested_local_action_with_exact_external_pin_passes(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./actions/outer",
            {
                "actions/outer/action.yml": (
                    "name: outer\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - uses: ./actions/inner\n"
                ),
                "actions/inner/action.yaml": (
                    "name: inner\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - uses: actions/checkout@"
                    "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
                ),
            },
        )
        self.assertEqual(errors, [])

    def test_local_action_reference_cycle_is_rejected(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_repository(
            canonical + "\n  - uses: ./actions/first",
            {
                "actions/first/action.yml": (
                    "name: first\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - uses: ./actions/second\n"
                ),
                "actions/second/action.yml": (
                    "name: second\n"
                    "runs:\n"
                    "  using: composite\n"
                    "  steps:\n"
                    "    - uses: ./actions/first\n"
                ),
            },
        )
        cycle_errors = [
            error for error in errors if "local action reference cycle" in error
        ]
        self.assertEqual(len(cycle_errors), 1, errors)
        self.assertIn(str(Path("actions/first/action.yml")), cycle_errors[0])
        self.assertIn(str(Path("actions/second/action.yml")), cycle_errors[0])

    def test_complex_and_alias_mapping_keys_are_rejected(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        prefix = (
            canonical
            + "\n  - name: anchor\n"
            + "    env:\n"
            + "      ACTION_KEY: &uses_key uses\n  "
        )
        variants = {
            "explicit scalar key": "- ? uses\n    : actions/checkout@v4",
            "explicit alias key": "- ? *uses_key\n    : actions/checkout@v4",
            "implicit alias key": "- *uses_key : actions/checkout@v4",
            "dotted alias key": "- *uses.key : actions/checkout@v4",
            "flow explicit key": "- { ? uses: actions/checkout@v4 }",
            "flow alias key": "- { *uses_key: actions/checkout@v4 }",
            "multi-line quoted key": (
                '- "us\\' + "\n" + '    es": actions/checkout@v4'
            ),
        }
        for name, variant in variants.items():
            with self.subTest(name=name):
                errors = self._validate_line("fixture.yml", prefix + variant)
                self.assertTrue(
                    any(
                        "unsupported YAML mapping forms are forbidden" in error
                        for error in errors
                    ),
                    errors,
                )

        errors = self._validate_line(
            "fixture.yml",
            canonical
            + "\n  - run: |\n"
            + "      echo safe\n"
            + "  - ? uses\n"
            + "    : actions/checkout@v4",
        )
        self.assertTrue(
            any(
                "unsupported YAML mapping forms are forbidden" in error
                for error in errors
            ),
            errors,
        )

    def test_question_mark_values_and_alias_values_are_allowed(self) -> None:
        canonical = f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        errors = self._validate_line(
            "fixture.yml",
            canonical
            + "\n  - name: ordinary values\n"
            + "    env:\n"
            + "      QUERY: https://example.invalid/?key=value\n"
            + "      VALUE: &value safe\n"
            + "      COPY: *value\n"
            + "  - &namespace:value anchored\n"
            + "  - *namespace:value\n"
            + "  - uses:value\n"
            + "  - {name: don't, run: echo ok}\n"
            + "  - {name: don\"t, run: echo ok}\n"
            + "  - {name: quoted, run: \"echo { ? uses: nope }\"}\n"
            + "  - run: echo \"?\"\n"
            + "  - run: 'echo { ? uses: actions/checkout@v4 }'\n"
            + "  - run: 'echo [ *ptr: value ]'\n"
            + "  - run: echo ok # { ? documentation: example }\n"
            + "  - run: |\n"
            + "      echo '{ ? uses: actions/checkout@v4 }'\n"
            + "      echo '[ *ptr: value ]'\n"
            + "      echo 'uses: actions/checkout@v4'",
        )
        self.assertEqual(errors, [])

    def test_noncanonical_forms_cannot_hide_beside_a_valid_reference(self) -> None:
        canonical = (
            f"- uses: {BUILD_PUSH_ACTION}@{VALID_REVISION} # {VALID_VERSION}"
        )
        alternate_forms = {
            "quoted value": f'- uses: "{BUILD_PUSH_ACTION}@v7"',
            "quoted key": f'- "uses": {BUILD_PUSH_ACTION}@v7',
            "unicode-escaped key": r'- "us\u0065s": docker/build-push-action@v7',
            "hex-escaped key": r'- "\x75ses": docker/build-push-action@v7',
            "long-unicode-escaped key": (
                r'- "\U00000075ses": docker/build-push-action@v7'
            ),
            "escaped key in flow mapping": (
                r'- {"us\u0065s": docker/build-push-action@v7}'
            ),
            "flow mapping": f"- {{uses: {BUILD_PUSH_ACTION}@v7}}",
            "flow plain apostrophe before uses": (
                "- {name: don't, uses: actions/checkout@v4}"
            ),
            "flow plain quote before uses": (
                '- {name: don"t, uses: actions/checkout@v4}'
            ),
            "flow spaced plain apostrophe before uses": (
                "- {name: hello 'friend, uses: actions/checkout@v4}"
            ),
            "flow spaced plain quote before uses": (
                '- {name: hello "friend, uses: actions/checkout@v4}'
            ),
            "anchored flow mapping": (
                "- &unpinned {uses: actions/checkout@v4}"
            ),
            "tagged flow mapping": (
                "- !!map {uses: actions/checkout@v4}"
            ),
            "verbatim-tagged flow mapping": (
                "- !<tag:yaml.org,2002:map> {uses: actions/checkout@v4}"
            ),
            "tagged key": "- !!str uses: actions/checkout@v4",
            "verbatim-tagged key": (
                "- !<tag:yaml.org,2002:str> uses: actions/checkout@v4"
            ),
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
