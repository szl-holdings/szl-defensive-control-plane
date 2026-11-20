from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from defensive_control_plane.integrations import (
    IntegrationManifest,
    IntegrationValidationError,
    MANIFEST_SCHEMA,
    PROVIDER_CONTRACTS,
)


class IntegrationManifestExampleTests(unittest.TestCase):
    def test_example_is_complete_loadable_and_inert(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "docs" / "integrations-manifest.example.json"
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        manifest = IntegrationManifest.from_mapping(payload)
        self.assertEqual(len(manifest.bindings), len(PROVIDER_CONTRACTS))
        self.assertEqual(
            {binding.provider_id for binding in manifest.bindings},
            set(PROVIDER_CONTRACTS),
        )
        self.assertTrue(all(not binding.enabled for binding in manifest.bindings))
        for binding in manifest.bindings:
            for reference in binding.secret_refs.values():
                self.assertTrue(reference.startswith("env://"))
        self.assertEqual(
            set(manifest.approved_private_endpoints),
            {"registered_cmdb", "registered_siem"},
        )
        for forbidden in (
            "ghp_",
            "github_pat_",
            "Bearer ",
            "BEGIN PRIVATE KEY",
            "client_secret",
            "password",
        ):
            self.assertNotIn(forbidden, raw)


    def test_duplicate_manifest_keys_and_nonfinite_constants_are_rejected(self) -> None:
        # No tenant authority can be inferred from last-write-wins JSON objects.
        schema = json.dumps(MANIFEST_SCHEMA)
        cases = (
            f'{{"schema":{schema},"bindings":[],"bindings":[]}}',
            f'{{"schema":{schema},"bindings":[{{"tenant_id":"tenant:alpha","provider_id":"microsoft_defender_xdr","enabled":false,"enabled":true}}]}}',
            f'{{"schema":{schema},"bindings":[],"approved_private_endpoints":{{"registered_cmdb":["https://cmdb.example"],"registered_cmdb":["https://other.example"]}}}}',
            f'{{"schema":{schema},"bindings":[],"untrusted":NaN}}',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            for raw in cases:
                with self.subTest(raw=raw):
                    path.write_text(raw, encoding="utf-8")
                    with self.assertRaises(IntegrationValidationError):
                        IntegrationManifest.from_json_file(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
