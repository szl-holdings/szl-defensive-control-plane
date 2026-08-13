from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from defensive_control_plane import (
    AuthenticatedPrincipal,
    AuthorizationError,
    ConflictError,
    ControlPlane,
    DefensiveControlEnvelopeV1,
    EvidenceState,
    FakeTicketConnector,
    IngestDisposition,
    SQLiteStore,
    ValidationError,
)
from defensive_control_plane.core import PACKAGE_VERSION


class PublicContractTests(unittest.TestCase):
    """Lock the deliberately small, documented public API."""

    def test_package_version_matches_pyproject(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with (root / "pyproject.toml").open("rb") as handle:
            metadata = tomllib.load(handle)
        self.assertEqual(metadata["project"]["version"], PACKAGE_VERSION)

    def test_expected_types_are_public(self) -> None:
        for value in (
            ControlPlane,
            AuthenticatedPrincipal,
            SQLiteStore,
            EvidenceState,
            IngestDisposition,
            DefensiveControlEnvelopeV1,
            FakeTicketConnector,
            ValidationError,
            ConflictError,
        ):
            self.assertIsNotNone(value)

    def test_evidence_truth_vocabulary_is_explicit(self) -> None:
        values = {str(member.value) for member in EvidenceState}
        self.assertTrue(
            {
                "VERIFIED_LOCAL",
                "VERIFIED_CONNECTOR",
                "VERIFIED_RUNTIME",
                "MODELED",
                "UNAVAILABLE",
                "DIVERGENT",
                "FAILED_CLOSED",
            }.issubset(values)
        )

    def test_control_plane_constructor_contract(self) -> None:
        parameters = inspect.signature(ControlPlane).parameters
        self.assertEqual(
            list(parameters),
            [
                "db_path",
                "event_signing_key",
                "evidence_signing_key",
                "ticket_connector",
            ],
        )
        self.assertIsNone(parameters["evidence_signing_key"].default)
        self.assertIsNone(parameters["ticket_connector"].default)

    def test_control_plane_operation_contracts(self) -> None:
        self.assertEqual(
            list(inspect.signature(ControlPlane.derive_event_source_key).parameters),
            ["root_key", "tenant_id", "source"],
        )
        self.assertEqual(
            list(inspect.signature(ControlPlane.sign_event).parameters),
            ["event", "key"],
        )
        expected = {
            "bootstrap_tenant": ["self", "tenant_id", "principals"],
            "authenticate_principal": [
                "self",
                "tenant_id",
                "identity",
                "secret",
                "ttl_seconds",
            ],
            "ingest_event": ["self", "event", "signature"],
            "create_envelope": [
                "self",
                "tenant_id",
                "action_type",
                "target_refs",
                "requested_by",
                "parameters",
                "dry_run",
                "ttl_seconds",
                "idempotency_key",
            ],
            "preview_envelope": ["self", "envelope_id"],
            "issue_approval": ["self", "envelope_id", "approver", "ttl_seconds"],
            "execute_envelope": [
                "self",
                "envelope_id",
                "approval_token",
            ],
            "reconcile_execution": ["self", "envelope_id", "principal"],
            "transition_case": ["self", "case_id", "new_state", "actor"],
            "export_case": ["self", "case_id", "principal"],
            "verify_case_export": ["self", "bundle"],
            "run_backup_restore_drill": ["self"],
            "build_info": ["self"],
            "livez": ["self"],
            "readyz": ["self"],
            "lane_statuses": ["self"],
        }
        for method_name, names in expected.items():
            with self.subTest(method=method_name):
                method = getattr(ControlPlane, method_name)
                self.assertEqual(list(inspect.signature(method).parameters), names)

    def test_sign_event_is_canonical_lowercase_hmac_sha256(self) -> None:
        event = {
            "tenantId": "tenant:test",
            "source": "fixture:unit",
            "unicode": "café",
            "nested": {"z": 2, "a": 1},
        }
        reordered = {
            "nested": {"a": 1, "z": 2},
            "unicode": "café",
            "source": "fixture:unit",
            "tenantId": "tenant:test",
        }
        key = b"canonical-test-key-strong"
        canonical = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        source_key = ControlPlane.derive_event_source_key(
            key, event["tenantId"], event["source"]
        )
        expected = hmac.new(source_key, canonical, hashlib.sha256).hexdigest()
        actual = ControlPlane.sign_event(event, key)
        self.assertEqual(actual, expected)
        self.assertEqual(ControlPlane.sign_event(reordered, key), actual)
        self.assertRegex(actual, r"^[0-9a-f]{64}$")

    def test_sign_event_rejects_non_finite_json_numbers(self) -> None:
        with self.assertRaises((TypeError, ValueError, ValidationError)):
            ControlPlane.sign_event({"value": float("nan")}, b"key")

    def test_event_and_evidence_keys_must_be_distinct_and_strong(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "invalid-keys.sqlite3"
            with self.assertRaises(ValidationError):
                ControlPlane(db_path, b"short", b"different-but-long-key")
            with self.assertRaises(ValidationError):
                ControlPlane(db_path, b"event-key-at-least-16", None)
            shared = b"same-key-material-123"
            with self.assertRaises(ValidationError):
                ControlPlane(db_path, shared, shared)

    def test_self_asserted_principal_type_cannot_replace_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plane = ControlPlane(
                Path(directory) / "identity.sqlite3",
                b"event-test-key-strong",
                b"evidence-test-key-strong",
            )
            plane.bootstrap_tenant(
                "tenant:test",
                {
                    "operator:requester": {
                        "secret": b"requester-secret-0001",
                        "roles": ["requester"],
                    }
                },
            )
            with self.assertRaises(AuthorizationError):
                plane.authenticate_principal(
                    "tenant:test", "operator:requester", b"wrong-secret-material"
                )
            forged = AuthenticatedPrincipal(
                tenant_id="tenant:test",
                identity="operator:requester",
                roles=("requester",),
                expires_at="2999-01-01T00:00:00Z",
                assertion="0" * 64,
            )
            with self.assertRaises(AuthorizationError):
                plane.create_envelope(
                    "tenant:test",
                    "OPEN_TEST_TICKET",
                    ["asset:test-endpoint-01"],
                    forged,
                )

    def test_fresh_local_instances_need_no_network_or_external_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "control-plane.sqlite3"
            connector = FakeTicketConnector()
            plane = ControlPlane(
                db_path,
                b"event-test-key-strong",
                b"evidence-test-key-strong",
                ticket_connector=connector,
            )
            self.assertTrue(db_path.exists())
            self.assertEqual(connector.calls, [])
            self.assertIsInstance(plane.build_info(), dict)
            self.assertIsInstance(plane.livez(), dict)
            self.assertIsInstance(plane.readyz(), dict)
            self.assertIsInstance(plane.lane_statuses(), (dict, list))


if __name__ == "__main__":
    unittest.main()
