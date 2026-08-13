from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from defensive_control_plane import (
    AuthenticatedPrincipal,
    AuthorizationError,
    ConflictError,
    ControlPlane,
    EvidenceState,
    FakeTicketConnector,
    IngestDisposition,
    SQLiteStore,
    ValidationError,
)
from defensive_control_plane.server import create_server


EVENT_KEY = b"behavior-event-signing-key"
EVIDENCE_KEY = b"behavior-evidence-signing-key"
REQUESTER_SECRET = b"requester-secret-0001"
APPROVER_SECRET = b"approver-secret-0002"
ANALYST_SECRET = b"analyst-secret-00003"


class CountingFailureConnector(FakeTicketConnector):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def perform(self, envelope):
        self.attempts += 1
        raise RuntimeError("simulated ambiguous remote failure")


class RemoteSuccessThenTimeoutConnector(FakeTicketConnector):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def perform(self, envelope):
        self.attempts += 1
        super().perform(envelope)
        raise TimeoutError("remote committed but response was lost")


class WrongDeterministicRemoteIdConnector(FakeTicketConnector):
    def perform(self, envelope):
        result = super().perform(envelope)
        result["remoteId"] = "fake-ticket-wrong-but-same-prefix"
        return result


class DefensiveControlPlaneBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = Path(self.temporary.name) / "control-plane.sqlite3"
        self.connector = FakeTicketConnector()
        self.plane = ControlPlane(
            self.db_path, EVENT_KEY, EVIDENCE_KEY, ticket_connector=self.connector
        )
        self.plane.bootstrap_tenant(
            "tenant:test",
            {
                "operator:requester": {
                    "secret": REQUESTER_SECRET,
                    "roles": ["requester", "approver"],
                },
                "operator:approver": {
                    "secret": APPROVER_SECRET,
                    "roles": ["approver"],
                },
                "operator:analyst": {
                    "secret": ANALYST_SECRET,
                    "roles": ["analyst", "auditor"],
                },
            },
        )
        self.requester = self.plane.authenticate_principal(
            "tenant:test", "operator:requester", REQUESTER_SECRET
        )
        self.approver = self.plane.authenticate_principal(
            "tenant:test", "operator:approver", APPROVER_SECRET
        )
        self.analyst = self.plane.authenticate_principal(
            "tenant:test", "operator:analyst", ANALYST_SECRET
        )

    def event(
        self,
        event_type: str = "iam.privilege_escalation",
        source_event_id: str = "event-1",
        *,
        tenant_id: str = "tenant:test",
        asset_ref: str = "asset:test-endpoint-01",
        source: str = "fixture:unit",
        attributes: dict | None = None,
    ) -> dict:
        return {
            "schema": "NormalizedSecurityEventV1",
            "tenantId": tenant_id,
            "source": source,
            "sourceEventId": source_event_id,
            "eventType": event_type,
            "occurredAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor": {"id": "identity:test-user"},
            "assetRef": asset_ref,
            "severity": "high",
            "attributes": dict(attributes or {}),
        }

    def ingest(self, event: dict):
        return self.plane.ingest_event(event, self.plane.sign_event(event, EVENT_KEY))

    def seed_case(self, source_event_id: str = "seed-event"):
        result = self.ingest(self.event(source_event_id=source_event_id))
        self.assertEqual(result.disposition, IngestDisposition.ACCEPTED)
        self.assertEqual(len(result.case_ids), 1)
        return result

    def live_envelope(self, source_event_id: str = "seed-live"):
        self.seed_case(source_event_id)
        return self.plane.create_envelope(
            "tenant:test",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            self.requester,
            {"summary": "Local test ticket"},
            dry_run=False,
            ttl_seconds=300,
        )

    def scalar(self, sql: str, parameters: tuple = ()) -> int:
        with self.plane.store.connect() as connection:
            return int(connection.execute(sql, parameters).fetchone()[0])

    def test_all_eight_detection_categories_create_expected_alerts(self) -> None:
        scenarios = (
            ("auth.brute_force", {}, "DET-AUTH-BRUTE-FORCE"),
            ("auth.impossible_travel", {}, "DET-IMPOSSIBLE-TRAVEL"),
            ("iam.privilege_escalation", {}, "DET-PRIVILEGE-ESCALATION"),
            ("data.exfiltration", {}, "DET-DATA-EXFILTRATION"),
            ("oauth.abuse", {}, "DET-OAUTH-ABUSE"),
            ("security.control_disabled", {}, "DET-CONTROL-DISABLED"),
            ("backup.failed", {}, "DET-BACKUP-FAILURE"),
            ("malware.detected", {}, "DET-ENDPOINT-THREAT"),
            ("process.suspicious", {}, "DET-ENDPOINT-THREAT"),
        )
        for index, (event_type, attributes, expected_rule) in enumerate(scenarios):
            with self.subTest(event_type=event_type):
                result = self.ingest(
                    self.event(event_type, f"detect-{index}", attributes=attributes)
                )
                self.assertTrue(result.accepted)
                self.assertEqual(len(result.alert_ids), 1)
                with self.plane.store.connect() as connection:
                    rule = connection.execute(
                        "SELECT rule_id FROM alerts WHERE id=?", (result.alert_ids[0],)
                    ).fetchone()["rule_id"]
                self.assertEqual(rule, expected_rule)

    def test_threshold_detections_and_unknown_telemetry(self) -> None:
        threshold_events = (
            ("auth.failed", {"attempts": 5}),
            ("data.transfer", {"bytes": 10 * 1024 * 1024}),
            ("auth.success", {"distanceKm": 500, "minutesApart": 60}),
            ("oauth.consent", {"highRiskConsent": True}),
        )
        for index, (event_type, attributes) in enumerate(threshold_events):
            result = self.ingest(
                self.event(event_type, f"threshold-{index}", attributes=attributes)
            )
            self.assertEqual(len(result.alert_ids), 1)

        unknown = self.ingest(self.event("telemetry.unknown", "unknown-event"))
        self.assertTrue(unknown.accepted)
        self.assertEqual(unknown.alert_ids, ())
        self.assertEqual(unknown.case_ids, ())

    def test_invalid_signature_and_malformed_signed_event_are_quarantined(self) -> None:
        event = self.event(source_event_id="bad-signature")
        invalid = self.plane.ingest_event(event, "0" * 64)
        self.assertTrue(invalid.quarantined)
        self.assertEqual(invalid.reason, "INVALID_SIGNATURE")

        malformed = self.event(source_event_id="missing-actor")
        malformed.pop("actor")
        malformed_result = self.plane.ingest_event(
            malformed, self.plane.sign_event(malformed, EVENT_KEY)
        )
        self.assertTrue(malformed_result.quarantined)
        self.assertIn("missing event fields", malformed_result.reason or "")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM events"), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM quarantined_events"), 2)

    def test_event_signature_is_bound_to_tenant_and_source(self) -> None:
        original = self.event(
            "telemetry.unknown", "shared-source-id", source="fixture:source-a"
        )
        original_signature = self.plane.sign_event(original, EVENT_KEY)
        accepted = self.plane.ingest_event(original, original_signature)
        self.assertEqual(accepted.disposition, IngestDisposition.ACCEPTED)

        other_tenant = copy.deepcopy(original)
        other_tenant["tenantId"] = "tenant:other"
        tenant_signature = self.plane.sign_event(other_tenant, EVENT_KEY)
        self.assertNotEqual(original_signature, tenant_signature)
        rejected_tenant = self.plane.ingest_event(other_tenant, original_signature)
        self.assertEqual(rejected_tenant.reason, "INVALID_SIGNATURE")
        self.assertEqual(
            self.plane.ingest_event(other_tenant, tenant_signature).disposition,
            IngestDisposition.ACCEPTED,
        )

        other_source = copy.deepcopy(original)
        other_source["source"] = "fixture:source-b"
        source_signature = self.plane.sign_event(other_source, EVENT_KEY)
        self.assertNotEqual(original_signature, source_signature)
        rejected_source = self.plane.ingest_event(other_source, original_signature)
        self.assertEqual(rejected_source.reason, "INVALID_SIGNATURE")
        self.assertEqual(
            self.plane.ingest_event(other_source, source_signature).disposition,
            IngestDisposition.ACCEPTED,
        )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM events"), 3)

    def test_forged_or_self_asserted_principals_are_rejected(self) -> None:
        self.seed_case("forged-principal-seed")
        forged = AuthenticatedPrincipal(
            tenant_id="tenant:test",
            identity="operator:requester",
            roles=("requester", "approver", "auditor"),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z"),
            assertion="0" * 64,
        )
        with self.assertRaises(AuthorizationError):
            self.plane.create_envelope(
                "tenant:test",
                "OPEN_TEST_TICKET",
                ["asset:test-endpoint-01"],
                forged,
            )
        with self.assertRaises(AuthorizationError):
            self.plane.create_envelope(
                "tenant:test",
                "OPEN_TEST_TICKET",
                ["asset:test-endpoint-01"],
                "operator:requester",
            )

    def test_exact_replay_is_idempotent_and_id_collision_is_quarantined(self) -> None:
        event = self.event(source_event_id="replay-event")
        first = self.ingest(event)
        second = self.ingest(event)
        self.assertEqual(first.event_id, second.event_id)
        self.assertEqual(second.disposition, IngestDisposition.REPLAYED)
        self.assertTrue(second.duplicate)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM events"), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM alerts"), 1)

        collision = copy.deepcopy(event)
        collision["attributes"]["changed"] = True
        collision_result = self.ingest(collision)
        self.assertTrue(collision_result.quarantined)
        self.assertEqual(collision_result.reason, "EVENT_ID_COLLISION")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM events"), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM quarantined_events"), 1)

    def test_oversized_event_fails_before_storage(self) -> None:
        event = self.event(source_event_id="oversized", attributes={"blob": "x" * (300 * 1024)})
        signature = self.plane.sign_event(event, EVENT_KEY)
        with self.assertRaises(ValidationError):
            self.plane.ingest_event(event, signature)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM events"), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM quarantined_events"), 0)

    def test_dry_run_calls_no_connector_and_cannot_be_approved(self) -> None:
        self.seed_case("dry-run-seed")
        envelope = self.plane.create_envelope(
            "tenant:test",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            self.requester,
            {"summary": "Preview only"},
        )
        preview = self.plane.preview_envelope(envelope.id)
        self.assertEqual(preview.status, "DRY_RUN")
        self.assertEqual(preview.result["mutationCalls"], 0)
        self.assertEqual(self.connector.calls, [])
        with self.assertRaises(AuthorizationError):
            self.plane.issue_approval(envelope.id, self.approver)

    def test_envelope_rejects_code_urls_unknown_actions_and_cross_tenant_targets(self) -> None:
        self.seed_case("envelope-reject-seed")
        common = (
            "tenant:test",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            self.requester,
        )
        with self.assertRaises(ValidationError):
            self.plane.create_envelope(
                "tenant:test", "RUN_COMMAND", ["asset:test-endpoint-01"], self.requester
            )
        for parameters in ({"command": "whoami"}, {"url": "https://example.invalid"}):
            with self.subTest(parameters=parameters), self.assertRaises(ValidationError):
                self.plane.create_envelope(*common, parameters)
        with self.assertRaises(ValidationError):
            self.plane.create_envelope(
                "tenant:test", "OPEN_TEST_TICKET", ["https://example.invalid"], self.requester
            )
        with self.assertRaises(AuthorizationError):
            self.plane.create_envelope(
                "tenant:other",
                "OPEN_TEST_TICKET",
                ["asset:test-endpoint-01"],
                self.requester,
            )

    def test_live_action_requires_a_detection_backed_open_case(self) -> None:
        telemetry = self.ingest(
            self.event(
                "telemetry.unknown",
                "inventory-only-telemetry",
                asset_ref="asset:test-inventory-only",
            )
        )
        self.assertTrue(telemetry.accepted)
        self.assertEqual(telemetry.case_ids, ())
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM assets"), 1)

        with self.assertRaises(AuthorizationError):
            self.plane.create_envelope(
                "tenant:test",
                "OPEN_TEST_TICKET",
                ["asset:test-inventory-only"],
                self.requester,
                {"summary": "Must not run without an incident"},
                dry_run=False,
            )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM envelopes"), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM approvals"), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM executions"), 0)

    def test_envelopes_are_immutable_and_revalidated_before_use(self) -> None:
        envelope = self.live_envelope("immutable-envelope-seed")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute(
                    "UPDATE envelopes SET action_type='RUN_COMMAND' WHERE id=?",
                    (envelope.id,),
                )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute("DELETE FROM envelopes WHERE id=?", (envelope.id,))

        # Simulate storage corruption after deliberately removing the local guard;
        # every read path must still recompute and reject the protected hash.
        with self.plane.store.connect() as connection:
            connection.execute("DROP TRIGGER envelope_no_update")
            connection.execute(
                "UPDATE envelopes SET canonical_request_hash=? WHERE id=?",
                ("0" * 64, envelope.id),
            )
        with self.assertRaises(ConflictError):
            self.plane.preview_envelope(envelope.id)

    def test_approval_is_independent_hash_only_bound_and_replay_safe(self) -> None:
        envelope = self.live_envelope("approval-seed")
        with self.assertRaises(AuthorizationError):
            self.plane.issue_approval(envelope.id, self.requester)
        approval = self.plane.issue_approval(envelope.id, self.approver)
        with self.plane.store.connect() as connection:
            row = connection.execute(
                "SELECT token_hash, bound_hash FROM approvals WHERE id=?",
                (approval.approval_id,),
            ).fetchone()
        self.assertNotEqual(row["token_hash"], approval.token)
        self.assertEqual(len(row["token_hash"]), 64)
        self.assertEqual(row["bound_hash"], envelope.canonical_request_hash)

        first = self.plane.execute_envelope(envelope.id, approval.token)
        second = self.plane.execute_envelope(envelope.id, approval.token)
        self.assertEqual(first.status, "SUCCEEDED")
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.execution_id, second.execution_id)
        self.assertEqual(len(self.connector.calls), 1)
        with self.assertRaises(AuthorizationError):
            self.plane.execute_envelope(envelope.id, "wrong-token-that-is-long-enough")

        exported = self.plane.export_case(envelope.case_id or "", self.analyst)
        serialized = json.dumps(exported, sort_keys=True)
        self.assertNotIn(approval.token, serialized)
        self.assertNotIn(row["token_hash"], serialized)

    def test_same_client_idempotency_key_is_isolated_between_tenants(self) -> None:
        other_requester_secret = b"other-requester-secret"
        other_approver_secret = b"other-approver-secret-1"
        self.plane.bootstrap_tenant(
            "tenant:other",
            {
                "operator:other-requester": {
                    "secret": other_requester_secret,
                    "roles": ["requester"],
                },
                "operator:other-approver": {
                    "secret": other_approver_secret,
                    "roles": ["approver"],
                },
            },
        )
        other_requester = self.plane.authenticate_principal(
            "tenant:other", "operator:other-requester", other_requester_secret
        )
        other_approver = self.plane.authenticate_principal(
            "tenant:other", "operator:other-approver", other_approver_secret
        )
        self.seed_case("shared-idem-tenant-a")
        other_ingest = self.ingest(
            self.event(
                source_event_id="shared-idem-tenant-b",
                tenant_id="tenant:other",
                asset_ref="asset:test-other-endpoint",
            )
        )
        self.assertEqual(len(other_ingest.case_ids), 1)

        client_key = "same-client-key"
        first = self.plane.create_envelope(
            "tenant:test",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            self.requester,
            dry_run=False,
            idempotency_key=client_key,
        )
        second = self.plane.create_envelope(
            "tenant:other",
            "OPEN_TEST_TICKET",
            ["asset:test-other-endpoint"],
            other_requester,
            dry_run=False,
            idempotency_key=client_key,
        )
        first_result = self.plane.execute_envelope(
            first.id, self.plane.issue_approval(first.id, self.approver).token
        )
        second_result = self.plane.execute_envelope(
            second.id, self.plane.issue_approval(second.id, other_approver).token
        )

        self.assertEqual(len(self.connector.calls), 2)
        self.assertEqual({call["tenantId"] for call in self.connector.calls}, {
            "tenant:test", "tenant:other"
        })
        self.assertEqual({call["idempotencyKey"] for call in self.connector.calls}, {client_key})
        self.assertEqual(len({call["providerIdempotencyKey"] for call in self.connector.calls}), 2)
        self.assertEqual(len({call["envelopeId"] for call in self.connector.calls}), 2)
        self.assertEqual(len({call["remoteId"] for call in self.connector.calls}), 2)
        for envelope, result in ((first, first_result), (second, second_result)):
            self.assertEqual(result.result["tenantId"], envelope.tenant_id)
            self.assertEqual(result.result["envelopeId"], envelope.id)
            self.assertEqual(result.result["actionType"], envelope.action_type)
            self.assertEqual(result.result["targetRefs"], list(envelope.target_refs))
            self.assertEqual(result.result["idempotencyKey"], client_key)
            self.assertEqual(
                result.result["canonicalRequestHash"], envelope.canonical_request_hash
            )

    def test_approval_cannot_authorize_a_different_envelope(self) -> None:
        first = self.live_envelope("binding-seed")
        second = self.plane.create_envelope(
            "tenant:test",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            self.requester,
            {"summary": "Different envelope"},
            dry_run=False,
        )
        grant = self.plane.issue_approval(first.id, self.approver)
        with self.assertRaises(AuthorizationError):
            self.plane.execute_envelope(second.id, grant.token)

    def test_expired_approval_fails_closed_without_connector_call(self) -> None:
        envelope = self.live_envelope("expiry-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver, ttl_seconds=1)
        time.sleep(1.1)
        with self.assertRaises(AuthorizationError):
            self.plane.execute_envelope(envelope.id, grant.token)
        self.assertEqual(self.connector.calls, [])

    def test_concurrent_execution_invokes_connector_exactly_once(self) -> None:
        envelope = self.live_envelope("concurrency-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        def execute(_index: int):
            return self.plane.execute_envelope(envelope.id, grant.token)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(execute, range(8)))
        self.assertEqual(len(self.connector.calls), 1)
        self.assertEqual(len({result.execution_id for result in results}), 1)
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertTrue(all(result.status == "SUCCEEDED" for result in results))

    def test_waiter_timeout_reports_the_durable_claim_without_inventing_terminal_state(self) -> None:
        envelope = self.live_envelope("durable-claimed-waiter")
        claimed_payload = {
            "state": EvidenceState.QUEUED.value,
            "retry": False,
            "idempotencyKey": envelope.idempotency_key,
        }
        with self.plane.store.connect() as connection:
            connection.execute(
                """
                INSERT INTO executions(
                    id, envelope_id, tenant_id, status, remote_id,
                    result_json, created_at, completed_at
                ) VALUES(?, ?, ?, 'CLAIMED', NULL, ?, ?, NULL)
                """,
                (
                    "manual-claimed-execution",
                    envelope.id,
                    envelope.tenant_id,
                    json.dumps(claimed_payload, sort_keys=True, separators=(",", ":")),
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                ),
            )
        with patch("defensive_control_plane.core.time.sleep", return_value=None):
            observed = self.plane._await_execution(envelope.id)
        self.assertEqual(observed.status, "CLAIMED")
        self.assertEqual(observed.result, claimed_payload)
        self.assertTrue(observed.replayed)
        with self.plane.store.connect() as connection:
            durable_status = connection.execute(
                "SELECT status FROM executions WHERE envelope_id=?", (envelope.id,)
            ).fetchone()["status"]
        self.assertEqual(durable_status, "CLAIMED")

    def test_connector_failure_is_durably_blocked_uncertain_and_never_retried(self) -> None:
        envelope = self.live_envelope("failure-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        connector = CountingFailureConnector()
        self.connector = connector
        self.plane = ControlPlane(
            self.db_path, EVENT_KEY, EVIDENCE_KEY, ticket_connector=connector
        )
        first = self.plane.execute_envelope(envelope.id, grant.token)
        second = self.plane.execute_envelope(envelope.id, grant.token)
        self.assertEqual(first.status, "BLOCKED_UNCERTAIN")
        self.assertEqual(first.result["remoteOutcome"], "UNCERTAIN")
        self.assertFalse(first.result["retry"])
        self.assertTrue(second.replayed)
        self.assertEqual(second.status, "BLOCKED_UNCERTAIN")
        self.assertFalse(second.result["retry"])
        self.assertEqual(first.execution_id, second.execution_id)
        self.assertEqual(connector.attempts, 1)
        with self.plane.store.connect() as connection:
            durable = connection.execute(
                "SELECT status, result_json, completed_at FROM executions WHERE id=?",
                (first.execution_id,),
            ).fetchone()
        self.assertEqual(durable["status"], "BLOCKED_UNCERTAIN")
        self.assertIsNotNone(durable["completed_at"])
        self.assertFalse(json.loads(durable["result_json"])["retry"])

    def test_same_prefix_but_nondeterministic_remote_id_is_blocked_uncertain(self) -> None:
        envelope = self.live_envelope("wrong-remote-id-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        connector = WrongDeterministicRemoteIdConnector()
        self.connector = connector
        self.plane = ControlPlane(
            self.db_path, EVENT_KEY, EVIDENCE_KEY, ticket_connector=connector
        )

        result = self.plane.execute_envelope(envelope.id, grant.token)
        self.assertEqual(result.status, "BLOCKED_UNCERTAIN")
        self.assertIsNone(result.remote_id)
        self.assertEqual(result.result["errorType"], "ConflictError")
        self.assertEqual(result.result["remoteOutcome"], "UNCERTAIN")
        self.assertFalse(result.result["retry"])
        self.assertEqual(len(connector.calls), 1)
        self.assertNotEqual(
            "fake-ticket-wrong-but-same-prefix", connector.calls[0]["remoteId"]
        )

        replay = self.plane.execute_envelope(envelope.id, grant.token)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.status, "BLOCKED_UNCERTAIN")
        self.assertEqual(len(connector.calls), 1)

    def test_uncertain_remote_success_reconciles_by_lookup_without_redispatch(self) -> None:
        envelope = self.live_envelope("reconciliation-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        connector = RemoteSuccessThenTimeoutConnector()
        self.connector = connector
        self.plane = ControlPlane(
            self.db_path, EVENT_KEY, EVIDENCE_KEY, ticket_connector=connector
        )
        uncertain = self.plane.execute_envelope(envelope.id, grant.token)
        self.assertEqual(uncertain.status, "BLOCKED_UNCERTAIN")
        self.assertEqual(connector.attempts, 1)
        self.assertEqual(len(connector.calls), 1)

        reconciled = self.plane.reconcile_execution(envelope.id, self.analyst)
        self.assertEqual(reconciled.status, "SUCCEEDED")
        self.assertTrue(reconciled.replayed)
        self.assertEqual(reconciled.remote_id, connector.calls[0]["remoteId"])
        self.assertEqual(connector.attempts, 1)
        self.assertEqual(len(connector.calls), 1)

        replay = self.plane.reconcile_execution(envelope.id, self.analyst)
        self.assertEqual(replay.execution_id, reconciled.execution_id)
        self.assertEqual(replay.status, "SUCCEEDED")
        self.assertEqual(connector.attempts, 1)
        self.assertEqual(len(connector.calls), 1)

    def test_reconciliation_requires_an_authentic_same_tenant_analyst(self) -> None:
        envelope = self.live_envelope("reconciliation-auth-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        connector = CountingFailureConnector()
        self.connector = connector
        self.plane = ControlPlane(
            self.db_path, EVENT_KEY, EVIDENCE_KEY, ticket_connector=connector
        )
        uncertain = self.plane.execute_envelope(envelope.id, grant.token)
        self.assertEqual(uncertain.status, "BLOCKED_UNCERTAIN")

        forged = AuthenticatedPrincipal(
            tenant_id="tenant:test",
            identity="operator:analyst",
            roles=("analyst",),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z"),
            assertion="0" * 64,
        )
        with self.assertRaises(AuthorizationError):
            self.plane.reconcile_execution(envelope.id, "operator:analyst")
        with self.assertRaises(AuthorizationError):
            self.plane.reconcile_execution(envelope.id, forged)

        other_secret = b"other-reconcile-secret"
        self.plane.bootstrap_tenant(
            "tenant:other",
            {
                "operator:other-analyst": {
                    "secret": other_secret,
                    "roles": ["analyst"],
                }
            },
        )
        other_analyst = self.plane.authenticate_principal(
            "tenant:other", "operator:other-analyst", other_secret
        )
        with self.assertRaises(AuthorizationError):
            self.plane.reconcile_execution(envelope.id, other_analyst)
        with self.assertRaises(TypeError):
            self.plane.reconcile_execution(
                envelope.id, self.analyst, FakeTicketConnector()
            )

        still_uncertain = self.plane.reconcile_execution(envelope.id, self.analyst)
        self.assertEqual(still_uncertain.status, "BLOCKED_UNCERTAIN")
        self.assertTrue(still_uncertain.replayed)
        self.assertEqual(connector.attempts, 1)

    def test_case_state_machine_and_evidence_chain_fail_closed(self) -> None:
        result = self.seed_case("case-state-seed")
        case_id = result.case_ids[0]
        with self.assertRaises(ConflictError):
            self.plane.transition_case(case_id, "CONTAINED", self.analyst)
        for state in (
            "TRIAGED",
            "CONTAINMENT_APPROVED",
            "CONTAINED",
            "RECOVERING",
            "RECOVERED",
            "CLOSED",
        ):
            transition = self.plane.transition_case(case_id, state, self.analyst)
            self.assertEqual(transition["to"], state)
        self.assertTrue(self.plane.verify_evidence_chain(case_id))

    def test_case_transition_and_export_are_tenant_scoped(self) -> None:
        other_secret = b"other-analyst-secret-01"
        self.plane.bootstrap_tenant(
            "tenant:other",
            {
                "operator:other-analyst": {
                    "secret": other_secret,
                    "roles": ["analyst", "auditor"],
                }
            },
        )
        other_analyst = self.plane.authenticate_principal(
            "tenant:other", "operator:other-analyst", other_secret
        )
        our_case = self.seed_case("tenant-scope-ours").case_ids[0]
        other_case = self.ingest(
            self.event(
                source_event_id="tenant-scope-other",
                tenant_id="tenant:other",
                asset_ref="asset:test-other-endpoint",
            )
        ).case_ids[0]

        with self.assertRaises(AuthorizationError):
            self.plane.transition_case(other_case, "TRIAGED", self.analyst)
        with self.assertRaises(AuthorizationError):
            self.plane.transition_case(our_case, "TRIAGED", other_analyst)
        with self.assertRaises(AuthorizationError):
            self.plane.export_case(other_case, self.analyst)
        with self.assertRaises(AuthorizationError):
            self.plane.export_case(our_case, other_analyst)

        transition = self.plane.transition_case(other_case, "TRIAGED", other_analyst)
        self.assertEqual(transition["actor"], "operator:other-analyst")
        self.assertTrue(self.plane.verify_case_export(
            self.plane.export_case(other_case, other_analyst)
        ))

    def test_storage_triggers_reject_cross_tenant_relationships(self) -> None:
        seeded = self.seed_case("tenant-trigger-seed")
        alert_id = seeded.alert_ids[0]
        case_id = seeded.case_ids[0]
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute(
                    "UPDATE alerts SET tenant_id='tenant:other' WHERE id=?",
                    (alert_id,),
                )

        envelope = self.live_envelope("tenant-trigger-live")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        execution = self.plane.execute_envelope(envelope.id, grant.token)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute(
                    "UPDATE approvals SET tenant_id='tenant:other' WHERE id=?",
                    (grant.approval_id,),
                )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute(
                    "UPDATE executions SET tenant_id='tenant:other' WHERE id=?",
                    (execution.execution_id,),
                )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO evidence(
                        id, tenant_id, case_id, kind, payload_json,
                        previous_hash, entry_hash, created_at
                    ) VALUES('cross-tenant-evidence', 'tenant:other', ?, 'invalid',
                             '{}', ?, ?, '2026-08-11T00:00:00Z')
                    """,
                    (case_id, "0" * 64, "0" * 64),
                )

    def test_evidence_rows_reject_update_and_delete(self) -> None:
        case_id = self.seed_case("append-only-seed").case_ids[0]
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute(
                    "UPDATE evidence SET kind='tampered' WHERE case_id=?", (case_id,)
                )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.plane.store.connect() as connection:
                connection.execute("DELETE FROM evidence WHERE case_id=?", (case_id,))
        self.assertTrue(self.plane.verify_evidence_chain(case_id))

    def test_export_rejects_a_directly_corrupted_database_chain(self) -> None:
        case_id = self.seed_case("corrupt-database-export-seed").case_ids[0]
        with self.plane.store.connect() as connection:
            connection.execute("DROP TRIGGER evidence_no_update")
            connection.execute(
                "UPDATE evidence SET payload_json='{}' WHERE case_id=? AND rowid=(SELECT MIN(rowid) FROM evidence WHERE case_id=?)",
                (case_id, case_id),
            )
        self.assertFalse(self.plane.verify_evidence_chain(case_id))
        with self.assertRaises(ConflictError):
            self.plane.export_case(case_id, self.analyst)

    def test_case_export_detects_payload_and_evidence_tampering(self) -> None:
        case_id = self.seed_case("export-seed").case_ids[0]
        bundle = self.plane.export_case(case_id, self.analyst)
        self.assertTrue(self.plane.verify_case_export(bundle))

        payload_tamper = copy.deepcopy(bundle)
        payload_tamper["payload"]["case"]["title"] = "tampered"
        self.assertFalse(self.plane.verify_case_export(payload_tamper))

        evidence_tamper = copy.deepcopy(bundle)
        evidence_tamper["payload"]["evidence"][0]["payload_json"] = "{}"
        evidence_bytes = json.dumps(
            evidence_tamper["payload"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        evidence_tamper["payloadDigest"] = hashlib.sha256(evidence_bytes).hexdigest()
        evidence_tamper["signature"] = hmac.new(
            EVIDENCE_KEY, evidence_bytes, hashlib.sha256
        ).hexdigest()
        self.assertFalse(self.plane.verify_case_export(evidence_tamper))

    def test_invalid_or_empty_evidence_exports_are_rejected(self) -> None:
        case_id = self.seed_case("invalid-export-seed").case_ids[0]
        bundle = self.plane.export_case(case_id, self.analyst)
        self.assertFalse(self.plane.verify_case_export({}))
        self.assertFalse(self.plane.verify_case_export({"schema": "UnknownBundleV9"}))
        self.assertFalse(self.plane.verify_case_export([]))

        empty = copy.deepcopy(bundle)
        empty["payload"]["evidence"] = []
        payload_bytes = json.dumps(
            empty["payload"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        empty["payloadDigest"] = hashlib.sha256(payload_bytes).hexdigest()
        empty["signature"] = hmac.new(
            EVIDENCE_KEY, payload_bytes, hashlib.sha256
        ).hexdigest()
        self.assertFalse(self.plane.verify_case_export(empty))

    def test_nonfinite_corrupt_evidence_makes_readiness_fail_closed(self) -> None:
        case_id = self.seed_case("nonfinite-readiness-seed").case_ids[0]
        with self.plane.store.connect() as connection:
            connection.executescript(
                """
                DROP TRIGGER evidence_no_update;
                CREATE TRIGGER evidence_no_update
                BEFORE UPDATE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'evidence is append-only');
                END;
                """
            )
            connection.execute("DROP TRIGGER evidence_no_update")
            connection.execute(
                "UPDATE evidence SET payload_json='{\"nonfinite\":NaN}' WHERE case_id=? AND rowid=(SELECT MIN(rowid) FROM evidence WHERE case_id=?)",
                (case_id, case_id),
            )
            connection.executescript(
                """
                CREATE TRIGGER evidence_no_update
                BEFORE UPDATE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'evidence is append-only');
                END;
                """
            )
        readiness = self.plane.readyz()
        self.assertEqual(readiness["status"], "not_ready")
        self.assertEqual(readiness["state"], EvidenceState.FAILED_CLOSED.value)
        self.assertEqual(readiness["evidenceChain"], "unavailable_or_invalid")

    def test_pathological_evidence_exceptions_make_readiness_fail_closed(self) -> None:
        self.seed_case("pathological-readiness-seed")
        for error_type in (RecursionError, OverflowError, ValueError):
            with self.subTest(error_type=error_type.__name__):
                with patch(
                    "defensive_control_plane.core._canonical_bytes",
                    side_effect=error_type("pathological evidence fixture"),
                ) as canonical:
                    readiness = self.plane.readyz()
                self.assertTrue(canonical.called)
                self.assertEqual(readiness["status"], "not_ready")
                self.assertEqual(readiness["state"], EvidenceState.FAILED_CLOSED.value)
                self.assertEqual(
                    readiness["evidenceChain"], "unavailable_or_invalid"
                )

    def test_schema_version_mismatches_are_rejected_without_rewrite(self) -> None:
        future_path = Path(self.temporary.name) / "future-schema.sqlite3"
        connection = sqlite3.connect(future_path)
        try:
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema_version', '999')"
            )
            connection.execute("PRAGMA user_version = 999")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(future_path)
        connection = sqlite3.connect(future_path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "999",
            )
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 999)
        finally:
            connection.close()

        mismatch_path = Path(self.temporary.name) / "user-version-mismatch.sqlite3"
        SQLiteStore(mismatch_path)
        connection = sqlite3.connect(mismatch_path)
        try:
            connection.execute("PRAGMA user_version = 999")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(mismatch_path)
        connection = sqlite3.connect(mismatch_path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "2",
            )
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 999)
        finally:
            connection.close()

    def test_malformed_unique_foreign_key_and_trigger_definitions_are_rejected(self) -> None:
        unique_path = Path(self.temporary.name) / "missing-unique.sqlite3"
        SQLiteStore(unique_path)
        connection = sqlite3.connect(unique_path)
        try:
            dependent_triggers = connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type='trigger' AND lower(sql) LIKE '%envelopes%'
                ORDER BY name
                """
            ).fetchall()
            for trigger_name, _trigger_sql in dependent_triggers:
                quoted_name = trigger_name.replace('"', '""')
                connection.execute(f'DROP TRIGGER "{quoted_name}"')
            connection.executescript(
                """
                PRAGMA foreign_keys = OFF;
                CREATE TABLE envelopes_new (
                    id TEXT PRIMARY KEY,
                    schema_name TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    case_id TEXT REFERENCES cases(id),
                    action_type TEXT NOT NULL,
                    target_refs_json TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
                    policy_revision TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    canonical_request_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                DROP TABLE envelopes;
                ALTER TABLE envelopes_new RENAME TO envelopes;
                """
            )
            for _trigger_name, trigger_sql in dependent_triggers:
                connection.execute(trigger_sql)
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(unique_path)

        foreign_key_path = Path(self.temporary.name) / "missing-foreign-key.sqlite3"
        SQLiteStore(foreign_key_path)
        connection = sqlite3.connect(foreign_key_path)
        try:
            connection.executescript(
                """
                PRAGMA foreign_keys = OFF;
                CREATE TABLE alerts_new (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (event_id, rule_id)
                );
                DROP TABLE alerts;
                ALTER TABLE alerts_new RENAME TO alerts;
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(foreign_key_path)

        trigger_path = Path(self.temporary.name) / "malformed-trigger.sqlite3"
        SQLiteStore(trigger_path)
        connection = sqlite3.connect(trigger_path)
        try:
            connection.executescript(
                """
                DROP TRIGGER evidence_no_update;
                CREATE TRIGGER evidence_no_update
                BEFORE UPDATE ON evidence
                BEGIN
                    SELECT 1;
                END;
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(trigger_path)

    def test_extra_unique_foreign_key_and_table_sql_comment_tricks_are_rejected(self) -> None:
        extra_unique_path = Path(self.temporary.name) / "extra-unique.sqlite3"
        SQLiteStore(extra_unique_path)
        connection = sqlite3.connect(extra_unique_path)
        try:
            connection.execute(
                "CREATE UNIQUE INDEX unexpected_case_unique ON cases(tenant_id, asset_ref)"
            )
            self.assertTrue(
                connection.execute(
                    "SELECT 1 FROM pragma_index_list('cases') WHERE name='unexpected_case_unique' AND [unique]=1"
                ).fetchone()
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(extra_unique_path)

        extra_fk_path = Path(self.temporary.name) / "extra-foreign-key.sqlite3"
        SQLiteStore(extra_fk_path)
        connection = sqlite3.connect(extra_fk_path)
        try:
            connection.executescript(
                """
                PRAGMA foreign_keys = OFF;
                CREATE TABLE verification_receipts_new (
                    id TEXT PRIMARY KEY,
                    suite TEXT NOT NULL REFERENCES cases(id),
                    evidence_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                DROP TABLE verification_receipts;
                ALTER TABLE verification_receipts_new RENAME TO verification_receipts;
                """
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM pragma_foreign_key_list('verification_receipts')"
                ).fetchone()[0],
                1,
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(extra_fk_path)

        comment_path = Path(self.temporary.name) / "check-comment-trick.sqlite3"
        SQLiteStore(comment_path)
        connection = sqlite3.connect(comment_path)
        try:
            connection.execute("PRAGMA writable_schema = ON")
            connection.execute(
                """
                UPDATE sqlite_master
                SET sql=replace(
                    sql,
                    'CHECK (dry_run IN (0, 1))',
                    'CHECK (dry_run IN (0, 1) /* altered but semantically similar */)'
                )
                WHERE type='table' AND name='envelopes'
                """
            )
            connection.execute("PRAGMA writable_schema = OFF")
            connection.commit()
            self.assertIn(
                "altered but semantically similar",
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='envelopes'"
                ).fetchone()[0],
            )
        finally:
            connection.close()
        with self.assertRaises(ConflictError):
            SQLiteStore(comment_path)

    def test_disposable_backup_restore_preserves_counts_and_evidence(self) -> None:
        envelope = self.live_envelope("restore-seed")
        grant = self.plane.issue_approval(envelope.id, self.approver)
        self.plane.execute_envelope(envelope.id, grant.token)
        result = self.plane.run_backup_restore_drill()
        self.assertEqual(result["state"], EvidenceState.VERIFIED_LOCAL.value)
        self.assertEqual(result["integrityCheck"], "ok")
        self.assertTrue(result["countsMatch"])
        self.assertTrue(result["contentDigestsMatch"])
        self.assertTrue(result["schemaDigestMatch"])
        self.assertTrue(result["evidenceChainValid"])
        self.assertFalse(result["productionRestore"])
        self.assertRegex(result["backupDigest"], r"^[0-9a-f]{64}$")

    def test_truth_labels_never_promote_external_connectors(self) -> None:
        before = self.plane.lane_statuses()
        self.assertFalse(before["productionOperational"])
        self.assertTrue(
            all(item["state"] == EvidenceState.UNAVAILABLE.value for item in before["connectors"])
        )
        self.assertEqual(
            next(item for item in before["lanes"] if item["name"] == "cybersecurity")["state"],
            EvidenceState.PARTIAL.value,
        )
        digest = "a" * 64
        self.plane.record_local_verification("behavior-suite", digest)
        after = self.plane.lane_statuses()
        self.assertEqual(
            next(item for item in after["lanes"] if item["name"] == "cybersecurity")["state"],
            EvidenceState.PARTIAL.value,
        )
        self.assertEqual(after["selfReportedReceiptCount"], 1)
        self.assertEqual(after["selfReportedReceiptsState"], EvidenceState.PARTIAL.value)
        self.assertTrue(all(not item["evidenceIds"] for item in after["lanes"]))
        self.assertFalse(after["productionOperational"])
        self.assertTrue(
            all(item["state"] == EvidenceState.UNAVAILABLE.value for item in after["connectors"])
        )

    def test_build_revision_environment_never_self_attests_or_promotes(self) -> None:
        with patch.dict(os.environ, {"CONTROL_PLANE_REVISION": "local-claim-only"}):
            info = self.plane.build_info()
        self.assertEqual(info["sourceRevision"], "local-claim-only")
        self.assertEqual(info["state"], EvidenceState.PARTIAL.value)
        self.assertEqual(info["revisionAttestation"], EvidenceState.PARTIAL.value)
        self.assertFalse(info["deploymentVerified"])
        self.assertEqual(info["scope"], "local")

    def test_http_server_refuses_non_loopback_binding(self) -> None:
        with self.assertRaises(ValidationError):
            create_server(self.plane, host="0.0.0.0", port=0)


if __name__ == "__main__":
    unittest.main()
