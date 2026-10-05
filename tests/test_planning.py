from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_control_plane import planning


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "defensive-snapshot.example.json"
AS_OF = "2026-10-05T01:00:00Z"


class PlanningTests(unittest.TestCase):
    """Every test denies network, process, credential, database and effector use."""

    def setUp(self) -> None:
        self.snapshot = json.loads(EXAMPLE.read_bytes())
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        targets = (
            "socket.socket", "socket.create_connection", "socket.getaddrinfo",
            "urllib.request.urlopen", "urllib.request.OpenerDirector.open",
            "subprocess.Popen", "os.system", "os.getenv", "sqlite3.connect",
            "defensive_control_plane.core.ControlPlane.__init__",
            "defensive_control_plane.core.FakeTicketConnector.perform",
            "defensive_control_plane.integrations.EnvironmentSecretResolver.__call__",
            "defensive_control_plane.integrations.StdlibJsonTransport.execute",
            "defensive_control_plane.integrations.GovernedIntegrationPlane.observe",
        )
        self.guards = [self.stack.enter_context(patch(target, side_effect=AssertionError("Forbidden planning side effect")))
                       for target in targets]

    def tearDown(self) -> None:
        for guard in self.guards:
            guard.assert_not_called()

    def report(self, snapshot=None, as_of=AS_OF):
        result = planning.assess_snapshot(json.dumps(self.snapshot if snapshot is None else snapshot), as_of=as_of)
        for boundary in [result, *result["plans"]]:
            self.assertIs(boundary["dryRun"], True)
            self.assertEqual(boundary["mutationCalls"], 0)
            self.assertEqual(boundary["externalWrites"], "DISABLED")
            self.assertEqual(boundary["effectors"], [])
            self.assertIs(boundary["productionReady"], False)
            self.assertIs(boundary["deploymentVerified"], False)
        return result

    def record(self, kind):
        return next(record for record in self.snapshot["evidence"] if record["kind"] == kind)

    def capability(self, kind):
        return next(row for row in self.report()["capabilities"] if row["capability"] == kind)

    def row(self, kind):
        return next(row for row in self.report()["evidence"] if row["kind"] == kind)

    def plan(self, name, report=None):
        return next(plan for plan in (report or self.report())["plans"] if plan["id"] == name)

    def test_example_has_separate_seven_assessments_and_three_inert_plans(self):
        report = self.report()
        self.assertEqual([item["capability"] for item in report["capabilities"]], list(planning.CAPABILITIES))
        self.assertEqual(len(report["plans"]), 3)
        for plan in report["plans"]:
            self.assertFalse(plan["executable"])
            self.assertFalse(plan["incidentConfirmed"])
            self.assertEqual(plan["approvalState"], "NOT_REQUESTED")
            self.assertTrue(all(step["mode"] == "human_only" for step in plan["steps"]))
            self.assertTrue(all(set(step) == {"mode", "text"} for step in plan["steps"]))

    def test_replay_is_deterministic_and_input_is_not_mutated(self):
        before = copy.deepcopy(self.snapshot)
        first = self.report()
        self.assertEqual(first, self.report())
        self.assertEqual(self.snapshot, before)
        compact = json.dumps(self.snapshot, sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, planning.assess_snapshot(compact, as_of=AS_OF))

    def test_changed_input_or_assessment_time_changes_checksum(self):
        first = self.report()
        self.record("detection")["facts"]["eventCount"] += 1
        changed = self.report()
        self.assertNotEqual(first["inputSha256"], changed["inputSha256"])
        self.assertNotEqual(first["receipt"], changed["receipt"])
        later = self.report(as_of="2026-10-05T02:00:00Z")
        self.assertEqual(changed["inputSha256"], later["inputSha256"])
        self.assertNotEqual(changed["receipt"], later["receipt"])

    def test_receipt_is_recomputable_unsigned_integrity_only(self):
        report = self.report()
        receipt = report.pop("receipt")
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        self.assertEqual(receipt["reportSha256"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(receipt["purpose"], "integrity_checksum_only")
        self.assertFalse(receipt["signed"])
        self.assertFalse(receipt["independentAttestation"])

    def test_sample_or_declared_pass_never_becomes_operational_pass(self):
        for classification in ("SAMPLE", "DECLARED"):
            self.record("governance")["source"]["classification"] = classification
            row = self.capability("governance")
            self.assertEqual(row["status"], "pass")
            self.assertEqual(row["operationalStatus"], "unknown")
            self.assertEqual(row["verification"], "UNVERIFIED")
            evidence = self.row("governance")
            self.assertFalse(evidence["provenance"]["digestBindingVerified"])

    def test_missing_evidence_is_unknown_not_fail_or_pass(self):
        self.snapshot["evidence"] = []
        for row in self.report()["capabilities"]:
            self.assertEqual(row["status"], "unknown")
            self.assertIsNone(row["coverage"])

    def test_unknown_scope_or_denominator_has_null_coverage(self):
        for complete in (False, None):
            self.snapshot["scope"]["complete"] = complete
            row = self.capability("inventory")
            self.assertEqual(row["status"], "unknown")
            self.assertIsNone(row["coverage"])
        self.snapshot["scope"]["complete"] = True
        self.snapshot["scope"]["assetDenominator"] = None
        self.assertIsNone(self.capability("inventory")["coverage"])

    def test_inventory_coverage_requires_explicit_denominator(self):
        self.snapshot["scope"]["assetDenominator"] = 2
        row = self.capability("inventory")
        self.assertEqual(row["coverage"], 0.5)
        self.assertEqual(row["status"], "fail")

    def test_not_applicable_requires_explicit_complete_zero_subject_scope(self):
        self.snapshot["scope"]["identityIds"] = []
        self.snapshot["scope"]["identityDenominator"] = 0
        self.snapshot["evidence"] = [item for item in self.snapshot["evidence"] if item["kind"] != "identity"]
        self.assertEqual(self.capability("identity")["status"], "not_applicable")
        self.snapshot["scope"]["complete"] = None
        self.assertEqual(self.capability("identity")["status"], "unknown")

    def test_missing_and_false_mfa_are_distinct(self):
        facts = self.record("identity")["facts"]
        facts["active"] = True
        for value in (None, "missing"):
            facts["mfaEnabled"] = value
            if value == "missing":
                del facts["mfaEnabled"]
            self.assertEqual(self.capability("identity")["status"], "unknown")
        facts["mfaEnabled"] = False
        self.assertEqual(self.capability("identity")["status"], "fail")
        facts["mfaEnabled"] = True
        self.assertEqual(self.capability("identity")["status"], "pass")

    def test_fresh_import_does_not_refresh_stale_source(self):
        source = self.record("identity")["source"]
        source["sourceAsOf"] = "2026-10-01T00:00:00Z"
        source["importedAt"] = AS_OF
        self.assertEqual(self.capability("identity")["status"], "unknown")
        self.assertEqual(self.row("identity")["freshness"]["state"], "stale")
        plan = self.plan("credential_misuse")
        self.assertEqual(plan["historicalRelevance"], "supported_by_supplied_facts")
        self.assertEqual(plan["currentRelevance"], "unknown")

    def test_freshness_boundary_is_inclusive_and_missing_is_unknown(self):
        source = self.record("governance")["source"]
        source["sourceAsOf"] = "2026-10-04T01:00:00Z"
        self.assertEqual(self.row("governance")["freshness"]["state"], "fresh")
        source["sourceAsOf"] = "2026-10-04T00:59:59Z"
        self.assertEqual(self.row("governance")["status"], "unknown")
        source["sourceAsOf"] = None
        self.assertEqual(self.row("governance")["freshness"]["state"], "missing")

    def test_partial_or_empty_telemetry_is_unknown(self):
        facts = self.record("detection")["facts"]
        for complete, count in ((False, 10), (None, 10), (True, 0), (True, None)):
            facts.update(telemetryComplete=complete, eventCount=count)
            row = self.capability("detection")
            self.assertEqual(row["status"], "unknown")
            self.assertIsNone(row["coverage"])

    def test_inactive_identity_success_is_suspected_not_confirmed(self):
        plan = self.plan("credential_misuse")
        self.assertEqual(plan["hypothesis"], "suspected_misuse")
        self.assertFalse(plan["incidentConfirmed"])
        self.assertEqual(plan["currentRelevance"], "supported_by_supplied_facts")
        self.record("identity")["facts"]["active"] = None
        self.assertEqual(self.plan("credential_misuse")["historicalRelevance"], "unknown")

    def test_dependency_finding_is_exact_version_bound_and_not_malicious(self):
        row = self.row("dependency")
        self.assertEqual(row["binding"]["findingVersion"], row["binding"]["installedVersion"])
        self.assertEqual(self.plan("dependency_finding")["hypothesis"], "vulnerability_finding")
        self.record("dependency")["facts"]["findingVersion"] = "2.0.0"
        with self.assertRaises(planning.SnapshotError):
            self.report()

    def test_backup_job_without_restore_is_unknown(self):
        self.record("backup")["facts"].pop("restoreSucceeded")
        self.assertEqual(self.capability("backup")["status"], "unknown")
        self.assertIsNone(self.row("backup")["recovery"]["rtoSeconds"])

    def test_failed_restore_is_availability_gap_with_unknown_rto_rpo(self):
        self.assertEqual(self.capability("backup")["status"], "fail")
        recovery = self.row("backup")["recovery"]
        self.assertEqual(recovery, {"rtoSeconds": None, "rtoStatus": "unknown", "rpoSeconds": None, "rpoStatus": "unknown"})
        plan = self.plan("restore_failure")
        self.assertEqual(plan["hypothesis"], "availability_gap")
        self.assertNotIn("T1490", json.dumps(plan))

    def test_successful_restore_missing_reference_keeps_rpo_unknown(self):
        facts = self.record("backup")["facts"]
        facts["restoreSucceeded"] = True
        self.assertEqual(self.row("backup")["recovery"]["rtoSeconds"], 300)
        self.assertIsNone(self.row("backup")["recovery"]["rpoSeconds"])
        self.assertEqual(self.capability("backup")["status"], "unknown")
        facts["recoveryReferenceAsOf"] = "2026-10-05T00:00:00Z"
        self.assertEqual(self.capability("backup")["status"], "pass")
        facts["rtoTargetSeconds"] = 100
        self.assertEqual(self.capability("backup")["status"], "fail")

    def test_contradictory_facts_remain_unresolved_without_latest_wins(self):
        opposite = copy.deepcopy(self.record("identity"))
        opposite["id"] = "evidence:identity-conflict"
        opposite["facts"]["active"] = True
        opposite["source"]["sourceAsOf"] = AS_OF
        self.snapshot["evidence"].append(opposite)
        self.assertEqual(self.capability("identity")["status"], "unknown")
        self.assertTrue(self.capability("identity")["contradictionsUnresolved"])
        self.assertIsNone(self.capability("identity")["coverage"])
        self.assertEqual(self.plan("credential_misuse")["historicalRelevance"], "unresolved")

    def test_no_cross_record_stitching_of_missing_facts(self):
        facts = self.record("identity")["facts"]
        facts.pop("active")
        second = copy.deepcopy(self.record("identity"))
        second["id"] = "evidence:identity-second"
        second["facts"] = {"active": False}
        self.snapshot["evidence"].append(second)
        self.assertEqual(self.plan("credential_misuse")["historicalRelevance"], "unknown")

    def test_future_naive_non_utc_and_invalid_times_reject(self):
        for value in ("2026-10-05T02:00:00Z", "2026-10-05T00:00:00", "2026-10-05T00:00:00+01:00",
                      "2026-02-30T00:00:00Z", "2026-10-05", 5):
            self.record("inventory")["source"]["sourceAsOf"] = value
            with self.subTest(value=value), self.assertRaises(planning.SnapshotError):
                self.report()
        for value in ("2026-10-05T01:00:00", "2026-10-05T01:00:00+00:00"):
            with self.assertRaises(planning.SnapshotError):
                self.report(as_of=value)

    def test_invalid_import_and_recovery_order_reject(self):
        source = self.record("inventory")["source"]
        source["importedAt"] = "2026-10-04T00:00:00Z"
        with self.assertRaises(planning.SnapshotError):
            self.report()
        del source["importedAt"]
        facts = self.record("backup")["facts"]
        facts["recoveryReferenceAsOf"] = "2026-10-04T22:00:00Z"
        with self.assertRaises(planning.SnapshotError):
            self.report()

    def test_duplicate_json_keys_reject_at_all_depths(self):
        for payload in ('{"schema":1,"schema":2}', '{"facts":{"mfaEnabled":true,"mfaEnabled":false}}'):
            with self.assertRaisesRegex(planning.SnapshotError, "Duplicate JSON key"):
                planning.assess_snapshot(payload, as_of=AS_OF)

    def test_nonfinite_floats_and_huge_numbers_reject(self):
        for value in ("NaN", "Infinity", "-Infinity", "1e999", "1.0", "9" * 1000):
            with self.assertRaises(planning.SnapshotError):
                planning.assess_snapshot('{"value":' + value + '}', as_of=AS_OF)

    def test_size_depth_malformed_utf8_and_json_reject(self):
        for value in (b" " * (planning.MAX_BYTES + 1), "[" * 11 + "]" * 11, b"\xff", '{"x":', '{} []', "null", "[]", "\ud800"):
            with self.subTest(length=len(value)), self.assertRaises(planning.SnapshotError):
                planning.assess_snapshot(value, as_of=AS_OF)

    def test_cross_tenant_out_of_scope_and_duplicate_bindings_reject(self):
        original = copy.deepcopy(self.snapshot)
        for field, value in (("tenantId", "tenant:other"), ("subjectId", "asset:other"), ("id", "evidence:inventory")):
            self.snapshot = copy.deepcopy(original)
            self.record("identity")[field] = value
            with self.assertRaises(planning.SnapshotError):
                self.report()
        self.snapshot = original
        self.record("inventory")["facts"]["observedAssetIds"] = ["asset:other"]
        with self.assertRaises(planning.SnapshotError):
            self.report()

    def test_approval_commands_urls_credentials_and_output_fields_reject(self):
        for field, value in (("approved", True), ("dryRun", False), ("approval", {"approvedBy": "owner"}),
                             ("command", "do something"), ("url", "https://example.invalid"),
                             ("credential", "DO_NOT_ECHO"), ("outputPath", "somewhere.json"), ("productionReady", True)):
            for location in (self.snapshot, self.record("identity")["facts"], self.record("identity")["source"]):
                location[field] = value
                with self.assertRaises(planning.SnapshotError) as error:
                    self.report()
                self.assertNotIn("DO_NOT_ECHO", str(error.exception))
                del location[field]

    def test_hostile_text_and_untrusted_verification_labels_reject_redacted(self):
        record = self.record("identity")
        for value in ("https://example.invalid/DO_NOT_ECHO", "$(DO_NOT_ECHO)", "\nDO_NOT_ECHO", "__import__('DO_NOT_ECHO')"):
            record["subjectId"] = value
            with self.assertRaises(planning.SnapshotError) as error:
                self.report()
            self.assertNotIn("DO_NOT_ECHO", str(error.exception))
        record["subjectId"] = "identity:sample-operator"
        record["source"]["classification"] = "VERIFIED"
        with self.assertRaises(planning.SnapshotError):
            self.report()

    def test_strict_types_limits_and_unknown_kinds(self):
        original = copy.deepcopy(self.snapshot)
        mutations = (
            lambda x: x["scope"].update(assetDenominator=True),
            lambda x: x["scope"].update(assetDenominator=0),
            lambda x: x["scope"].update(complete="true"),
            lambda x: x["scope"].update(assetIds=["asset:sample-service"] * 129),
            lambda x: x["evidence"][0].update(kind=[]),
            lambda x: x["evidence"][0].update(kind="execute"),
            lambda x: x["evidence"][1]["facts"].update(mfaEnabled=1),
            lambda x: x["evidence"][2]["facts"].update(eventCount=True),
            lambda x: x["evidence"][2]["facts"].update(eventCount=-1),
            lambda x: x.update(evidence=x["evidence"] * 33),
        )
        for mutation in mutations:
            value = copy.deepcopy(original)
            mutation(value)
            with self.assertRaises(planning.SnapshotError):
                self.report(value)

    def test_json_objects_cannot_bypass_the_parser(self):
        with self.assertRaises(planning.SnapshotError):
            planning.assess_snapshot(self.snapshot, as_of=AS_OF)

    def test_cli_valid_file_stdout_only_and_errors_redacted(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = planning.main(["--snapshot", str(EXAMPLE), "--as-of", AS_OF])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), self.report())
        self.assertEqual(errors.getvalue(), "")
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as folder:
            bad = Path(folder) / "DO_NOT_ECHO.json"
            bad.write_text('{"token":"DO_NOT_ECHO"}', encoding="utf-8")
            for path in (str(bad), str(bad) + "-missing", "https://example.invalid/DO_NOT_ECHO", "\\\\host\\DO_NOT_ECHO"):
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(planning.main(["--snapshot", path, "--as-of", AS_OF]), 2)
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("DO_NOT_ECHO", errors.getvalue())

    def test_cli_unknown_flags_are_redacted_and_cannot_execute(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as error:
            planning.main(["--snapshot", str(EXAMPLE), "--as-of", AS_OF, "--execute", "DO_NOT_ECHO"])
        self.assertEqual(error.exception.code, 2)
        self.assertNotIn("DO_NOT_ECHO", errors.getvalue())

    def test_cli_rejects_large_regular_file_and_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as folder:
            path = Path(folder) / "oversized.json"
            path.write_bytes(b" " * (planning.MAX_BYTES + 1))
            for candidate in (path, Path(folder)):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(planning.main(["--snapshot", str(candidate), "--as-of", AS_OF]), 2)

    def test_standalone_file_has_no_repository_or_execution_dependencies(self):
        module = ROOT / "defensive_control_plane" / "planning.py"
        source = module.read_text(encoding="utf-8")
        allowed = {"__future__", "argparse", "hashlib", "json", "re", "stat", "sys", "datetime", "pathlib", "typing"}
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name in allowed for alias in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                self.assertIn(node.module, allowed)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"eval", "exec", "compile", "__import__"})
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as folder:
            portable = Path(folder) / "planning.py"
            portable.write_text(source, encoding="utf-8")
            namespace = runpy.run_path(str(portable))
            result = namespace["assess_snapshot"](EXAMPLE.read_bytes(), as_of=AS_OF)
        self.assertEqual(result, self.report())


if __name__ == "__main__":
    unittest.main()
