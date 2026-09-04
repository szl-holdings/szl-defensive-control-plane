from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import ControlPlane, FakeTicketConnector
from .server import CLUSTER_READONLY_MODE, LOCAL_MODE, serve


DEMO_EVENT_KEY = b"ephemeral-demo-event-root-key-v1"
DEMO_EVIDENCE_KEY = b"ephemeral-demo-evidence-key-v1"
DEMO_REQUESTER_SECRET = "ephemeral-requester-secret-v1"
DEMO_APPROVER_SECRET = "ephemeral-approver-secret-v1"
DEMO_AUDITOR_SECRET = "ephemeral-auditor-secret-v1"


def _event(source_event_id: str = "demo-event-1") -> dict[str, Any]:
    return {
        "schema": "NormalizedSecurityEventV1",
        "tenantId": "tenant:local-demo",
        "source": "fixture:local",
        "sourceEventId": source_event_id,
        "eventType": "iam.privilege_escalation",
        "occurredAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor": {"id": "identity:test-actor"},
        "assetRef": "asset:test-endpoint-01",
        "severity": "critical",
        "attributes": {"role": "test-admin", "fixture": True},
    }


def run_demo() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="defensive-control-plane-demo-") as directory:
        connector = FakeTicketConnector()
        plane = ControlPlane(
            Path(directory) / "control-plane.sqlite3",
            DEMO_EVENT_KEY,
            DEMO_EVIDENCE_KEY,
            connector,
        )
        plane.bootstrap_tenant(
            "tenant:local-demo",
            {
                "operator:alice": {
                    "secret": DEMO_REQUESTER_SECRET,
                    "roles": ["requester", "analyst"],
                },
                "operator:bob": {
                    "secret": DEMO_APPROVER_SECRET,
                    "roles": ["approver"],
                },
                "operator:auditor": {
                    "secret": DEMO_AUDITOR_SECRET,
                    "roles": ["auditor"],
                },
            },
        )
        requester = plane.authenticate_principal(
            "tenant:local-demo", "operator:alice", DEMO_REQUESTER_SECRET
        )
        approver = plane.authenticate_principal(
            "tenant:local-demo", "operator:bob", DEMO_APPROVER_SECRET
        )
        auditor = plane.authenticate_principal(
            "tenant:local-demo", "operator:auditor", DEMO_AUDITOR_SECRET
        )
        event = _event()
        signature = plane.sign_event(event, DEMO_EVENT_KEY)
        ingest = plane.ingest_event(event, signature)
        replay = plane.ingest_event(event, signature)
        dry_run = plane.create_envelope(
            "tenant:local-demo",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            requester,
            {"summary": "Local defensive canary"},
        )
        preview = plane.preview_envelope(dry_run.id)

        live = plane.create_envelope(
            "tenant:local-demo",
            "OPEN_TEST_TICKET",
            ["asset:test-endpoint-01"],
            requester,
            {"summary": "Approved local fake ticket"},
            dry_run=False,
        )
        approval = plane.issue_approval(live.id, approver)
        execution = plane.execute_envelope(live.id, approval.token)
        bundle = plane.export_case(ingest.case_ids[0], auditor)
        restore = plane.run_backup_restore_drill()
        proof_digest = hashlib.sha256(
            json.dumps(
                {
                    "ingest": ingest.disposition.value,
                    "replay": replay.disposition.value,
                    "preview": preview.status,
                    "execute": execution.status,
                    "exportVerified": plane.verify_case_export(bundle),
                    "restore": restore["state"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        plane.record_local_verification("demo-vertical-slice", proof_digest)
        return {
            "scope": "local-fixture-only",
            "eventDisposition": ingest.disposition.value,
            "replayDisposition": replay.disposition.value,
            "alerts": len(ingest.alert_ids),
            "cases": len(ingest.case_ids),
            "dryRunStatus": preview.status,
            "dryRunMutationCalls": preview.result["mutationCalls"],
            "executionStatus": execution.status,
            "connectorCalls": len(connector.calls),
            "caseExportVerified": plane.verify_case_export(bundle),
            "restoreDrill": restore,
            "lanes": plane.lane_statuses(),
            "productionOperational": False,
            "externalConnectors": "IMPLEMENTED_AUTH_REQUIRED",
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evidence-bound local defensive control-plane vertical slice"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run the disposable end-to-end local canary")

    server_parser = subparsers.add_parser("serve", help="serve read-only local status APIs")
    server_parser.add_argument("--db", type=Path, default=Path("control-plane.sqlite3"))
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=8080)
    server_parser.add_argument(
        "--mode",
        choices=(LOCAL_MODE, CLUSTER_READONLY_MODE),
        default=LOCAL_MODE,
    )
    server_parser.add_argument(
        "--trusted-host",
        action="append",
        default=[],
        help="exact Host name allowed in cluster-readonly mode; may be repeated",
    )
    server_parser.add_argument("--request-timeout-seconds", type=float, default=10.0)
    server_parser.add_argument("--max-concurrency", type=int, default=32)

    args = parser.parse_args()
    if args.command == "demo":
        print(json.dumps(run_demo(), indent=2, sort_keys=True))
        return 0
    try:
        event_key = bytes.fromhex(os.environ["DCP_EVENT_ROOT_KEY_HEX"])
        evidence_key = bytes.fromhex(os.environ["DCP_EVIDENCE_KEY_HEX"])
    except KeyError as exc:
        parser.error(f"missing required environment variable: {exc.args[0]}")
    except ValueError:
        parser.error("DCP signing keys must be valid hexadecimal bytes")
    trusted_hosts = list(args.trusted_host)
    trusted_hosts.extend(
        value.strip()
        for value in os.environ.get("DCP_TRUSTED_HOSTS", "").split(",")
        if value.strip()
    )
    plane = ControlPlane(args.db, event_key, evidence_key)
    serve(
        plane,
        host=args.host,
        port=args.port,
        mode=args.mode,
        trusted_hosts=trusted_hosts,
        request_timeout_seconds=args.request_timeout_seconds,
        max_concurrency=args.max_concurrency,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
