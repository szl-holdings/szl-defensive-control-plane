from __future__ import annotations

import contextlib
import http.client
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from defensive_control_plane.integration_cli import main
from defensive_control_plane.integration_status_server import (
    create_integration_status_server,
)
from defensive_control_plane.integrations import GovernedIntegrationPlane, IntegrationManifest


class FailingTransport:
    def execute(self, _plan):  # pragma: no cover - any call is a test failure
        raise AssertionError("HTTP status surface attempted provider egress")


def disabled_manifest() -> dict:
    return {
        "schema": "szl.defensive-integrations/v1",
        "approved_private_endpoints": {},
        "bindings": [
            {
                "tenant_id": "tenant:test",
                "provider_id": "microsoft_defender_xdr",
                "enabled": False,
                "resources": {},
                "secret_refs": {"token": "env://TEST_GRAPH_TOKEN"},
            }
        ],
    }


def auth_required_manifest() -> dict:
    value = disabled_manifest()
    value["bindings"][0]["enabled"] = True
    return value


class IntegrationSurfaceTests(unittest.TestCase):
    def _manifest_file(self, directory: str, value: dict) -> Path:
        path = Path(directory) / "integrations.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_cli_validate_and_status_require_no_provider_egress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest_file(directory, auth_required_manifest())
            validate_output = io.StringIO()
            with contextlib.redirect_stdout(validate_output):
                self.assertEqual(main(["validate", "--manifest", str(path)]), 0)
            validated = json.loads(validate_output.getvalue())
            self.assertEqual(validated["state"], "VALID")
            self.assertEqual(validated["binding_count"], 1)
            self.assertEqual(validated["external_writes"], "DISABLED")

            status_output = io.StringIO()
            with contextlib.redirect_stdout(status_output):
                self.assertEqual(main(["status", "--manifest", str(path)]), 0)
            status = json.loads(status_output.getvalue())
            self.assertEqual(status["state"], "AUTH_REQUIRED")
            self.assertEqual(status["effectors"], [])
            self.assertFalse(status["automatic_remediation"])

    def test_cli_observe_disabled_binding_is_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest_file(directory, disabled_manifest())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["observe", "--manifest", str(path)]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["state"], "DISABLED")
            self.assertEqual(report["external_writes"], "DISABLED")
            self.assertEqual(report["effectors"], [])

    def test_status_server_exposes_only_local_truth_and_never_observes(self) -> None:
        plane = GovernedIntegrationPlane(
            IntegrationManifest.from_mapping(auth_required_manifest()),
            secret_resolver=lambda _reference: None,
            transport=FailingTransport(),
        )
        server = create_integration_status_server(plane, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request("GET", "/api/v1/connectors")
            response = connection.getresponse()
            payload = json.loads(response.read())
            connection.close()
            self.assertEqual(response.status, 200)
            self.assertEqual(payload["state"], "AUTH_REQUIRED")
            self.assertEqual(payload["connector_count"], 1)
            self.assertEqual(payload["external_writes"], "DISABLED")
            self.assertEqual(payload["effectors"], [])

            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request("GET", "/readyz")
            response = connection.getresponse()
            ready = json.loads(response.read())
            connection.close()
            self.assertEqual(response.status, 200)
            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["connector_state"], "AUTH_REQUIRED")
            self.assertFalse(ready["provider_egress_on_http"])

            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request("POST", "/api/v1/connectors", body=b"{}")
            response = connection.getresponse()
            rejected = json.loads(response.read())
            connection.close()
            self.assertEqual(response.status, 405)
            self.assertEqual(rejected["error"], "METHOD_NOT_ALLOWED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_status_server_rejects_untrusted_host(self) -> None:
        plane = GovernedIntegrationPlane(
            IntegrationManifest.from_mapping(disabled_manifest()),
            transport=FailingTransport(),
        )
        server = create_integration_status_server(plane, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.putrequest("GET", "/livez", skip_host=True)
            connection.putheader("Host", "attacker.example")
            connection.endheaders()
            response = connection.getresponse()
            payload = json.loads(response.read())
            connection.close()
            self.assertEqual(response.status, 400)
            self.assertEqual(payload["error"], "INVALID_HOST")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
