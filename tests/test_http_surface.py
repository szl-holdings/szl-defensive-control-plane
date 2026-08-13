from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from defensive_control_plane import ControlPlane, EvidenceState, ValidationError
from defensive_control_plane.server import (
    CLUSTER_READONLY_MODE,
    LOCAL_MODE,
    create_server,
)


class LocalHttpSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.plane = ControlPlane(
            Path(self.temp_directory.name) / "http.sqlite3",
            b"http-event-key-strong",
            b"http-evidence-key-strong",
        )
        self.server = create_server(self.plane, host="127.0.0.1", port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        host, port = self.server.server_address[:2]
        self.server_host = host
        self.server_port = port
        self.base_url = f"http://{host}:{port}"

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _get_json(self, path: str) -> tuple[int, dict | list, object]:
        request = urllib.request.Request(
            self.base_url + path,
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            return response.status, body, response.headers

    def test_liveness_route_matches_direct_truth(self) -> None:
        status, body, headers = self._get_json("/livez")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.plane.livez())
        self.assertTrue(headers.get_content_type() == "application/json")
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(
            headers.get("Content-Security-Policy"),
            "default-src 'none'; frame-ancestors 'none'",
        )
        self.assertEqual(headers.get("Cross-Origin-Resource-Policy"), "same-origin")

    def test_readiness_route_matches_direct_truth(self) -> None:
        status, body, headers = self._get_json("/readyz")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.plane.readyz())
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_build_info_route_is_json_not_static_html(self) -> None:
        status, body, headers = self._get_json("/api/build-info")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.plane.build_info())
        self.assertEqual(headers.get_content_type(), "application/json")

    def test_lane_status_route_preserves_explicit_truth_labels(self) -> None:
        status, body, _headers = self._get_json("/api/lanes")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.plane.lane_statuses())

    def test_unknown_route_and_wrong_method_fail_closed(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as unknown:
            self._get_json("/does-not-exist")
        self.assertEqual(unknown.exception.code, 404)

        request = urllib.request.Request(
            self.base_url + "/livez",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as wrong_method:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(wrong_method.exception.code, 405)

    def test_server_binds_loopback_by_default(self) -> None:
        default_server = create_server(self.plane, port=0)
        try:
            self.assertIn(default_server.server_address[0], {"127.0.0.1", "::1"})
        finally:
            default_server.server_close()

    def test_cluster_readonly_mode_requires_unspecified_bind_and_exact_hosts(self) -> None:
        with self.assertRaises(ValidationError):
            create_server(
                self.plane,
                host="127.0.0.1",
                mode=CLUSTER_READONLY_MODE,
                trusted_hosts=["defensive-control-plane.test.svc"],
            )
        with self.assertRaises(ValidationError):
            create_server(
                self.plane,
                host="0.0.0.0",
                mode=CLUSTER_READONLY_MODE,
            )
        with self.assertRaises(ValidationError):
            create_server(
                self.plane,
                host="0.0.0.0",
                mode=CLUSTER_READONLY_MODE,
                trusted_hosts=["*.test.svc"],
            )
        with self.assertRaises(ValidationError):
            create_server(self.plane, host="0.0.0.0", mode=LOCAL_MODE)

    def test_cluster_readonly_mode_accepts_only_allowlisted_host(self) -> None:
        cluster = create_server(
            self.plane,
            host="0.0.0.0",
            port=0,
            mode=CLUSTER_READONLY_MODE,
            trusted_hosts=["defensive-control-plane.test.svc"],
            max_concurrency=4,
            request_timeout_seconds=3,
        )
        thread = threading.Thread(target=cluster.serve_forever, daemon=True)
        thread.start()
        try:
            port = cluster.server_address[1]
            for host_header, expected_status in (
                ("defensive-control-plane.test.svc", 200),
                ("DEFENSIVE-CONTROL-PLANE.TEST.SVC:8080", 200),
                ("127.0.0.1", 400),
                ("defensive-control-plane.test.svc.attacker.example", 400),
            ):
                with self.subTest(host_header=host_header):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        connection.putrequest("GET", "/livez", skip_host=True)
                        connection.putheader("Host", host_header)
                        connection.endheaders()
                        response = connection.getresponse()
                        payload = json.loads(response.read().decode("utf-8"))
                    finally:
                        connection.close()
                    self.assertEqual(response.status, expected_status)
                    if expected_status == 200:
                        self.assertEqual(payload, self.plane.livez())
                    else:
                        self.assertEqual(payload, {"error": "INVALID_HOST"})
            self.assertEqual(cluster.deployment_mode, CLUSTER_READONLY_MODE)
            self.assertEqual(cluster.max_concurrency, 4)
            self.assertEqual(cluster.request_timeout_seconds, 3.0)
        finally:
            cluster.shutdown()
            cluster.server_close()
            thread.join(timeout=5)

    def test_invalid_listener_ports_are_rejected(self) -> None:
        for port in (-1, 65536, "8080", None):
            with self.subTest(port=port), self.assertRaises(ValidationError):
                create_server(self.plane, port=port)

    def test_invalid_server_resource_limits_are_rejected(self) -> None:
        for timeout in (0, -1, 61, True, "10"):
            with self.subTest(timeout=timeout), self.assertRaises(ValidationError):
                create_server(self.plane, request_timeout_seconds=timeout)
        for concurrency in (0, -1, 257, True, "32"):
            with self.subTest(concurrency=concurrency), self.assertRaises(ValidationError):
                create_server(self.plane, max_concurrency=concurrency)

    def test_non_loopback_or_missing_host_header_is_rejected(self) -> None:
        for host_header in (
            "attacker.example",
            "127.0.0.1.attacker.example",
            "[::1].invalid",
            "[::1]:123456",
            "[::1]:²",
            "127.0.0.1:65536",
            "127.0.0.1:123456",
            "127.0.0.1:-1",
            "127.0.0.1:not-a-port",
            "127.0.0.1:²",
            "",
        ):
            with self.subTest(host_header=host_header):
                connection = http.client.HTTPConnection(
                    self.server_host, self.server_port, timeout=5
                )
                try:
                    connection.putrequest("GET", "/livez", skip_host=True)
                    if host_header:
                        connection.putheader("Host", host_header)
                    connection.endheaders()
                    response = connection.getresponse()
                    payload = json.loads(response.read().decode("utf-8"))
                finally:
                    connection.close()
                self.assertEqual(response.status, 400)
                self.assertEqual(payload, {"error": "INVALID_HOST"})

    def test_duplicate_host_headers_are_rejected(self) -> None:
        connection = http.client.HTTPConnection(
            self.server_host, self.server_port, timeout=5
        )
        try:
            connection.putrequest("GET", "/livez", skip_host=True)
            connection.putheader("Host", "127.0.0.1")
            connection.putheader("Host", "localhost")
            connection.endheaders()
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
        finally:
            connection.close()
        self.assertEqual(response.status, 400)
        self.assertEqual(payload, {"error": "INVALID_HOST"})

    def test_corrupt_nonfinite_evidence_returns_readiness_503_not_exception(self) -> None:
        with self.plane.store.connect() as connection:
            connection.execute(
                """
                INSERT INTO cases(
                    id, tenant_id, asset_ref, title, severity, state,
                    created_at, updated_at
                ) VALUES(
                    'http-corrupt-case', 'tenant:http', 'asset:test-http',
                    'HTTP corrupt evidence fixture', 'high', 'NEW',
                    '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z'
                )
                """
            )
            connection.execute(
                """
                INSERT INTO evidence(
                    id, tenant_id, case_id, kind, payload_json,
                    previous_hash, entry_hash, created_at
                ) VALUES(
                    'http-corrupt-evidence', 'tenant:http', 'http-corrupt-case',
                    'fixture.corrupt', '{"nonfinite":NaN}', ?, ?,
                    '2026-08-11T00:00:00Z'
                )
                """,
                ("0" * 64, "0" * 64),
            )
        direct = self.plane.readyz()
        self.assertEqual(direct["status"], "not_ready")
        self.assertEqual(direct["state"], EvidenceState.FAILED_CLOSED.value)

        request = urllib.request.Request(self.base_url + "/readyz", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as unavailable:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(unavailable.exception.code, 503)
        body = json.loads(unavailable.exception.read().decode("utf-8"))
        self.assertEqual(body, direct)

    def test_pathological_evidence_exceptions_return_http_503(self) -> None:
        with self.plane.store.connect() as connection:
            connection.execute(
                """
                INSERT INTO cases(
                    id, tenant_id, asset_ref, title, severity, state,
                    created_at, updated_at
                ) VALUES(
                    'http-pathological-case', 'tenant:http', 'asset:test-http',
                    'HTTP pathological evidence fixture', 'high', 'NEW',
                    '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z'
                )
                """
            )
            connection.execute(
                """
                INSERT INTO evidence(
                    id, tenant_id, case_id, kind, payload_json,
                    previous_hash, entry_hash, created_at
                ) VALUES(
                    'http-pathological-evidence', 'tenant:http',
                    'http-pathological-case', 'fixture.pathological', '{}', ?, ?,
                    '2026-08-11T00:00:00Z'
                )
                """,
                ("0" * 64, "0" * 64),
            )

        for error_type in (RecursionError, OverflowError, ValueError):
            with self.subTest(error_type=error_type.__name__):
                with patch(
                    "defensive_control_plane.core._canonical_bytes",
                    side_effect=error_type("pathological evidence fixture"),
                ) as canonical:
                    direct = self.plane.readyz()
                    request = urllib.request.Request(
                        self.base_url + "/readyz", method="GET"
                    )
                    with self.assertRaises(urllib.error.HTTPError) as unavailable:
                        urllib.request.urlopen(request, timeout=5)
                    body = json.loads(unavailable.exception.read().decode("utf-8"))
                self.assertTrue(canonical.called)
                self.assertEqual(unavailable.exception.code, 503)
                self.assertEqual(direct["status"], "not_ready")
                self.assertEqual(body, direct)


if __name__ == "__main__":
    unittest.main()
