from __future__ import annotations

import ipaddress
import json
import socket
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .integrations import GovernedIntegrationPlane, STATUS_SCHEMA
from .server import (
    CLUSTER_READONLY_MODE,
    LOCAL_MODE,
    SERVE_MODES,
    _host_from_header,
    _normalize_trusted_hosts,
)


def create_integration_status_server(
    integration_plane: GovernedIntegrationPlane,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    mode: str = LOCAL_MODE,
    trusted_hosts: Iterable[str] | None = None,
    request_timeout_seconds: float = 10.0,
    max_concurrency: int = 32,
) -> ThreadingHTTPServer:
    """Create a fail-closed status service that never triggers provider egress."""

    if not isinstance(integration_plane, GovernedIntegrationPlane):
        raise TypeError("integration_plane must be a GovernedIntegrationPlane")
    if mode not in SERVE_MODES:
        raise ValueError(f"mode must be one of: {', '.join(sorted(SERVE_MODES))}")
    try:
        bind_address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("the status service requires a numeric bind address") from exc
    if mode == LOCAL_MODE and not bind_address.is_loopback:
        raise ValueError("local mode must bind to loopback")
    if mode == CLUSTER_READONLY_MODE and not bind_address.is_unspecified:
        raise ValueError("cluster-readonly mode must bind to 0.0.0.0 or ::")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    if (
        not isinstance(request_timeout_seconds, (int, float))
        or isinstance(request_timeout_seconds, bool)
        or not 0 < float(request_timeout_seconds) <= 60
    ):
        raise ValueError("request timeout must be greater than 0 and at most 60 seconds")
    if (
        not isinstance(max_concurrency, int)
        or isinstance(max_concurrency, bool)
        or not 1 <= max_concurrency <= 256
    ):
        raise ValueError("max concurrency must be between 1 and 256")

    allowed_hosts = _normalize_trusted_hosts(trusted_hosts)
    if mode == CLUSTER_READONLY_MODE and not allowed_hosts:
        raise ValueError("cluster-readonly mode requires at least one trusted host")
    if mode == LOCAL_MODE and allowed_hosts:
        raise ValueError("trusted hosts are only valid in cluster-readonly mode")

    class Handler(BaseHTTPRequestHandler):
        server_version = "DefensiveIntegrations/0.5"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(float(request_timeout_seconds))

        def version_string(self) -> str:
            return self.server_version

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            )
            self.send_header(
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=()",
            )
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
            if not self._host_is_allowed():
                self._send_json(400, {"error": "INVALID_HOST"})
                return
            path = urlsplit(self.path).path
            if path == "/livez":
                self._send_json(
                    200,
                    {
                        "status": "alive",
                        "schema": STATUS_SCHEMA,
                        "provider_egress_on_http": False,
                    },
                )
                return
            if path == "/readyz":
                status = integration_plane.statuses()
                self._send_json(
                    200,
                    {
                        "status": "ready",
                        "schema": STATUS_SCHEMA,
                        "connector_state": status["state"],
                        "connector_count": status["connector_count"],
                        "external_writes": "DISABLED",
                        "effectors": [],
                        "provider_egress_on_http": False,
                    },
                )
                return
            if path in {"/api/connectors", "/api/v1/connectors"}:
                self._send_json(200, integration_plane.statuses())
                return
            self._send_json(404, {"error": "NOT_FOUND", "path": path})

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
            self._reject_mutation()

        def do_PUT(self) -> None:  # noqa: N802 - stdlib handler contract
            self._reject_mutation()

        def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler contract
            self._reject_mutation()

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler contract
            self._reject_mutation()

        def _reject_mutation(self) -> None:
            if not self._host_is_allowed():
                self._send_json(400, {"error": "INVALID_HOST"})
                return
            self._send_json(405, {"error": "METHOD_NOT_ALLOWED"})

        def _host_is_allowed(self) -> bool:
            host_values = self.headers.get_all("Host", [])
            if len(host_values) != 1:
                return False
            candidate = _host_from_header(host_values[0])
            if candidate is None:
                return False
            if mode == CLUSTER_READONLY_MODE:
                return candidate in allowed_hosts
            if candidate == "localhost":
                return True
            try:
                return ipaddress.ip_address(candidate).is_loopback
            except ValueError:
                return False

        def log_message(self, _format: str, *_args: object) -> None:
            return

    class BoundedIntegrationStatusServer(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if bind_address.version == 6 else socket.AF_INET
        daemon_threads = True
        block_on_close = True
        request_queue_size = min(max_concurrency, 128)

        def __init__(self, server_address: tuple[str, int]) -> None:
            self._request_slots = threading.BoundedSemaphore(max_concurrency)
            super().__init__(server_address, Handler)
            self.deployment_mode = mode
            self.trusted_hosts = allowed_hosts
            self.max_concurrency = max_concurrency
            self.request_timeout_seconds = float(request_timeout_seconds)
            self.provider_egress_on_http = False

        def process_request(self, request: socket.socket, client_address: Any) -> None:
            if not self._request_slots.acquire(blocking=False):
                try:
                    request.sendall(
                        b"HTTP/1.1 503 Service Unavailable\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Cache-Control: no-store\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 23\r\n\r\n"
                        b'{"error":"SERVER_BUSY"}'
                    )
                finally:
                    request.close()
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._request_slots.release()
                raise

        def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._request_slots.release()

    return BoundedIntegrationStatusServer((host, port))


def serve_integration_status(
    integration_plane: GovernedIntegrationPlane,
    host: str = "127.0.0.1",
    port: int = 8090,
    *,
    mode: str = LOCAL_MODE,
    trusted_hosts: Iterable[str] | None = None,
    request_timeout_seconds: float = 10.0,
    max_concurrency: int = 32,
) -> None:
    """Serve the read-only integration status surface until interrupted."""

    server = create_integration_status_server(
        integration_plane,
        host=host,
        port=port,
        mode=mode,
        trusted_hosts=trusted_hosts,
        request_timeout_seconds=request_timeout_seconds,
        max_concurrency=max_concurrency,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
