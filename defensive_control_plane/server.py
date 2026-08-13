from __future__ import annotations

import ipaddress
import json
import signal
import socket
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import FrameType
from typing import Any
from urllib.parse import urlsplit

from .core import ControlPlane, ValidationError


LOCAL_MODE = "local"
CLUSTER_READONLY_MODE = "cluster-readonly"
SERVE_MODES = frozenset({LOCAL_MODE, CLUSTER_READONLY_MODE})
_DNS_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def _is_valid_hostname(value: str) -> bool:
    """Validate an ASCII DNS name with one linear, bounded scan."""

    if not 1 <= len(value) <= 253 or value.startswith(".") or value.endswith("."):
        return False
    for label in value.split("."):
        if (
            not 1 <= len(label) <= 63
            or label[0] == "-"
            or label[-1] == "-"
            or any(character not in _DNS_CHARACTERS for character in label)
        ):
            return False
    return True


def _normalize_trusted_hosts(values: Iterable[str] | None) -> frozenset[str]:
    normalized: set[str] = set()
    for raw_value in values or ():
        if not isinstance(raw_value, str) or raw_value != raw_value.strip():
            raise ValidationError("trusted hosts must be exact host names without whitespace")
        value = raw_value.lower()
        if not value or value == "*" or "://" in value or "/" in value:
            raise ValidationError("trusted hosts must be exact host names, not URLs or wildcards")
        try:
            value = ipaddress.ip_address(value).compressed
        except ValueError:
            if not _is_valid_hostname(value):
                raise ValidationError(f"invalid trusted host: {raw_value!r}")
        normalized.add(value)
    return frozenset(normalized)


def _host_from_header(host_header: str) -> str | None:
    if (
        not host_header
        or len(host_header) > 260
        or host_header != host_header.strip()
    ):
        return None
    if host_header.startswith("["):
        closing = host_header.find("]")
        if closing < 0:
            return None
        candidate = host_header[1:closing]
        suffix = host_header[closing + 1 :]
        if suffix and not _valid_port_suffix(suffix):
            return None
    else:
        if host_header.count(":") > 1:
            return None
        if ":" in host_header:
            candidate, suffix = host_header.rsplit(":", 1)
            if not _valid_port_suffix(":" + suffix):
                return None
        else:
            candidate = host_header
    if not candidate or candidate != candidate.strip():
        return None
    lowered = candidate.lower()
    try:
        return ipaddress.ip_address(lowered).compressed
    except ValueError:
        return lowered if _is_valid_hostname(lowered) else None


def _valid_port_suffix(suffix: str) -> bool:
    digits = suffix[1:] if suffix.startswith(":") else ""
    if (
        not digits
        or len(digits) > 5
        or any(character not in "0123456789" for character in digits)
    ):
        return False
    try:
        port_value = int(digits, 10)
    except (TypeError, ValueError, OverflowError):
        return False
    return 0 <= port_value <= 65535


def create_server(
    control_plane: ControlPlane,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    mode: str = LOCAL_MODE,
    trusted_hosts: Iterable[str] | None = None,
    request_timeout_seconds: float = 10.0,
    max_concurrency: int = 32,
) -> ThreadingHTTPServer:
    """Create a fail-closed read-only status server.

    ``local`` mode binds only to a numeric loopback address and accepts only
    loopback Host headers. ``cluster-readonly`` is an explicit deployment mode:
    it binds only to an unspecified numeric address and requires a nonempty,
    exact Host allowlist. Neither mode exposes mutation endpoints.
    """

    if mode not in SERVE_MODES:
        raise ValidationError(f"mode must be one of: {', '.join(sorted(SERVE_MODES))}")
    try:
        bind_address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError("the server requires a numeric bind address") from exc
    if mode == LOCAL_MODE and not bind_address.is_loopback:
        raise ValidationError("local mode must bind to loopback")
    if mode == CLUSTER_READONLY_MODE and not bind_address.is_unspecified:
        raise ValidationError("cluster-readonly mode must bind to 0.0.0.0 or ::")
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValidationError("port must be between 0 and 65535")
    if (
        not isinstance(request_timeout_seconds, (int, float))
        or isinstance(request_timeout_seconds, bool)
        or not 0 < float(request_timeout_seconds) <= 60
    ):
        raise ValidationError("request timeout must be greater than 0 and at most 60 seconds")
    if (
        not isinstance(max_concurrency, int)
        or isinstance(max_concurrency, bool)
        or not 1 <= max_concurrency <= 256
    ):
        raise ValidationError("max concurrency must be between 1 and 256")

    allowed_hosts = _normalize_trusted_hosts(trusted_hosts)
    if mode == CLUSTER_READONLY_MODE and not allowed_hosts:
        raise ValidationError("cluster-readonly mode requires at least one trusted host")
    if mode == LOCAL_MODE and allowed_hosts:
        raise ValidationError("trusted hosts are only valid in cluster-readonly mode")

    class Handler(BaseHTTPRequestHandler):
        server_version = "DefensiveControlPlane/0.4"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(float(request_timeout_seconds))

        def version_string(self) -> str:
            return self.server_version

        def _send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
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
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
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
                self._send_json(200, control_plane.livez())
            elif path == "/readyz":
                payload = control_plane.readyz()
                self._send_json(200 if payload["status"] == "ready" else 503, payload)
            elif path == "/api/build-info":
                self._send_json(200, control_plane.build_info())
            elif path in {"/api/lanes", "/api/v1/lanes"}:
                self._send_json(200, control_plane.lane_statuses())
            else:
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

        def log_message(self, _format: str, *_args: object) -> None:
            return

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

    class BoundedStatusServer(ThreadingHTTPServer):
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

    return BoundedStatusServer((host, port))


def serve(
    control_plane: ControlPlane,
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    mode: str = LOCAL_MODE,
    trusted_hosts: Iterable[str] | None = None,
    request_timeout_seconds: float = 10.0,
    max_concurrency: int = 32,
) -> None:
    server = create_server(
        control_plane,
        host=host,
        port=port,
        mode=mode,
        trusted_hosts=trusted_hosts,
        request_timeout_seconds=request_timeout_seconds,
        max_concurrency=max_concurrency,
    )
    previous_handlers: dict[signal.Signals, Any] = {}

    def request_shutdown(_signum: int, _frame: FrameType | None) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        for signal_name in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signal_name] = signal.getsignal(signal_name)
            signal.signal(signal_name, request_shutdown)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        for signal_name, previous_handler in previous_handlers.items():
            signal.signal(signal_name, previous_handler)
