from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .integration_status_server import serve_integration_status
from .integrations import GovernedIntegrationPlane, IntegrationState
from .server import CLUSTER_READONLY_MODE, LOCAL_MODE


def _write_json(value: dict[str, Any]) -> None:
    print(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    )


def _plane(path: Path) -> GovernedIntegrationPlane:
    return GovernedIntegrationPlane.from_json_file(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defensive-integrations",
        description=(
            "Tenant-isolated, read-only provider observations with secret-free receipts"
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser(
        "validate",
        help="validate a manifest without resolving credentials or contacting providers",
    )
    validate.add_argument("--manifest", type=Path, required=True)

    status = commands.add_parser(
        "status",
        help="report configured connector and credential-reference readiness without egress",
    )
    status.add_argument("--manifest", type=Path, required=True)

    observe = commands.add_parser(
        "observe",
        help="perform an explicit bounded read-only provider observation",
    )
    observe.add_argument("--manifest", type=Path, required=True)
    observe.add_argument("--tenant")
    observe.add_argument("--provider")

    serve = commands.add_parser(
        "serve",
        help="serve connector status only; HTTP requests never trigger provider egress",
    )
    serve.add_argument("--manifest", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8090)
    serve.add_argument(
        "--mode",
        choices=(LOCAL_MODE, CLUSTER_READONLY_MODE),
        default=LOCAL_MODE,
    )
    serve.add_argument(
        "--trusted-host",
        action="append",
        default=[],
        help="exact Host name allowed in cluster-readonly mode; may be repeated",
    )
    serve.add_argument("--request-timeout-seconds", type=float, default=10.0)
    serve.add_argument("--max-concurrency", type=int, default=32)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        plane = _plane(args.manifest)
        if args.command == "validate":
            _write_json(
                {
                    "schema": "szl.defensive-integrations-validation/v1",
                    "state": "VALID",
                    "binding_count": len(plane.manifest.bindings),
                    "providers": sorted(
                        {binding.provider_id for binding in plane.manifest.bindings}
                    ),
                    "external_writes": "DISABLED",
                    "effectors": [],
                }
            )
            return 0
        if args.command == "status":
            _write_json(plane.statuses())
            return 0
        if args.command == "observe":
            report = plane.observe(
                tenant_id=args.tenant,
                provider_id=args.provider,
            )
            _write_json(report)
            state = report["state"]
            if state in {
                IntegrationState.OBSERVED.value,
                IntegrationState.DISABLED.value,
            }:
                return 0
            if state == IntegrationState.AUTH_REQUIRED.value:
                return 3
            return 4
        if args.command == "serve":
            serve_integration_status(
                plane,
                host=args.host,
                port=args.port,
                mode=args.mode,
                trusted_hosts=args.trusted_host,
                request_timeout_seconds=args.request_timeout_seconds,
                max_concurrency=args.max_concurrency,
            )
            return 0
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        parser.exit(2, f"defensive-integrations: {exc}\n")
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
