from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise SystemExit(f"{label} target drifted: {old[:100]!r}")
    return source.replace(old, new, 1)


def update_readme() -> None:
    path = ROOT / "README.md"
    source = path.read_text(encoding="utf-8")
    source = replace_once(
        source,
        """Version 0.4.0 has two intentionally separate surfaces:

- The Python library implements the complete local event-to-case-to-approved
  fake-ticket vertical slice.
- The HTTP service is read-only and exposes only liveness, readiness, build
  identity, and lane status. It exposes no ingestion, approval, execution, or
  other mutation endpoint.
""",
        """Version 0.4.0 has three intentionally separate surfaces:

- The Python library implements the complete local event-to-case-to-approved
  fake-ticket vertical slice.
- The original HTTP service is read-only and exposes only liveness, readiness,
  build identity, and lane status. It exposes no ingestion, approval, execution,
  or other mutation endpoint.
- The tenant integration fabric validates provider bindings, reports credential
  readiness without egress, performs only explicit bounded observations, and
  exposes a separate status-only HTTP service that never calls a provider.
""",
        "README surface count",
    )
    source = replace_once(
        source,
        """The implementation uses Python's standard library and SQLite at runtime. The
only local connector is `FakeTicketConnector`; real identity, endpoint, SIEM,
email, cloud, and ticketing connectors remain unavailable until separately
implemented, reviewed, configured, and observed.
""",
        """The implementation uses Python's standard library and SQLite at runtime.
`FakeTicketConnector` remains the only executable response effector. The tenant
integration fabric now implements read-only observation adapters for Microsoft
Defender XDR, Entra ID, Intune, Sentinel, Defender for Cloud, CrowdStrike, Wiz,
Okta, AWS Security Hub, Google Security Command Center, ServiceNow, Jira, and
administrator-approved CMDB/SIEM endpoints. Every binding remains `DISABLED` or
`AUTH_REQUIRED` until a tenant supplies an approved credential and a bounded
observation succeeds; no adapter is silently called live.
""",
        "README provider truth",
    )
    source = replace_once(
        source,
        """The current image needs no application egress. Real provider connectors,
managed backups, key rotation, authenticated mutation APIs, and off-host
evidence storage require distinct reviewed changes and narrowly scoped network
policy.
""",
        """The default image and both status services need no application egress. Provider
egress occurs only when an operator explicitly invokes `defensive-integrations
observe` for an enabled tenant binding. That deployment must admit only the
binding's fixed provider origin. Managed backups, key rotation, authenticated
mutation APIs, write-capable provider actions, and off-host evidence storage
remain distinct reviewed changes with separate authorization and network policy.
""",
        "README egress boundary",
    )
    source = replace_once(
        source,
        "- `UNAVAILABLE`: real external integrations without current observations.\n",
        """- `AUTH_REQUIRED`: an adapter and tenant binding exist, but no approved credential
  and successful provider observation have been established.
- `OBSERVED`: a bounded read-only provider call returned valid JSON and produced
  a secret-free hash receipt; this grants no write authority.
- `UNAVAILABLE`: the provider transport or response contract failed closed.
""",
        "README integration states",
    )
    marker = "## HTTP contract\n"
    section = """## Tenant integration fabric

The read-only provider fabric and its exact credential boundary are documented
in [`docs/TENANT_INTEGRATIONS.md`](docs/TENANT_INTEGRATIONS.md). A complete,
loadable, disabled-by-default configuration is provided at
`docs/integrations-manifest.example.json`.

```powershell
defensive-integrations validate --manifest integrations.json
defensive-integrations status --manifest integrations.json
defensive-integrations observe --manifest integrations.json --tenant tenant:example --provider microsoft_defender_xdr
defensive-integrations serve --manifest integrations.json --mode local --host 127.0.0.1 --port 8090
```

`validate`, `status`, and the status-only HTTP service perform no provider
egress. `observe` is the sole explicit egress command. Observation receipts
contain hashes, counts, timing, and request identity only—never provider records
or credential values. All adapters preserve `external_writes=DISABLED` and
`effectors=[]`.

"""
    if "## Tenant integration fabric" in source:
        raise SystemExit("README tenant integration section already exists")
    source = replace_once(source, marker, section + marker, "README section")
    path.write_text(source, encoding="utf-8")


def update_demo() -> None:
    path = ROOT / "defensive_control_plane" / "__main__.py"
    source = path.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '            "externalConnectors": "UNAVAILABLE",\n',
        '            "externalConnectors": "IMPLEMENTED_AUTH_REQUIRED",\n',
        "demo connector truth",
    )
    path.write_text(source, encoding="utf-8")


def update_verifier() -> None:
    path = ROOT / "verify.py"
    source = path.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "    manifest = source_manifest()\n",
        """    integration_status: dict[str, Any] | None = None
    integration_error: str | None = None
    try:
        from defensive_control_plane.integrations import GovernedIntegrationPlane

        integration_plane = GovernedIntegrationPlane.from_json_file(
            ROOT / "docs" / "integrations-manifest.example.json"
        )
        integration_status = integration_plane.statuses()
    except Exception as exc:  # receipt must record a closed failure, never hide it
        integration_error = f"{type(exc).__name__}: {exc}"

    manifest = source_manifest()
""",
        "verification integration anchor",
    )
    source = replace_once(
        source,
        """        and demo.get("restoreDrill", {}).get("state") == "VERIFIED_LOCAL"
    )
""",
        """        and demo.get("restoreDrill", {}).get("state") == "VERIFIED_LOCAL"
        and integration_status is not None
        and integration_status.get("state") == "DISABLED"
        and integration_status.get("connector_count") == 14
        and integration_status.get("external_writes") == "DISABLED"
        and integration_status.get("effectors") == []
    )
""",
        "verification pass predicate",
    )
    source = replace_once(
        source,
        '        "scope": "local-python-sqlite-fake-connector",\n',
        '        "scope": "local-python-sqlite-fake-connector-plus-provider-adapters",\n',
        "verification scope",
    )
    source = replace_once(
        source,
        '        "externalConnectors": "UNAVAILABLE",\n',
        '        "externalConnectors": "IMPLEMENTED_AUTH_REQUIRED",\n',
        "verification connector truth",
    )
    source = replace_once(
        source,
        '        "deployedRuntime": "UNAVAILABLE",\n',
        """        "integrationFabric": integration_status,
        "integrationError": integration_error,
        "deployedRuntime": "UNAVAILABLE",
""",
        "verification integration receipt",
    )
    path.write_text(source, encoding="utf-8")


def main() -> int:
    update_readme()
    update_demo()
    update_verifier()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
