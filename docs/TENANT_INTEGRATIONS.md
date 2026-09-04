# Tenant Integration Fabric v1

The tenant integration fabric is executable software for bounded, read-only
observations of approved enterprise providers. It does not contain tenant
credentials, create OAuth applications, grant itself permissions, or convert an
unobserved provider into a live integration.

## Truth states

| State | Meaning |
|---|---|
| `DISABLED` | The binding is intentionally inert. No credential resolution or provider request occurs. |
| `AUTH_REQUIRED` | The adapter and binding are valid, but a required `env://` reference is absent, unresolved, or rejected. |
| `READY` | Required references resolve and a request plan can be constructed. This is not proof that the provider accepted it. |
| `OBSERVED` | A bounded provider request returned valid JSON and produced a secret-free observation receipt. |
| `UNAVAILABLE` | Transport, provider, timeout, redirect, response-size, or JSON validation failed. |
| `INVALID_CONFIG` | The binding violates a host, resource, URL, path, tenant, or manifest invariant. |

`READY` is not `OBSERVED`, and `OBSERVED` is not authorization for an external
write. The complete fabric keeps:

```text
external_writes = DISABLED
effectors = []
automatic_remediation = false
production_authorization = false
```

## Implemented adapters

| Provider ID | Provider lane | Fixed observation |
|---|---|---|
| `microsoft_defender_xdr` | Microsoft Defender XDR | Microsoft Graph security incidents |
| `microsoft_entra_id` | Microsoft Entra ID | Microsoft Graph sign-in audit events |
| `microsoft_intune` | Microsoft Intune | Microsoft Graph managed devices |
| `microsoft_sentinel` | Microsoft Sentinel | Security Insights incidents for one exact subscription/resource group/workspace |
| `azure_defender_cloud` | Microsoft Defender for Cloud | Security assessments for one exact subscription |
| `crowdstrike_falcon` | CrowdStrike Falcon | Alerts query on one admitted Falcon cloud |
| `wiz` | Wiz | One fixed read-only GraphQL issue query |
| `okta` | Okta | System Log observations |
| `aws_security_hub` | AWS Security Hub | SigV4-signed `GetFindings` for one exact region |
| `gcp_security_command_center` | Google Security Command Center | Findings for one exact organization |
| `servicenow` | ServiceNow | Active incident table read |
| `jira_cloud` | Jira Cloud | Bounded enhanced-JQL issue read |
| `registered_cmdb` | Customer CMDB | Administrator-approved origin and bounded `/api/` collection path |
| `registered_siem` | Customer SIEM | Administrator-approved origin and bounded `/api/` collection path |

The Wiz query is implemented as a fixed read-only template, but it remains
`AUTH_REQUIRED` and unobserved until qualified against an authorized tenant.
The two registered-provider adapters exist for systems that do not have a
first-class contract; they cannot accept a caller-supplied origin. Their exact
origins must be declared separately in `approved_private_endpoints`.

## Manifest contract

Start from `docs/integrations-manifest.example.json`. Every binding is scoped by
an exact `(tenant_id, provider_id)` pair. Secret material is never placed in the
manifest. Only an environment reference is admitted:

```json
{
  "tenant_id": "tenant:example",
  "provider_id": "microsoft_defender_xdr",
  "enabled": true,
  "resources": {},
  "secret_refs": {
    "token": "env://DCP_MICROSOFT_GRAPH_TOKEN"
  }
}
```

The manifest rejects:

- literal credential values;
- duplicate tenant/provider bindings;
- HTTP origins;
- URL user information, ports, paths, queries, or fragments in origins;
- IP literals and localhost;
- provider domains outside the fixed contract;
- unapproved CMDB/SIEM origins;
- traversal or non-`/api/` private collection paths;
- malformed Azure subscription/resource identities, AWS regions, and GCP
  organization identifiers;
- more than 128 bindings or a manifest larger than 512 KiB.

## Validate and inspect without egress

```powershell
python -m defensive_control_plane.integration_cli validate `
  --manifest docs\integrations-manifest.example.json

python -m defensive_control_plane.integration_cli status `
  --manifest docs\integrations-manifest.example.json
```

After installation, the same commands are available as:

```powershell
defensive-integrations validate --manifest integrations.json
defensive-integrations status --manifest integrations.json
```

Validation does not resolve credentials. Status resolves only explicit
`env://` references to determine readiness; it does not call a provider and it
never returns the resolved value.

## Perform an explicit observation

Provider egress occurs only through the explicit `observe` command:

```powershell
defensive-integrations observe `
  --manifest integrations.json `
  --tenant tenant:example `
  --provider microsoft_defender_xdr
```

The command prints a receipt containing only:

- tenant and provider identifiers;
- state and observation time;
- method and semantic operation;
- endpoint fingerprint;
- HTTP status and bounded record count;
- byte count and latency;
- response SHA-256 and provider request ID when available;
- observation and batch receipt SHA-256 values;
- the permanent no-write/no-effector boundary.

Raw provider records and credentials are discarded. A provider failure does not
become zero findings, an empty market, or a successful observation.

## Status-only HTTP service

```powershell
defensive-integrations serve `
  --manifest integrations.json `
  --mode local `
  --host 127.0.0.1 `
  --port 8090
```

The service exposes:

| Method | Path | Contract |
|---|---|---|
| `GET` | `/livez` | Process status only. |
| `GET` | `/readyz` | Manifest/status-service readiness plus aggregate connector truth state. |
| `GET` | `/api/connectors` | Connector configuration and credential-reference states. |
| `GET` | `/api/v1/connectors` | Versioned alias. |

HTTP requests never trigger provider observation. `POST`, `PUT`, `PATCH`, and
`DELETE` return 405. The service uses the same loopback or exact trusted-Host
admission model as the defensive control-plane status surface.

## Credential setup boundary

Each tenant administrator must create or approve the provider-side identity,
select the smallest read-only roles/scopes needed for the fixed endpoint, issue
or federate short-lived credentials, place them in the deployment secret store,
and bind the secret store to the declared `env://` reference. The fabric cannot
and does not grant itself access.

Recommended production posture:

1. Prefer workload identity, managed identity, or short-lived OAuth over static
   tokens.
2. Scope the identity to a single tenant and the read-only API represented by the
   provider contract.
3. Store no token in Git, manifests, container layers, logs, receipts, or command
   history.
4. Deny all egress except the admitted provider origins.
5. Run `validate` and `status` before enabling a binding.
6. Run an explicit observation and retain its secret-free receipt.
7. Compare provider-side audit logs with the receipt request time and request ID.
8. Rotate or revoke the provider identity without changing historical receipts.

## Production admission

A connector is not production-operational until all of the following are
observed for the exact deployment revision:

- reviewed source and green tests;
- built package/container provenance;
- tenant-specific manifest admission;
- provider-side least-privilege identity approval;
- secret-store injection without value disclosure;
- network policy admitting only the provider origin;
- successful `OBSERVED` receipt;
- provider-side audit corroboration;
- restart and credential-rotation behavior;
- independent readback showing no write, no effector, and no raw-record
  persistence.

A later write-capable integration requires a different versioned envelope,
independent requester/approver separation, a target/action allowlist, dry-run,
durable exactly-once claim, provider readback, rollback or reconciliation, and a
separate production authorization. This v1 fabric intentionally grants none of
those capabilities.
