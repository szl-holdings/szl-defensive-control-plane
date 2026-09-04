# SZL Defensive Control Plane

The SZL Defensive Control Plane is an evidence-bound, defensive-only engine for
signed security-event ingestion, deterministic detections, incident cases,
governed response approvals, tightly allowlisted connector execution, and
tamper-evident case evidence.

It is not an exploit payload, remote administration tool, arbitrary command
runner, or authorization to operate against systems outside an approved
defensive scope.

Version 0.4.0 has three intentionally separate surfaces:

- The Python library implements the complete local event-to-case-to-approved
  fake-ticket vertical slice.
- The original HTTP service is read-only and exposes only liveness, readiness,
  build identity, and lane status. It exposes no ingestion, approval, execution,
  or other mutation endpoint.
- The tenant integration fabric validates provider bindings, reports credential
  readiness without egress, performs only explicit bounded observations, and
  exposes a separate status-only HTTP service that never calls a provider.

The implementation uses Python's standard library and SQLite at runtime.
`FakeTicketConnector` remains the only executable response effector. The tenant
integration fabric now implements read-only observation adapters for Microsoft
Defender XDR, Entra ID, Intune, Sentinel, Defender for Cloud, CrowdStrike, Wiz,
Okta, AWS Security Hub, Google Security Command Center, ServiceNow, Jira, and
administrator-approved CMDB/SIEM endpoints. Every binding remains `DISABLED` or
`AUTH_REQUIRED` until a tenant supplies an approved credential and a bounded
observation succeeds; no adapter is silently called live.

## Local verification

Python 3.11 or newer is required.

```powershell
python -B -m unittest discover -s tests -v
python -B -m defensive_control_plane demo
python -B verify.py
```

`verify.py` writes `evidence/local-verification.json`. That report binds the
observed test/demo result to a SHA-256 manifest of release-relevant source
files. It is local evidence only; it does not certify a container, deployment,
external connector, production runtime, or independent witness.

## Install and run

```powershell
python -m pip install .
defensive-control-plane demo
```

The status service requires two distinct hexadecimal keys. Each must decode to
at least 16 bytes; production deployments should use independently managed
32-byte values and a documented rotation procedure.

```powershell
$env:DCP_EVENT_ROOT_KEY_HEX = '<64 lowercase hex characters>'
$env:DCP_EVIDENCE_KEY_HEX = '<a different 64 lowercase hex characters>'
python -B -m defensive_control_plane serve `
  --db .\control-plane.sqlite3 `
  --mode local `
  --host 127.0.0.1 `
  --port 8080
```

Local mode is the fail-closed default. It accepts only a numeric loopback bind
address and only loopback or `localhost` Host headers.

## Cluster-readonly mode

Cluster mode must be selected explicitly. It binds only to `0.0.0.0` or `::`
and refuses startup unless at least one exact trusted Host name is configured.
Wildcards, URLs, suffix matches, and implicit DNS trust are rejected.

```powershell
$env:DCP_EVENT_ROOT_KEY_HEX = '<managed value>'
$env:DCP_EVIDENCE_KEY_HEX = '<different managed value>'
$env:DCP_TRUSTED_HOSTS = 'szl-defensive-control-plane,szl-defensive-control-plane.szl-defensive-control-plane.svc'
python -B -m defensive_control_plane serve `
  --db .\data\control-plane.sqlite3 `
  --mode cluster-readonly `
  --host 0.0.0.0 `
  --port 8080
```

Cluster-readonly mode is a status surface, not an authentication system. It
must remain behind an authenticated service-mesh or reverse-proxy boundary and
a default-deny network policy. Do not expose the standard-library server
directly through a public ingress. Kubernetes probes must send one of the
configured trusted Host values.

## Tenant integration fabric

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

## HTTP contract

| Method | Path | Meaning |
|---|---|---|
| `GET` | `/livez` | The local process can answer. |
| `GET` | `/readyz` | SQLite schema/integrity and evidence-chain state are acceptable for this local service. |
| `GET` | `/api/build-info` | Package and source-revision claim; never self-promotes deployment verification. |
| `GET` | `/api/lanes` | Current lane and connector truth states. |
| `GET` | `/api/v1/lanes` | Versioned alias of `/api/lanes`. |

Unknown routes return 404. POST, PUT, PATCH, and DELETE return 405 after Host
validation. Responses are `no-store` JSON with restrictive browser security
headers. The server enforces bounded concurrency, request timeouts, exact Host
validation, and graceful SIGINT/SIGTERM shutdown.

## Container

The Dockerfile uses a digest-pinned Python 3.12 base, builds a wheel in a
separate stage, installs only the wheel into the runtime stage, and runs as
numeric UID/GID 10001. It contains no credentials, database, generated
verification report, or internal handoff notes.

```powershell
docker build `
  --build-arg SOURCE_REVISION=$(git rev-parse HEAD) `
  --build-arg SOURCE_VERSION=0.4.0 `
  -t defensive-control-plane:local .

docker run --rm -p 127.0.0.1:8080:8080 `
  -e DCP_EVENT_ROOT_KEY_HEX='<managed value>' `
  -e DCP_EVIDENCE_KEY_HEX='<different managed value>' `
  -e DCP_TRUSTED_HOSTS='localhost' `
  -v dcp-data:/data `
  defensive-control-plane:local
```

The production image is published only by the protected release workflow. A
fleet deployment must consume `ghcr.io/szl-holdings/defensive-control-plane`
by immutable `sha256` digest, with its exact source revision, SBOM, provenance,
and signature checked separately.

## Architecture and safety properties

The public package surface is deliberately small:

- `ControlPlane` coordinates validation, signed ingestion, detection, cases,
  approvals, execution, evidence export, backup/restore, and truth reporting.
- `AuthenticatedPrincipal` is a short-lived tenant-scoped, HMAC-authenticated
  identity assertion issued only after a stored credential digest is checked.
- `SQLiteStore` owns durable state, transactions, replay decisions, execution
  claims/results, exact schema validation, and the append-only evidence chain.
- `DefensiveControlEnvelopeV1` is a versioned data-only action contract. It
  cannot carry shell commands, scripts, or arbitrary URLs.
- `FakeTicketConnector` is the only executable connector shipped here. It
  models one allowlisted test-ticket action and supports deterministic readback.

The main local flow is:

```text
canonical signed event
  -> tenant/source-bound HMAC verification
  -> replay or collision decision
  -> deterministic detection
  -> evidence-backed incident case
  -> authenticated requester
  -> immutable data-only response envelope
  -> dry-run preview with zero connector calls
  -> independent bound approval
  -> durable exactly-once execution claim
  -> allowlisted fake connector
  -> stored result and append-only evidence
  -> authenticated read-only reconciliation if outcome is uncertain
```

Security invariants include:

- Separate event-root and evidence-signing keys.
- Tenant/source-derived event MAC keys and canonical JSON.
- Exact replay idempotency and fail-closed event-ID collision quarantine.
- Authenticated tenant principals and role checks, not asserted actor strings.
- A detection-backed, eligible open case for every live action.
- Immutable envelopes revalidated at approval and execution.
- Independent requester/approver separation.
- Hash-bound, expiring, single-use approvals.
- Durable execution claims committed before dispatch.
- No automatic retry after an uncertain external outcome.
- Tenant/envelope/action/target/request-hash binding on connector readback.
- Append-only chained evidence and fail-closed export verification.
- Exact schema/trigger/constraint validation before readiness or restore.
- Backups compared by schema and per-table content digests before use.
- Explicit `VERIFIED_LOCAL`, `PARTIAL`, `MODELED`, `UNAVAILABLE`, and
  `FAILED_CLOSED` truth states.

## Deployment constraints

SQLite makes this a single-writer service. The reference deployment contract
therefore requires one replica, `Recreate` updates, one ReadWriteOnce volume,
and no horizontal autoscaler. High availability or rolling multi-replica
operation requires a separately designed server-database persistence layer.

The two signing keys are read at startup. Rotation must retain key IDs and old
verification material or migrate the evidence format; replacing an evidence
key blindly makes historical signatures unverifiable.

The default image and both status services need no application egress. Provider
egress occurs only when an operator explicitly invokes `defensive-integrations
observe` for an enabled tenant binding. That deployment must admit only the
binding's fixed provider origin. Managed backups, key rotation, authenticated
mutation APIs, write-capable provider actions, and off-host evidence storage
remain distinct reviewed changes with separate authorization and network policy.

## Truth boundary

A passing source suite can establish only the behavior it directly observes:

- `VERIFIED_LOCAL`: Python, SQLite, fake connector, and local HTTP behavior.
- `MODELED`: the fake ticket connector's representation of an external action.
- `PARTIAL`: source/build identity without deployed-runtime attestation.
- `AUTH_REQUIRED`: an adapter and tenant binding exist, but no approved credential
  and successful provider observation have been established.
- `OBSERVED`: a bounded read-only provider call returned valid JSON and produced
  a secret-free hash receipt; this grants no write authority.
- `UNAVAILABLE`: the provider transport or response contract failed closed.

A passing pull request is source-admission evidence. A published image is
artifact evidence. A deployed digest is deployment evidence. Healthy endpoints
are runtime evidence. An independent external probe is witness evidence. None
of these states silently substitutes for another, and `productionOperational`
remains false until the entire required chain is observed.

## Security reporting

Report vulnerabilities through GitHub private vulnerability reporting. See
[SECURITY.md](SECURITY.md). Do not open a public issue containing a credential,
exploit procedure, customer data, or unpatched vulnerability detail.

## License

Copyright 2026 SZL Holdings. Licensed under the Apache License, Version 2.0.
See [LICENSE](LICENSE).
