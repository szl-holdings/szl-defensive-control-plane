# Offline defensive evidence and planning

`defensive_control_plane/planning.py` is an additive, standard-library-only
planning surface in the governance/evidence layer. It reads one explicitly
selected local JSON snapshot and writes a JSON report to stdout. It imports
neither the core engine nor the integration fabric and can run as a single
portable file with Python 3.11 or newer.

This is **MODELED planning**, not an operational deployment. All supplied facts
are **SAMPLE** or **DECLARED**, and their provenance remains **UNVERIFIED**.
Even a `pass` means only that supplied facts meet the documented snapshot
predicate. Every capability's `operationalStatus` remains `unknown`. A source
digest is a caller declaration: this module does not fetch, authenticate, or
verify the source bytes. Missing, stale, invalid or unverified evidence never
becomes production proof. No compliance certification is claimed.

Every report and incident plan carries these constants:

```json
{
  "dryRun": true,
  "mutationCalls": 0,
  "externalWrites": "DISABLED",
  "effectors": [],
  "productionReady": false,
  "deploymentVerified": false
}
```

## Run and reuse

From the repository root:

```powershell
python -B -m defensive_control_plane.planning --snapshot docs/defensive-snapshot.example.json --as-of 2026-10-05T01:00:00Z
```

For the portable artifact, copy `planning.py` and supply your own snapshot:

```powershell
python -B planning.py --snapshot snapshot.json --as-of 2026-10-05T01:00:00Z
```

The clock is mandatory and never defaults to import time or wall time. The
example's timestamps and all-zero source digests are synthetic fixtures, not
captured estate evidence. A later assessment clock will correctly make them
stale. The CLI has no execution switch, output-path option, stdin stream,
provider observation, credential resolver, database, or external writer.
Exit 0 means a structurally valid report was produced, including reports with
`fail` or `unknown` predicates; it does not mean a passing security posture.
Exit 2 means input was rejected and no report was produced. Errors do not echo
input values, filenames, credentials, or hostile text.

The module-local API is:

```python
from defensive_control_plane.planning import assess_snapshot, SnapshotError

report = assess_snapshot(snapshot_bytes, as_of="2026-10-05T01:00:00Z")
```

`parse_snapshot(payload, *, as_of)` validates without assessing. Both APIs take
JSON bytes or text, not pre-parsed dictionaries that bypass parser checks.
The returned dictionary is data for human review; it is not a core response
envelope and cannot approve or execute one.

## Snapshot contract

The exact root fields are `schema` (`DefensivePlanningSnapshotV1`), `tenantId`,
`scope`, and `evidence`. All other fields are rejected at every object level.
There is no free-text instruction, URL, credential, script, approval, or output
path field. Rejected fields include `approved`, `approval`, `command`, `url`,
`credential`, `dryRun`, and `productionReady`. Approved-looking JSON grants no
authority. Operators must use synthetic or sanitized references; the validator
is not a general detector of secrets disguised as valid identifiers.

Limits: 256 KiB UTF-8 JSON, container depth 10, 256 evidence records, 128 asset
references and 128 identity references. Duplicate JSON keys, duplicate evidence
IDs, duplicate scope references, malformed JSON/UTF-8, nonfinite numbers,
floating-point values, negative counts, and booleans used as integers are
rejected. Integers range from 0 to 1,000,000,000. The file read is bounded to
the byte limit plus one. URL, UNC/device, alternate-stream, nonregular and
direct symlink input paths are rejected. Use an operator-controlled local
regular file; mounted filesystems and path replacement races are outside this
offline parser's trust boundary.

`scope` requires `assetIds`, `identityIds`, `assetDenominator`,
`identityDenominator`, and `complete`. Denominators are integers or null;
`complete` is a boolean or null. A denominator smaller than its listed scope is
invalid. Unknown scope or denominator yields null coverage. A complete scope
with zero subjects and no evidence yields `not_applicable` for the corresponding
subject capability. No empty or missing evidence set silently passes.

Each evidence record requires:

| Field | Contract |
|---|---|
| `id` | Unique `evidence:` reference. |
| `tenantId` | Exact root tenant; cross-tenant records are rejected. |
| `kind` | One of the seven capability names below, or `dependency`. |
| `subjectId` | Tenant for inventory/response/evidence/governance; an in-scope identity for identity; an in-scope asset for detection/backup/dependency. |
| `source` | Exact fields `id`, `sha256`, `classification`, `sourceAsOf`; optional `importedAt`. |
| `facts` | Only the fields for that kind listed below. |

Opaque IDs use their named prefix and a lowercase alphanumeric, underscore or
hyphen suffix of 1–48 characters, beginning with an alphanumeric character.
The tenant uses `tenant:`, assets `asset:`, identities `identity:`, sources
`source:`, packages `package:`, findings `finding:`. Source `sha256` must be 64
lowercase hexadecimal characters, but its binding remains unverified.
`classification` can only be `SAMPLE` or `DECLARED`.

Times use exactly `YYYY-MM-DDTHH:MM:SSZ`; naive, offset, invalid-calendar and
future source/import/recovery times are rejected. `sourceAsOf` may be null,
making freshness `missing`; `importedAt` may also be null. A non-null import
cannot precede the source time. Freshness is the age of **sourceAsOf** relative
to `--as-of`, with an inclusive fixed 86,400-second window. Importing an old
record now cannot make it current. Recovery times cannot exceed source time,
and a recovery point cannot be later than its recovery reference.

## Seven separate capability assessments

Boolean facts accept `true`, `false`, null or omission. Null and omitted facts
are unknown, distinct from false. Count/duration/target fields accept bounded
integers, null or omission. Recovery timestamps accept explicit UTC, null or
omission. Inventory and dependency binding fields listed below are required.

| Capability | Accepted facts and snapshot predicate |
|---|---|
| inventory | Required `observedAssetIds`, a unique subset of scope asset IDs. With complete scope and known denominator, all observed is pass; a shortfall is fail. |
| identity | `mfaEnabled`, `active`, `successfulAuthentication`. Explicit false MFA fails; missing MFA is unknown. Inactive plus successful authentication in the same record fails and supports suspected misuse. Otherwise this narrow predicate evaluates MFA only, not overall identity security. |
| detection | `telemetryComplete`, `eventCount`, `ruleValidationPassed`. Partial/unknown/empty telemetry is unknown; complete nonempty telemetry then uses the declared rule-validation result. It does not run or replace detectors. |
| response | `planDocumented`, `exercisePassed`. Both true pass; either false fails; otherwise unknown. No response executes. |
| backup | `backupJobSucceeded`, `restoreSucceeded`, `restoreDurationSeconds`, `rtoTargetSeconds`, `rpoTargetSeconds`, `recoveryPointAsOf`, `recoveryReferenceAsOf`. Failed restore fails. Backup job alone is unknown. Passing requires a successful restore, successful backup, known RTO/RPO values and targets met. |
| evidence | `integrityCheckPassed`, `sourceBindingComplete`. Both true pass the supplied-fact predicate; this is not the module's own verification or a signature. |
| governance | `ownerAssigned`, `reviewCurrent`. Both true pass the supplied-fact predicate; neither establishes approval or authorization. |

`dependency` records are incident inputs, not an eighth capability and not an
extra detector. Their required fields are `packageId`, `installedVersion`,
`findingVersion`, `findingId`, with optional boolean `vulnerable`.
Both version strings must be identical, begin with a digit, and contain at most
40 alphanumeric, dot, plus or hyphen characters. This is exact string binding,
not version-range resolution, package discovery, advisory fetching, or a claim
of malicious code. A missing vulnerability fact remains unknown.

Each evidence row retains its supplied-fact result separately from its current
result, provenance, and freshness. Stale/missing-time rows have current status
`unknown`. Contradictory non-null facts on the same kind/subject remain
unresolved; dependency contradictions additionally bind package, version and
finding. No newest-record override or cross-record fact stitching is used.
Historical differences may therefore require human reconciliation even if a
newer record appears complete.

Capability aggregation gives unresolved contradictions `unknown`, then records
an explicit fresh failure as `fail`. A pass requires complete scope, the full
denominator, fresh noncontradictory evidence, and every predicate passing.
Otherwise it is unknown. Coverage measures represented subjects, not detector
effectiveness: inventory uses observed assets, identity uses identities, and
detection/backup use assets. Tenant-level capabilities use denominator one.
Coverage is null if scope/denominator, evidence freshness, or any predicate is
unknown, or if contradictory; zero-denominator coverage is also null.

RTO is the supplied duration only after a successful restore. RPO is the
supplied recovery-reference time minus recovery-point time only after success.
Failed or absent restore gives null RTO/RPO; missing reference gives unknown
RPO. These are evaluations of supplied facts, not measurements taken here.

## Three human-only plans

All three templates are emitted deterministically, including when evidence is
missing. Every step has `mode: human_only`; no executable command or destination
is emitted. Each plan retains evidence IDs, subjects, freshness, contradiction
flags, declared classification and unverified provenance. Historical relevance
and current relevance are separate. Relevance means only support in supplied
facts. `incidentConfirmed` is always false, `approvalState` is `NOT_REQUESTED`,
and `executable` is false.

| Plan | Bounded hypothesis and human review |
|---|---|
| credential_misuse | Inactive identity plus successful authentication supports **suspected** misuse. Reconcile account lifecycle and authentication context before considering any separately approved control change. |
| dependency_finding | An exactly version-bound vulnerability supports a vulnerability finding. Review applicability, remediation tests and rollback before a separately reviewed dependency change. A vulnerability is not evidence of a malicious package or supply-chain attack. |
| restore_failure | A failed restore supports an availability gap. Review recovery facts and a separately authorized isolated exercise. Failure alone is not deliberate recovery inhibition or an ATT&CK T1490 attribution. |

No MFA/security-setting changes, token revocation, isolation, log transfer,
external ticket, paid job, model operation or training occurs here. Those need
distinct approval and a qualified implementation outside this planner. No
trading, legal, aircraft, weapon, or other consequential domain decision is
made by these templates.

## Civilian product-lane planning map (documentation only)

These are proposed **MODELED** uses of the same evidence contract, not new
business-lane API names, connected products or qualified integrations. The
existing `cybersecurity`, `product`, `engineering`, `data-ai`, `operations`,
`people`, and `governance` lane API is unchanged.

| Product lane | Existing business-lane context | Candidate offline evidence packet and next qualification gap |
|---|---|---|
| Lyte civilian observability | engineering, operations | Sanitized service inventory, telemetry completeness and rule-validation facts; qualify source timestamps and denominators against an authorized exporter. |
| Vessels civilian maritime | operations, cybersecurity | Shore-side service identity and restore evidence; qualify maritime data ownership and offline replay. No navigation, vehicle, aircraft or weapon control. |
| Terra real estate | product, operations | Property-service inventory and records-backup evidence; qualify tenant isolation and restore acceptance. No transaction, valuation or access-control decision. |
| Counsel legal records | governance, operations | Records-integrity, retention-process review and restore facts; qualify approved records provenance and custodial handling. No legal advice, privilege or case decision. |
| Carlota advisory | people, governance | Advisory-workspace access, review ownership and evidence completeness; qualify owner review and source lineage. No automated advisory decision. |
| Finance evidence | governance, operations | Reconciliation-source inventory, integrity and restore evidence; qualify evidence lineage and human financial review. No trading or transaction execution. |

For each proposed lane, first agree an authorized tenant and sanitized subject
scope, record known denominators or null, and supply dated facts with source
references. Review the unknowns and inert plans. Independently qualify actual
source collection, identity, restore and governance before any connector or
deployment claim. JSON declarations alone cannot close those gaps.

Existing local inventory, authenticated principals, eight detectors, the fake
test-ticket effector, backup demo and provider adapters are not duplicated.
The planner neither invokes them nor claims provider readiness. The Sentra /
Killinchu topology ambiguity in issue #25 remains outside this slice.

## Integrity and verification

Given the same input and explicit clock, output is deterministic. `inputSha256`
hashes canonical parsed JSON (sorted object keys, compact separators, ASCII
escaping, no NaN); whitespace/key-order changes do not change it. Array order
is retained in that input digest. Changed facts change the digest. The report
receipt hashes canonical report JSON excluding `receipt`. It includes the
assessment clock and fixed freshness policy via the report body.

The receipt says `signed: false`, `independentAttestation: false` and
`purpose: integrity_checksum_only`. Anyone can recompute it, including after
editing the report. It is not tamper-authentication, source authentication,
approval, an independent witness or a signed receipt.

Run the scoped and existing verification commands:

```powershell
python -B -m unittest discover -s tests -p test_planning.py -v
python -B -m unittest discover -s tests -v
python -B -m defensive_control_plane demo
python -B verify.py
```

Every scoped regression denies and checks for network, subprocess, credential,
database and effector calls. The existing demo uses disposable local SQLite and
one fake-ticket call; its result is separate from the planner's zero-call
contract. `verify.py` writes its existing ignored local evidence report. None
of these commands performs a provider `observe`, establishes deployment, or
replaces independent review of the exact proposed source head before merge.
