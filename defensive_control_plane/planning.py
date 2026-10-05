"""Bounded, unsigned, offline snapshot assessment and human-only planning.

No core/integration imports: this file can also run alone with Python 3.11+.
An assessment pass describes supplied facts, never verified operational posture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_BYTES = 262_144
MAX_DEPTH = 10
MAX_RECORDS = 256
MAX_SUBJECTS = 128
MAX_AGE_SECONDS = 86_400
CAPABILITIES = ("inventory", "identity", "detection", "response", "backup", "evidence", "governance")
SCHEMA = "DefensivePlanningSnapshotV1"
_BOOL_FIELDS = {
    "identity": ("mfaEnabled", "active", "successfulAuthentication"),
    "detection": ("telemetryComplete", "ruleValidationPassed"),
    "response": ("planDocumented", "exercisePassed"),
    "backup": ("backupJobSucceeded", "restoreSucceeded"),
    "evidence": ("integrityCheckPassed", "sourceBindingComplete"),
    "governance": ("ownerAssigned", "reviewCurrent"),
    "dependency": ("vulnerable",),
    "inventory": (),
}
_INT_FIELDS = {
    "detection": ("eventCount",),
    "backup": ("restoreDurationSeconds", "rtoTargetSeconds", "rpoTargetSeconds"),
}
_TIME_FIELDS = {"backup": ("recoveryPointAsOf", "recoveryReferenceAsOf")}
_EXTRA_FIELDS = {
    "inventory": ("observedAssetIds",),
    "dependency": ("packageId", "installedVersion", "findingVersion", "findingId"),
}


class SnapshotError(ValueError):
    """Closed validation failure; messages never include supplied values."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SnapshotError(message)


def _object(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    _require(type(value) is dict, "Expected an object.")
    _require(required <= value.keys() <= required | (optional or set()), "Unsupported or missing fields.")


def _identifier(value: Any, prefix: str) -> None:
    _require(type(value) is str and re.fullmatch(prefix + r":[a-z0-9][a-z0-9_-]{0,47}", value) is not None,
             "Invalid opaque reference.")


def _utc(value: Any) -> datetime:
    _require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
             "Expected an explicit UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form.")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise SnapshotError("Invalid UTC timestamp.") from None


def _integer(value: Any) -> None:
    _require(value is None or (type(value) is int and 0 <= value <= 1_000_000_000),
             "Expected a bounded nonnegative integer or null.")


def _refs(value: Any, prefix: str) -> None:
    _require(type(value) is list and len(value) <= MAX_SUBJECTS, "Invalid reference list.")
    for item in value:
        _identifier(item, prefix)
    _require(len(set(value)) == len(value), "Duplicate reference.")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate JSON key.")
        result[key] = value
    return result


def _no_float(value: str) -> None:
    raise SnapshotError("Floating-point and nonfinite numbers are unsupported.")


def _parse_int(value: str) -> int:
    _require(len(value) <= 10, "Integer exceeds bounds.")
    return int(value)


def _check_depth(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            _require(depth <= MAX_DEPTH, "JSON nesting exceeds limit.")
        elif character in "]}":
            depth -= 1


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def parse_snapshot(payload: bytes | str, *, as_of: str) -> dict[str, Any]:
    """Parse bounded JSON and validate all bindings against an explicit clock.

    Only JSON bytes/text enter the public assessment API, so dictionaries cannot
    bypass duplicate-key, byte, depth, or value validation.
    """
    now = _utc(as_of)
    _require(type(payload) in (bytes, str), "Expected JSON bytes or text.")
    _require(len(payload) <= MAX_BYTES, "Snapshot exceeds byte limit.")
    try:
        raw = payload if type(payload) is bytes else payload.encode("utf-8")
        _require(len(raw) <= MAX_BYTES, "Snapshot exceeds byte limit.")
        text = raw.decode("utf-8")
    except UnicodeError:
        raise SnapshotError("Snapshot must be valid UTF-8.") from None
    _check_depth(text)
    try:
        snapshot = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_float,
                              parse_float=_no_float, parse_int=_parse_int)
    except (ValueError, RecursionError) as error:
        if isinstance(error, SnapshotError):
            raise
        raise SnapshotError("Malformed JSON snapshot.") from None
    _object(snapshot, {"schema", "tenantId", "scope", "evidence"})
    _require(snapshot["schema"] == SCHEMA, "Unsupported snapshot schema.")
    tenant = snapshot["tenantId"]
    _identifier(tenant, "tenant")
    scope = snapshot["scope"]
    _object(scope, {"assetIds", "identityIds", "assetDenominator", "identityDenominator", "complete"})
    _require(scope["complete"] is None or type(scope["complete"]) is bool, "Invalid scope completeness.")
    for prefix in ("asset", "identity"):
        _refs(scope[prefix + "Ids"], prefix)
        denominator = scope[prefix + "Denominator"]
        _integer(denominator)
        _require(denominator is None or denominator >= len(scope[prefix + "Ids"]), "Scope exceeds denominator.")
    records = snapshot["evidence"]
    _require(type(records) is list and len(records) <= MAX_RECORDS, "Invalid evidence list.")
    ids: set[str] = set()
    for record in records:
        _object(record, {"id", "tenantId", "kind", "subjectId", "source", "facts"})
        _identifier(record["id"], "evidence")
        _require(record["id"] not in ids, "Duplicate evidence reference.")
        ids.add(record["id"])
        _require(record["tenantId"] == tenant, "Cross-tenant evidence is forbidden.")
        kind = record["kind"]
        _require(type(kind) is str and kind in _BOOL_FIELDS, "Unsupported evidence kind.")
        subjects = (scope["identityIds"] if kind == "identity" else scope["assetIds"]
                    if kind in ("detection", "dependency", "backup") else [tenant])
        _require(type(record["subjectId"]) is str and record["subjectId"] in subjects,
                 "Evidence subject is outside the declared scope.")
        source = record["source"]
        _object(source, {"id", "sha256", "classification", "sourceAsOf"}, {"importedAt"})
        _identifier(source["id"], "source")
        _require(type(source["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) is not None,
                 "Invalid source digest.")
        _require(type(source["classification"]) is str and source["classification"] in ("SAMPLE", "DECLARED"),
                 "Source classification must remain SAMPLE or DECLARED.")
        for field in ("sourceAsOf", "importedAt"):
            if source.get(field) is not None:
                _require(_utc(source[field]) <= now, "Future source or import timestamp.")
        if source["sourceAsOf"] is not None and source.get("importedAt") is not None:
            _require(_utc(source["sourceAsOf"]) <= _utc(source["importedAt"]), "Import precedes source time.")
        facts = record["facts"]
        allowed = set(_BOOL_FIELDS[kind] + _INT_FIELDS.get(kind, ()) + _TIME_FIELDS.get(kind, ()) + _EXTRA_FIELDS.get(kind, ()))
        required = set(_EXTRA_FIELDS.get(kind, ()))
        _object(facts, required, allowed)
        for field in _BOOL_FIELDS[kind]:
            _require(facts.get(field) is None or type(facts[field]) is bool, "Expected boolean or null fact.")
        for field in _INT_FIELDS.get(kind, ()):
            _integer(facts.get(field))
        for field in _TIME_FIELDS.get(kind, ()):
            if facts.get(field) is not None:
                moment = _utc(facts[field])
                _require(source["sourceAsOf"] is not None and moment <= _utc(source["sourceAsOf"]),
                         "Recovery timestamp exceeds source time or lacks a source time.")
        if kind == "inventory":
            _refs(facts["observedAssetIds"], "asset")
            _require(set(facts["observedAssetIds"]) <= set(scope["assetIds"]), "Inventory reference is outside scope.")
        if kind == "dependency":
            _identifier(facts["packageId"], "package")
            _identifier(facts["findingId"], "finding")
            for field in ("installedVersion", "findingVersion"):
                _require(type(facts[field]) is str and re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,39}", facts[field]) is not None,
                         "Invalid exact package version.")
            _require(facts["installedVersion"] == facts["findingVersion"], "Dependency version binding mismatch.")
        if kind == "backup" and facts.get("recoveryPointAsOf") and facts.get("recoveryReferenceAsOf"):
            _require(_utc(facts["recoveryPointAsOf"]) <= _utc(facts["recoveryReferenceAsOf"]),
                     "Recovery point is after its reference.")
    return snapshot


def _freshness(source: dict[str, Any], now: datetime) -> dict[str, Any]:
    if source["sourceAsOf"] is None:
        return {"state": "missing", "ageSeconds": None, "maxAgeSeconds": MAX_AGE_SECONDS}
    age = int((now - _utc(source["sourceAsOf"])).total_seconds())
    return {"state": "fresh" if age <= MAX_AGE_SECONDS else "stale", "ageSeconds": age,
            "maxAgeSeconds": MAX_AGE_SECONDS}


def _booleans(facts: dict[str, Any], fields: tuple[str, ...]) -> str:
    values = [facts.get(field) for field in fields]
    if any(value is False for value in values):
        return "fail"
    return "pass" if all(value is True for value in values) else "unknown"


def _recovery(facts: dict[str, Any]) -> dict[str, Any]:
    # A failed or absent restore cannot establish measured recovery time/point.
    duration = facts.get("restoreDurationSeconds") if facts.get("restoreSucceeded") is True else None
    point = facts.get("recoveryPointAsOf")
    reference = facts.get("recoveryReferenceAsOf")
    gap = int((_utc(reference) - _utc(point)).total_seconds()) if (
        facts.get("restoreSucceeded") is True and point and reference) else None
    def target_status(value: int | None, target: int | None) -> str:
        return "unknown" if value is None or target is None else "pass" if value <= target else "fail"
    return {"rtoSeconds": duration, "rtoStatus": target_status(duration, facts.get("rtoTargetSeconds")),
            "rpoSeconds": gap, "rpoStatus": target_status(gap, facts.get("rpoTargetSeconds"))}


def _predicate(record: dict[str, Any], scope: dict[str, Any]) -> str:
    kind, facts = record["kind"], record["facts"]
    if kind == "inventory":
        denominator = scope["assetDenominator"]
        if scope["complete"] is not True or denominator is None:
            return "unknown"
        return "pass" if len(facts["observedAssetIds"]) == denominator else "fail"
    if kind == "identity":
        if facts.get("active") is False and facts.get("successfulAuthentication") is True:
            return "fail"
        return _booleans(facts, ("mfaEnabled",))
    if kind == "detection":
        if facts.get("telemetryComplete") is not True or facts.get("eventCount") in (None, 0):
            return "unknown"
        return _booleans(facts, ("ruleValidationPassed",))
    if kind == "backup":
        if facts.get("restoreSucceeded") is False:
            return "fail"
        if facts.get("restoreSucceeded") is not True:
            return "unknown"
        recovery = _recovery(facts)
        statuses = [_booleans(facts, ("backupJobSucceeded",)), recovery["rtoStatus"], recovery["rpoStatus"]]
        return "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
    if kind == "dependency":
        return "unknown" if facts.get("vulnerable") is None else "fail" if facts["vulnerable"] else "pass"
    return _booleans(facts, _BOOL_FIELDS[kind])


def _contradictions(records: list[dict[str, Any]]) -> set[str]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for record in records:
        key = (record["kind"], record["subjectId"])
        if record["kind"] == "dependency":
            key += (record["facts"]["packageId"], record["facts"]["installedVersion"], record["facts"]["findingId"])
        groups.setdefault(key, []).append(record)
    conflicts: set[str] = set()
    for group in groups.values():
        fields = {field for record in group for field in record["facts"]}
        for field in fields:
            values = {_canonical(sorted(value) if type(value) is list else value)
                      for record in group if (value := record["facts"].get(field)) is not None}
            if len(values) > 1:
                conflicts.update(record["id"] for record in group)
    return conflicts


def _boundary() -> dict[str, Any]:
    return {"dryRun": True, "mutationCalls": 0, "externalWrites": "DISABLED", "effectors": [],
            "productionReady": False, "deploymentVerified": False}


_PLAN_STEPS = {
    "credential_misuse": (
        "Have the authorized owner reconcile account lifecycle and authentication evidence.",
        "Have an independent reviewer assess context before classifying suspected misuse.",
        "Any credential or security-setting change needs distinct approval and a qualified control path.",
    ),
    "dependency_finding": (
        "Have the maintainer verify the exact installed package and version against the finding.",
        "Review applicability and a proposed remediation with its test and rollback evidence.",
        "Any dependency change needs separate source review; vulnerability alone does not establish malicious code.",
    ),
    "restore_failure": (
        "Have the recovery owner reconcile restore outcome, recovery point, and timing evidence.",
        "Review a separately authorized isolated restore exercise and its acceptance criteria.",
        "Treat failure as an availability gap; deliberate recovery inhibition requires separate evidence.",
    ),
}


def _plans(records: list[dict[str, Any]], rows: dict[str, dict[str, Any]], tenant: str) -> list[dict[str, Any]]:
    plans = []
    for name, kind, hypothesis in (
        ("credential_misuse", "identity", "suspected_misuse"),
        ("dependency_finding", "dependency", "vulnerability_finding"),
        ("restore_failure", "backup", "availability_gap"),
    ):
        candidates = []
        for record in records:
            facts = record["facts"]
            supported = (facts.get("active") is False and facts.get("successfulAuthentication") is True
                         if name == "credential_misuse" else facts.get("vulnerable") is True
                         if name == "dependency_finding" else facts.get("restoreSucceeded") is False)
            if record["kind"] == kind and supported:
                row = rows[record["id"]]
                candidates.append({"evidenceId": record["id"], "subjectId": record["subjectId"],
                                   "freshness": row["freshness"]["state"], "contradictory": row["contradictory"],
                                   "classification": row["provenance"]["classification"],
                                   "verification": "UNVERIFIED"})
        unresolved = any(item["contradictory"] for item in candidates)
        plans.append({"id": name, "tenantId": tenant, "state": "MODELED", "hypothesis": hypothesis,
                      "historicalRelevance": "unresolved" if unresolved else "supported_by_supplied_facts" if candidates else "unknown",
                      "currentRelevance": "unresolved" if unresolved else "supported_by_supplied_facts" if any(
                          item["freshness"] == "fresh" for item in candidates) else "unknown",
                      "incidentConfirmed": False, "approvalState": "NOT_REQUESTED", "executable": False,
                      "evidence": candidates, "steps": [{"mode": "human_only", "text": text} for text in _PLAN_STEPS[name]],
                      **_boundary()})
    return plans


def assess_snapshot(payload: bytes | str, *, as_of: str) -> dict[str, Any]:
    """Return deterministic snapshot predicates, evidence gaps, and inert plans."""
    snapshot = parse_snapshot(payload, as_of=as_of)
    now = _utc(as_of)
    scope = snapshot["scope"]
    records = sorted(snapshot["evidence"], key=lambda record: record["id"])
    conflicts = _contradictions(records)
    rows: dict[str, dict[str, Any]] = {}
    for record in records:
        freshness = _freshness(record["source"], now)
        predicate = _predicate(record, scope)
        contradictory = record["id"] in conflicts
        row = {"id": record["id"], "kind": record["kind"], "subjectId": record["subjectId"],
               "suppliedFactStatus": predicate, "status": "unknown" if contradictory or freshness["state"] != "fresh" else predicate,
               "contradictory": contradictory, "freshness": freshness,
               "provenance": {**record["source"], "verification": "UNVERIFIED", "digestBindingVerified": False}}
        if record["kind"] == "backup":
            row["recovery"] = _recovery(record["facts"])
        if record["kind"] == "dependency":
            row["binding"] = {field: record["facts"][field] for field in _EXTRA_FIELDS["dependency"]}
        rows[record["id"]] = row
    capabilities = []
    for capability in CAPABILITIES:
        selected = [rows[record["id"]] for record in records if record["kind"] == capability]
        prefix = "identity" if capability == "identity" else "asset" if capability in ("inventory", "detection", "backup") else None
        denominator = scope[prefix + "Denominator"] if prefix else 1
        scoped = scope["complete"] is True and denominator is not None
        subjects = {row["subjectId"] for row in selected}
        if capability == "inventory":
            observed = {asset for record in records if record["kind"] == "inventory" for asset in record["facts"]["observedAssetIds"]}
            count = len(observed)
        else:
            count = len(subjects)
        usable = bool(selected) and all(row["freshness"]["state"] == "fresh" and not row["contradictory"]
                                        and row["status"] != "unknown" for row in selected)
        coverage = count / denominator if scoped and denominator and usable else None
        statuses = [row["status"] for row in selected]
        if any(row["contradictory"] for row in selected):
            status = "unknown"
        elif scoped and denominator == 0 and not selected:
            status = "not_applicable"
        elif "fail" in statuses:
            status = "fail"
        elif not usable or not scoped or count != denominator or "unknown" in statuses:
            status = "unknown"
        else:
            status = "pass"
        capabilities.append({"capability": capability, "status": status, "scope": "supplied_snapshot_predicates_only",
                             "operationalStatus": "unknown", "evidenceIds": [row["id"] for row in selected],
                             "coverage": coverage, "denominator": denominator, "observedSubjects": count,
                             "provenanceClasses": sorted({row["provenance"]["classification"] for row in selected}),
                             "verification": "UNVERIFIED", "contradictionsUnresolved": any(row["contradictory"] for row in selected)})
    report = {"schema": "DefensivePlanningReportV1", "tenantId": snapshot["tenantId"], "assessedAt": as_of,
              "state": "MODELED", "inputSha256": _digest(snapshot), "policy": {"maxAgeSeconds": MAX_AGE_SECONDS},
              "capabilities": capabilities, "evidence": list(rows.values()),
              "plans": _plans(records, rows, snapshot["tenantId"]), **_boundary()}
    report["receipt"] = {"algorithm": "sha256", "reportSha256": _digest(report), "signed": False,
                         "independentAttestation": False, "purpose": "integrity_checksum_only",
                         "scope": "canonical_report_without_receipt"}
    return report


def _read_snapshot(path: str) -> bytes:
    # Reject URL/UNC/device paths; snapshot strings never select a path themselves.
    _require("://" not in path and not path.startswith(("\\\\", "//")) and "\x00" not in path,
             "A local regular snapshot file is required.")
    source = Path(path)
    # Reject alternate data streams while permitting an ordinary Windows drive.
    _require(":" not in str(source)[len(source.drive):], "A local regular snapshot file is required.")
    _require(not source.is_symlink(), "Snapshot symlinks are unsupported.")
    metadata = source.stat()
    _require(stat.S_ISREG(metadata.st_mode), "A local regular snapshot file is required.")
    _require(metadata.st_size <= MAX_BYTES, "Snapshot exceeds byte limit.")
    with source.open("rb") as handle:
        return handle.read(MAX_BYTES + 1)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "planning: invalid arguments; use --help.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="Assess explicit offline evidence and print human-only plans; no execution.", allow_abbrev=False)
    parser.add_argument("--snapshot", required=True, help="explicit local JSON file, at most 256 KiB")
    parser.add_argument("--as-of", required=True, help="assessment UTC time: YYYY-MM-DDTHH:MM:SSZ")
    args = parser.parse_args(argv)
    try:
        # Validate clock before reading the only operator-selected input file.
        _utc(args.as_of)
        report = assess_snapshot(_read_snapshot(args.snapshot), as_of=args.as_of)
    except (SnapshotError, OSError):
        print("planning: rejected snapshot, file, or timestamp; no plan produced.", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
