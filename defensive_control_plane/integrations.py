from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


MANIFEST_SCHEMA = "szl.defensive-integrations/v1"
STATUS_SCHEMA = "szl.defensive-integrations-status/v1"
OBSERVATION_SCHEMA = "szl.defensive-connector-observation/v1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_BINDINGS = 128
MAX_RECORDS = 100
_SECRET_REF = re.compile(r"^env://[A-Z][A-Z0-9_]{0,127}$")
_RESOURCE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_AZURE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._()-]{0,88}[A-Za-z0-9)]$")
_AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_SAFE_PATH = re.compile(r"^/api/[A-Za-z0-9._~!$&'()*+,;=:@%/?=-]{1,400}$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class IntegrationError(RuntimeError):
    """Base class for governed integration failures."""


class IntegrationValidationError(IntegrationError):
    """The binding or provider contract is invalid."""


class AuthenticationRequired(IntegrationError):
    """A required secret reference is absent or unresolved."""


class ProviderTransportError(IntegrationError):
    """A provider could not be observed safely."""


class IntegrationState(str, Enum):
    DISABLED = "DISABLED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    READY = "READY"
    OBSERVED = "OBSERVED"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_CONFIG = "INVALID_CONFIG"


@dataclass(frozen=True)
class ProviderContract:
    provider_id: str
    display_name: str
    required_resources: tuple[str, ...]
    required_secrets: tuple[str, ...]
    default_base_url: str | None
    exact_hosts: tuple[str, ...] = ()
    host_suffixes: tuple[str, ...] = ()
    method: str = "GET"
    semantic_operation: str = "READ"
    documentation: str = ""
    external_writes: str = "DISABLED"
    effectors: tuple[str, ...] = ()


@dataclass(frozen=True)
class TenantConnectorBinding:
    tenant_id: str
    provider_id: str
    enabled: bool = True
    base_url: str | None = None
    resources: Mapping[str, str] = field(default_factory=dict)
    secret_refs: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TenantConnectorBinding":
        if not isinstance(value, Mapping):
            raise IntegrationValidationError("binding must be an object")
        tenant_id = value.get("tenant_id")
        provider_id = value.get("provider_id")
        enabled = value.get("enabled", True)
        base_url = value.get("base_url")
        resources = value.get("resources", {})
        secret_refs = value.get("secret_refs", {})
        if not isinstance(tenant_id, str) or not _RESOURCE_TOKEN.fullmatch(tenant_id):
            raise IntegrationValidationError("tenant_id must be a bounded identifier")
        if not isinstance(provider_id, str) or not _RESOURCE_TOKEN.fullmatch(provider_id):
            raise IntegrationValidationError("provider_id must be a bounded identifier")
        if not isinstance(enabled, bool):
            raise IntegrationValidationError("enabled must be boolean")
        if base_url is not None and not isinstance(base_url, str):
            raise IntegrationValidationError("base_url must be a string when present")
        if not isinstance(resources, Mapping) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in resources.items()
        ):
            raise IntegrationValidationError("resources must map strings to strings")
        if not isinstance(secret_refs, Mapping) or not all(
            isinstance(key, str)
            and isinstance(item, str)
            and _SECRET_REF.fullmatch(item)
            for key, item in secret_refs.items()
        ):
            raise IntegrationValidationError(
                "secret_refs must contain env:// references, never secret values"
            )
        return cls(
            tenant_id=tenant_id,
            provider_id=provider_id,
            enabled=enabled,
            base_url=base_url,
            resources=dict(resources),
            secret_refs=dict(secret_refs),
        )


@dataclass(frozen=True)
class IntegrationManifest:
    bindings: tuple[TenantConnectorBinding, ...]
    approved_private_endpoints: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "IntegrationManifest":
        if not isinstance(value, Mapping) or value.get("schema") != MANIFEST_SCHEMA:
            raise IntegrationValidationError(f"manifest schema must be {MANIFEST_SCHEMA}")
        raw_bindings = value.get("bindings")
        if not isinstance(raw_bindings, list) or len(raw_bindings) > MAX_BINDINGS:
            raise IntegrationValidationError(
                f"bindings must be a list with at most {MAX_BINDINGS} entries"
            )
        bindings = tuple(TenantConnectorBinding.from_mapping(item) for item in raw_bindings)
        identities = [(item.tenant_id, item.provider_id) for item in bindings]
        if len(identities) != len(set(identities)):
            raise IntegrationValidationError("tenant/provider bindings must be unique")

        raw_approved = value.get("approved_private_endpoints", {})
        if not isinstance(raw_approved, Mapping):
            raise IntegrationValidationError("approved_private_endpoints must be an object")
        approved: dict[str, tuple[str, ...]] = {}
        for provider_id, entries in raw_approved.items():
            if provider_id not in {"registered_cmdb", "registered_siem"}:
                raise IntegrationValidationError(
                    "private endpoint approvals are limited to registered_cmdb and registered_siem"
                )
            if not isinstance(entries, list) or not entries:
                raise IntegrationValidationError(
                    f"{provider_id} approvals must be a non-empty list"
                )
            normalized = tuple(sorted({_normalize_base_url(item) for item in entries}))
            approved[provider_id] = normalized
        return cls(bindings=bindings, approved_private_endpoints=approved)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "IntegrationManifest":
        source = Path(path)
        if not source.is_file():
            raise IntegrationValidationError(f"integration manifest not found: {source}")
        if source.stat().st_size > 512 * 1024:
            raise IntegrationValidationError("integration manifest exceeds 512 KiB")
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrationValidationError("integration manifest is not valid JSON") from exc
        return cls.from_mapping(payload)


@dataclass(frozen=True)
class RequestPlan:
    provider_id: str
    tenant_id: str
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    semantic_operation: str
    endpoint_fingerprint: str


@dataclass(frozen=True)
class TransportResult:
    status_code: int
    payload: Any
    response_sha256: str
    byte_count: int
    latency_ms: int
    request_id: str | None = None


class SecretResolver(Protocol):
    def __call__(self, reference: str) -> str | None:
        """Resolve one secret reference without persisting the value."""


class Transport(Protocol):
    def execute(self, plan: RequestPlan) -> TransportResult:
        """Execute one already-validated provider request."""


class EnvironmentSecretResolver:
    """Resolve only explicit env:// references."""

    def __call__(self, reference: str) -> str | None:
        if not _SECRET_REF.fullmatch(reference):
            raise IntegrationValidationError("invalid secret reference")
        value = os.environ.get(reference.removeprefix("env://"))
        return value if value else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class StdlibJsonTransport:
    """Bounded HTTPS JSON transport with redirects disabled."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if not 0 < float(timeout_seconds) <= 60:
            raise IntegrationValidationError("timeout must be between 0 and 60 seconds")
        if not 1024 <= max_response_bytes <= 16 * 1024 * 1024:
            raise IntegrationValidationError("response byte limit is outside the safe range")
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = int(max_response_bytes)
        self._opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def execute(self, plan: RequestPlan) -> TransportResult:
        parsed = urllib.parse.urlsplit(plan.url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ProviderTransportError("provider request is not approved HTTPS")
        request = urllib.request.Request(
            plan.url,
            data=plan.body,
            headers=dict(plan.headers),
            method=plan.method,
        )
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                status = int(response.status)
                if not 200 <= status < 300:
                    raise ProviderTransportError(f"provider returned HTTP {status}")
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > self.max_response_bytes:
                    raise ProviderTransportError("provider response exceeds byte limit")
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise ProviderTransportError("provider response exceeds byte limit")
                final_url = response.geturl()
                if final_url != plan.url:
                    raise ProviderTransportError("provider attempted a redirect")
                request_id = _first_header(
                    response.headers,
                    (
                        "request-id",
                        "x-request-id",
                        "x-ms-request-id",
                        "x-amzn-requestid",
                        "x-okta-request-id",
                        "x-seraph-loginreason",
                    ),
                )
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise AuthenticationRequired(
                    f"{plan.provider_id} rejected the configured credential"
                ) from None
            raise ProviderTransportError(
                f"{plan.provider_id} returned HTTP {exc.code}"
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ProviderTransportError(
                f"{plan.provider_id} transport unavailable: {type(exc).__name__}"
            ) from None
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda value: (_raise_invalid_constant(value)),
            )
        except (UnicodeError, ValueError, RecursionError, IntegrationValidationError):
            raise ProviderTransportError(
                f"{plan.provider_id} returned invalid JSON"
            ) from None
        latency_ms = max(0, int((time.monotonic() - started) * 1000))
        return TransportResult(
            status_code=status,
            payload=payload,
            response_sha256=hashlib.sha256(raw).hexdigest(),
            byte_count=len(raw),
            latency_ms=latency_ms,
            request_id=request_id,
        )


class GovernedIntegrationPlane:
    """Tenant-isolated, read-only provider observation plane."""

    def __init__(
        self,
        manifest: IntegrationManifest,
        *,
        secret_resolver: SecretResolver | None = None,
        transport: Transport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.manifest = manifest
        self.secret_resolver = secret_resolver or EnvironmentSecretResolver()
        self.transport = transport or StdlibJsonTransport()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        unknown = sorted(
            {binding.provider_id for binding in manifest.bindings} - set(PROVIDER_CONTRACTS)
        )
        if unknown:
            raise IntegrationValidationError(
                "unknown provider contract(s): " + ", ".join(unknown)
            )
        for binding in manifest.bindings:
            self._validate_binding(binding)

    @classmethod
    def from_json_file(
        cls,
        path: str | Path,
        **kwargs: Any,
    ) -> "GovernedIntegrationPlane":
        return cls(IntegrationManifest.from_json_file(path), **kwargs)

    def statuses(self) -> dict[str, Any]:
        connectors = [self._status(binding) for binding in self.manifest.bindings]
        aggregate = _aggregate_state(item["state"] for item in connectors)
        return {
            "schema": STATUS_SCHEMA,
            "state": aggregate,
            "connector_count": len(connectors),
            "connectors": connectors,
            "external_writes": "DISABLED",
            "effectors": [],
            "automatic_remediation": False,
            "production_authorization": False,
        }

    def observe(
        self,
        *,
        tenant_id: str | None = None,
        provider_id: str | None = None,
    ) -> dict[str, Any]:
        selected = [
            binding
            for binding in self.manifest.bindings
            if (tenant_id is None or binding.tenant_id == tenant_id)
            and (provider_id is None or binding.provider_id == provider_id)
        ]
        if not selected:
            raise IntegrationValidationError("no integration binding matched the selector")
        observations = [self._observe_one(binding) for binding in selected]
        report: dict[str, Any] = {
            "schema": "szl.defensive-connector-observation-batch/v1",
            "observed_at": _iso(self.clock()),
            "state": _aggregate_state(item["state"] for item in observations),
            "observations": observations,
            "external_writes": "DISABLED",
            "effectors": [],
        }
        report["receipt_sha256"] = _digest(report)
        return report

    def build_request_plan(self, binding: TenantConnectorBinding) -> RequestPlan:
        self._validate_binding(binding)
        if not binding.enabled:
            raise IntegrationValidationError("disabled connector cannot build a request")
        contract = PROVIDER_CONTRACTS[binding.provider_id]
        secrets = self._resolve_secrets(binding, contract)
        if binding.provider_id == "aws_security_hub":
            return self._aws_security_hub_plan(binding, secrets)
        return self._http_plan(binding, contract, secrets)

    def _status(self, binding: TenantConnectorBinding) -> dict[str, Any]:
        contract = PROVIDER_CONTRACTS[binding.provider_id]
        missing_references = [
            key for key in contract.required_secrets if key not in binding.secret_refs
        ]
        unresolved = []
        for key in contract.required_secrets:
            reference = binding.secret_refs.get(key)
            if reference and not self.secret_resolver(reference):
                unresolved.append(key)
        if not binding.enabled:
            state = IntegrationState.DISABLED.value
        elif missing_references or unresolved:
            state = IntegrationState.AUTH_REQUIRED.value
        else:
            state = IntegrationState.READY.value
        return {
            "tenant_id": binding.tenant_id,
            "provider_id": binding.provider_id,
            "display_name": contract.display_name,
            "state": state,
            "missing_secret_references": sorted(missing_references),
            "unresolved_secret_references": sorted(unresolved),
            "required_resources": list(contract.required_resources),
            "configured_resources": sorted(binding.resources),
            "endpoint_fingerprint": self._endpoint_fingerprint(binding),
            "semantic_operation": contract.semantic_operation,
            "http_method": contract.method,
            "external_writes": contract.external_writes,
            "effectors": list(contract.effectors),
        }

    def _observe_one(self, binding: TenantConnectorBinding) -> dict[str, Any]:
        observed_at = _iso(self.clock())
        if not binding.enabled:
            result = {
                "schema": OBSERVATION_SCHEMA,
                "tenant_id": binding.tenant_id,
                "provider_id": binding.provider_id,
                "state": IntegrationState.DISABLED.value,
                "observed_at": observed_at,
                "external_writes": "DISABLED",
                "effectors": [],
            }
            result["receipt_sha256"] = _digest(result)
            return result
        try:
            plan = self.build_request_plan(binding)
            response = self.transport.execute(plan)
            result = {
                "schema": OBSERVATION_SCHEMA,
                "tenant_id": binding.tenant_id,
                "provider_id": binding.provider_id,
                "state": IntegrationState.OBSERVED.value,
                "observed_at": observed_at,
                "endpoint_fingerprint": plan.endpoint_fingerprint,
                "semantic_operation": plan.semantic_operation,
                "http_method": plan.method,
                "status_code": response.status_code,
                "record_count": _record_count(response.payload),
                "response_sha256": response.response_sha256,
                "byte_count": response.byte_count,
                "latency_ms": response.latency_ms,
                "request_id": response.request_id,
                "external_writes": "DISABLED",
                "effectors": [],
            }
        except AuthenticationRequired as exc:
            result = self._failure_observation(
                binding,
                observed_at,
                IntegrationState.AUTH_REQUIRED,
                str(exc),
            )
        except (IntegrationValidationError, ProviderTransportError) as exc:
            state = (
                IntegrationState.INVALID_CONFIG
                if isinstance(exc, IntegrationValidationError)
                else IntegrationState.UNAVAILABLE
            )
            result = self._failure_observation(binding, observed_at, state, str(exc))
        result["receipt_sha256"] = _digest(result)
        return result

    @staticmethod
    def _failure_observation(
        binding: TenantConnectorBinding,
        observed_at: str,
        state: IntegrationState,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "schema": OBSERVATION_SCHEMA,
            "tenant_id": binding.tenant_id,
            "provider_id": binding.provider_id,
            "state": state.value,
            "observed_at": observed_at,
            "reason": reason[:240],
            "external_writes": "DISABLED",
            "effectors": [],
        }

    def _validate_binding(self, binding: TenantConnectorBinding) -> None:
        contract = PROVIDER_CONTRACTS[binding.provider_id]
        missing_resources = [
            key
            for key in contract.required_resources
            if not binding.resources.get(key)
        ]
        if missing_resources:
            raise IntegrationValidationError(
                f"{binding.provider_id} missing resource(s): {', '.join(missing_resources)}"
            )
        for key, value in binding.resources.items():
            if not isinstance(value, str) or not value or len(value) > 512:
                raise IntegrationValidationError(f"invalid resource value: {key}")
            _validate_resource(binding.provider_id, key, value)
        if binding.provider_id != "aws_security_hub":
            self._validated_base(binding, contract)

    def _resolve_secrets(
        self,
        binding: TenantConnectorBinding,
        contract: ProviderContract,
    ) -> dict[str, str]:
        values: dict[str, str] = {}
        for key in contract.required_secrets:
            reference = binding.secret_refs.get(key)
            if not reference:
                raise AuthenticationRequired(
                    f"{binding.provider_id} requires secret reference {key}"
                )
            value = self.secret_resolver(reference)
            if not value:
                raise AuthenticationRequired(
                    f"{binding.provider_id} secret reference {key} is unresolved"
                )
            values[key] = value
        optional_session = binding.secret_refs.get("session_token")
        if optional_session:
            value = self.secret_resolver(optional_session)
            if value:
                values["session_token"] = value
        return values

    def _http_plan(
        self,
        binding: TenantConnectorBinding,
        contract: ProviderContract,
        secrets: Mapping[str, str],
    ) -> RequestPlan:
        base_url = self._validated_base(binding, contract)
        path, body, extra_headers = _provider_request(binding)
        url = _join_url(base_url, path)
        headers = {
            "Accept": "application/json",
            "User-Agent": "SZL-Defensive-Control-Plane/0.5",
            "Authorization": f"Bearer {secrets['token']}",
        }
        headers.update(extra_headers)
        return RequestPlan(
            provider_id=binding.provider_id,
            tenant_id=binding.tenant_id,
            method=contract.method,
            url=url,
            headers=headers,
            body=body,
            semantic_operation=contract.semantic_operation,
            endpoint_fingerprint=_endpoint_fingerprint(url),
        )

    def _aws_security_hub_plan(
        self,
        binding: TenantConnectorBinding,
        secrets: Mapping[str, str],
    ) -> RequestPlan:
        region = binding.resources["region"]
        partition = binding.resources.get("partition", "aws")
        suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
        host = f"securityhub.{region}.{suffix}"
        url = f"https://{host}/findings"
        body = _canonical_json({"MaxResults": min(MAX_RECORDS, 100)})
        now = self.clock().astimezone(timezone.utc)
        headers = _aws_sigv4_headers(
            method="POST",
            url=url,
            body=body,
            region=region,
            service="securityhub",
            access_key_id=secrets["access_key_id"],
            secret_access_key=secrets["secret_access_key"],
            session_token=secrets.get("session_token"),
            now=now,
            extra_headers={
                "content-type": "application/json",
            },
        )
        headers["Accept"] = "application/json"
        headers["User-Agent"] = "SZL-Defensive-Control-Plane/0.5"
        return RequestPlan(
            provider_id=binding.provider_id,
            tenant_id=binding.tenant_id,
            method="POST",
            url=url,
            headers=headers,
            body=body,
            semantic_operation="READ",
            endpoint_fingerprint=_endpoint_fingerprint(url),
        )

    def _validated_base(
        self,
        binding: TenantConnectorBinding,
        contract: ProviderContract,
    ) -> str:
        raw = binding.base_url or contract.default_base_url
        if not raw:
            raise IntegrationValidationError(
                f"{binding.provider_id} requires an approved base_url"
            )
        normalized = _normalize_base_url(raw)
        hostname = urllib.parse.urlsplit(normalized).hostname or ""
        if contract.exact_hosts and hostname not in contract.exact_hosts:
            raise IntegrationValidationError(
                f"{binding.provider_id} host is outside the fixed allowlist"
            )
        if contract.host_suffixes and not any(
            hostname.endswith(suffix) and hostname != suffix.lstrip(".")
            for suffix in contract.host_suffixes
        ):
            raise IntegrationValidationError(
                f"{binding.provider_id} host is outside the provider domain"
            )
        if binding.provider_id in {"registered_cmdb", "registered_siem"}:
            approved = self.manifest.approved_private_endpoints.get(binding.provider_id, ())
            if normalized not in approved:
                raise IntegrationValidationError(
                    f"{binding.provider_id} endpoint is not in the administrator allowlist"
                )
        return normalized

    def _endpoint_fingerprint(self, binding: TenantConnectorBinding) -> str:
        contract = PROVIDER_CONTRACTS[binding.provider_id]
        if binding.provider_id == "aws_security_hub":
            region = binding.resources["region"]
            partition = binding.resources.get("partition", "aws")
            suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
            return _endpoint_fingerprint(f"https://securityhub.{region}.{suffix}/")
        return _endpoint_fingerprint(self._validated_base(binding, contract))


PROVIDER_CONTRACTS: dict[str, ProviderContract] = {
    "microsoft_defender_xdr": ProviderContract(
        "microsoft_defender_xdr",
        "Microsoft Defender XDR",
        (),
        ("token",),
        "https://graph.microsoft.com",
        exact_hosts=("graph.microsoft.com",),
        documentation="Microsoft Graph /v1.0/security/incidents",
    ),
    "microsoft_entra_id": ProviderContract(
        "microsoft_entra_id",
        "Microsoft Entra ID",
        (),
        ("token",),
        "https://graph.microsoft.com",
        exact_hosts=("graph.microsoft.com",),
        documentation="Microsoft Graph /v1.0/auditLogs/signIns",
    ),
    "microsoft_intune": ProviderContract(
        "microsoft_intune",
        "Microsoft Intune",
        (),
        ("token",),
        "https://graph.microsoft.com",
        exact_hosts=("graph.microsoft.com",),
        documentation="Microsoft Graph /v1.0/deviceManagement/managedDevices",
    ),
    "microsoft_sentinel": ProviderContract(
        "microsoft_sentinel",
        "Microsoft Sentinel",
        ("subscription_id", "resource_group", "workspace"),
        ("token",),
        "https://management.azure.com",
        exact_hosts=("management.azure.com",),
        documentation="Security Insights incidents list 2025-09-01",
    ),
    "azure_defender_cloud": ProviderContract(
        "azure_defender_cloud",
        "Microsoft Defender for Cloud",
        ("subscription_id",),
        ("token",),
        "https://management.azure.com",
        exact_hosts=("management.azure.com",),
        documentation="Microsoft.Security assessments list",
    ),
    "crowdstrike_falcon": ProviderContract(
        "crowdstrike_falcon",
        "CrowdStrike Falcon",
        (),
        ("token",),
        None,
        exact_hosts=(
            "api.crowdstrike.com",
            "api.us-2.crowdstrike.com",
            "api.eu-1.crowdstrike.com",
            "api.laggar.gcw.crowdstrike.com",
        ),
        documentation="Falcon Alerts query v2",
    ),
    "wiz": ProviderContract(
        "wiz",
        "Wiz",
        (),
        ("token",),
        None,
        host_suffixes=(".app.wiz.io",),
        method="POST",
        documentation="Wiz GraphQL fixed read-only issue query",
    ),
    "okta": ProviderContract(
        "okta",
        "Okta",
        (),
        ("token",),
        None,
        host_suffixes=(
            ".okta.com",
            ".okta-emea.com",
            ".oktapreview.com",
            ".okta-gov.com",
        ),
        documentation="Okta System Log /api/v1/logs",
    ),
    "aws_security_hub": ProviderContract(
        "aws_security_hub",
        "AWS Security Hub",
        ("region",),
        ("access_key_id", "secret_access_key"),
        None,
        method="POST",
        documentation="AWS Security Hub GetFindings",
    ),
    "gcp_security_command_center": ProviderContract(
        "gcp_security_command_center",
        "Google Cloud Security Command Center",
        ("organization_id",),
        ("token",),
        "https://securitycenter.googleapis.com",
        exact_hosts=("securitycenter.googleapis.com",),
        documentation="SCC v2 findings list",
    ),
    "servicenow": ProviderContract(
        "servicenow",
        "ServiceNow",
        (),
        ("token",),
        None,
        host_suffixes=(".service-now.com",),
        documentation="ServiceNow Table API incident GET",
    ),
    "jira_cloud": ProviderContract(
        "jira_cloud",
        "Jira Cloud",
        (),
        ("token",),
        None,
        host_suffixes=(".atlassian.net",),
        documentation="Jira REST v3 enhanced JQL search",
    ),
    "registered_cmdb": ProviderContract(
        "registered_cmdb",
        "Registered CMDB",
        ("collection_path",),
        ("token",),
        None,
        documentation="Administrator-approved private CMDB collection",
    ),
    "registered_siem": ProviderContract(
        "registered_siem",
        "Registered SIEM",
        ("collection_path",),
        ("token",),
        None,
        documentation="Administrator-approved private SIEM collection",
    ),
}


def _provider_request(
    binding: TenantConnectorBinding,
) -> tuple[str, bytes | None, dict[str, str]]:
    provider_id = binding.provider_id
    if provider_id == "microsoft_defender_xdr":
        return "/v1.0/security/incidents?%24top=50", None, {}
    if provider_id == "microsoft_entra_id":
        return "/v1.0/auditLogs/signIns?%24top=50", None, {}
    if provider_id == "microsoft_intune":
        return "/v1.0/deviceManagement/managedDevices?%24top=50", None, {}
    if provider_id == "microsoft_sentinel":
        subscription = urllib.parse.quote(binding.resources["subscription_id"], safe="")
        group = urllib.parse.quote(binding.resources["resource_group"], safe="")
        workspace = urllib.parse.quote(binding.resources["workspace"], safe="")
        return (
            f"/subscriptions/{subscription}/resourceGroups/{group}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{workspace}/providers/"
            "Microsoft.SecurityInsights/incidents"
            "?api-version=2025-09-01&%24top=100"
            "&%24orderby=properties%2FlastModifiedTimeUtc%20desc",
            None,
            {},
        )
    if provider_id == "azure_defender_cloud":
        subscription = urllib.parse.quote(binding.resources["subscription_id"], safe="")
        return (
            f"/subscriptions/{subscription}/providers/Microsoft.Security/assessments"
            "?api-version=2020-01-01",
            None,
            {},
        )
    if provider_id == "crowdstrike_falcon":
        return (
            "/alerts/queries/alerts/v2?limit=100&sort=created_timestamp.desc",
            None,
            {},
        )
    if provider_id == "wiz":
        query = (
            "query SzlReadOnlyIssues($first:Int!){"
            "issues(first:$first){nodes{id severity status createdAt updatedAt}"
            "pageInfo{hasNextPage endCursor}}}"
        )
        body = _canonical_json({"query": query, "variables": {"first": 100}})
        return "/graphql", body, {"Content-Type": "application/json"}
    if provider_id == "okta":
        return "/api/v1/logs?limit=100&sortOrder=DESCENDING", None, {}
    if provider_id == "gcp_security_command_center":
        organization = urllib.parse.quote(binding.resources["organization_id"], safe="")
        return (
            f"/v2/organizations/{organization}/sources/-/locations/global/findings"
            "?pageSize=100&orderBy=eventTime%20desc",
            None,
            {},
        )
    if provider_id == "servicenow":
        return (
            "/api/now/v1/table/incident?sysparm_limit=100"
            "&sysparm_query=active%3Dtrue%5EORDERBYDESCsys_updated_on"
            "&sysparm_fields=sys_id%2Cnumber%2Cshort_description%2Cstate%2C"
            "severity%2Cpriority%2Csys_updated_on",
            None,
            {},
        )
    if provider_id == "jira_cloud":
        return (
            "/rest/api/3/search/jql?jql=updated%20%3E%3D%20-7d%20"
            "ORDER%20BY%20updated%20DESC&maxResults=100"
            "&fields=summary%2Cstatus%2Cpriority%2Cupdated",
            None,
            {},
        )
    if provider_id in {"registered_cmdb", "registered_siem"}:
        return binding.resources["collection_path"], None, {}
    raise IntegrationValidationError(f"no request template for {provider_id}")


def _validate_resource(provider_id: str, key: str, value: str) -> None:
    if key == "subscription_id" and not _UUID.fullmatch(value):
        raise IntegrationValidationError("subscription_id must be a UUID")
    if key in {"resource_group", "workspace"} and not _AZURE_NAME.fullmatch(value):
        raise IntegrationValidationError(f"{key} has invalid Azure resource syntax")
    if key == "organization_id" and (not value.isdigit() or len(value) > 30):
        raise IntegrationValidationError("organization_id must be numeric")
    if key == "region" and not _AWS_REGION.fullmatch(value):
        raise IntegrationValidationError("region is not a valid AWS region identifier")
    if key == "partition" and value not in {"aws", "aws-us-gov", "aws-cn"}:
        raise IntegrationValidationError("partition is not supported")
    if key == "collection_path":
        if (
            not _SAFE_PATH.fullmatch(value)
            or ".." in value
            or value.startswith("//")
            or "#" in value
        ):
            raise IntegrationValidationError(
                f"{provider_id} collection_path must be a bounded /api/ path"
            )


def _normalize_base_url(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or len(value) > 512:
        raise IntegrationValidationError("base URL must be a bounded exact string")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise IntegrationValidationError(
            "base URL must be an origin-only HTTPS URL without credentials or a port"
        )
    hostname = parsed.hostname.lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise IntegrationValidationError("provider base URL cannot be an IP literal")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise IntegrationValidationError("provider base URL cannot target localhost")
    return f"https://{hostname}"


def _join_url(base_url: str, path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or ".." in path:
        raise IntegrationValidationError("provider path is not bounded")
    return base_url.rstrip("/") + path


def _endpoint_fingerprint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    value = f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"
    if parsed.query:
        value = f"{value}?{parsed.query}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record_count(payload: Any) -> int:
    if isinstance(payload, list):
        return min(len(payload), MAX_RECORDS)
    if not isinstance(payload, Mapping):
        return 0
    for key in ("value", "items", "findings", "Findings", "resources", "Resources", "result", "issues"):
        value = payload.get(key)
        if isinstance(value, list):
            return min(len(value), MAX_RECORDS)
        if isinstance(value, Mapping):
            for nested_key in ("nodes", "edges", "items"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    return min(len(nested), MAX_RECORDS)
    data = payload.get("data")
    if isinstance(data, Mapping):
        for value in data.values():
            if isinstance(value, Mapping):
                for key in ("nodes", "edges", "items"):
                    rows = value.get(key)
                    if isinstance(rows, list):
                        return min(len(rows), MAX_RECORDS)
    return 0


def _aggregate_state(states: Sequence[str] | Any) -> str:
    values = list(states)
    if not values:
        return IntegrationState.AUTH_REQUIRED.value
    priority = (
        IntegrationState.INVALID_CONFIG.value,
        IntegrationState.UNAVAILABLE.value,
        IntegrationState.DEGRADED.value,
        IntegrationState.AUTH_REQUIRED.value,
        IntegrationState.READY.value,
        IntegrationState.OBSERVED.value,
        IntegrationState.DISABLED.value,
    )
    for state in priority:
        if state in values:
            return state
    return IntegrationState.UNAVAILABLE.value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise IntegrationValidationError("clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _raise_invalid_constant(value: str) -> None:
    raise IntegrationValidationError(f"invalid JSON constant: {value}")


def _first_header(headers: Any, names: Sequence[str]) -> str | None:
    for name in names:
        value = headers.get(name)
        if value:
            return str(value)[:200]
    return None


def _aws_sigv4_headers(
    *,
    method: str,
    url: str,
    body: bytes,
    region: str,
    service: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
    now: datetime,
    extra_headers: Mapping[str, str],
) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise IntegrationValidationError("AWS endpoint must be HTTPS")
    timestamp = now.astimezone(timezone.utc)
    amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = timestamp.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers: dict[str, str] = {
        "host": parsed.hostname,
        "x-amz-date": amz_date,
    }
    canonical_headers.update({key.lower(): " ".join(value.split()) for key, value in extra_headers.items()})
    if session_token:
        canonical_headers["x-amz-security-token"] = session_token
    signed_names = sorted(canonical_headers)
    canonical_header_text = "".join(
        f"{name}:{canonical_headers[name]}\n" for name in signed_names
    )
    canonical_request = "\n".join(
        (
            method,
            parsed.path or "/",
            parsed.query,
            canonical_header_text,
            ";".join(signed_names),
            payload_hash,
        )
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        )
    )
    date_key = hmac.new(
        ("AWS4" + secret_access_key).encode("utf-8"),
        date_stamp.encode("ascii"),
        hashlib.sha256,
    ).digest()
    region_key = hmac.new(date_key, region.encode("ascii"), hashlib.sha256).digest()
    service_key = hmac.new(region_key, service.encode("ascii"), hashlib.sha256).digest()
    signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 "
        f"Credential={access_key_id}/{scope}, "
        f"SignedHeaders={';'.join(signed_names)}, "
        f"Signature={signature}"
    )
    result = {name.title(): value for name, value in canonical_headers.items()}
    result["Authorization"] = authorization
    return result
