from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from typing import Any

from defensive_control_plane.integrations import (
    AuthenticationRequired,
    GovernedIntegrationPlane,
    IntegrationManifest,
    IntegrationState,
    IntegrationValidationError,
    PROVIDER_CONTRACTS,
    ProviderTransportError,
    RequestPlan,
    TenantConnectorBinding,
    TransportResult,
)


FIXED_TIME = datetime(2026, 9, 4, 3, 30, tzinfo=timezone.utc)
SUBSCRIPTION_ID = "d0cfe6b2-9ac0-4464-9919-dccaee2e48c0"


class RecordingResolver:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = values or {}
        self.references: list[str] = []

    def __call__(self, reference: str) -> str | None:
        self.references.append(reference)
        return self.values.get(reference)


class RecordingTransport:
    def __init__(self, payload: Any | None = None, *, fail: bool = False) -> None:
        self.payload = payload if payload is not None else {"value": [{"id": "one"}]}
        self.fail = fail
        self.plans: list[RequestPlan] = []

    def execute(self, plan: RequestPlan) -> TransportResult:
        self.plans.append(plan)
        if self.fail:
            raise ProviderTransportError("bounded test transport unavailable")
        raw = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode()
        return TransportResult(
            status_code=200,
            payload=self.payload,
            response_sha256="a" * 64,
            byte_count=len(raw),
            latency_ms=12,
            request_id="request-1",
        )


def manifest(*bindings: dict[str, Any], approved: dict[str, list[str]] | None = None) -> IntegrationManifest:
    return IntegrationManifest.from_mapping(
        {
            "schema": "szl.defensive-integrations/v1",
            "approved_private_endpoints": approved or {},
            "bindings": list(bindings),
        }
    )


def graph_binding(provider_id: str, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "tenant_id": "tenant:alpha",
        "provider_id": provider_id,
        "enabled": True,
        "resources": {},
        "secret_refs": {"token": "env://TEST_PROVIDER_TOKEN"},
    }
    value.update(overrides)
    return value


class TenantIntegrationFabricTests(unittest.TestCase):
    def test_registers_the_complete_provider_matrix(self) -> None:
        self.assertEqual(
            set(PROVIDER_CONTRACTS),
            {
                "microsoft_defender_xdr",
                "microsoft_entra_id",
                "microsoft_intune",
                "microsoft_sentinel",
                "azure_defender_cloud",
                "crowdstrike_falcon",
                "wiz",
                "okta",
                "aws_security_hub",
                "gcp_security_command_center",
                "servicenow",
                "jira_cloud",
                "registered_cmdb",
                "registered_siem",
            },
        )
        for provider in PROVIDER_CONTRACTS.values():
            self.assertEqual(provider.external_writes, "DISABLED")
            self.assertEqual(provider.effectors, ())
            self.assertEqual(provider.semantic_operation, "READ")

    def test_literal_secrets_and_duplicate_tenant_bindings_are_rejected(self) -> None:
        invalid = graph_binding("microsoft_defender_xdr")
        invalid["secret_refs"] = {"token": "literal-secret"}
        with self.assertRaises(IntegrationValidationError):
            manifest(invalid)
        with self.assertRaises(IntegrationValidationError):
            manifest(
                graph_binding("microsoft_defender_xdr"),
                graph_binding("microsoft_defender_xdr"),
            )

    def test_missing_credentials_report_auth_required_without_transport(self) -> None:
        resolver = RecordingResolver()
        transport = RecordingTransport()
        plane = GovernedIntegrationPlane(
            manifest(graph_binding("microsoft_defender_xdr")),
            secret_resolver=resolver,
            transport=transport,
            clock=lambda: FIXED_TIME,
        )
        status = plane.statuses()
        self.assertEqual(status["state"], IntegrationState.AUTH_REQUIRED.value)
        self.assertEqual(status["external_writes"], "DISABLED")
        self.assertEqual(status["effectors"], [])
        observed = plane.observe()
        self.assertEqual(observed["state"], IntegrationState.AUTH_REQUIRED.value)
        self.assertEqual(transport.plans, [])
        self.assertNotIn("TEST_PROVIDER_TOKEN", json.dumps(observed))

    def test_disabled_connector_is_inert_and_secret_free(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "should-not-leak"})
        transport = RecordingTransport()
        binding = graph_binding("microsoft_defender_xdr", enabled=False)
        plane = GovernedIntegrationPlane(
            manifest(binding),
            secret_resolver=resolver,
            transport=transport,
            clock=lambda: FIXED_TIME,
        )
        observed = plane.observe()
        self.assertEqual(observed["state"], IntegrationState.DISABLED.value)
        self.assertEqual(transport.plans, [])
        self.assertNotIn("should-not-leak", json.dumps(observed))

    def test_graph_connectors_use_fixed_read_only_paths(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        cases = {
            "microsoft_defender_xdr": "/v1.0/security/incidents",
            "microsoft_entra_id": "/v1.0/auditLogs/signIns",
            "microsoft_intune": "/v1.0/deviceManagement/managedDevices",
        }
        for provider_id, expected_path in cases.items():
            with self.subTest(provider_id=provider_id):
                plane = GovernedIntegrationPlane(
                    manifest(graph_binding(provider_id)),
                    secret_resolver=resolver,
                    transport=RecordingTransport(),
                    clock=lambda: FIXED_TIME,
                )
                plan = plane.build_request_plan(plane.manifest.bindings[0])
                self.assertEqual(plan.method, "GET")
                self.assertIn(expected_path, plan.url)
                self.assertEqual(plan.semantic_operation, "READ")
                self.assertEqual(plan.headers["Authorization"], "Bearer token-value")

    def test_sentinel_and_defender_cloud_bind_exact_subscription_resources(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        sentinel = graph_binding(
            "microsoft_sentinel",
            resources={
                "subscription_id": SUBSCRIPTION_ID,
                "resource_group": "security-rg",
                "workspace": "security-workspace",
            },
        )
        defender = graph_binding(
            "azure_defender_cloud",
            resources={"subscription_id": SUBSCRIPTION_ID},
        )
        plane = GovernedIntegrationPlane(
            manifest(sentinel, defender),
            secret_resolver=resolver,
            transport=RecordingTransport(),
            clock=lambda: FIXED_TIME,
        )
        sentinel_plan = plane.build_request_plan(plane.manifest.bindings[0])
        cloud_plan = plane.build_request_plan(plane.manifest.bindings[1])
        self.assertIn(SUBSCRIPTION_ID, sentinel_plan.url)
        self.assertIn("security-rg", sentinel_plan.url)
        self.assertIn("security-workspace", sentinel_plan.url)
        self.assertIn("api-version=2025-09-01", sentinel_plan.url)
        self.assertIn("Microsoft.Security/assessments", cloud_plan.url)
        self.assertIn("api-version=2020-01-01", cloud_plan.url)

    def test_provider_hosts_are_allowlisted_and_redirectable_urls_are_rejected(self) -> None:
        for provider_id, bad_url in (
            ("crowdstrike_falcon", "https://attacker.example"),
            ("wiz", "https://wiz.io"),
            ("okta", "https://example.com"),
            ("servicenow", "https://service-now.com"),
            ("jira_cloud", "https://atlassian.net"),
        ):
            with self.subTest(provider_id=provider_id):
                with self.assertRaises(IntegrationValidationError):
                    GovernedIntegrationPlane(
                        manifest(graph_binding(provider_id, base_url=bad_url))
                    )
        for bad_url in (
            "http://example.okta.com",
            "https://user:pass@example.okta.com",
            "https://example.okta.com:8443",
            "https://127.0.0.1",
            "https://example.okta.com/path",
        ):
            with self.subTest(url=bad_url):
                with self.assertRaises(IntegrationValidationError):
                    GovernedIntegrationPlane(
                        manifest(graph_binding("okta", base_url=bad_url))
                    )

    def test_registered_private_endpoints_require_separate_administrator_allowlist(self) -> None:
        binding = graph_binding(
            "registered_cmdb",
            base_url="https://cmdb.security.example",
            resources={"collection_path": "/api/v1/assets?limit=100"},
        )
        with self.assertRaises(IntegrationValidationError):
            GovernedIntegrationPlane(manifest(binding))
        plane = GovernedIntegrationPlane(
            manifest(
                binding,
                approved={"registered_cmdb": ["https://cmdb.security.example"]},
            )
        )
        self.assertEqual(plane.manifest.bindings[0].provider_id, "registered_cmdb")
        traversal = dict(binding)
        traversal["resources"] = {"collection_path": "/api/v1/../admin"}
        with self.assertRaises(IntegrationValidationError):
            GovernedIntegrationPlane(
                manifest(
                    traversal,
                    approved={"registered_cmdb": ["https://cmdb.security.example"]},
                )
            )

    def test_wiz_post_is_a_fixed_query_without_mutation_fields(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        plane = GovernedIntegrationPlane(
            manifest(
                graph_binding("wiz", base_url="https://tenant.app.wiz.io")
            ),
            secret_resolver=resolver,
            transport=RecordingTransport(),
            clock=lambda: FIXED_TIME,
        )
        plan = plane.build_request_plan(plane.manifest.bindings[0])
        self.assertEqual(plan.method, "POST")
        self.assertEqual(plan.semantic_operation, "READ")
        self.assertEqual(plan.url, "https://tenant.app.wiz.io/graphql")
        body = json.loads((plan.body or b"").decode())
        self.assertIn("query SzlReadOnlyIssues", body["query"])
        self.assertNotIn("mutation", body["query"].lower())

    def test_aws_security_hub_sigv4_is_deterministic_and_bound_to_region(self) -> None:
        resolver = RecordingResolver(
            {
                "env://AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
                "env://AWS_SECRET_ACCESS_KEY": "test-secret-access-key",
                "env://AWS_SESSION_TOKEN": "session-token",
            }
        )
        binding = {
            "tenant_id": "tenant:alpha",
            "provider_id": "aws_security_hub",
            "enabled": True,
            "resources": {"region": "us-east-1", "partition": "aws"},
            "secret_refs": {
                "access_key_id": "env://AWS_ACCESS_KEY_ID",
                "secret_access_key": "env://AWS_SECRET_ACCESS_KEY",
                "session_token": "env://AWS_SESSION_TOKEN",
            },
        }
        plane = GovernedIntegrationPlane(
            manifest(binding),
            secret_resolver=resolver,
            transport=RecordingTransport(),
            clock=lambda: FIXED_TIME,
        )
        first = plane.build_request_plan(plane.manifest.bindings[0])
        second = plane.build_request_plan(plane.manifest.bindings[0])
        self.assertEqual(first.headers["Authorization"], second.headers["Authorization"])
        self.assertIn("Credential=AKIDEXAMPLE/20260904/us-east-1/securityhub/aws4_request", first.headers["Authorization"])
        self.assertEqual(first.url, "https://securityhub.us-east-1.amazonaws.com/")
        self.assertEqual(first.headers["X-Amz-Target"], "AWSSecurityHub_20181127.GetFindings")
        self.assertNotIn("test-secret-access-key", json.dumps(dict(first.headers)))

    def test_gcp_okta_servicenow_and_jira_templates_are_bounded(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        bindings = (
            graph_binding(
                "gcp_security_command_center",
                resources={"organization_id": "123456789012"},
            ),
            graph_binding("okta", base_url="https://tenant.okta.com"),
            graph_binding("servicenow", base_url="https://tenant.service-now.com"),
            graph_binding("jira_cloud", base_url="https://tenant.atlassian.net"),
        )
        plane = GovernedIntegrationPlane(
            manifest(*bindings),
            secret_resolver=resolver,
            transport=RecordingTransport(),
            clock=lambda: FIXED_TIME,
        )
        urls = [plane.build_request_plan(item).url for item in plane.manifest.bindings]
        self.assertIn("/v2/organizations/123456789012/sources/-/locations/global/findings", urls[0])
        self.assertIn("/api/v1/logs", urls[1])
        self.assertIn("/api/now/v1/table/incident", urls[2])
        self.assertIn("/rest/api/3/search/jql", urls[3])
        self.assertTrue(all("limit" in url.lower() or "pageSize" in url or "maxResults" in url for url in urls))

    def test_observation_records_hashes_and_counts_but_discards_provider_payload(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        payload = {"value": [{"id": "sensitive-1", "secret": "discard-me"}]}
        transport = RecordingTransport(payload)
        plane = GovernedIntegrationPlane(
            manifest(graph_binding("microsoft_defender_xdr")),
            secret_resolver=resolver,
            transport=transport,
            clock=lambda: FIXED_TIME,
        )
        report = plane.observe()
        serialized = json.dumps(report, sort_keys=True)
        self.assertEqual(report["state"], IntegrationState.OBSERVED.value)
        observation = report["observations"][0]
        self.assertEqual(observation["record_count"], 1)
        self.assertEqual(observation["response_sha256"], "a" * 64)
        self.assertRegex(observation["receipt_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["receipt_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("sensitive-1", serialized)
        self.assertNotIn("discard-me", serialized)
        self.assertNotIn("token-value", serialized)

    def test_transport_failures_return_unavailable_not_empty_success(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        plane = GovernedIntegrationPlane(
            manifest(graph_binding("microsoft_defender_xdr")),
            secret_resolver=resolver,
            transport=RecordingTransport(fail=True),
            clock=lambda: FIXED_TIME,
        )
        report = plane.observe()
        self.assertEqual(report["state"], IntegrationState.UNAVAILABLE.value)
        observation = report["observations"][0]
        self.assertEqual(observation["state"], IntegrationState.UNAVAILABLE.value)
        self.assertNotIn("record_count", observation)

    def test_tenant_and_provider_selection_never_crosses_bindings(self) -> None:
        resolver = RecordingResolver({"env://TEST_PROVIDER_TOKEN": "token-value"})
        transport = RecordingTransport()
        alpha = graph_binding("microsoft_defender_xdr")
        beta = graph_binding("microsoft_entra_id", tenant_id="tenant:beta")
        plane = GovernedIntegrationPlane(
            manifest(alpha, beta),
            secret_resolver=resolver,
            transport=transport,
            clock=lambda: FIXED_TIME,
        )
        report = plane.observe(tenant_id="tenant:beta")
        self.assertEqual(len(report["observations"]), 1)
        self.assertEqual(report["observations"][0]["tenant_id"], "tenant:beta")
        self.assertEqual(transport.plans[0].tenant_id, "tenant:beta")
        with self.assertRaises(IntegrationValidationError):
            plane.observe(tenant_id="tenant:missing")

    def test_request_plan_with_unresolved_secret_fails_before_egress(self) -> None:
        plane = GovernedIntegrationPlane(
            manifest(graph_binding("microsoft_defender_xdr")),
            secret_resolver=RecordingResolver(),
            transport=RecordingTransport(),
            clock=lambda: FIXED_TIME,
        )
        with self.assertRaises(AuthenticationRequired):
            plane.build_request_plan(plane.manifest.bindings[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
