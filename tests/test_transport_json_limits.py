"""Provider parser limits become unavailable observations without aborting a batch."""
import io
import json
import sys
import unittest

from defensive_control_plane.integrations import GovernedIntegrationPlane, StdlibJsonTransport
from test_integrations import FIXED_TIME, RecordingResolver, graph_binding, manifest


class JsonResponse(io.BytesIO):
    status = 200
    headers = {}

    def __init__(self, raw, url):
        super().__init__(raw)
        self.url = url

    def geturl(self):
        return self.url


class SequenceOpener:
    def __init__(self, raw):
        self.raw = iter((raw, b'{"value":[{"id":"healthy"}]}'))

    def open(self, request, timeout):
        return JsonResponse(next(self.raw), request.full_url)


class ProviderJsonLimitTests(unittest.TestCase):
    def assert_batch_survives(self, raw):
        transport = StdlibJsonTransport()
        transport._opener = SequenceOpener(raw)
        plane = GovernedIntegrationPlane(
            manifest(graph_binding("microsoft_entra_id"), graph_binding("microsoft_intune")),
            transport=transport,
            secret_resolver=RecordingResolver({"env://TEST_PROVIDER_TOKEN": "offline-fixture"}),
            clock=lambda: FIXED_TIME,
        )
        report = plane.observe()
        failed, healthy = report["observations"]
        self.assertEqual(failed["state"], "UNAVAILABLE")
        self.assertEqual(failed["reason"], "microsoft_entra_id returned invalid JSON")
        self.assertEqual(healthy["state"], "OBSERVED")
        self.assertEqual(healthy["record_count"], 1)
        self.assertEqual(report["external_writes"], "DISABLED")
        self.assertIn("receipt_sha256", report)
        self.assertNotIn("offline-fixture", json.dumps(report))

    def test_deeply_nested_response_does_not_abort_remaining_providers(self):
        self.assert_batch_survives(b"[" * 10000 + b"0" + b"]" * 10000)

    def test_integer_parser_limit_does_not_abort_remaining_providers(self):
        limit = sys.get_int_max_str_digits()
        if not limit:
            self.skipTest("interpreter integer-string limit is disabled")
        self.assert_batch_survives(b'{"value":' + b"9" * (limit + 1) + b"}")

    def test_existing_invalid_json_cases_remain_unavailable(self):
        for raw in (b"{", b"\xff", b'{"value":NaN}'):
            with self.subTest(raw=raw):
                self.assert_batch_survives(raw)


if __name__ == "__main__":
    unittest.main()
