from __future__ import annotations

import re
import unittest

from defensive_control_plane.integrations import _endpoint_fingerprint


class EndpointFingerprintTests(unittest.TestCase):
    def test_query_semantics_are_bound_without_exposing_query_text(self) -> None:
        first_url = "https://cmdb.security.example/api/findings?scope=a&limit=100"
        second_url = "https://cmdb.security.example/api/findings?scope=b&limit=100"

        first = _endpoint_fingerprint(first_url)
        repeat = _endpoint_fingerprint(first_url)
        second = _endpoint_fingerprint(second_url)

        self.assertEqual(first, repeat)
        self.assertNotEqual(first, second)
        self.assertRegex(first, re.compile(r"^[0-9a-f]{64}$"))
        self.assertNotIn("scope=a", first)
        self.assertNotIn("limit=100", first)


if __name__ == "__main__":
    unittest.main()
