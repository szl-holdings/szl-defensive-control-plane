from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from defensive_control_plane.planning import SnapshotError, assess_snapshot


RECORD = Path(__file__).resolve().parents[1] / "docs" / "research" / "hugging-face-pdoom-survey.json"


class ResearchQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = RECORD.read_bytes()
        self.record = json.loads(self.raw)

    def test_record_has_dated_official_provenance_and_bounded_api_claim(self) -> None:
        record = self.record
        self.assertEqual(record["schema"], "ResearchSourceQualificationV1")
        self.assertEqual(record["qualification"], "UNQUALIFIED_RESEARCH_REFERENCE")
        reviewed = datetime.strptime(record["reviewedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.assertEqual(record["source"]["announcementDate"], "2026-10-05")
        self.assertLessEqual(record["source"]["announcementDate"], reviewed.date().isoformat())
        self.assertEqual(record["source"]["url"], "https://huggingface.co/changelog/pdoom-survey")
        self.assertEqual(record["source"]["nature"], "public_profile_opinion_survey")
        self.assertEqual(record["source"]["evidenceClass"], "DECLARED")
        api = record["apiQualification"]
        self.assertEqual(api["status"], "NOT_DOCUMENTED_IN_INSPECTED_SOURCES")
        self.assertEqual(api["inspectedUrls"], ["https://huggingface.co/docs/hub/api", "https://huggingface.co/.well-known/openapi.json"])
        self.assertEqual(api["inspectedPathCount"], 298)
        self.assertEqual(api["matchingDocumentedPaths"], [])
        self.assertIsNone(api["surveyEndpoint"])
        self.assertIn("remain unknown", api["coverage"])
        for digest in (record["source"]["retrievedPageSha256"], api["openapiSha256"]):
            self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")

    def test_unavailable_results_and_non_numeric_answers_are_never_zero(self) -> None:
        results = self.record["aggregateResults"]
        self.assertEqual(results["status"], "UNAVAILABLE_IN_INSPECTED_SOURCES")
        for field in ("publicationDate", "resultsUrl", "datasetId", "sampleSize", "statistics"):
            self.assertIsNone(results[field])
        self.assertEqual(self.record["reuseLicense"], {"status": "NOT_ESTABLISHED", "identifier": None, "url": None})
        interpretation = self.record["interpretation"]
        self.assertEqual(interpretation["measurementType"], "self_reported_opinion")
        self.assertIsNone(interpretation["objectiveRiskProbability"])
        for policy, category in (("rejectPremisePolicy", "non_numeric_response"), ("missingAnswerPolicy", "unknown")):
            self.assertEqual(interpretation[policy], {"category": category, "probability": None, "convertToZero": False})

    def test_record_is_inert_and_cannot_enter_the_defensive_planner(self) -> None:
        boundaries = self.record["boundaries"]
        self.assertIs(boundaries["humanReviewRequired"], True)
        disabled = {"dataReuseApproved", "individualAnswersCollected", "profileScrapingEnabled", "surveySubmissionEnabled",
                    "automatedIngestionEnabled", "providerAdapterImplemented", "influencesPosture", "influencesSeverity",
                    "influencesReadiness", "influencesResponse"}
        self.assertEqual(set(boundaries), disabled | {"humanReviewRequired"})
        for field in disabled:
            self.assertIs(boundaries[field], False)
        self.assertIs(self.record["nextReview"]["scheduled"], False)
        with patch("socket.create_connection", side_effect=AssertionError("No network permitted")) as network:
            with self.assertRaises(SnapshotError):
                assess_snapshot(self.raw, as_of=self.record["reviewedAt"])
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
