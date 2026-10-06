# Hugging Face P(doom) survey: research qualification

**UNQUALIFIED_RESEARCH_REFERENCE**, reviewed 2026-10-05 at 20:33:39 UTC.
This is a dated research note and static qualification record. It is not a
provider integration, defensive observation, or risk estimate.

The [official announcement](https://huggingface.co/changelog/pdoom-survey), dated
October 5, 2026, describes a public profile feature for self-reported opinions
about AI existential risk. Individual answers appear on profiles; Hugging Face
announced aggregate, anonymized survey results for two weeks later. No aggregate
results or linked dataset were available in the inspected announcement at this
review. Results, sample size, statistics and publication date remain null in
the [qualification record](hugging-face-pdoom-survey.json). The announcement's
engagement counters are not a survey sample size or result.

The [Hub API documentation](https://huggingface.co/docs/hub/api) directs readers
to the [OpenAPI specification](https://huggingface.co/.well-known/openapi.json).
The inspected specification had 298 paths; case-insensitive path-name checks for
`pdoom` and `survey` found no matches. No survey endpoint was established from
these sources. This is a bounded documentation observation, not a claim that no
undocumented, differently named or future interface exists. No profiles, survey
submission route, or speculative endpoint were probed.

No survey-data reuse license was established in the inspected announcement or
API references. The license identifier and URL remain null. Public visibility
does not itself establish reuse permission or qualification for this project.
This observation is not a legal determination.

## Interpretation and boundaries

The record treats the source as self-reported opinion, not measured objective
risk, representative population evidence, a calibrated forecast, or defensive
incident telemetry. It contains no individual answers, usernames or invented
statistics. Its `DECLARED` label identifies publisher-stated survey behavior;
it does not certify the survey, responses or future results.

If a future response rejects the premise, preserve it as non-numeric with a
null probability. Never convert rejection to zero probability. Missing answers
also remain unknown/null. These are interpretation safeguards for any later
proposal, not a claim that particular responses or UI options were observed.

No runtime reads this research record. It is not a
`DefensivePlanningSnapshotV1`, and the existing planner rejects it. The planner
schema, capability assessments, severity, readiness and incident responses are
unchanged. This addition creates no adapter, collection job, subscription,
scheduled follow-up, submission, network client, credential path or model input.
The URLs are citations for human review, not executable destinations.

## Future qualification requires a separate review

A human can revisit the official aggregate publication when available. Before
any data-use or ingestion proposal, establish its source, methodology, sample
and limitations; a documented access contract if automation is proposed; reuse
license or permission; and privacy and intended-use review. Continued absence
of any item stays unknown or unqualified. A promised publication date is not
evidence that results have arrived.

The record includes SHA-256 digests of the downloaded announcement and OpenAPI
bytes for review traceability. They are local integrity checksums, not publisher
signatures or independently verified attestations. Raw pages and profile data
are not bundled. Qualification is valid only as a dated observation; it does
not refresh itself or authorize collection.

## Validation and source proposal

```powershell
python -B -m unittest discover -s tests -p test_research_qualification.py -v
```

The static tests keep unavailable values null, preserve non-numeric rejection,
check the inert boundaries and reject the record at the planner boundary. They
use no network and do not establish future availability or licensing.

This proposal touches only this note, its adjacent JSON record, and the small
validation test. It leaves DCP #34 and all runtime, workflow and release files
unchanged. Draft review is required before any subsequent merge or publication.
