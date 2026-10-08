# Requirements-to-test checklist

| Area | Acceptance/check |
|---|---|
| A: identity | duplicate occurrence, corrected revision, stable export IDs and clocks, private scope isolation |
| A: parsing | HTML boilerplate, publication/incident precision, stable spans/offsets, PDF gaps, EML segments, CSV context |
| A: security | unsafe URL/redirect, size limits, path traversal, explicit path with spaces, original unchanged, origin/host checks, prompt injection |
| A: exports | STIX schema/pattern/reference validation, native MISP validation, zero IOC context, unsupported imports/losses |
| B: facts | dangling spans/unsupported claims, invalid ATT&CK IDs, changed authored facts, negation/benign indicators |
| B: relevance | two customers same facts/different fit, sector mismatch + technology, Unknown default, overrides/history |
| B: catalogs | real UUID/GUID/commit, cited versus independent search counts, unsupported Sigma visible, conversion |
| B: detection | positive, negative, missing-field synthetic evaluation; no live/prevention/SOC promotion |
| B: ledger | baseline vs new gap, failure/retest, stale dependencies, nonnegative pending durations, history |
| C: Gmail | frozen request, pasted/upload/path imports, context mismatch, snippets/partial/missing attachments, serial segments, duplicate split batches |
| C: isolation | switch/edit customer during job, scoped artifact/evidence/destination access |
| Jobs | duplicate concurrent submission, cancellation, failure/restart/resume, extraction cache reuse |
| D: generality | held-out changed facts; unseen live extraction separately NOT VERIFIED when unavailable |
| D: runtime | CLI/API same services, health, frontend build, browser workflow and real screenshot |
| External | real selected report retrieval; converter; Gmail selected handoff; live model; MISP readback each independent |

## Completion evidence (2026-10-08)

48 regression tests pass (`validation/pytest.xml`). Concrete mappings:

- Source/security/format checks: `tests/test_sources.py`, including the current DFIR layout regression, unsafe redirects, immutable copies/revisions, benign/victim indicators, long MIME, text/image-only PDF and CSV column mapping.
- Frozen context/relevance/jobs/detection/ledger: `tests/test_workflow.py`, including switched profile during a running job, concurrent submission, replay hash rejection, failed live runs and synthetic SDK refusal/unsupported evidence, baseline/new-gap histories and stale dependencies.
- Standards/Gmail/MISP/API: `tests/test_exports_gmail_api.py`, including zero-IOC useful exports, STIX identity/pattern gates, MISP attribute preservation, handoff scope/parts/partial failures, all three import transports, origin/host controls and uncertain MISP writes without duplicates.
- Actual running HTTP acceptance: `validation/api-acceptance.json`; bounded live report index listing: `validation/index-listing.json`.
- Five-fixture measured extraction: `validation/evaluation.json` / `.html`. One cloud behavior missed; no suppression of the failure. Exact rules searched and cited/independent retrieval counts retained.
- Capability states and skipped external prerequisites: `validation/readiness.json`, `VALIDATION.md`. Browser not run because permitted browser control was unavailable; live AI/Gmail handoff/MISP/SIEM outcomes are not claimed.
