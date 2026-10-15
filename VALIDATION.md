# Actual validation record

This document reports checks performed during the build on 2026-10-08. Machine timestamps, exact versions and detailed results are in `validation/pytest.xml`, `validation/evaluation.json`, `validation/api-acceptance.json` and each artifact manifest. All generated operational timings use actual execution/recording timestamps. Test-suite mocks and synthetic fixtures are never operational coverage measurements.

## Capability readiness

| Capability | Implemented | Fixture tested | Live/actual acceptance | Status / missing prerequisite |
|---|---|---|---|---|
| Local API, SQLite jobs, profiles and scope | Yes | Passed | Actual loopback HTTP walkthrough passed | Local-only POC |
| React/TypeScript/Vite | Yes | TypeScript + production build passed | Browser NOT RUN | IAB unavailable; Computer Use denied Chrome access because not approved |
| Selected DFIR URL intake | Yes | Layout/security tests passed | Actual public report fetched and normalized | Eight bounded recognized behaviors, seven observables; 43 image-only regions remain gaps |
| Curated replay and bounded offline analyzer | Yes | Passed scoped tests | Local demonstration executed | Replay is not new inference; offline recognizer is narrow |
| General live structured extraction | Yes | Synthetic SDK refusal/evidence rejection checks passed | NOT VERIFIED; actual acceptance failed visibly | No configured API key/model; no fallback |
| Existing Gmail plugin | Not an app-native connector | Not claimed | User confirms already configured/tested | No setup changes made |
| New Gmail handoff workflow | Yes | JSON, upload, local path, MIME, duplicates, partial/split batches tested | Synthetic local HTTP import passed; live handoff NOT RUN | Operator retrieval query/scope was requested and not supplied; no mailbox content retrieved |
| STIX 2.1 export | Yes | All five fixture exports validate | Actual local library/schema/pattern/reference validation | Not semantic truth or universal TIP compatibility |
| Native MISP export | Yes | PyMISP + bundled lax schema pass | Actual local validation | Events unpublished, organization-only; no invented TLP |
| MISP-STIX converter | Yes | All five fixture conversions completed | Actual maintained converter executed locally | Observable values preserved in measured fixtures; native workflow EventReport structure differs |
| Optional MISP import/readback | Yes | Duplicate/timeout/conflict fake-transport checks pass | NOT RUN | No configured MISP server/key/destination |
| Sigma discovery / Splunk conversion | Yes | Pinned UUIDs, fields and conversion checked | Actual pySigma conversion | Eight-rule subset, no whole-catalog claim; no live Splunk execution |
| Synthetic detection evaluation | Yes | Positive/negative/missing-field distinct | Actual local matcher execution | One rule; supported stateless subset only |
| Lab/live detection, prevention, SOC response | Recording supported | Transition/history tests pass | NOT RUN | Requires approved environment execution and real evidence |
| Git initialization / implementation commit | Attempted | N/A | Blocked | Runtime protects `.git` as read-only; identity exists, no identity invented |
| Linux execution | Portable implementation | N/A | NOT RUN | Build host is Apple Silicon macOS |

## Commands actually run

```sh
.venv/bin/python -m pytest -q --junitxml=validation/pytest.xml
./scripts/iti eval
./scripts/iti demo
npm --prefix web run build
./scripts/run
.venv/bin/python scripts/acceptance.py
```

Final suite at this checkpoint: **48 passed**. The actual HTTP walkthrough checks health, profiles, ingestion/assessment/evidence, package generation, every download/ZIP, cross-customer artifact rejection, synthetic fixture execution, unchanged live coverage, an improvement record, and synthetic Gmail prepare/preview/process/idempotent reimport. It is an API walkthrough, not a browser screenshot or visual UI test.

The regression suite covers public-address/redirect checks, normalization/provenance and indicator roles, source revisions and clocks, path spaces/Unicode/symlinks and originals, HTML boilerplate/current publisher layout/scripts, text and image-only PDFs, long multipart email and serial/attachment boundaries, CSV mapping, negation and injection, dangling spans and invented ATT&CK/rule IDs, source-cited retrieval versus independent candidates, unsupported Sigma constructs, zero-IOC/insufficient/mismatch cases, customer switching during jobs, concurrency/cancellation/restart, unavailable live model/refusal/invalid evidence, schema/export/import behavior, MISP uncertain-write reconciliation/conflicts, synthetic isolation, stale test dependencies, baseline/new-gap classifications and append-only failure/retest history.

## Measured extraction evaluation

Five fixtures: one limited real-report derivative, three initial independently authored cases, plus one untuned cloud-identity case added after the bounded recognizer was implemented. Gold annotations are developer/model-curated by inspecting source text, **not owner-reviewed**, not independent human adjudication, and not generated from extractor output.

On the **13 labeled behaviors**, 12 were recovered, with 0 false positives and 1 false negative: precision **1.0**, recall **0.9231**. The missed cloud-account creation behavior is a real limitation of the bounded offline recognizer; the app abstains from a cloud plan and displays Unknown relevance. Replay accuracy does not measure AI reasoning. These five small fixtures do not establish broad CTI or detection accuracy. Indicator recovery and retained qualifiers are reported independently in the JSON, including any conservative omission of a disputed source value.

The detection fixture set produced positive `match`, benign negative `no match`, and missing-field `inconclusive`. It tests selected Sigma semantics against authored events, not an actual SIEM rule, deployed control, or adversary emulation. Source-cited rule retrieval is reported separately from lexical discovery and must not be described as inference ability.

## Failures found and fixed

- STIX timestamp formatting and nullable validator warning/error lists required library-specific handling.
- `stix2-validator` 3.3.1's installed wheel omitted schemas. Pinned tested 3.2.0, which includes them; no standards validator was recreated.
- PyMISP `load` mutates its input. Validation/import now copies dictionaries so native content survives.
- misp-stix can return a single `MISPEvent` through `misp_events`; normalized that shape before comparison.
- The publisher's current report body lives under `.single-content-section .content-column`, while its `<main>` region contained footer content. The full URL acceptance initially extracted the footer, producing no recognized intelligence. Added a layout regression, fixed the adapter and reran the real source. The corrected result has 23,884 normalized characters, eight recognized behaviors and seven observables, with 43 image-only evidence gaps. This is deterministic analysis, not live AI.
- Initial npm/uv default caches were outside writable roots; cache locations now remain under `runtime/`.

Earlier failed job/package versions remain in ignored runtime history; successful new package versions do not erase them. No external credentials were inferred or copied.

## Exact external follow-ups

**Live model:** configure `OPENAI_API_KEY`, `OPENAI_MODEL` and any approved `OPENAI_BASE_URL` in `.env`, then:

```sh
./scripts/iti ingest /absolute/path/to/unseen-report.txt --kind path --mode live
```

For a long report, consciously adjust the conservative token budget. Inspect the completed job and evidence gates, then `./scripts/iti export ASSESSMENT_ID --customer fictional-bank`. A successful actual request plus evaluated output is needed before changing NOT VERIFIED.

**Gmail:** copy `runtime/gmail-request.txt` into the already-connected conversation, or prepare a fresh scoped request in the app. Retrieve only the selected messages, preserve returned content, download the handoff, then:

```sh
./scripts/iti gmail-import ~/Downloads/gmail-handoff.json --preview
./scripts/iti gmail-import ~/Downloads/gmail-handoff.json --mode offline
```

No OAuth/API setup is necessary. Record actual retrieval completeness and the resulting source/provenance job before marking live handoff acceptance. Do not confuse that with live model analysis.

**MISP:** configure `MISP_URL` and `MISP_API_KEY` (verified TLS), set the same destination on the selected customer, reassess/regenerate, inspect preview, then run twice:

```sh
./scripts/iti misp-check PACKAGE_ID --customer fictional-bank
```

Both calls must retrieve/compare the same event identity. Review returned server version and differences; never label only JSON/converter success “MISP verified.”

**Browser:** open http://127.0.0.1:8000 in an approved browser and follow `DEMO.md`; no screenshot was fabricated. **Splunk/lab/SOC:** use the generated human-led procedures on an approved environment and attach actual versioned evidence. The app does not execute these external activities.

## Attack Flow acceptance — 2026-10-15 UTC (2026-10-14 America/Chicago)

- **56 Python tests passed**, including six focused Attack Flow tests. Existing export, MISP reconciliation, job, evidence, clock and coverage checks remain passing. Machine output: `validation/attack-flow/pytest.xml`.
- **20 frontend tests passed (7 Attack Flow + 13 existing App/theme checks)**: exact URL encoding; readiness origin/window/nonce/package checks; load-event insufficiency; immediate scope removal and stale results; error/retry without losing human scenarios; historical/empty state; missing build and bounded timeout. Machine output: `validation/attack-flow/frontend-tests.json`.
- Workbench TypeScript/Vite production build and pinned upstream Vue type-check/Vite production build passed. Upstream emits its large-chunk warning (main JS about 3 MB uncompressed). No failing check was bypassed. A Node 25 Vue DevTools build incompatibility was resolved by excluding the development-only plugin, keeping the requested revision/lock.
- Existing evaluation rerun: **5 fixtures, 12 true positives, 0 false positives, 1 missed labeled behavior**, precision 1.0 / recall 0.9231 on that narrow labeled subset. This remains replay/deterministic evidence, not new live model accuracy.
- **Real browser tested (Codex in-app Chromium)**: ActiveMQ eight-node unordered flow; authored three-action case with one correctly directed temporal arrow and one disconnected action. Read-only iframe has no title/sidebar/chat/edit controls. Initially readable viewport fit, wheel zoom, independent drag pan, Fit, Expand/fullscreen, and JSON download worked. Download bytes matched the package SHA-256 `6da88e38ffa1dbacb359fcff80c56a0a36265ab6110b30b267c378bea25c108c`.
- **Editable Builder tested**: Open in Builder opened the same scoped artifact in a separate local tab with Properties/File/Edit controls and no Chat. Changing a draft title left the saved artifact unchanged. These are draft edits, not package approval or a round-trip integration.
- **Scope switching tested in the real browser**: switching to Cedar Cloud immediately left zero iframes and no previous customer's flow. Unit tests additionally inject stale/forged messages and enforce environment gates; backend tests reject wrong customer/environment artifact requests.
- **Offline acceptance passed with application-scoped restrictions**: isolated loopback test server denied non-loopback DNS/socket connections; browser CSP restricted assets/connect requests to the same origin. Observed resource inventory contains only localhost, no AI or catalog calls, and console inspection returned no warnings/errors. This does not claim the host network adapter was disabled or constitute a full packet capture. `browser-resources.json` records observed resources; real screenshots are in `validation/attack-flow/`.
- **Not claimed**: complete sequence recovery from arbitrary reports; human review/approval; real intrusion emulation; live detection/prevention/SOC results; MISP support for the Attack Flow extension; new live AI or Gmail verification. Existing external acceptance limits remain unchanged.

Current saved ActiveMQ annotations contain no explicit inter-behavior relationship records; no arrows are invented from sequence integers. That is an honest supported limit. The authored fixture independently demonstrates the implemented edge path. Full reproduction/build/update instructions and source/patch details: `integrations/attack-flow/README.md`.

Final frontend reconciliation retained the existing GitHub dependency lock and required `typecheck test build` scripts. The existing App/theme suite runs alongside seven Attack Flow tests against the same `App.tsx` used in production. One old-package button expectation was updated to “Generate updated package”; customer-scope fields were added to authored API fixtures. Final checks passed with Node 24.19.0, TypeScript 7.0.2, Vite 8.3.3, Vitest 5.0.3 and jsdom 30.1.2. Upstream Builder remains isolated on its unchanged pinned lock.

Initial GitHub CI flagged the pinned Windows registry schema checksum as a generic API key because the schema filename contains “key.” The pin metadata now uses explicit `path`/`sha256` records; digest values and pinned schema bytes are unchanged, and the scanner remains enabled without exclusions.

The initial strict Semgrep run reported no security findings but failed on five unescaped JSX ampersands. Encoded those visible labels without changing rendered text. Gitleaks 8.24.3 now passes the pin/schema directory with default rules and no exclusions; Ruff 0.17.0 correctness rules pass.
The rerun of Semgrep 1.180.0 with all six existing strict rules passed: 34 supported source/test targets, zero findings, zero parsing errors.
