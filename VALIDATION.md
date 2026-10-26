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

## D3FEND enhancement — 2026-10-15

Actual local results: **63 Python tests passed; 24 frontend tests passed; TypeScript typecheck and production build passed**. Machine results and real screenshots: `validation/d3fend/`. The seven focused backend tests use pinned real T1105 mappings and T1027.003 (unmapped child of mapped T1027), distinct missing/unsupported/catalog-failure states, exact candidate membership, customer/environment/assessment rejection, 10 concurrent duplicate submissions, frozen snapshots/profile versions, origin tampering rejection, manual compatibility, edits/deployment/closure/retests, unchanged verification metrics, and unchanged package bytes after catalog changes. Frontend tests cover bounded lists, editable prefill, single-flight double click, reload persistence, updated deployment label, customer switching, late responses and catalog-failure fallback. These are workflow regressions, not measurements of defensive effectiveness.

Actual browser acceptance used the existing attributed limited ActiveMQ replay in isolated `runtime/d3fend-smoke`: opened the Purple Team scenario and real T1190 → D3-APCA association; inspected catalog provenance; entered an owner and edited proposed change/retest; saved; viewed the action in Coverage/history; reloaded and found **View improvement · open**; edited priority; verified exactly one persisted action and zero tests. The existing Attack Flow viewer still rendered. Customer switching removed prior candidates. Browser console had no warnings/errors. The test server rejected non-loopback DNS/socket connections, and existing same-origin browser CSP remained enabled. No official-reference navigation was needed for runtime lookup. This validates local/offline lookup, not a live deployment or prevention result.

Pinned catalog: Attack Flow `5c8bf4ca9ff64ef9b55c38a2505db318750cbcda`; normalized SHA256 in `catalogs/d3fend/pin.json`. Explicit offline re-transformation reproduced the same catalog bytes. Initial test assumptions about APCA's name and an unmapped parent were corrected against actual pinned data; no fabricated mapping was added. Final Ruff correctness checks and strict Semgrep (six established security rules, zero findings/parse errors) passed. Gitleaks default rules passed on the publishable file snapshot with no exclusions. A preliminary directory invocation included ignored runtime/dependency caches; that scope was corrected to the actual publication set rather than changing scanner rules.

The normal server was restarted only after verifying no active jobs. Browser-authored acceptance actions remain in the isolated store. No additional Gmail, MISP, live-model, SIEM, prevention or SOC verification was attempted or claimed. Catalog associations do not establish defense suitability; the upstream ontology release/version remains unknown. Historical CTI/STIX/MISP and Attack Flow packages are not rewritten by this feature.

## Vulnerability Intelligence — 2026-10-15

Actual local results: **81 Python tests passed (18 focused vulnerability tests plus 63 existing regressions); 30 frontend tests passed (6 new plus 24 existing); TypeScript typecheck and Vite production build passed**. Machine results: `validation/vulnerability/backend.xml` and `frontend.json`. Existing evaluation was rerun with **5 fixtures, 12 true positives, 0 false positives and 1 false negative**: precision 1.0, recall 0.9231 on that limited labeled subset. This is not a vulnerability-extraction accuracy claim or new live-model evaluation.

Focused tests cover literal CVE boundaries/dedup/exact offsets, no automatic exploitation/actor attribution, historical event/publication distinctions, low-confidence attribution, dangling evidence rejection, low-EPSS/unverified-control non-overrides, contrasting assets, CSV validation/idempotency/frozen context, changed finding identities, BYOVD/general absence guards, documented exclusions, review/override/commitment history, stale-review rejection, customer/profile isolation, concurrent action creation, original action linkage, evidence bytes/hash/scope requirements, failure/retest preservation, operational-schema verification freshness, synthetic/lab/attestation exclusion, mitigation/approval requirements, deadline and clock preservation, provider schema/cache/failure/staleness, same-origin API rejection, evidence upload/download and reopening the store. Authored records simulating operational evidence only test validation semantics; they are not live scanner acceptance.

Real browser acceptance used the production build in Codex in-app Chromium with isolated `runtime/vulnerability-smoke`. It loaded the two examples, inspected dated source links/spans/qualifiers, compared `build-01` expedite with `build-02` investigate, accepted a decision with a reason, created an edited owner action in the existing ledger, and recorded a passed **analyst attestation** that stayed **attestation / synthetic or lab evidence only**. A pasted CSV was previewed and imported as one synthetic unknown asset. Reload preserved the imported asset, owner action and verification history. Switching from Northstar to Juniper showed the empty other-customer scope and restored only Juniper's records. Original/Ocean/Midnight styles were exercised; actual screenshots are in `validation/vulnerability/`. The browser's application console inspection returned no warnings/errors after reload. Restarting the acceptance server caused an expected transient fetch error, dismissed after reconnect; no application data was lost. The browser automation host separately emitted telemetry-service 403 messages, which were not app requests or accepted external checks.

The isolated acceptance process denied non-loopback DNS/sockets, with same-origin browser CSP retained. Separately, the actual public enrichment adapter fetched CISA KEV, FIRST EPSS and both CVE/CNA records at **2026-10-15T15:10:43–44 UTC**. KEV and dated EPSS were available for both; TeamCity CNA CVSS was available; the driver record had **no CNA CVSS metric**, accurately unavailable despite successful retrieval. `validation/vulnerability/public-enrichment.json` records the actual URLs, times, hashes and statuses. This is live public enrichment, not live asset verification.

Primary CISA PDF and CrowdStrike HTML were fetched through the existing protected fetcher and inspected before authoring derivatives. Full articles stay ignored; bundled primary hashes/qualifiers and dated enrichment facts are attributable. No actual organizational inventory, vulnerability scan, patch deployment, compromise hunt, offensive test, prevention or verified exposure reduction was run. No new MISP, Gmail, live-model or SIEM acceptance is claimed. Those existing limits remain unchanged.

Final local required checks also passed: Ruff 0.17.0 correctness rules; Semgrep 1.180.0 with all six existing pinned security rules (42 supported targets, zero findings, zero parse errors); Gitleaks 8.24.3 default rules over the publishable snapshot (zero leaks, no exclusions). Existing dependency locks and remote CI/security workflows are preserved. GitHub CI results are checked on the feature PR separately from these local results.

## Phase 4 — manual CI/CD Pipeline Assurance (2026-10-26)

Baseline Phases 1–3 were merged in PRs #16, #17 and #20; this extension starts from `4cdef442d50bf34d581f192b225696b92834808b`. Existing SARIF message-normalization fixes are retained. No dependency locks, CI policies, database schema, ledger semantics or dashboard metrics were changed.

Actual local commands/results:

- `.venv/bin/python -m pytest -q tests/test_pipeline.py`: **61 passed**.
- `.venv/bin/python -m pytest -q -o faulthandler_timeout=30`: **278 passed in 37.37s**.
- `npm --prefix web run typecheck`: passed.
- `npm --prefix web test`: **54 passed across 8 files**.
- `npm --prefix web run build`: passed (TypeScript / Vite production build).
- Ruff 0.17.0 correctness rules `E9,F63,F7,F82` on `iti` and `tests`: passed.
- Semgrep 1.180.0, six established pinned security rules, strict parsing: **0 findings** on 52 applicable application targets. A separate explicit scan of all six new backend/frontend implementation files also returned **0 findings / 0 errors**.
- Gitleaks 8.24.3 default rules on the publishable file snapshot: **0 leaks**, no rule exclusions. Existing public path/owner-identifier scan passed; focused documentation links resolve.

Actual local Chromium acceptance used the production frontend and an isolated temporary SQLite/blob store. The application process denied non-loopback networking; browser requests were restricted to its loopback origin. Through real UI/API paths it imported three authored workflows (46 observations), confirmed imports, downloaded and compared all original source bytes/SHA-256 values, attached successful/skipped/failed supplied metadata, retained an incomplete run, rejected mismatched evidence, imported a revised snapshot without replacing old evidence, reloaded persisted history, changed customer scope, and exercised mobile layout/theme selection. No application JavaScript errors occurred. The README's eight PNGs are genuine screenshots of the running workspaces, using fictional/synthetic demo scopes and the existing attributed limited CTI replay.

Browser harness issues encountered and resolved: an existing temporary dataset violated the first-import assertion, so acceptance was restarted with fresh data; text selectors were corrected to match actual cells containing explanatory text. No product assertion or security control was relaxed. A local Semgrep settings-directory permission error was resolved by placing tool settings/logs in temporary storage.

This validates the local workbench, not GitHub execution or supply-chain security. No uploaded workflow ran, no external reusable definition was retrieved, no scanner was executed and no independent operational assurance was established. Existing live-model/MISP/SIEM and dependency-advisory limitations remain unchanged. GitHub PR checks are inspected separately before the user-authorized merge. See [control rules, evidence format and reproducible demo](docs/PIPELINE_ASSURANCE.md).

## macOS launcher build matching (2026-10-26)

The launcher now compares a frozen, non-path checkout/build identity from `/health` with the current checkout before reusing port 8000. A mismatch can stop a stale listener only after macOS `lsof` and `ps` establish both the same checkout working directory and the expected `iti.cli run` command. Unknown or unrelated listeners are not signaled. The installer also refuses to create a launcher before the frontend is built.

Six focused launcher tests cover the health identity, exact matching, same-checkout listener validation, graceful same-checkout termination, current-server reuse and the fail-closed unknown-listener path. The full backend regression suite passed **284 tests**; correctness lint passed; the established local Semgrep rules reported zero findings on the changed Python files; and the publishable snapshot passed Gitleaks with zero leaks. This Linux build environment cannot install or double-click the physical macOS Desktop bundle; final installation requires running `./scripts/bootstrap && ./scripts/install-desktop` once on the Mac. Existing runtime data is retained.
