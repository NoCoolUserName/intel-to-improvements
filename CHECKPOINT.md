# Final implementation checkpoint — 2026-10-08

Workspace: `/Users/amoore/src/intel-to-improvements`. No applicable AGENTS.md. Git initialization denied because runtime makes `.git` read-only. Existing Git identity is configured; no invented identity or workaround used.

Implementation complete for the bounded local POC:
- FastAPI/Pydantic/SQLite services, React/TypeScript/Vite workbench, shared CLI/API, locked local dependencies.
- Customer profiles/sectors/multiple environments; frozen job contexts, source occurrences, byte revisions, parser revisions, extraction revisions, assessments and artifacts.
- Selected public URL, explicit local file/upload/text, structured STIX/MISP/CSV, EML/text PDF; completeness/gaps and source safety gates.
- Exact-content replay, narrow deterministic general-input analysis, real configurable structured OpenAI provider with no tools/fallback.
- STIX/native MISP, maintained converter, hunts, safe human-led purple-team plans, eight pinned Sigma rules, ATT&CK/Atomic metadata, independent coverage ledger and improvement/test history.
- Existing Gmail plugin assisted request/handoff workflow only; sample generator, schema, all three import transports, request/context validation, partial/split batches and attachments.
- READMEs/spec/architecture/validation/walkthrough, schemas, license/notices, reusable limited real-case artifacts in `examples/activemq/`.

Actual verification:
- `pytest`: **48 passed**, latest `validation/pytest.xml`.
- TypeScript + Vite production build passed.
- Full real DFIR URL fetched: corrected adapter extracts 23,884 normalized characters, eight recognized behaviors, seven observables; 43 image-only regions explicitly unparsed. No live AI claim.
- Five-fixture eval: 12/13 labeled behaviors recovered, zero false positives; cloud behavior missed. Conservative role classification omits the disputed .62 address from malicious indicators (still preserved as an observable). All fixture STIX/native MISP exports validate; converter completed with measured observable preservation and explicit context differences.
- Actual HTTP acceptance: all downloads/ZIP, customer isolation, synthetic detection variants, improvement, Gmail prepare/preview/process/reimport passed.
- Actual bounded DFIR index listing returned five links.
- Server running at `http://127.0.0.1:8000`; session may stop when environment ends. Relaunch with `./scripts/run`.

External acceptance still unverified (do not repeat completed local work):
- Existing Gmail plugin user-confirmed working and callable here, but no operator retrieval scope response arrived. No mailbox messages accessed. Prepared request: `runtime/gmail-request.txt`; import downloaded actual handoff explicitly. Synthetic import passed.
- Live model request attempted and failed visibly for absent API key/model. No fallback; `runtime/live-acceptance.json`.
- Live MISP instance/readback unavailable; fake transport regression only. Configure destination/credentials and use documented `misp-check`.
- Live SIEM, lab execution, prevention and SOC evidence not supplied; synthetic results never promote these.
- IAB unavailable; Computer Use rejected Chrome because not approved. No screenshot/visual browser result fabricated.
- Linux portability not executed on this Mac host.

Compatibility decisions: pin stix2-validator 3.2.0 because observed 3.3.1 wheel lacked schemas; copy dictionaries before PyMISP.load; normalize converter's single-event result. Parser currently `parser-1.4`, package generator `packages-5`. Earlier failed packages/jobs remain under ignored runtime, with newer immutable revisions rather than erased history. Latest artifacts are selected by the UI; historical assessment revisions remain inspectable.

Follow `DEMO.md` for the five-minute walkthrough. `validation/run-manifest.json` and `validation/readiness.json` are the final handoff records. Future work is limited to explicitly external acceptance checks and documented extension points, not missing core scaffolding.

## Desktop / GitHub follow-up (2026-10-08)
- Added matching code-drawn shield/rising-arrow SVG favicon, Apple touch PNG and native macOS ICNS; inspected the actual rendered PNG.
- `./scripts/install-desktop --build-only` builds `runtime/desktop/Intel to Improvements.app`. `./scripts/install-desktop` installs it on Desktop when run by the owner outside this session's filesystem restriction. Desktop installation was NOT RUN here: writable scope is the project and temporary directories.
- Launcher reuses a healthy loopback workbench, otherwise starts it with runtime/launcher.log and opens the default browser. Headless startup/reuse verified; native Finder click not exercised.
- Frontend build and all 48 tests passed again. Favicon/touch endpoints, ICNS decoding, app plist and shell syntax checked.
- Private GitHub repository created: https://github.com/NoCoolUserName/intel-to-improvements . Source publication uses authenticated gh Git data API, because runtime policy rejects writing local .git metadata. No credentials, dependencies, caches, database or full third-party reports are included.

## Selectable appearance follow-up (2026-10-08)
- Main top bar now provides Appearance: Original · Forest, SailPoint · Ocean, Dropzone AI · Midnight. Original palette is preserved; added light navy/blue and dark charcoal/violet/teal palettes apply to navigation, forms, tables, drawers, evidence, statuses and focus indicators.
- Browser-local preference persists independently of customer/environment. Invalid/blocked storage falls back safely; browser meta color follows the selection. Narrow layouts retain the selector.
- Official company sites/linked stylesheet palettes were inspected; sources and adapted accessible button violet documented in docs/THEMES.md. No third-party logos/assets/CSS bundled.
- TypeScript/Vite build passed; 48 regression tests passed. Actual theme module checks passed with DOM/storage stubs; 28 checked text contrast pairs meet 4.5:1 (minimum 4.951). Results: validation/themes.json. Rendered-browser visual review remains NOT RUN under existing computer-use limitations.
- Publication uses the existing private GitHub repository and gh Git data API; local .git remains restricted by runtime policy.

## Timing and analysis-label correction (2026-10-14 client date)
- Reproduced screenshot duration: ledger API passed a generated package into the assessment view, so package creation replaced assessment completion and counted the idle wait before generation. API now passes the persisted assessment; ledger also resolves a supplied package back to its original assessment defensively.
- Coverage card is now Receipt → first assessment, a fixed completed milestone for source/customer/environment, including waiting time. Reassessment keeps that first milestone; selected-revision and package timing remain separate in History. Long durations display hours/days.
- UI processing labels now explain Local analysis · no AI, Saved demo analysis, and Model API analysis. Local means fixed text rules, not disconnected networking. Model mode requires API configuration and profile policy; it is selected on submission and never auto-promotes existing results.
- Insufficient-evidence and held-out authored examples are hidden from normal case/queue/demo choices behind Show test cases. Underlying fixtures/history remain intact. Actual submitted low-evidence sources stay visible.
- 49 tests passed, including an API/direct-ledger regression for a delayed package plus later reassessment; scoped presentation checks and frontend build passed. Restarted the confirmed project server with no active jobs, using approved escalation for the local process/loopback port. Native rendered-browser review remains unverified.

## Saved-demo mismatch recovery (2026-10-14 client date)
- Saved demo findings are exact-content annotations for the bundled limited excerpt. A full report fetched from the matching URL is different content; replay must reject it. The previous UI incorrectly offered replay for arbitrary inputs and Resume for this persistent mismatch.
- Manual intake now offers Local or Model API analysis; Load selected case still runs the curated demo. Legacy/new replay mismatch jobs show a plain explanation plus explicit recovery buttons instead of Resume. Tracebacks remain under Technical details.
- Recovery reuses the persisted source revision without fetching again, freezes the original customer/environment context, keeps receipt/ingestion clocks, retains the original failure, and deduplicates repeat requests. Model recovery never falls back automatically. No real failed source was automatically reprocessed or sent to a model.
- Added scoped service/API regression covering recovery, clock/context preservation, no refetch, idempotency, customer isolation and missing model credentials; checked legacy failure recognition. Frontend build and 50 tests passed. Local project server refreshed after checking no jobs were active.

## Attack Flow integration
- Requested pin: `5c8bf4ca9ff64ef9b55c38a2505db318750cbcda`, real Builder 4.0.1 and extension 2.0.0.
- Workspace remains authoritative; local `.git` is absent. Confirmed connected GitHub main at `7a1d99bf3d51de71c3a2c79108007f03a348a087`; publish using existing GitHub API workflow with expected-parent protection.
- Inspected URL/readonly loader and automatic horizontal STIX layout. Loader does not fit the STIX camera; add a narrow ready/error/fit bridge.
- Sequence numbers alone will not generate edges. Existing frozen relationships may support directed edges; unknown/partial order remains explicit.
- Existing native CTI/MISP and human scenarios remain independent. New generator revision; historical packages unchanged.

### Attack Flow implementation completed and verified
- Added `iti/attack_flow.py`, pinned schema/extension registry and separate export/provenance/manifest/ZIP integration. Generator `packages-6-attack-flow-2`; historical packages unchanged.
- Added isolated `scripts/build-attack-flow`, explicit upstream patch/bridge, license notices, FastAPI mount/CSP, scoped React panel and curated-mode label.
- Build verified at requested pin. Fixed missing shared root config, Node 25 development-plugin failure, overly tall unordered initial layout, and disabled upstream Atomic links/recommender/chat.
- 56 Python + 20 frontend tests passed (7 Attack Flow + 13 existing App/theme checks); both production builds passed. Existing eval rerun: 12 TP/0 FP/1 FN on 5 fixtures.
- Actual browser verified ActiveMQ no fabricated edges; authored temporal edge/disconnected action; read-only, fit, pan/zoom, fullscreen, byte-matching download, separate editable draft, customer change. Offline test server blocks outbound DNS/socket connections; CSP/resources show localhost-only browser loads, no console errors.
- Actual UI screenshots/resources and machine test reports are in `validation/attack-flow/`. Authored case uses isolated `runtime/attack-flow-smoke`; normal runtime still uses port 8000.
- Temporary acceptance server stopped and idle main server refreshed on the final backend. Source review complete; publication uses the existing GitHub API workflow with expected-parent protection. The returned commit and file-hash verification are recorded in ignored `runtime/attack-flow-publication-result.json`. No live model/MISP/Gmail claims added.
- Reconciled GitHub-only App/theme tests and the already-updated frontend lock before publishing. Restored the established App/entry-point split; all 20 frontend tests, required typecheck and build pass on bundled Node 24.19.0. Existing CI files are preserved unchanged.
- Initial publication `e672306` reached main. CI identified a false-positive generic-api-key in the pinned Windows registry schema checksum. Changed hash metadata to explicit path/sha256 records; no schema bytes, digest, scanner setting or exclusion changed. Focused validation rerun before the corrective commit.

The initial strict Semgrep run reported no security findings but failed on five unescaped JSX ampersands. Encoded those visible labels without changing rendered text. Gitleaks 8.24.3 now passes the pin/schema directory with default rules and no exclusions; Ruff 0.17.0 correctness rules pass.
