# Application Findings — Phase 1

A bounded, local manual SARIF 2.1.0 importer beside Vulnerability Intelligence. Application findings are scanner observations, including findings without CVEs. They do not enter the CVE-only `ExposureObservation`, response policy, enrichment or automatically create improvement/verification records. Human-governed remediation is available separately in [Phase 2](APPSEC_REMEDIATION.md). Scanning, execution of remediation/retests and enterprise risk scoring are **not performed**. Successful import does not establish that an application is secure.

## Import and inspect

For an existing installation, run `npm --prefix web run build`, restart with `./scripts/run`, and open http://127.0.0.1:8000. Fresh installations use `./scripts/bootstrap` first. No new dependencies, keys or external services are required.

1. Select an existing customer and environment in the top bar.
2. Open **Application Findings**, adjacent to **Vulnerability Intelligence**.
3. Choose a manually supplied `.sarif` / `.json` file. Optionally enter application, repository, branch/ref and commit. These are explicitly operator-supplied, never substituted into SARIF-reported provenance. Mark authored reports synthetic/demo.
4. **Preview SARIF**. Inspect findings, warnings, run metadata and frozen profile versions. Editing the input clears the UI preview.
5. **Confirm SARIF import**. Click a persisted rule to inspect its message, rule metadata, scanner/run, locations, fingerprints, identities, source hash, context and limitations. Import history also exposes empty reports and original evidence downloads.

Generate a SARIF report using your independently operated CodeQL or Semgrep workflow, then manually choose the resulting file here. This application neither runs those tools nor connects to GitHub. For an offline example, use `fixtures/application-findings/codeql.sarif.json` and `semgrep.sarif.json`. These are clearly labeled **authored synthetic fixtures, not real CodeQL/Semgrep scan outputs**. Each contains two findings sharing a CWE, without a CVE; CodeQL-shaped partial fingerprints, Semgrep-shaped full fingerprints and a fallback case are covered. Semgrep-shaped severity is deliberately unknown. Paths refer to authored text examples, not vulnerable executable code.

## Supported content and limits

The bundled SARIF 2.1.0 JSON Schema validates structures/types offline; the input `$schema` URI never selects a schema or triggers retrieval. Date/time formats are checked. The importer supports multiple runs; driver names/versions; driver and extension rule references by ID/index/GUID (including consistency checks); rule descriptions/properties; original text/Markdown/message IDs and bounded argument substitution; explicitly supplied result levels and rule default levels; all primary locations, artifact indexes, URI strings, line/column regions; fingerprints and partial fingerprints; explicit literal CWE/CVE identifiers in rule/result property metadata; version-control provenance; automation details and invocation metadata/timestamps.

Result messages use the same bounded substitution for direct text and supported ID lookups (the selected rule's `messageStrings`, then its tool component's `globalMessageStrings`). Plain text takes precedence over Markdown. Following SARIF [sections 3.11.5–3.11.11](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), `{0}` selects argument zero, repeated placeholders repeat that value, and `{{` / `}}` display literal braces. Arguments are inserted once as literal text, even when they contain braces or HTML-looking strings. There is no Python formatting, Markdown rendering, or HTML execution. An empty supplied argument is valid. Missing/out-of-range arguments leave their placeholders visible with a warning; unsupported formatting syntax stays literal. If the resolved message would exceed 32,768 characters, the entire original template is retained with a warning, without partial expansion. Original message objects and evidence bytes never change.

CWE and CVE extraction is literal and case-insensitive in explicit property metadata (including tags), not inferred from rule names or prose. Taxonomy references, code flows, fixes, suppressions, baselines, related locations and external property files are retained as evidence, not interpreted. Unsupported result/run fields receive visible warnings. Rule metadata and vendor properties remain inspectable. Missing metadata remains null/unknown. Scanner severity metadata is preserved with its original rule/result property path, with no conversion to enterprise risk priority. An explicit result level is distinguished from a rule default. Invocation rule-level overrides are not evaluated, so an overridden default remains unknown. SARIF's implicit default warning level is **not** invented when no level was supplied.

Reported invocation success is only a scanner assertion. False execution success, nonzero exit codes or execution notifications yield failed/incomplete. Missing success evidence remains unknown. Scan completeness always remains unknown, including empty reports. Import time is separate from explicit invocation start/end times. No commit, branch, ownership, reachability, exploitability, business impact or remediation state is inferred.

Limits: 4 MiB original bytes; 1,000 total results; 100 runs; nesting depth 32; 200,000 JSON nodes; 32,768 characters per string; 1,000 entries per collection; 16 MiB normalized finding data; 32 MiB including repeated frozen profile context. Duplicate JSON keys, invalid Unicode, nonfinite numbers, unresolved indexed references, malformed structures and unsupported versions are rejected. Message expansion is bounded. Split oversized reports outside this app. Errors do not echo report contents.

Artifact paths/URIs, Markdown and scanner messages are untrusted evidence strings. There is no fetching, source-file access, shell evaluation or HTML execution. The frontend renders text, never imported HTML or clickable artifact URI links. Original evidence downloads have an attachment disposition and generic binary media type. Existing loopback Host/Origin restrictions apply.

## Identities, evidence and isolation

Four identities remain distinct:

- **Source document**: customer/environment plus SHA-256 of exact uploaded bytes (including whitespace). Original bytes use existing immutable content-addressed blob storage; scoped source records control access even if identical bytes share a blob.
- **Import batch**: original hash, full frozen customer/environment context, operator context and normalizer version. An exact repeat in unchanged context with the same normalizer returns the first batch without rewriting timestamps or evidence. Changed profile, manual context or normalizer version creates a separate batch.
- **Normalized finding**: batch plus run/result indexes. Every occurrence is preserved, including identical results in the same report.
- **Logical finding**: customer/environment, available operator/reported repository context, tool/component and rule, plus full scanner fingerprints where supplied. Partial fingerprints also require location; the conservative fallback uses locations and original message. Missing repository/application context, rule or usable location/fingerprint makes correlation document-local. CWE alone is never an identity. Commit/ref changes may produce a different logical identity; there is no heuristic cross-branch merging. Logical correlation never collapses evidence occurrences.

Preview records use unguessable server-generated identifiers, freeze scope/context and normalizer version, and expire after one hour. Confirmation accepts only that identifier and selected customer/environment; it cannot accept client-forged normalized rows. Cross-scope, expired, changed-profile and changed-normalizer previews fail. Profile version comparison and all source/batch/finding/event records commit in one SQLite transaction; concurrent confirmations are idempotent. Validation completes before preview storage. Preview blobs/records remain local evidence even if never confirmed; they are not findings. No cleanup scheduler is introduced.

### Message normalization versions

`sarif-normalizer-2` corrects direct-message argument substitution and escaped literal braces. The preview displays its version, and the confirmed batch records that exact version. Version 1 batches/findings keep their original IDs, messages, timestamps and evidence references; existing imports are not rewritten or silently reprocessed. Old pending previews, which did not store a version, must be previewed again after upgrading.

To obtain corrected message text for a v1 import, explicitly preview and confirm the original file again. This creates one separate v2 batch and new normalized finding occurrences; subsequent identical v2 imports are idempotent. With unchanged scope/context, the original source bytes/hash and logical finding identities stay the same. A new occurrence conservatively makes earlier AppSec decisions stale under the existing freshness rules and requires renewed review. Historical reviews and actions remain preserved. Re-normalization is not a new scanner execution or remediation evidence. There is no database migration or automatic backfill.

Persistence adds record kinds to the existing SQLite store: `application_preview`, `application_source`, `application_batch`, `application_finding`. There is no migration or database reset. Prior records and raw evidence are not overwritten. A later report that omits a finding does not mean it was fixed, closed or verified. The importer creates no remediation state or ledger mutation; explicit Phase 2 governance is separate.

API routes under `/api/application-findings`: `POST /preview` (multipart file + scope + optional context), `POST /confirm` (JSON preview ID + scope), `GET /` (scoped list/history), `GET /{finding_id}`, `GET /imports/{batch_id}`, and `GET /sources/{source_id}` (original bytes). All reads require `customer_id` and `environment_id` query parameters. Scope is enforced server-side, independently of UI selection.

## Three-minute demo

- **0:00:** select Northstar Bank / Windows AD lab. Preview `codeql.sarif.json`, with application `Synthetic demo`. Inspect two CWE findings without CVEs and scanner-reported level provenance.
- **0:45:** confirm; inspect a rule, original message, partial fingerprints and evidence SHA-256. Download the original report.
- **1:30:** import `semgrep.sarif.json`. Observe unknown severity, the full fingerprint and fallback identity. Repeat the same import and observe the existing batch without added findings.
- **2:15:** reload to see persisted findings. Switch to Cedar Cloud: findings disappear from that scope. Return and inspect immutable import history. No scan-completeness, validated exposure, fixed finding or remediation claim is produced.

## Validation

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_sarif_messages.py
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Backend tests include real FastAPI multipart preview/confirm/list/detail/download, multiple runs and references, both fixtures, unknown metadata, severity provenance, logical identities, concurrent repeats, stale/expired/forged/cross-scope previews, unsafe strings, malformed/oversized/pathological inputs, source integrity and transaction rollback. Frontend tests cover import confirmation, preview invalidation, errors, escaped content and late scope responses. Existing regression suites cover CVE and ledger compatibility. All are offline and deterministic. The repository's unchanged CI runs correctness lint, tests, build, secrets and pinned Semgrep rules.

Phase 2 human-governed remediation is documented in [APPSEC_REMEDIATION.md](APPSEC_REMEDIATION.md). Phase 3 dashboards, prioritization, live scanner/GitHub/ticket integrations, automatic closure, background polling, AI analysis and autonomous remediation remain deferred and excluded.

Phase 1 validation on 2026-10-26: full backend suite **108 passed**; frontend **35 passed** across five files; TypeScript and production build passed; shared Ruff correctness rules passed; Semgrep 1.180.0 with the six pinned repository security rules found zero issues; Gitleaks 8.24.3 found zero leaks in the publishable snapshot. A real headless Chromium session against an isolated loopback server imported both fixtures (four persisted findings), inspected details, verified downloaded evidence hashes, reloaded persisted data, repeated imports without adding rows, switched scope, and checked mobile visibility/theme changes with zero page errors. These are synthetic import validations, not operational scanner or remediation results. Existing optional live-service acceptance limits remain unchanged.

Message-normalization v2 validation on 2026-10-26: **179 backend tests** and **44 frontend tests** passed, with TypeScript and production build passing. The two reported message regressions fail against unmodified `d83eaf0` and pass with this patch. API regressions cover direct messages, supported rule/component lookup paths, repeated/escaped/literal arguments, exact expansion limits, legacy record preservation, version-bound previews and scope isolation. A real Chromium import/confirmation/detail/download exercise verified both message forms, safe text rendering, exact source bytes/hash, repeat idempotency, reload, scope switching, theme and mobile visibility with zero page errors.
