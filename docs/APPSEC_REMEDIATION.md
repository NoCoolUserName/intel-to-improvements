# Human-governed AppSec remediation — Phase 2

This is a **local proof-of-concept governance workbench**, not an authenticated enterprise GRC or ticketing platform. It records the separate contributions of security reviewers, engineering owners, evidence reviewers and a named accepting authority. Names and approval authority are operator-declared; the application does not authenticate those people or authorize them through corporate RBAC.

Phase 1's SARIF importer, evidence bytes and finding identities remain unchanged. Phase 2 adds human triage, commitments in the existing improvement ledger, bounded exceptions and review of supplied retest evidence. It does not scan, fix code, deploy changes, integrate tickets, score enterprise risk, enrich non-CVE findings, poll external services, or call an LLM.

## Practical workflow

Select an existing customer/environment, open **Application Findings**, and inspect a persisted rule. Its original message, scanner level, source hash, locations and raw evidence remain available. The new **Human-governed remediation** section has three areas:

1. **Triage:** enter a reviewer, disposition and reason. The UI cites the inspected immutable source; the API also accepts supporting attachment IDs. Default is **Needs review**. Other choices are **Applicable / remediation warranted**, **Needs further investigation**, **Not applicable**, **False positive (reviewed determination)** and **Duplicate of another finding**. A false-positive determination is an analyst judgment, not a rewritten scanner result. Duplicate targets must exist in the same customer/environment; self-links (including another occurrence of the same logical finding) and cycles are rejected.
2. **Remediation:** after current applicable triage, create a ledger action with an engineering owner, rationale, proposed change, expected result and retest plan. Record the security reviewer separately. Priority is explicitly operator-selected; there is no computed risk priority. A target date is optional and creates no SLA or escalation. Updates require an actor and change/reopening reason. Enter an implementation reference (commit/build/change) and fix claim before selecting **Fix reported / verification pending**.
3. **Evidence & exceptions:** upload supporting evidence, record a reviewed retest or request a risk exception. Inspect the full immutable history, with stale/current dependencies and evidence classes kept visible. A request cannot approve itself; record an accepting authority and approval/rejection/revocation separately.

**Reported ≠ Reviewed ≠ Assigned ≠ Implemented ≠ Verified.** The UI reports triage, work status, evidence outcome and risk acceptance separately. Neither assignment, implementation claims, an exception, nor a status field proves removal of a vulnerability.

## Existing improvement ledger integration

`ledger.improve` and `ledger.record_test` accept a narrowly scoped AppSec subject. They reuse `ImprovementAction`, `TestRun`, `EvidenceAttachment`, existing `improvement`/`test` records, scope locks and append-only `activity` history. There is no second action/task table. Original action scope and `origin.kind=application_finding` are resolved from actual persisted records and retained across edits. AppSec actions do not require a CVE, ATT&CK behavior, or vulnerability assessment. An additive `supplied evidence` attachment category avoids claiming uploaded technical material was executed in a lab; the legacy CTI/CVE ledger rejects this new category, preserving its existing behavior.

One action is supported per existing Phase 1 logical finding. The action holds the original finding/source/review and application/repository provenance. Later occurrences of that same logical identity need a fresh review before updating the existing action, while retaining its original origin. Shared actions across different findings and automatic equivalence guesses are not supported.

Existing statuses are displayed with AppSec-specific labels:

| Stored status | AppSec meaning |
| --- | --- |
| `open` | Open, or explicitly reopened with a reason |
| `in progress` | Engineering work in progress |
| `retest requested` | Fix reported / verification pending |
| `closed` | Explicit closure backed by current evidence-reviewed supporting retest |

`deployed` is not accepted for AppSec; supplying a claim does not establish actual deployment. Reopening retains all earlier closure and test history and invalidates the earlier outcome. If later evidence contradicts a closed action, the displayed lifecycle becomes **Reopen/review required; prior closure is historical**. The system does not silently edit the stored work status or create a fictional reopened/closed timestamp.

## What a successful retest means

Retests identify the finding occurrence, current applicable review, linked action, exact declared implementation reference, frozen application/repository/ref/commit context hash, procedure, execution time, expected/actual result, reviewer and judgment. Technical methods require actual immutable attachments, checked against their stored hashes. The attachment category must support the selected method. Maximum attachment size is 2 MiB; filenames are checked, bytes are never executed or fetched, and downloads use attachment disposition and binary media type. HTML and supplied messages are rendered as text.

Distinct evidence classes are analyst/developer attestation, supplied scanner report, supplied configuration/version evidence, targeted human-led test evidence and synthetic/lab evidence. Targeted tests require their recorded approval reference; this workbench never performs them. Scanner retests must link an actual same-scope SARIF batch with matching declared repository/ref/commit context. Supporting evidence cannot be reused for another finding occurrence.

A passed **analyst attestation** stays **Fix attested; verification pending** and cannot authorize closure. A passed technical retest, with current dependencies and explicit reviewer judgment, can authorize an explicit closure. The result is labeled **supplied evidence reviewed; not independently verified**, or **synthetic/lab evidence reviewed**. Even operator-labeled production evidence does not create an independent operational verification claim. `independent_operational_verification` is always false for this workflow.

SARIF absence alone is always inconclusive in this phase. The application has no scanner-coverage/comparability inference engine. A missing finding, an incomplete invocation, an unavailable rule or mismatched commit cannot establish a fix. For a supported conclusion, record separately supplied direct configuration/version or approved targeted-test evidence and the human judgment that evaluates it. This still establishes evidence review, not authenticated scanner execution or independent operational assurance.

## Dependencies, time and history

Triage and exception decisions freeze the current finding occurrence, exact source hash, application context and current customer/environment versions. Every new imported occurrence of the same logical finding conservatively requires renewed review, even if the difference appears small. Exact idempotent reimports create no new occurrence and do not reset decisions.

Verification additionally depends on the current applicable review, proposed change/retest plan, implementation claim/reference and explicit reopening. Supplied execution time cannot be future-dated beyond the existing five-minute tolerance. A test older than 30 days (the workbench's existing freshness convention), or predating the recorded implementation change, cannot authorize current closure. An older execution cannot be submitted over a later retest to reverse its outcome. The latest recorded retest governs: later failure or inconclusive evidence cannot leave an earlier success current. Missing/corrupted supporting bytes also invalidate current evidence.

Phase 1 deliberately includes available branch/commit context in identity. A different commit can therefore create a different logical finding. A later import explicitly changing a known repository's context flags the old review/outcome for renewed inspection; it does not correlate or merge those findings. Inspect and review the new finding context explicitly. This phase does not move old actions between identities or infer equivalence across commits/repositories. Unknown repository context cannot support that comparison and is not guessed.

All original findings, reviews, retests, requests and decisions remain immutable. Action snapshots persist in append-only ledger history while the existing action record stores the current work state. Stale profile/action edits, unknown IDs, forged review/origin data and cross-scope links fail server-side. Governance validation, action/test writes and audit events execute in one SQLite transaction through a small transaction-bound Store adapter; no migration or database reset is required.

## Exceptions and acceptance

A request names its requester and captures business justification, residual risk, claimed compensating controls, source/attachment references and a timezone-aware expiration/mandatory review date. Submission creates an **unapproved request**. A separate endpoint/form records **approved**, **rejected** or **revoked**, with a named authority and reason. Requester and authority must be different declared names, which is a recording convention, not identity authentication.

Approval is explicitly **operator-recorded**. The recorded review/expiration time is evaluated on each read; expiry does not depend on a mutable current flag or scheduler. Historical expired approvals can be recorded, but immediately display expired. Changed finding/profile context makes acceptance stale. Requests and their decision histories remain independently inspectable. Active acceptance leaves the finding, scanner severity and engineering action unchanged. Expiry does not automatically reopen tickets or close findings.

## Synthetic demonstration (3–5 minutes)

For an existing installation run `npm --prefix web run build`, then `./scripts/run` and open http://127.0.0.1:8000. In **Application Findings**, click **Load synthetic remediation demo**. This explicitly creates/selects **Juniper Software · AppSec synthetic demo / Synthetic remediation lab**, a separate scope from the existing Juniper CVE examples and normal user data. Repeat loading returns the existing data and never resets operator edits.

- **0:00 — Case A:** inspect `synthetic/case-A`. Review the security judgment, engineering owner, fix claim, synthetic supporting attachment and qualified evidence-reviewed closure. Independent operational verification is not claimed.
- **0:45 — Case B:** inspect the latest `synthetic/case-B`. The action remains in progress. A later authored report still reports it, so the previous review is stale and the finding needs review.
- **1:30 — Case C:** inspect `synthetic/case-C-active`, `C-expired` and `C-unapproved` under **Evidence & exceptions**. Compare explicit approved acceptance, expired acceptance, and a request with no decision. None is a fix.
- **2:15 — Case D:** inspect the latest `synthetic/case-D`. History shows a synthetic passed retest, historical closure, later failure and another report. Record renewed applicable triage. Under **Remediation**, choose Open with an explicit reopening reason; then record a new implementation claim and request a retest.
- **3:15 — Review evidence:** upload a clearly synthetic technical result, select **synthetic/lab evidence**, and record a configuration/version retest with its actual entered execution time, expected/actual result and reviewer judgment. A passed synthetic record permits only a qualified synthetic evidence-reviewed closure. A failed/inconclusive/attestation result remains pending. Reload and switch customer to verify persistence and isolation.

The bundled `fixtures/appsec/governance.sarif.json` extends Phase 1's authored CodeQL-/Semgrep-shaped fixtures. It is not actual scanner output. All case timestamps, evidence and outcomes are explicitly authored synthetic examples. Initial acceptance lasts 30 days; its real date-based expiry is intentional. No real enterprise risk reduction is represented.

For a fully isolated local demo server with non-loopback network calls denied:

```sh
npm --prefix web run build
.venv/bin/python scripts/appsec-offline-smoke
# Open http://127.0.0.1:8002; stop with Ctrl-C.
```

This uses ignored `runtime/appsec-smoke`, seeds the same synthetic demo and preserves subsequent edits. It does not reset the ordinary app database. Use a fresh isolated store when testing first-load behavior. If the reserved demo customer exists without a completed demo marker, the loader refuses to overwrite it.

## API and validation

Under `/api/application-findings/{finding_id}`: `GET /governance`; `POST /review`, `/action`, `/retest`, `/exceptions`, `/exception-decisions`, `/attachments`; and `GET /attachments/{evidence_id}`. Reads require customer/environment query parameters. Mutations require the exact four-field profile `context` returned by governance. Action changes additionally submit `review_id`, `actor`, `reason` and optimistic `expected_updated_at`; the server constructs origin. Demo loading is an explicit `POST /api/appsec/demo`. Existing loopback Host/Origin, body limits, CSP and scope restrictions apply throughout.

```sh
.venv/bin/python -m pytest -q
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Focused tests are `tests/test_appsec.py` and `web/tests/appsec.test.tsx`. They cover default/explicit/stale triage, cycles, idempotence/concurrency, immutable action origins, transaction rollback, separate exception decisions and expiry, evidence scoping/integrity/limits, method classes, chronology, failed/inconclusive/attested/qualified outcomes, reopening, context changes, synthetic cases, safe rendering and UI forms. The full existing Phase 1, CTI, CVE, ledger, MISP/STIX, Sigma, Attack Flow and theme suites remain required. Tests run offline without keys or scanner services. Existing pinned Ruff, Semgrep and secret scanning gates remain unchanged.

Deferred: shared multi-finding remediation efforts, authenticated approvals/RBAC, cross-identity reconciliation, automatic SARIF coverage inference, live scanning, integrations, ticket automation, autonomous remediation, enterprise scoring, SLA engines, dashboards/analytics, and all Phase 3/4 work.

Local validation on 2026-10-26: **137 backend tests passed** (29 focused AppSec tests); **41 frontend tests passed** across six files; TypeScript, production build and shared Ruff correctness checks passed. Semgrep 1.180.0 ran the six pinned security rules on 59 supported targets with zero findings; Gitleaks 8.24.3 found zero leaks in the publishable snapshot. Genuine Chromium exercised all six synthetic case variants and completed renewed review → reopening → fix claim → immutable evidence upload → qualified retest → explicit closure, checking original action origin, evidence SHA-256, preserved failed/successful history, reload, cross-customer isolation, theme/mobile visibility and zero page errors. The smoke server and browser denied non-loopback traffic. These are synthetic workflow validations, not operational remediation or enterprise risk-reduction measurements.
