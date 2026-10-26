# Exposure Overview

Phase 3 adds a read-only management view of persisted CVE observations, application findings, existing improvement actions, retests and exceptions. Open **Exposure Overview** in the existing navigation and select the customer/environment above. Refresh is explicit. Measurements cover selected local records and available evidence only; they do not measure complete enterprise inventory, exploitation, risk reduction or organizational coverage.

This remains a local single-operator proof-of-concept workbench. Operator names, accepting authorities and uploaded evidence are not authenticated enterprise identities or independent scanner executions.

## Architecture and scope

`iti/exposure_overview.py` reads a consistent SQLite snapshot and indexes scoped records in memory. `GET /api/exposure-overview?customer_id=…&environment_id=…` validates the selected environment against its current customer profile. There is no global or all-environments view. Switching scopes clears the React workspace and ignores late responses, including demo responses.

The projection never calls the mutable CVE workspace/decision generator or source synchronizer. Reading metrics creates no records, decisions, clocks, activity or cached statistics. It uses persisted source mentions only; intake not yet synchronized by Vulnerability Intelligence is not included. Original source document bodies are omitted from the mention projection. It does not parse SARIF or retrieve external evidence.

Existing AppSec and infrastructure verification functions remain authoritative. An optional calculation timestamp lets both use the overview's UTC as-of instant; their existing callers retain their current behavior. The overview checks only the latest recorded retest for each subject. AppSec attachment integrity checks reuse the existing governance rules; this may read current supporting attachment bytes, never entire reports merely to count findings. Infrastructure qualification follows its existing method, evidence-kind, implementation, exposure and profile dependency rules; the overview additionally excludes missing or hash-mismatched supporting attachments. Internal consistency cannot authenticate uploaded evidence.

Limits are **5,000 scoped records / 64 MiB of stored record text**, and **64 MiB of current retest attachments to check** per request. Exceeding a limit returns an explicit error; no partial totals are returned. The SQLite schema, source models, ledger, dependencies and workflows are unchanged. There is no new infrastructure or persistent analytics store.

## Identities, provenance and current state

- AppSec: latest `(imported_at, id)` occurrence per existing logical finding identity. A repeated scan, import or normalizer revision does not add another logical finding. Distinct applications/contexts that Phase 1 cannot safely correlate stay distinct. An absent finding in a later report stays visible.
- Infrastructure: latest persisted asset/CVE observation per existing logical identity, preserving distinct assets. New finding IDs for the same asset/CVE remain observation revisions.
- Actions: unique current ledger action IDs. Existing action origins remain frozen. Multiple legitimate actions remain separate commitments. Actions whose origin disappeared are shown with unknown verification rather than discarded. CTI behavior actions are outside this exposure dashboard.
- Exceptions: each request with its latest recorded decision, preserving rejected/revoked and historical decisions in the existing detail workflow. Separate requests are not assumed to be revisions of each other.
- CVE mentions: distinct scoped CVE identifiers across persisted source revisions. This population may overlap CVEs in asset observations; the populations must not be added together as exposures.

Each row carries original record IDs, review/test references where applicable, environment and classification. **Inspect** opens the existing finding details (including triage, action, evidence and exception history) or the corresponding CVE workspace in the same scope. Infrastructure drill-down selects the CVE; its existing asset and action tabs retain separate asset identities. If an origin is unavailable, the appropriate scoped workspace remains accessible.

Current AppSec review dependencies must match the latest occurrence and profile. Stale reviews return to Needs review. Current reviewed not-applicable, false-positive and duplicate dispositions remain in the inventory but are excluded from outstanding exposures. Duplicate linkage never silently merges underlying evidence. An accepted exception does not remove a finding or count as remediation.

## Metric dictionary

All metrics include the shared selected scope and `as_of`, their definition, inclusion predicate, exclusions, population count and exact contributing row IDs. Counts are not percentages. The population count is the number of rows of the stated entity type (exposure, action, exception or mention), not enterprise coverage. Clicking a metric resets filters and reproduces its exact counted records; additional filters narrow that population explicitly.

| Metric | Included population and rules |
|---|---|
| Current logical AppSec findings | Latest occurrence per logical ID, including unknown and reviewed exclusions; raw occurrences are displayed separately. |
| Confirmed affected infrastructure | Current asset/CVE observation says confirmed affected; profile matches and observation is at most 30 days old. Synthetic observations remain labeled. |
| Potential / unassessed infrastructure | Needs-verification observations or observations with stale profile/age. No inference from CVE mentions. |
| Distinct CVEs mentioned in sources | Unique CVE IDs in existing scoped mention records; no asset exposure inferred. |
| AppSec needs review / reviewed applicable / reviewed duplicate | Current dependency-compatible disposition, or Needs review when absent/stale. |
| Outstanding exposure records | Current logical exposures without qualified resolution, excluding current reviewed AppSec exclusions and current assessed-not-affected infrastructure. Acceptance stays outstanding. |
| Outstanding remediation actions | Unique actions without a corresponding current qualified resolution; a closed status alone is insufficient. |
| Awaiting implementation | Outstanding actions with existing open/in-progress status. |
| Fix reported / retest requested | Outstanding actions with deployed/retest-requested status, without a qualified resolution. |
| Unassigned outstanding records / actions | Outstanding exposures without an asset/action owner, and outstanding ledger actions without an owner, respectively. Missing actions remain visible. |
| Actions past recorded target | Outstanding actions whose actual AppSec target date or infrastructure asset commitment deadline is before today UTC. An infrastructure review date is not a completion deadline. |
| Verification classes | Separate latest-outcome classes below; one class per exposure. Action status is separate. |
| Exceptions by state | One request counted under active operator-recorded acceptance, unapproved, expired, rejected, revoked or stale. Date expiry takes precedence, matching Phase 2. |
| Exceptions due within 7 days | Active acceptance whose recorded review/expiry instant is after as-of and at most seven days away. |
| Outstanding action age bands | Whole elapsed UTC days since recorded opened_at: 0–7, 8–30, 31–60, 61–90, over 90 or Unknown. These are descriptive categories, not corporate SLAs. |

Metrics can overlap (for example an overdue action is also outstanding). Inventory includes registered unresolved and resolved records; it is not a claim that every counted finding is exploitable or still affected. An asset's current recorded applicability and its verification outcome remain separate visible facts.

### Verification classes

The overview separates **Synthetic AppSec evidence reviewed**, **Supplied AppSec evidence reviewed**, **Operational infrastructure remediation**, **Operational mitigation only**, **Attestation only**, **Synthetic / lab evidence only**, **Retest failed**, **Retest inconclusive**, **Stale evidence**, **Pending / no qualifying evidence**, and **Fix reported / verification pending**.

AppSec success requires existing applicable review and valid supplied technical evidence under Phase 2 dependency/integrity/freshness rules. It never becomes independent operational verification. Only qualified closure clears its outstanding remediation action. A later failed test, changed implementation/profile/finding/context, expired evidence or missing attachment prevents old success from remaining current. Infrastructure operational remediation requires the existing supported method with live-system evidence, current exact dependencies, a current confirmed-affected observation and non-synthetic provenance. Mitigation alone does not resolve remediation. A test for another action cannot verify an unrelated action. Uploaded evidence remains operator-declared even when it meets the existing operational evidence schema.

Synthetic/lab results and attestation never enter operational infrastructure timing or remediation totals. Unknowns and stale evidence have neutral labels; there is no universal green “Verified” score.

### Ownership, dates and timing

The table separates action priority (operator-recorded), original scanner level and current applicability. No mapping creates a common risk score. Default order is alphabetical reference then stable row ID. Optional order uses owner, descending recorded overdue days or open age, with unknown dates last. Filters include origin, owner, status, verification, classification and overdue actions.

Target dates are date-only commitments evaluated against the UTC calendar date: due today is not overdue, yesterday is one day overdue. Exception dates are timezone-aware instants and expire at equality. Retest freshness uses elapsed time and the existing 30-day policy. Missing, malformed, timezone-less or future starting timestamps yield unknown durations, never zero. Closed/resolved actions have no outstanding-age/overdue duration.

Timing medians use only eligible current resolved exposures and show the sample size and contributing records:

- **Synthetic AppSec** and **Supplied AppSec**, separately: first persisted finding receipt (`imported_at`) to recording of the currently accepted successful retest (`recorded_at`), with qualified closed action. This is receipt-to-evidence-review time, not time since vulnerability introduction or scanner execution.
- **Operational infrastructure**: existing confirmed-exposure clock to the corresponding current qualifying remediation execution. A publication/disclosure date or mention receipt is never substituted.

Reopened, stale, unresolved, missing/invalid milestone and incompatible-cohort records are excluded. No eligible records means **Not available**, with a reason, not a zero-day median. Small synthetic durations demonstrate workflow mechanics only.

## Reproducible leadership demonstration (3–5 minutes)

Start the normal local app with `./scripts/run` (run `npm --prefix web run build` after frontend changes). Open **Exposure Overview** and choose **Load synthetic leadership demo**. This explicit action seeds `fictional-leadership-demo / leadership-lab` through existing services. It does not alter the earlier CVE/AppSec demo customers or seed on startup. Reloading is idempotent and preserves operator edits. A conflicting reserved customer without a completed marker causes an error rather than replacement.

1. **0:00:** compare 11 persisted AppSec occurrences with 10 logical findings. The last empty SARIF report does not close any finding. Compare one authored confirmed infrastructure observation, one unassessed asset and a separate source-only CVE mention.
2. **0:45:** click **Actions past recorded target**. Five outstanding actions have targets two days before demo creation. Inspect owner, action priority, unknown scanner severity and the recorded dates. Targets are commitments, not assumed SLAs.
3. **1:30:** expand verification/exception metrics. Inspect the pending fix claim, failed and inconclusive retests, one synthetic evidence-reviewed outcome and one stale historical closure. Operational infrastructure remediation remains zero.
4. **2:15:** compare active, expired and unapproved exceptions. Click each metric to see its underlying request; inspect the original finding and Phase 2 history. Acceptance leaves exposure unresolved.
5. **3:00:** inspect the stale finding to see the prior closed action requiring renewed review. Return to the overview; inspect the confirmed infrastructure row to open its CVE workspace. Unreviewed and unassigned findings remain visible with unknown metadata.
6. **4:00:** reload, switch appearance and customer. Other customer scopes do not show the leadership dataset. Choose Refresh to recompute current expiry/freshness.

All demo observations, owners, judgments and evidence are authored synthetic examples. The source-only CVE text is also explicitly fictional. Dates are deterministic offsets from the saved demo creation time; actual expiry and 30-day freshness continue to apply. To reproduce initial counts after editing/aging, use a fresh isolated data directory rather than overwriting normal user data:

```sh
ITI_DATA_DIR=/tmp/iti-leadership-demo .venv/bin/python -m uvicorn iti.api:create_app --factory --host 127.0.0.1 --port 8000
```

## Validation and limitations

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_exposure_overview.py
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Tests cover read-only snapshots, reconciliation, historical occurrences, dispositions, current/failed/stale/attested outcomes, eligible operational schemas, clocks and boundaries, bounded reads, deleted origins, scope separation, errors, accessible controls, safe text and late-response rejection. Existing Phase 1/2, CTI/CVE, ledger, integrations, themes and launcher suites remain required. CI retains its pinned Ruff, Semgrep, secret and privacy checks.

No automatic prioritization, risk percentage, scanner, ingestion redesign, workflow changes, ticketing, notifications, SLA enforcement, AI summary, background polling, all-environment aggregation, PDF export or Phase 4 pipeline assurance is included. The existing app's independent CTI refresh behavior is unchanged; this overview fetches only on entry or explicit refresh. Evidence quality and inventory completeness remain bounded by supplied local records.

Local validation on 2026-10-26: full backend suite **214 passed**, including **35 focused overview tests**; frontend **49 passed** across seven files; TypeScript and production build passed. Ruff correctness checks passed; Semgrep 1.180.0 ran the six pinned rules on 62 applicable files with zero findings. Real headless Chromium against an isolated loopback server reconciled all 38 metric populations, confirmed 11 occurrences / 10 logical findings and five overdue actions, exercised both existing detail workspaces, filters, reload, customer isolation, appearance and mobile layout with zero page errors. These are authored synthetic workflow results, not operational risk reduction.
