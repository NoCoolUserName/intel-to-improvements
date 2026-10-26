# Pipeline Assurance — Phase 4

Pipeline Assurance inspects manually supplied GitHub Actions configuration and optional run/job metadata in the existing local FastAPI/React workbench. It is an assessment aid, **not proof that a repository or its software supply chain is secure**. Configuration, reported execution, enforcement and independently verified effectiveness are different facts.

No GitHub connection, credentials, workflow execution, remote resolution, scanning, AI, polling, risk scoring or automatic remediation is involved. Pipeline observations are separate from SARIF findings and CVE exposures. They create no improvement actions and do not enter Exposure Overview metrics.

## Import and inspect

1. Start the application using the [README](../README.md#start). Select an existing customer and environment, then **Pipeline Assurance**.
2. Enter repository `owner/name`, branch/ref and optional application and 40-character commit SHA. These are explicitly **operator-provided**, not authenticated repository facts. A commit is required only when attaching execution metadata.
3. Choose one or more workflow `.yml`/`.yaml` files. Select the synthetic checkbox for authored demonstration data.
4. **Preview pipeline snapshot**, inspect the explanations and original configuration references, then **Confirm pipeline import**.
5. Inspect a saved snapshot, its source hashes/downloads and observations. Without supplied execution evidence, execution remains unknown. No snapshot is automatically declared current or deployed.

Filenames must be plain basenames, such as `quality.yml`. Their evidence paths are recorded as `.github/workflows/quality.yml`; they are never used to read the host filesystem. Import a modified file as a new snapshot to preserve both assessments. A caller and included local reusable definition must be selected together to establish the limited local association described below.

## Supported input and limits

- 1–20 workflow files, at most 512 KiB each and 4 MiB aggregate; 1–100 jobs per workflow and 1,000 total steps per snapshot.
- UTF-8 YAML, one document per file; depth 24, 20,000 parser events per file, 32,768 characters per scalar, 200 entries per collection, 256 characters per mapping key and 2,048 per source location. Normalized assessments are capped at 5,000 observations / 16 MiB.
- Safe, non-executing parsing. Duplicate/merge keys, non-string mapping keys, all anchors/aliases, custom tags, unsupported types and nonfinite numbers are rejected. Supply expanded configuration when aliases are used. GitHub's `on` key remains a string; ordinary date values remain text. The loader does not modify other PyYAML consumers.
- Expected workflow, trigger, permissions, job and step structures are validated. This is a bounded subset, not a complete GitHub workflow schema validator. Unsupported control semantics remain unassessed. Expressions, shell scripts, arbitrary actions, matrix expansions and organization defaults are not evaluated.
- Original YAML, including unassessed fields and comments, remains in immutable source bytes. UI text is escaped by React; URLs, action references and embedded commands are never followed or executed.

## Control definitions (`pipeline-assurance-1`)

Each observation stores a check ID, category, state, explanation, supporting value, workflow/key/line where available, rule version, assessment time, snapshot ID and customer/environment/repository scope. Within a snapshot, its ID identifies the check and source location; it is not a cross-snapshot vulnerability correlation ID.

| Check | Inspected evidence and supported conclusion | Limits / manual review |
| --- | --- | --- |
| Declared permissions | Workflow declaration and job overrides; inherited declarations retain their workflow source line. `write-all` is a potential concern; explicit read/none declarations are observed; individual writes require review. | Narrow `security-events`, `contents`, `actions`, `packages` or `id-token` writes can be legitimate. Absent declarations and effective organization/repository/runtime permissions remain unknown. No claim that every write is unsafe. |
| Action and reusable references | External `owner/repo[/path]@ref`: a full 40-hex commit SHA is observed immutable-reference syntax; other tags/refs are potential concerns. `docker://…@sha256:<64 hex>` is recognized digest syntax. | A SHA/digest does not establish legitimacy, trust or content. Local `./…` references and non-digest container references require review. Other forms are unknown. Nothing is fetched. |
| Checkout credentials | Direct `actions/checkout` `persist-credentials: false` is observed; true is a potential concern. Presence of a custom token is recorded. | Missing/dynamic persistence remains unknown. Token privileges, credential necessity and repository-wide safety are not established. |
| Trigger trust boundary | `pull_request_target` and `workflow_run` require review. Other trigger declarations are recorded. Explicit checkout refs under sensitive triggers receive a separate review observation. | No trust/data-flow or exploitability conclusion; branch/path filters and expressions are not evaluated. |
| Event interpolation | Direct `${{ github.event.pull_request… }}`, `issue`, `comment`, `head_commit` or `commits` references in a `run` string are flagged as potential concerns. | This identifies a reviewable pattern, not proven injection or compromise. Arbitrary scripts and data flow are outside the analysis. |
| Security testing | Direct CodeQL `analyze`, Semgrep action or `semgrep ci/scan`, Gitleaks action or `gitleaks detect/protect/git/dir`, dependency-review action, `pip-audit` / `npm audit`, and regression commands `pytest` (including `python[3] -m`), `npm test`, `go test`, `cargo test`, `dotnet test`. | Only direct command starts and supported action names count; a comment, echo or lint invocation is not a scanner. The first recognized category in a step is recorded. Script wrappers, aliases and other tools remain unassessed. Configuration establishes neither execution nor coverage. Dependency review is distinguished from vulnerability scanning. |
| Control gate | Job/step `continue-on-error`, `if`, strategy/matrix and `needs` are retained. Continuation or obvious `\|\| true`, `\|\| :`, `set +e`, `exit 0` masking is a concern. Conditional/matrix controls require review. | Otherwise only configured failure propagation is observed. This is not a shell interpreter. Dependency success, effective shell behavior, release blocking and bypass resistance are unverified. |
| Merge enforcement | Explicit unknown for every workflow. | YAML alone does not establish branch protection, required checks or rulesets. This phase does not accept authoritative enforcement evidence. |
| Delegated coverage | External reusable definitions remain referenced but uninspected; missing direct categories become **Unknown** where a reusable job delegates work. | No false “missing scanner” conclusion for `NoCoolUserName/code-quality` callers. Included local callable definitions are assessed separately, one hop only. Inputs, secrets, nested calls and actual delegated execution remain unresolved. |

States are **Observed configured**, **Potential concern**, **Not observed in supplied scope**, **Requires manual review**, **Unknown** and reserved **Not applicable**. “Not observed” means no supported direct invocation was recognized in the supplied steps; it is not enterprise-wide absence. A concern can be legitimate in context. Read the supporting value and reason before making a judgment. No CVE, CWE, severity, exploitability or security score is invented.

## Optional execution evidence

In an inspected snapshot, upload a JSON envelope containing manually obtained GitHub REST response objects:

```json
{
  "workflow_run": {"id": 100, "run_attempt": 1, "...": "original run response fields"},
  "jobs": {"total_count": 1, "jobs": [{"id": 200, "...": "original job response fields"}]}
}
```

The ellipses above are explanatory, not a valid complete import. [run.json](../fixtures/pipeline/run.json) is a complete **synthetic** example. Preserve original response fields; do not invent missing metadata. The workbench makes no API calls or log downloads.

Limits: 2 MiB, 200 jobs, 1,000 total steps, depth 24, 50,000 values, 1,000 entries per collection and 32,768 characters per string; normalized metadata is capped at 8 MiB. Duplicate JSON keys, malformed JSON and unsupported types/status values are rejected. Extra REST metadata fields are preserved within these bounds.

Matching requires exact repository `full_name`, included workflow path and commit (`head_sha`, case-insensitive hex), plus matching branch/ref (`refs/heads/` may be omitted). Run ID/attempt and job ID/run ID/attempt must be explicit positive integers and consistent. Job IDs and step numbers must be unique; optional job SHA must agree. Supplied timestamps must be timezone-aware and chronologically consistent; step times cannot fall outside known job execution times. Mismatches are rejected before confirmation.

Control execution is associated only with a unique literal job name (or job ID when no name is declared) and a unique explicit step name in the same workflow. Dynamic names, matrices, ambiguous names or unnamed controls remain unknown. Step numbers are preserved, but not used to infer equivalence because runner-added steps can shift numbering. A partial jobs response is visibly warned about; omitted jobs remain unknown.

Select a saved run explicitly to inspect it. Configuration previews never inherit an old run's outcomes. There is no automatic “latest successful” selection or supersession:

- **Reported successful** requires a completed run with a reported conclusion and an associated completed successful job/step with start/end times. It does not require every other job to succeed, and does not establish scanner coverage, findings, enforcement or effectiveness.
- **Reported failed**, **Reported skipped** and **Reported cancelled** retain the associated non-success outcome. A skipped/cancelled job cannot count as a successful scan.
- **Incomplete** covers unfinished associated runs/jobs/steps or missing completion evidence. Neutral/action-required/stale or unassociated outcomes remain **Unknown / no evidence**.

Overall workflow success alone never establishes scanner success. All imported results are **SUPPLIED EXECUTION METADATA; not independently authenticated**. Internally consistent bytes and matching context do not authenticate GitHub execution. Independent verification is always false in this phase.

## Scope, identity and history

Existing SQLite records, content-addressed blobs, frozen profile snapshots and append-only activity are reused; no database reset or migration is needed. Original source records are identified by scope, evidence path and SHA-256; the first capture remains unchanged when referenced again. A configuration snapshot identity includes frozen customer/environment versions, operator context, sorted file paths/hashes and rule version. An execution import identity includes its snapshot, raw JSON hash and rule version.

Exact repeats return the original record without replacing timestamps or evidence. Changed bytes, context or rule version create separate assessments. Original evidence can be downloaded only through scoped routes and its hash is checked. No assessment automatically closes a finding, verifies remediation or changes any ledger record.

Previews use unpredictable IDs, expire after one hour and freeze customer/environment versions and the rule version. Cross-scope, forged, expired and stale confirmations are rejected. All files validate before source storage; confirmation checks all hashes and commits source records, assessment and activity together. Concurrent confirmations are idempotent. Valid previews may retain unconfirmed blobs for inspection; they are not confirmed assessments.

API routes under `/api/pipeline-assurance`: multipart `POST /preview`, multipart `POST /execution-preview`, JSON `POST /confirm`, scoped `GET` list, `GET /{snapshot_id}` and `GET /sources/{source_id}`. They retain existing host/origin restrictions. This is local single-operator isolation, not enterprise authentication or approval enforcement.

## Three-to-five-minute offline demonstration

All files in [fixtures/pipeline](../fixtures/pipeline/) are authored synthetic evidence, not actual GitHub executions. Placeholder SHA pins are syntax examples, not real approved actions. **Do not install these fixtures as executable workflows.** Normal startup seeds no pipeline demo records.

1. **0:00–1:00:** Select a fictional customer/environment. Open Pipeline Assurance. Enter repository `synthetic/juniper`, ref `main`, commit `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, an optional application label, and select **Synthetic configuration snapshot**. Choose `good.yml`, `concerns.yml` and `shared.yml` together. Preview and confirm.
2. **1:00–2:00:** Inspect permissions, SHA versus tag references, checkout persistence, direct controls and failure continuation. In `shared.yml`, show the pinned `NoCoolUserName/code-quality` reference and unknown downstream behavior. Explain that no remote definition was inspected and no workflow ran.
3. **2:00–3:00:** Attach `run.json` through execution preview/confirmation. Select that run: SAST reports success, secrets scanning is skipped, regression testing fails. Its overall success declaration does not override individual job results. It remains supplied synthetic metadata.
4. **3:00–4:00:** Attach/select `incomplete.json` and observe Incomplete, then try `mismatch.json`: the commit mismatch is rejected. Return to the older run to show preserved evidence rather than automatic latest-success selection.
5. **4:00–5:00:** Import `revised/good.yml` with the same operator context. Its basename remains `good.yml`. Inspect the separate snapshot; execution starts unknown and the previous configuration/run history remains available. Reimport identical files to demonstrate idempotency. Change customer to demonstrate isolation.

## Validation

From the repository root after bootstrap:

```sh
.venv/bin/python -m pytest -q tests/test_pipeline.py
.venv/bin/python -m pytest -q
npm --prefix web run typecheck
npm --prefix web test
npm --prefix web run build
```

Repository Code quality, Security and Public path privacy workflows remain unchanged. Focused tests exercise YAML safety, REST matching, atomic/scoped persistence, version/expiry checks, immutable downloads, honest execution states, UI preview/confirm/history/error handling and escaped text. The full suites cover existing CTI, CVE, AppSec, dashboard, ledger and export behavior.

Actual local Chromium acceptance used these fixtures against the production build and a separate temporary database, with outbound application networking denied and browser requests restricted to the local origin. It exercised import/confirmation, source-byte/hash downloads, successful/skipped/failed/incomplete evidence, mismatch rejection, revised snapshots, reload/scope changes, mobile layout and theme selection. [README screenshots](../README.md#visual-tour) show real local UI states, not independent operational verification.

Deferred: authenticated GitHub retrieval, continuous monitoring, execution, complete workflow-language analysis, recursive reusable resolution, branch-protection validation, scoring and automated remediation. No additional project phase is implemented.
