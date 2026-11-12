# Brotli exposure response — from intelligence to verified outcomes

This is a **fictional, offline working case** for `CVE-2026-111497`. The customer is **Harborlight Capital — fictional Brotli demo** and the environment is **Financial-services application estate — synthetic**. Edward Jones is the presentation audience only; this case contains no Edward Jones asset, employee, architecture or targeting assertion. The workbench records governance judgments and engineering commitments; it does not patch, deploy, scan, investigate a live SIEM or authenticate a real approval.

## Start and load

From the repository root after the normal bootstrap:

```sh
./scripts/run
# Open http://127.0.0.1:8000
```

Open **Add Intelligence → Load Brotli working case**. The card previews the separate fictional scope. Loading is explicit; normal startup neither seeds this case nor changes customer selection. The loader stages service-validated records, publishes them in one database transaction, and refuses a collision with a preexisting customer under its reserved ID. Reopening preserves operator edits and the original receipt/history clocks. For a clean rehearsal without touching ordinary runtime data:

```sh
ITI_DATA_DIR=/tmp/iti-brotli-rehearsal .venv/bin/python -m uvicorn iti.api:create_app --factory --host 127.0.0.1 --port 8000
```

Use a fresh **new** directory for a new initial-state rehearsal; do not erase an ordinary runtime directory. The entry point after loading is **Cases & Analysis → Brotli exposure response**. Expand the already open case guide for links to all thirteen existing workspaces, actual record IDs, source pages, fixture downloads, a human-readable summary and the versioned relationship manifest. Browser Back/Forward and explicit customer/environment scope work with the action links.

## Five-minute leadership route

| Time | Navigation | Question and expected starting state |
| --- | --- | --- |
| 0:00 | Add Intelligence → Load Brotli working case → Cases & Analysis | **What do we know?** Dated vendor and research statements, exact dossier spans, source gaps and a hypothetical two-entry Attack Flow; no customer intrusion. |
| 0:45 | Guide → Vulnerability Intelligence → CVE-2026-111497 → Assets & decisions | **Where does it matter?** Six distinct synthetic asset observations. Client API, research fetcher and advisor package are affected with modeled untrusted decoding; reporting service has an affected component but no identified untrusted path in the reviewed scope; vendor package is unknown; patched reference is a starting exclusion. |
| 1:40 | Guide → Improvement Actions → advisor-package action; open originating workflow | **Who owns the change?** Advisor engineering owns bundle rebuild/deploy. Exposure management owns the decision and evidence requirement. The CVE action asks for running artifact identity; the AppSec action owns the complementary rebuild/redeploy work. |
| 2:30 | Guide → Application Findings → `demo/self-contained-package` | **Why is the claim insufficient?** Host/shared runtime 8.0.33 was reported, while the deployed self-contained application still embeds 8.0.32. Attestation is inconclusive; the latest synthetic technical retest fails. |
| 3:20 | Guide → Pipeline Assurance → initial and revised snapshots; then Purple Team | **What evidence changes the decision?** Overall success with a skipped authored security step and an unassessed native/runtime script cannot close the finding. Require compatible build, deployed bundle identity, benign path results, telemetry sufficiency and a reviewed retest. |
| 4:20 | Guide → Exposure Overview, Coverage, Intelligence Exports | **What can leadership report?** Owners, open commitments, failed/pending outcomes and qualified replay. Do not add CVE mentions, SARIF findings and pipeline observations into a unique-exposure count. Coverage is telemetry/test coverage, not estate patch coverage. |

## Script for the meeting with Steve

**Before the meeting:** open Customer Profiles, select **Harborlight Capital**, choose the sector and save. This brings the PHP2Shell and Brotli environments into the company dashboard.

**Start on Exposure Overview (30 seconds).** “Steve, I want to show how I can take an advisory through to accountable work and evidence. This dashboard brings together the selected company’s saved cases. I can see outstanding exposure, open actions and work waiting for retest. These are demonstration records, not a claim about your estate.”

**Open the Brotli case from the case list (45 seconds).** “I can trace this case back to its source material. I keep the published vulnerability information separate from the fictional assets and analyst assumptions used in this demonstration.”

**Open Vulnerability Intelligence → Assets & decisions (one minute).** “My first question is where the affected decoder is actually used. This example includes inbound application requests, outbound responses and a self-contained application bundle. I need an asset-specific decision and an owner for each relevant path.”

**Open Application Findings → the advisor package finding (one minute).** “Here is why a reported patch is not enough. The host update was reported, but the deployed application still contains the older bundled runtime. The supplied technical check fails. I keep the work open until the evidence supports the intended change.”

**Open Improvement Actions, then Pipeline Assurance (one minute).** “I can show the engineering owner, proposed change and required retest. A successful pipeline result also needs context: a skipped security check or an unassessed runtime script cannot prove the deployed artifact is safe. This example records supplied evidence; it does not run a deployment.”

**Return to Exposure Overview (30 seconds).** “I want leadership to see what still needs a decision, who owns the next step and which outcomes have evidence. The dashboard updates automatically. For a pilot, I would start with one real case and agree the inventory, owners and evidence needed to close it.”

If asked whether this proves a compromise or a successful fix: “No. This is a synthetic workflow demonstration. A real conclusion needs evidence from the relevant deployed environment, and investigating earlier activity is a separate task.”

## Practitioner route

1. **Customer Profiles:** inspect role-based fictional owners, business consequence, fourteen-day *declared* retention and the inbound-only filter claim. No telemetry availability was independently confirmed.
2. **Add Intelligence / Cases & Analysis:** separate publisher facts from analyst-authored path hypotheses and synthetic inventory. The source is an attributed dossier; its content hash is fixed to this scenario version. A changed dossier is rejected, never given the same curated conclusions.
3. **Vulnerability Intelligence:** inspect the immutable source assertion, separate exploitation and asset-specific impact assessments, current `vulnerability-response-2` proposal and explicit response reviews. Follow the assessment walkthrough below. The loader preserves manual assessment review; source assertions and accepted response decisions are not independent assessment reviews.
4. **Application Findings:** inspect the original SARIF bytes, repo/ref/commit and source locations. The named tool is an **authored review**, never a scanner run. Review the client API evidence-gate success as a synthetic candidate check; inspect the advisor attestation followed by failed technical evidence. The research control-scope finding has a two-day fictional exception with a separate accepting authority, residual risk and permanent-fix plan. Approval is not a fix.
5. **Hunts / Coverage:** work inbound, outbound and process hypotheses independently. `events.json` has investigation signals, ordinary Brotli, benign truncation, legitimate process execution and missing-telemetry controls. Check source fields, retention and process start/boot identity before interpreting PID or no hits. No SIEM query ran. Authored rules remain drafts; unsupported correlations are procedures, not claimed Sigma matches or deployed detections.
6. **Purple Team:** inspect the pinned-schema Attack Flow with two branches into conditional decoder processing, plus catalog-derived D3FEND candidates. D3FEND suggestions can be promoted only through the existing action workflow. Plans use benign replay by default and require separately authorized human lab scope for any actual test. A benign pass establishes only that path's tested behavior.
7. **Pipeline Assurance:** inspect `fixtures/brotli/initial-pipeline.yml` and `initial-run.json`, then revised files. Each supplied run uses exact repository, path, ref, commit, job and step identity. A language dependency check does not establish embedded decoder, built image or running artifact coverage. The custom runtime script is conservatively unassessed by the existing parser. Configured, reported executed, enforced and effective remain distinct.
8. **Improvement Actions / Exposure Overview:** follow the original CVE/AppSec/D3FEND ledger records. The relationship manifest lists actual resolved IDs and explains complementary work and overlapping evidence. The overview reads existing scoped records and excludes synthetic results from operational timing/verification.
9. **Intelligence Exports / Evaluation:** download the existing package, STIX/MISP, hunts, purple-team plans, Attack Flow and provenance. Use the separate scenario summary and manifest for governance and pipeline links that the standards exports cannot faithfully represent. The case integrity checks and regression tests are workflow evidence, not a security score.

## Review exploitation and impact separately

Use a fresh isolated rehearsal directory as described above, load the case, and retain the loaded customer/environment profile unchanged while checking the initial state. Profile edits or observations older than 30 days can change applicability and recommendations; reopening does not reset them.

Open **Vulnerability Intelligence → CVE-2026-111497 → Assets & decisions**. Each asset shows **Exploitation** (shared for this CVE/customer/environment) and **Impact if exploited** (specific to that asset). Initially both cards show **Not assessed / Not reviewed**, with empty **Assessment history**. The exploitation editor suggests **Observed exploitation** from the existing reviewed Datadog assertion; impact suggests **Unknown**. Neither suggestion is an approved judgment. The loader already accepts the six policy responses as fictional response reviews and creates five CVE actions; those records do not supply assessment confidence or impact ratings.

| Synthetic asset | Initial proposal under `vulnerability-response-2` | Basis, independent of an impact rating |
| --- | --- | --- |
| `client-api` | Expedite remediation/mitigation | Confirmed affected and reachable; critical asset importance and reviewed exploitation reporting. |
| `research-fetcher` | Expedite remediation/mitigation | Confirmed affected and reachable through outbound decoding; high asset importance and reviewed exploitation reporting. |
| `advisor-package` | Expedite remediation/mitigation | Confirmed affected and reachable self-contained bundle; high asset importance and reviewed exploitation reporting. |
| `reporting-service` | Prioritize within the existing remediation program | Confirmed affected; no untrusted path identified in the supplied synthetic scope. |
| `vendor-analytics-agent` | Investigate applicability/exposure | Applicability needs verification; reviewed exploitation adds the urgent-applicability reason. |
| `patched-reference` | Not applicable | Documented starting exclusion; no campaign remediation credit. |

1. **Inspect the source basis first.** In **Sources**, read the dossier spans, source gaps, **Dated source assertions**, and **Evidence references and source-scoped aliases**. The Datadog assertion is attributed reporting, not independently retrieved intrusion evidence. No direct KEV snapshot was imported. Preserve the distinction between publisher/event dates and application receipt/review dates.
2. **Review exploitation manually.** Return to **Assets & decisions**, select **Review exploitation** on one asset, and inspect **Evidence supporting this assessment**. If your review supports Observed exploitation, select the existing reviewed observed-exploitation assertion and relevant dossier source. Enter your own assessment reviewer, confidence and confidence explanation, rationale, uncertainties and change reason; explicitly retain the derivative-source and synthetic-scope limitations. Do not copy a suggestion as an approved finding. **Save selected assessments**, then inspect the shared result on the other assets. This judgment concerns reported exploitation of the CVE, not Harborlight compromise or current activity.
3. **Review impact per asset.** Select **Review impact** for the asset being examined. Choose a category only when supported; leave it unassessed or record Unknown with the evidence gaps when insufficient. A non-Unknown rating requires the current exposure revision plus a technical source or reviewed assertion, and explanations of technical outcome, additional privilege/capability, confidentiality/integrity/availability effects, business scope, access prerequisites and assumptions/boundary evidence. Critical also requires why High understates the consequence. Supply independent confidence, rationale, uncertainties and change reason. Asset criticality, a vendor High label, or another asset's rating is not an impact assessment. Any saved exercise judgment must remain explicitly synthetic; no new fixture judgment is required to run this case.
4. **Inspect evidence and revisions.** After saving, expand **Dated evidence and assumptions** and **Assessment history → Frozen assessment and evidence** on each reviewed axis. Check the selected evidence references/hashes, reviewer, confidence explanation, rationale, uncertainties, assessed time, review deadline and change reason. A subsequent justified review appends a revision; it does not rewrite the prior assessment. Source/context changes or the review deadline can require review again. See [Independent exploitation and impact assessments](VULNERABILITY_INTELLIGENCE_DEMO.md#independent-exploitation-and-impact-assessments) for validation and freshness rules.
5. **Explain the recommendation separately.** Compare **PROPOSED RESPONSE**, its reasons, **Frozen decision inputs**, and **Immutable decision and review history** before and after a review. `vulnerability-response-2` retains the source-exploitation, applicability and reachability gates. A current reviewed High/Critical impact with Medium/High confidence provides an additional consequence route to expedited action; it does not establish exploitation or reachability. The first three assets already expedite through asset criticality, so an assessment can add explanation/history without changing the response. High impact alone cannot bypass the reporting service's reachability limitation, the vendor package's unknown applicability, or the patched reference's exclusion. Saving an assessment does not accept a recommendation: separately use **Accept recommendation** or **Record override** with a reason when warranted. Existing accepted commitments remain protected; a lower, stale or disputed assessment does not silently release urgency. Reuse the existing asset action rather than creating a duplicate; any link to a newly reviewed decision preserves its original provenance.

These reviews do not convert synthetic inventory, candidate checks or failed bundle evidence into actual customer exposure or operational remediation. Prior-compromise investigation remains separate.

## Source support and provenance

The exact dossier bytes are hashed as `45b98ae6a0e2a8b92074f6dd39f1cb6cf59a823c182cb5df048f36a2c1af4157`. `fixtures/brotli/sources.json` records the publisher URL, available publication date, selected readable text or a concise paraphrase, retrieval failures, and the actual web-renderer retrieval time **2026-11-07 10:37:18 UTC**. On load, each stored excerpt or paraphrase is hashed separately in the source metadata and scenario manifest. These are **stored-text hashes**, never original publisher-page hashes. The authored dossier has its own input hash and exact normalized evidence spans. The full publisher HTML/PDF and direct NVD text were not obtained by this fixture.

| Source | Dated support used here |
| --- | --- |
| [Google Brotli v1.2.1 release](https://github.com/google/brotli/releases/tag/v1.2.1) | 21 October: upstream security release for CVE-2026-111497; no broad package-version inference. |
| [Node.js security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [24.22.1 release](https://nodejs.org/en/blog/release/v24.22.1) | 21 October: affected bundled decoder requires an application to decompress attacker-controlled Brotli input; 22.x, 24.x and 26.x fixes. Historical first fixed versions: 22.23.4, 24.22.1 and 26.12.1 respectively. The fixture's 24.22.0/24.22.1 comparison is branch-specific. |
| [Microsoft .NET advisory](https://github.com/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9) | 25 October: affected .NET 8 before 8.0.33, 9 before 9.0.22 and 10 before 10.0.14 for listed packages. Self-contained applications need rebuilding and redeploying with the updated runtime; a host update alone is insufficient. |
| [Red Hat assessment](https://access.redhat.com/security/cve/cve-2026-111497) | Product-specific assessment and conditional untrusted decompression path. No Red Hat installed-package or backport finding is asserted. |
| [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/node2shell-cve-2026-111497-nodejs-brotli-decoder/) | 29 October: first-party reproduction on Node.js 24.22.0, outbound response-decoding path, and a dated report of confirmed in-the-wild exploitation. The underlying cases were not independently retrieved; no actor or Harborlight compromise is inferred. |
| [Splunk detection story](https://research.splunk.com/stories/node2shell/) | 28 October: request-error and Linux process-image-change investigation leads; telemetry and benign comparisons are required. |
| [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-111497), [CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | NVD returned no readable lines and CISA returned HTTP 403 to this retrieval. No direct CVSS/KEV values, federal dates or EPSS score were imported. Datadog's catalog statement remains attributed secondary reporting. |

Node.js calls the issue **High**; Microsoft labels its advisory **High**. No single cross-vendor CVSS score is calculated. Missing EPSS is unknown, not zero. Public disclosure, publisher updates and synthetic asset observations are separate from the actual source-receipt, assessment, review and test-recording times. The `2026-11-06` event timestamps in fixture JSON are explicitly synthetic replay times, not backdated application audit records. No CISA federal date becomes a fictional company deadline; the local two-day review/exception dates are authored governance decisions recorded on load.

## Stored relationships and outcome limits

The versioned marker `brotli-cve-2026-111497-v1` stores source revision, extraction, assessment, package, six exposure/decision IDs, CVE actions/tests, SARIF findings/actions/tests, pipeline snapshot IDs and the D3FEND action ID. The CVE-to-AppSec and pipeline links are **scenario-manifest relationships** where no native cross-domain foreign key exists. Shared CVE text alone never creates a relationship. The case keeps one CVE asset action per supported asset; AppSec's client gate and advisor rebuild actions are complementary and explicitly disclose overlapping evidence.

`client-api` has a passing **synthetic candidate-artifact** check while its baseline remains affected and operational remediation open. `advisor-package` has an inconclusive host attestation followed by failed synthetic bundle review. The reviewed research exception is time-bounded and retains residual risk. The patched reference starts fixed and receives no campaign credit. No synthetic or lab result becomes live verified remediation, a shorter operational clock, a proved detection, an absent compromise finding or a universal green badge.

The investigation remains separate: a patch and a green build cannot answer whether activity occurred before the fix. Missing response/process telemetry yields inconclusive, and an HTTP Brotli header, decoder error or crash is only an investigation signal. This bundle contains no exploit bytes, memory-corruption probe, malware, external-target test, scanner execution or autonomous remediation.

## Checks performed for this implementation

From the repository root on 7 November 2026:

```sh
.venv/bin/python -m pytest -q tests/test_brotli_demo.py
# 7 passed
.venv/bin/python -m pytest -q
# 323 passed, 3 subtests passed
npm --prefix web test
# 68 passed across 12 files
npm --prefix web run typecheck
# passed
npm --prefix web run build
# passed
```

The local check harness supplied `CODEX_CHECK_ID` and `CODEX_CHECK_INPUTS_JSON` metadata to these invocations; the executable commands are shown above. The repository's pinned shared correctness-lint selector passed. The pinned Semgrep rules found zero issues in the application, tests and scenario fixtures. The public-path privacy check passed. Pinned Gitleaks 8.24.3 passed its fake-key self-test and scanned 379 tracked files with zero findings.

Actual browser acceptance used a fresh isolated `/private/tmp/iti-brotli-browser-20261107` data directory on port 8017. It exercised explicit load, case guide, a selected advisor SARIF finding, a scoped CVE action deep link, Back/Forward, all four themes, a 390-pixel mobile layout without horizontal overflow, and the embedded four-action/three-link hypothetical flow. This was a local browser test, not a desktop launcher refresh or production deployment. Security/privacy gate results and Git/PR status are reported in the implementation handoff, not inferred from these application tests.

## Demonstrating remediation roles

Each of the eight Brotli actions has its existing fictional engineering implementation owner, a **Fictional exposure-management coordinator**, and a reviewer for vulnerability assurance, AppSec evidence, or detection validation. Open Improvement Actions to show the three roles and the next-step owner, then inspect the original workflow to edit assignments. The coordinator drives follow-up while engineering implements and the assigned reviewer assesses evidence. These are authored synthetic role assignments, not actual staff or authenticated identities. Loading an older copy of this case fills missing assignments only; existing assignments, technical results, implementation records and evidence qualifications remain intact.

