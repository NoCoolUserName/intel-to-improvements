# Five-minute walkthrough

For a screenshot overview of the workspaces, see the [README visual tour](README.md#visual-tour). Separate focused demos cover [AppSec remediation](docs/APPSEC_REMEDIATION.md), [Exposure Overview](docs/EXPOSURE_MANAGEMENT_DASHBOARD.md) and [Pipeline Assurance](docs/PIPELINE_ASSURANCE.md#three-to-five-minute-offline-demonstration). Pipeline examples are manual, synthetic, offline imports; configuration and supplied execution are kept separate.

Before presenting: `./scripts/bootstrap`, `./scripts/iti demo`, `./scripts/run`. Open **http://127.0.0.1:8000**. Use the latest case/profile version. Repeated demo runs preserve ingestion clocks and existing records. This is an actual local workflow; no prerecorded operational timeline is represented as live evidence.

**0:00–0:40 — Customer, sector and source.** Select **Northstar Bank · fictional → Windows / AD lab**. Customer Profiles exposes the financial-services sector, priorities and editable environment telemetry. In **Add Intelligence**, choose **ActiveMQ → LockBit** and **Load selected case**. Explain that this is an exact-content curated replay of a limited, attributed real report derivative. URL mode can fetch the full operator-selected report; the full source is retained only in the ignored cache. Publication is February 2026; the intrusion began in February 2024. Do not interchange these dates.

**0:40–1:15 — Relevance and evidence.** Select the newest ActiveMQ case in the queue/Working Case dropdown. Open **Cases & Analysis**, then a finding. Inspect the exact supporting span, heading, normalized offsets, source representation and qualifiers. The source-supported case references are TB27524/PR39767; local document identity is separately visible. Explain the .52/.62 C2 discrepancy, source assessment about the leaked builder, image gaps and the distinction between extraction certainty and reliability.

**1:15–2:00 — Operational outputs.** Click **Generate package**. Open **Intelligence Exports**, preview native MISP and download ZIP. STIX and native MISP validation and the misp-stix conversion comparison are separate checks; no live server import is claimed. Open **Hunts** for ordered telemetry verification → search → context pivots → bounded closure. Open **Purple Team** for a human-led harmless lab approximation, stop conditions, cleanup and evidence template. Dangerous intrusion stages are not reproduced.

**2:00–2:45 — Genuine rule and unresolved dependencies.** In **Coverage**, open the CertUtil rule candidates. Show actual UUID `19b08b1c-861d-4e75-a1ef-ea0c1baf202b`, author, pinned source commit, full conditions and converted raw Splunk query. The search covered **8 pinned public SigmaHQ rules**, not all Sigma. It was source-cited retrieval, not proof of independent inference. Index/time values require substitution; live execution is not tested. Find LSASS / obfuscated PowerShell rows: process-access/script-block telemetry is deliberately absent. Missing telemetry is an open coverage gap, not evidence of no threat.

**2:45–3:25 — Run scoped detection fixtures.** Click **Run synthetic fixtures**. Inspect positive `match`, benign negative `no match` and missing-field `inconclusive`. The missing-field case remains inconclusive even though that is the expected test-harness behavior. Close the drawer and inspect history: detection/prevention/SOC remain not tested. A synthetic rule match did not turn the ledger green. Evidence uses actual local execution time and stored fixture-result hash.

**3:25–4:10 — Improvement and retest history.** Click **Record improvement / result**. Choose a behavior, record owner, priority, missing-telemetry rationale, a proposed logging change and a benign retest. Record a failed synthetic result if demonstrating baseline history; use a synthetic reference and label it clearly. In history, **Mark deployed** is an operator record, not independently observed deployment. **Record retest** links the result to the same improvement. Record only actual synthetic/attested evidence unless real lab evidence exists. Show failures preserved alongside later results. Explain that live baseline/new-coverage classifications and durations require applicable versioned evidence; automated tests exercise those transitions on synthetic test data, not on this organization.

**4:10–4:40 — Show limits.** Switch to Cedar Cloud’s macOS/AWS/SaaS environment and its independently assessed ActiveMQ case. Windows rows are not applicable; no macOS equivalent is invented. Alternatively open **Zero IOCs** to show useful CTI and plans without indicators, or **Insufficient intelligence** to show Unknown relevance and no justified emulation. In Evaluation, the untuned cloud fixture is an explicit missed behavior by the bounded analyzer; live extraction is NOT VERIFIED.

**4:40–5:00 — Existing Gmail workflow.** Open **Add Intelligence → Gmail**. Specify a bounded query/label/dates/limit, **Prepare Gmail Request**, **Copy request** into the already-connected conversation. Import the returned JSON by file/path/paste, **Preview**, then **Process**. For a no-mail demo, **Load synthetic handoff sample** is clearly labeled and demonstrates partial attachment gaps, serial segments and provenance. No Gmail setup, OAuth or fake in-app mailbox search appears. Live handoff acceptance still requires actual scoped retrieval and processing.

Optional real checks after presentation:

- Live model: configure explicit API key/model and run `./scripts/iti ingest /absolute/path/to/unseen-report.txt --kind path --mode live`. Inspect the persisted success/failure; never substitute replay.
- MISP: configure exact customer destination plus `MISP_URL` / `MISP_API_KEY`, reassess/generate, preview, then `./scripts/iti misp-check PACKAGE_ID --customer fictional-bank`. Repeat it to verify stable identity/readback.
- Actual lab/SIEM: execute only approved human-led steps, collect environment/control-versioned evidence, and record method/scope/outcomes separately. This app never runs red-team tools or searches a SIEM.

The local walkthrough demonstrates evidence handling, source-to-action decisions and selected detection semantics. Actual organizational detection/prevention coverage remains conditional on that environment’s evidence.

Appearance labels describe analysis methods: Local analysis uses fixed rules, Model API analysis makes a configured API request, and Saved demo analysis reuses curated exact-content findings. These are unrelated to network status. The receipt-to-first-assessment card is fixed at completion and includes waiting time; use History for revision/package clocks. Toggle **Show test cases** to inspect the insufficient-evidence and held-out edge examples.

### Attack Flow addition

On **Purple Team**, select ActiveMQ and click **Generate updated package** when shown. The panel above the scenarios displays eight evidenced actions, an explicit unordered warning and extraction gaps. Explain why no arrows were invented from the old sequence numbering. Expand, zoom/pan, Fit, and download the JSON. Open in Builder to show the real MITRE editor and explain that edits are separate drafts.

For a supported arrow, run the isolated authored smoke fixture described in `integrations/attack-flow/README.md`: download precedes remote service execution, while AnyDesk timing is unknown. Its temporal arrow is not a causal claim and its fixture is not operational evidence. The existing human plans, Sigma assessment and coverage ledger remain independent.

## D3FEND suggestion → improvement (about one minute)

1. Select Northstar Bank / Windows AD and **ActiveMQ → LockBit · limited derived case**. Open **Purple Team** (generate a package if none exists).
2. In the first scenario, inspect **Possible defensive countermeasures**. T1190 has 14 pinned associations; the first three are sorted by ID, not ranked. Expand catalog provenance or follow the official reference. Behavior applicability and defensive suitability are separate.
3. Select **Create improvement for D3-APCA**. Review the source evidence/rationale, enter an owner, replace the proposed change with a named lab control/configuration, and edit the retest plan. Save.
4. Open **Coverage → History and independent clocks → View improvement**. Expand its D3FEND origin. Reload and revisit the scenario: **View improvement · open** replaces Create. Detection/prevention remain untested and their durations pending.
5. For an empty-state example, inspect the remote-service behavior T1569.002: no mapping exists in this pinned catalog; the manual improvement workflow remains usable. This does not mean no countermeasure exists.

Validation created an explicitly authored acceptance action in isolated `runtime/d3fend-smoke`, not the owner's normal ledger. Screenshots are in `validation/d3fend/`. No countermeasure was deployed or emulated by this feature.
