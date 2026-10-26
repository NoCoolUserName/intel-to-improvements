# Threat-Informed Defense workbench

The workbench follows **Understand → Assess → Validate → Improve → Measure → Repeat**. Workspaces share customer/environment scope, source evidence and the existing improvement ledger. Analysts can enter anywhere in this lifecycle.

| Navigation group | Workspaces, in order |
| --- | --- |
| Overview | Exposure Overview · Coverage |
| Intelligence | Add Intelligence · Cases & Analysis · Vulnerability Intelligence · Intelligence Exports |
| Exposures & Improvements | Application Findings · Improvement Actions |
| Validation | Hunts · Purple Team |
| Assurance & Quality | Pipeline Assurance · Evaluation |
| Workspace | Customer Profiles |

CTEM aligns with these capabilities: profiles define scope; supplied findings and CVE evidence support discovery; relevance, applicability and triage support prioritization; hunts and human-led tests support validation; owners, commitments and exceptions support mobilization. Coverage and Exposure Overview provide distinct feedback. This alignment adds no engine, risk score or mandatory sequence.

**Coverage** retains intelligence-assessment, telemetry, test and timing meanings. **Exposure Overview** retains its defined leadership metrics and source-record drill-downs. **Pipeline Assurance** keeps configuration, supplied execution and effectiveness separate; its observations do not become findings or ledger actions automatically. **Evaluation** describes the workbench's analytical quality, not an organization's control effectiveness.

## Follow existing work

**Improvement Actions** reads the existing CTI/D3FEND, vulnerability and AppSec ledger records in the selected customer/environment. It displays the original owner, change, work status and retest plan alongside qualified outcomes. Inspect an action to see its frozen origin, evidence references, linked retests and existing exceptions. **Open originating workflow** opens the existing case action drawer, the finding's Remediation tab, or the CVE's Actions & verification tab. Those established workflows retain their mutation, freshness and review rules; there is no second ledger or new action CRUD path.

An AppSec origin retains its original source/hash while its management link opens the latest occurrence in the same logical series. CVE rows label the existing asset-level verification separately from this action's linked retests. Case actions show only action-linked retests; an unrelated behavior test does not verify the action. Work status and a fix claim never substitute for qualified evidence.

Related-case controls connect analysis, Coverage, Hunts, Purple Team and the actions tied to that exact assessment. AppSec governance, CVE actions and Exposure Overview records with an existing action ID link directly to Improvement Actions. Records without a stored relationship receive no invented association. Missing origins remain inspectable as saved actions with an unavailable-origin explanation.

The sidebar scrolls vertically on desktop. Smaller screens use horizontal, grouped navigation with standard keyboard-accessible buttons. All four existing palettes remain available, including Golden Ledger.

## Links and compatibility

Workspace bookmarks use fragments such as `#/cases-and-analysis` and `#/improvement-actions/ACTION_ID?customer=CUSTOMER_ID&environment=ENVIRONMENT_ID`. Action links restore explicit scope; missing or cross-scope actions show a recoverable message. Browser Back/Forward updates the active workspace. The legacy `#/case-overview` spelling and encoded internal workspace names are accepted. The original root URL still opens Coverage. Backend routes, record identifiers and export contracts retain their names.

This change deliberately leaves exception approval, action editing and retests in the original domain workflows. It adds no cross-finding remediation engine, inferred case correlation, unified score, new schema, model call or pipeline-to-exposure conversion. The action list has a bounded limit of 1,000 scoped actions / 16 MiB and reports unavailability rather than silently truncating.
