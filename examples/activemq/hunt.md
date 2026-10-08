# Evidence-led hunt package
Customer: fictional-bank v1; environment: windows-ad v1
Mode: replay; source completeness: partial
Source: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/#limited-derived
Relevance: High — Supported shared technology matches: Active Directory, ActiveMQ, PowerShell, RDP, Windows. Sector mismatch does not veto technical relevance.

These are analyst proposals. Generated plans do not establish deployed or verified coverage.

## Extraction gaps
- Limited developer-curated derivative, not the full report; original contains image-only evidence
- C2 address discrepancy .52 versus .62 requires source review

## 1. An unauthorized operator may reproduce this observed behavior: The report describes exploitation of vulnerable ActiveMQ on Windows.
Behavior: behavior_ee153d6de3ee5cb58cd98a3bd214e1e4; supporting spans: span_5f0a75f789005e0a8ac065f40713d402

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: high

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- proxy
- Confirm event timestamps and retention boundaries

### Required Fields
- url
- src_ip

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of The report describes exploitation of vulnerable ActiveMQ on Windows.?", "procedure": "Review proxy records for the source-described behavior on in-scope hosts. No tested backend query is available for this behavior. Preserve candidate records and exact procedure.", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query origin**: hand-authored analyst procedure; no executable query available

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 2. An unauthorized operator may reproduce this observed behavior: CertUtil downloaded a payload.
Behavior: behavior_efa888780f4c50ccaf41a33c6043bf7f; supporting spans: span_a958d48ad5c15d1986b44a86b0cddb77

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: medium

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- process_creation
- Confirm event timestamps and retention boundaries

### Required Fields
- CommandLine
- Image
- OriginalFileName

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of CertUtil downloaded a payload.?", "procedure": "index=$INDEX$ earliest=$EARLIEST$ latest=$LATEST$ EventCode=1 (Image=\"*\\\\certutil.exe\" OR OriginalFileName=\"CertUtil.exe\" CommandLine IN (\"*urlcache *\", \"*verifyctl *\", \"*URL *\") CommandLine=\"*http*\")", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query**: index=$INDEX$ earliest=$EARLIEST$ latest=$LATEST$ EventCode=1 (Image="*\\certutil.exe" OR OriginalFileName="CertUtil.exe" CommandLine IN ("*urlcache *", "*verifyctl *", "*URL *") CommandLine="*http*")

**query origin**: pySigma conversion + explicit raw EventCode/index/time template

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 3. An unauthorized operator may reproduce this observed behavior: Java parentage accompanied command execution.
Behavior: behavior_7eac9ec8e2c45cb78b360058f151a3be; supporting spans: span_a958d48ad5c15d1986b44a86b0cddb77

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: medium

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- process_creation
- Confirm event timestamps and retention boundaries

### Required Fields
- Image
- OriginalFileName
- ParentImage
- CommandLine
- User
- Computer
- UtcTime

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of Java parentage accompanied command execution.?", "procedure": "Review process_creation records for the source-described behavior on in-scope hosts. No tested backend query is available for this behavior. Preserve candidate records and exact procedure.", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query origin**: hand-authored analyst procedure; no executable query available

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 4. An unauthorized operator may reproduce this observed behavior: Processes accessed LSASS memory.
Behavior: behavior_19541a05f89350228e60ff7aa5280579; supporting spans: span_498643b16e395ea891910ee45f2c558c

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: high

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- process_access
- Confirm event timestamps and retention boundaries

### Required Fields

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of Processes accessed LSASS memory.?", "procedure": "Review process_access records for the source-described behavior on in-scope hosts. No tested backend query is available for this behavior. Preserve candidate records and exact procedure.", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query origin**: hand-authored analyst procedure; no executable query available

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 5. An unauthorized operator may reproduce this observed behavior: Remote services launched payloads on other Windows hosts.
Behavior: behavior_aad5e0ce01025b5e80506bfd6184e1ef; supporting spans: span_3e85678c09ec5a0f8c67b052e2983d29

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: medium

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- service_install
- process_creation
- Confirm event timestamps and retention boundaries

### Required Fields
- Company
- Description
- Image
- Product

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of Remote services launched payloads on other Windows hosts.?", "procedure": "index=$INDEX$ earliest=$EARLIEST$ latest=$LATEST$ EventCode=1 (Image IN (\"*\\\\AnyDesk.exe\", \"*\\\\AnyDeskMSI.exe\") OR Description=\"AnyDesk\" OR Product=\"AnyDesk\" OR Company=\"AnyDesk Software GmbH\")", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query**: index=$INDEX$ earliest=$EARLIEST$ latest=$LATEST$ EventCode=1 (Image IN ("*\\AnyDesk.exe", "*\\AnyDeskMSI.exe") OR Description="AnyDesk" OR Product="AnyDesk" OR Company="AnyDesk Software GmbH")

**query origin**: pySigma conversion + explicit raw EventCode/index/time template

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 6. An unauthorized operator may reproduce this observed behavior: Obfuscated PowerShell appeared during remote-service activity.
Behavior: behavior_5d00d525ea505fab9e8d4308ac2a6463; supporting spans: span_3e85678c09ec5a0f8c67b052e2983d29

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: medium

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- process_creation
- powershell_scriptblock
- Confirm event timestamps and retention boundaries

### Required Fields
- Image
- OriginalFileName
- ParentImage
- CommandLine
- User
- Computer
- UtcTime

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of Obfuscated PowerShell appeared during remote-service activity.?", "procedure": "Review process_creation, powershell_scriptblock records for the source-described behavior on in-scope hosts. No tested backend query is available for this behavior. Preserve candidate records and exact procedure.", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query origin**: hand-authored analyst procedure; no executable query available

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 7. An unauthorized operator may reproduce this observed behavior: AnyDesk installed an automatically starting service.
Behavior: behavior_3a87a565cd2e545f8eaa52b254a80000; supporting spans: span_bc8057780dbc51f4b7e86f4a73e01948

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: medium

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- process_creation
- service_install
- Confirm event timestamps and retention boundaries

### Required Fields
- Company
- Description
- Image
- Product

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of AnyDesk installed an automatically starting service.?", "procedure": "index=$INDEX$ earliest=$EARLIEST$ latest=$LATEST$ EventCode=1 (Image IN (\"*\\\\AnyDesk.exe\", \"*\\\\AnyDeskMSI.exe\") OR Description=\"AnyDesk\" OR Product=\"AnyDesk\" OR Company=\"AnyDesk Software GmbH\")", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query**: index=$INDEX$ earliest=$EARLIEST$ latest=$LATEST$ EventCode=1 (Image IN ("*\\AnyDesk.exe", "*\\AnyDeskMSI.exe") OR Description="AnyDesk" OR Product="AnyDesk" OR Company="AnyDesk Software GmbH")

**query origin**: pySigma conversion + explicit raw EventCode/index/time template

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## 8. An unauthorized operator may reproduce this observed behavior: RDP sessions carried ransomware execution.
Behavior: behavior_4a431faf3b075841bfe83bacfd7ed92a; supporting spans: span_9a9409e03a4a508895e62df5bba7a4af

### Assumptions
- Environment declaration is accurate
- Analyst has approved access to retained logs
- Source representation may be partial

**question**: Was this reported behavior present in our environment?

**priority**: high

**rationale**: Potential privileged access or business disruption; hypothesis is not a finding of compromise

**scope**: Northstar Bank · fictional / Windows / AD lab; approved asset list only

### Prerequisites
- logon
- process_creation
- Confirm event timestamps and retention boundaries

### Required Fields

**retention days**: 30

### Steps
- {"order": 1, "question": "Can this search answer the question for the selected time and host scope?", "procedure": "Check source configuration and known benign events for each required field. Compare earliest retained event with the incident window. Record missing intervals and ingestion lag.", "on_missing": "Stop automated interpretation; record telemetry gap and request source owner validation."}
- {"order": 2, "question": "Is there evidence of RDP sessions carried ransomware execution.?", "procedure": "Review logon, process_creation records for the source-described behavior on in-scope hosts. No tested backend query is available for this behavior. Preserve candidate records and exact procedure.", "on_hit": "Preserve original events and query time bounds; pivot to process ancestry and user session.", "on_no_hit": "If telemetry checks passed, record no matching evidence within the bounded search only; otherwise inconclusive."}
- {"order": 3, "question": "Do source indicators corroborate the behavior?", "procedure": "Search normalized malicious-role indicators in retained DNS/proxy/endpoint evidence. Never resolve or visit them. Treat historical values as leads, not automatic block recommendations.", "parameters": [{"type": "ipv4", "value": "166.62.100.52", "role": "malicious"}], "on_no_hit": "No corroboration in retained data; continue behavior investigation."}
- {"order": 4, "question": "Is the observed action authorized and isolated, or part of a related sequence?", "procedure": "Correlate host, user, process GUID/PID and event time with service installation, network connections and identity activity. Compare maintenance tickets and known tool owners. Do not infer unobserved stages.", "on_suspicious": "Escalate with evidence, uncertainty and affected assets; request approved response containment.", "on_benign": "Document authorization, matching control example and remaining visibility gaps."}

**query origin**: hand-authored analyst procedure; no executable query available

**backend**: Splunk raw events

**field mapping**
```json
{
  "CommandLine": "CommandLine",
  "Computer": "Computer",
  "Image": "Image",
  "OriginalFileName": "OriginalFileName",
  "ParentImage": "ParentImage",
  "User": "User",
  "UtcTime": "UtcTime"
}
```

**parameters**
```json
{
  "INDEX": "operator-selected actual raw-event index",
  "EARLIEST": "operator-selected supported window",
  "LATEST": "operator-selected window end"
}
```

**expected**: Behavior-consistent process/service/session evidence with host and user correlation

### Benign
- Authorized administration or software deployment
- Security lab tests with documented scope

### Negative Controls
- Known benign administrative action
- Known event with required field deliberately omitted

**branches**
```json
{
  "suspicious": "Preserve and escalate; correlate subsequent steps",
  "no_hit_sufficient_telemetry": "Bounded no-evidence finding, never proof of no compromise",
  "missing_telemetry": "Inconclusive; open improvement",
  "benign": "Record authorization and residual gaps"
}
```

### Preserve
- Raw event export and hash
- Query/procedure, UTC time bounds, timezone
- Host/user/process identifiers
- Analyst reasoning and ticket reference

**escalation**: Unauthorized behavior with corroborating context or suspicious privileged activity merits IR review

**closure**: Close this hypothesis only with bounded findings, data sufficiency and unresolved gaps recorded

## Evidence excerpts

span_5f0a75f789005e0a8ac065f40713d402 · ActiveMQ to LockBit · limited derived case · normalized 0:196
The DFIR Report describes two intrusions through an exposed Windows ActiveMQ server vulnerable to CVE-2023-46604. The incident began in mid-February 2024; the second access followed 18 days later.

span_a958d48ad5c15d1986b44a86b0cddb77 · ActiveMQ to LockBit · limited derived case · normalized 198:281
CertUtil downloaded a Metasploit payload. Java was the parent of command execution.

span_498643b16e395ea891910ee45f2c558c · ActiveMQ to LockBit · limited derived case · normalized 283:441
Malicious processes accessed LSASS memory. A privileged service account subsequently enabled lateral activity; its credential origin is an analyst assessment.

span_3e85678c09ec5a0f8c67b052e2983d29 · ActiveMQ to LockBit · limited derived case · normalized 443:554
Remote services launched payloads on additional Windows hosts. Obfuscated PowerShell appeared in this activity.

span_bc8057780dbc51f4b7e86f4a73e01948 · ActiveMQ to LockBit · limited derived case · normalized 556:617
AnyDesk was installed with an automatically starting service.

span_9a9409e03a4a508895e62df5bba7a4af · ActiveMQ to LockBit · limited derived case · normalized 619:784
RDP sessions carried ransomware execution. Attribution to the established LockBit operation is not confirmed: the authors assess independent use of a leaked builder.
