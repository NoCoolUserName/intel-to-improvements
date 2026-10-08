# Human-led controlled validation plan
Customer: fictional-bank v1; environment: windows-ad v1
Mode: replay; source completeness: partial
Source: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/#limited-derived
Relevance: High — Supported shared technology matches: Active Directory, ActiveMQ, PowerShell, RDP, Windows. Sector mismatch does not veto technical relevance.

These are analyst proposals. Generated plans do not establish deployed or verified coverage.

## Extraction gaps
- Limited developer-curated derivative, not the full report; original contains image-only evidence
- C2 address discrepancy .52 versus .62 requires source review

## 1. Can the declared control observe this variant of The report describes exploitation of vulnerable ActiveMQ on Windows.?
Behavior: behavior_ee153d6de3ee5cb58cd98a3bd214e1e4; supporting spans: span_5f0a75f789005e0a8ac065f40713d402

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1190

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- proxy

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Do not execute the reported exploit, credential extraction, lateral payload or ransomware.
- Replay a separately labeled synthetic event in the local matcher or approved isolated SIEM test index.
- For actual control validation, have the control owner approve a benign vendor-supported simulation and document attempted action plus enforcement outcome.
- Record this as a telemetry/control approximation; it does not reproduce compromise or ransomware prevention.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap
- Dangerous stage not reproduced; use benign telemetry/control objective

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_ee153d6de3ee5cb58cd98a3bd214e1e4",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 2. Can the declared control observe this variant of CertUtil downloaded a payload.?
Behavior: behavior_efa888780f4c50ccaf41a33c6043bf7f; supporting spans: span_a958d48ad5c15d1986b44a86b0cddb77

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1105

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- process_creation

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- In an isolated Windows lab, create a harmless text file on an analyst-controlled HTTP server with no Internet egress.
- Confirm Sysmon process events arrive and Image/OriginalFileName/CommandLine fields survive ingestion.
- After human approval, use certutil -urlcache -split -f http://<LAB_HOST>:<LAB_PORT>/harmless.txt <LAB_DIRECTORY>\iti-harmless.txt. Substitute only the approved lab address.
- Run the benign comparison certutil -store My. Preserve both process records, actual alert outcome and relevant control logs.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates
- {"guid": "dd3b61dd-7bbc-48cd-ab51-49ad1a776df0", "name": "certutil download (urlcache)", "path": "atomics/T1105/T1105.yaml", "url": "https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1105/T1105.yaml", "revision": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43", "platforms": ["windows"], "prerequisites": [], "inputs": {"remote_file": {"description": "URL of file to copy", "type": "url", "default": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt"}, "local_path": {"description": "Local path to place file", "type": "path", "default": "Atomic-license.txt"}}, "cleanup": "del #{local_path} >nul 2>&1\n", "executor": "command_prompt", "fit": "partial behavior approximation", "limitations": "Atomic defaults may fetch external content. Do not run defaults; use the separate benign plan and lab-controlled content. Same technique is not full intrusion reproduction."}
- {"guid": "ffd492e3-0455-4518-9fb1-46527c9f241b", "name": "certutil download (verifyctl)", "path": "atomics/T1105/T1105.yaml", "url": "https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1105/T1105.yaml", "revision": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43", "platforms": ["windows"], "prerequisites": [], "inputs": {"remote_file": {"description": "URL of file to copy", "type": "url", "default": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt"}, "local_path": {"description": "Local path to place file", "type": "path", "default": "Atomic-license.txt"}}, "cleanup": "Remove-Item \"certutil-$(Get-Date -format yyyy_MM_dd)\" -Force -Recurse -ErrorAction Ignore\n", "executor": "powershell", "fit": "partial behavior approximation", "limitations": "Atomic defaults may fetch external content. Do not run defaults; use the separate benign plan and lab-controlled content. Same technique is not full intrusion reproduction."}

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_efa888780f4c50ccaf41a33c6043bf7f",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 3. Can the declared control observe this variant of Java parentage accompanied command execution.?
Behavior: behavior_7eac9ec8e2c45cb78b360058f151a3be; supporting spans: span_a958d48ad5c15d1986b44a86b0cddb77

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1059.003

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- process_creation

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Verify telemetry with an approved benign process event in an isolated Windows VM.
- Have the analyst create a harmless command/process variant matching the relevant rule conditions, using only approved local tools and no persistence.
- Run a known benign negative control.
- Preserve raw records and separately record rule match, alert delivery, prevention and SOC handling if actually observed.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_7eac9ec8e2c45cb78b360058f151a3be",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 4. Can the declared control observe this variant of Processes accessed LSASS memory.?
Behavior: behavior_19541a05f89350228e60ff7aa5280579; supporting spans: span_498643b16e395ea891910ee45f2c558c

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1003.001

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- process_access

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Do not execute the reported exploit, credential extraction, lateral payload or ransomware.
- Replay a separately labeled synthetic event in the local matcher or approved isolated SIEM test index.
- For actual control validation, have the control owner approve a benign vendor-supported simulation and document attempted action plus enforcement outcome.
- Record this as a telemetry/control approximation; it does not reproduce compromise or ransomware prevention.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap
- Dangerous stage not reproduced; use benign telemetry/control objective

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_19541a05f89350228e60ff7aa5280579",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 5. Can the declared control observe this variant of Remote services launched payloads on other Windows hosts.?
Behavior: behavior_aad5e0ce01025b5e80506bfd6184e1ef; supporting spans: span_3e85678c09ec5a0f8c67b052e2983d29

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1569.002

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- service_install
- process_creation

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Do not execute the reported exploit, credential extraction, lateral payload or ransomware.
- Replay a separately labeled synthetic event in the local matcher or approved isolated SIEM test index.
- For actual control validation, have the control owner approve a benign vendor-supported simulation and document attempted action plus enforcement outcome.
- Record this as a telemetry/control approximation; it does not reproduce compromise or ransomware prevention.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap
- Dangerous stage not reproduced; use benign telemetry/control objective

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_aad5e0ce01025b5e80506bfd6184e1ef",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 6. Can the declared control observe this variant of Obfuscated PowerShell appeared during remote-service activity.?
Behavior: behavior_5d00d525ea505fab9e8d4308ac2a6463; supporting spans: span_3e85678c09ec5a0f8c67b052e2983d29

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1059.001

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- process_creation
- powershell_scriptblock

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Verify telemetry with an approved benign process event in an isolated Windows VM.
- Have the analyst create a harmless command/process variant matching the relevant rule conditions, using only approved local tools and no persistence.
- Run a known benign negative control.
- Preserve raw records and separately record rule match, alert delivery, prevention and SOC handling if actually observed.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates
- {"guid": "1c0a870f-dc74-49cf-9afc-eccc45e58790", "name": "ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments", "path": "atomics/T1059.001/T1059.001.yaml", "url": "https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1059.001/T1059.001.yaml", "revision": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43", "platforms": ["windows"], "prerequisites": [{"description": "The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.", "prereq_command": "$RequiredModule = Get-Module -Name AtomicTestHarnesses -ListAvailable\nif (-not $RequiredModule) {exit 1}\nif (-not $RequiredModule.ExportedCommands['Out-ATHPowerShellCommandLineParameter']) {exit 1} else {exit 0}", "get_prereq_command": "Install-Module -Name AtomicTestHarnesses -Scope CurrentUser -Force\n"}], "inputs": {"command_line_switch_type": {"description": "The type of supported command-line switch to use", "type": "string", "default": "Hyphen"}, "command_param_variation": {"description": "The \"Command\" parameter variation to use", "type": "string", "default": "C"}, "encoded_arguments_param_variation": {"description": "The \"EncodedArguments\" parameter variation to use", "type": "string", "default": "EA"}}, "cleanup": null, "executor": "powershell", "fit": "partial behavior approximation", "limitations": "Atomic defaults may fetch external content. Do not run defaults; use the separate benign plan and lab-controlled content. Same technique is not full intrusion reproduction."}
- {"guid": "86a43bad-12e3-4e85-b97c-4d5cf25b95c3", "name": "ATHPowerShellCommandLineParameter -EncodedCommand parameter variations", "path": "atomics/T1059.001/T1059.001.yaml", "url": "https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1059.001/T1059.001.yaml", "revision": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43", "platforms": ["windows"], "prerequisites": [{"description": "The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.", "prereq_command": "$RequiredModule = Get-Module -Name AtomicTestHarnesses -ListAvailable\nif (-not $RequiredModule) {exit 1}\nif (-not $RequiredModule.ExportedCommands['Out-ATHPowerShellCommandLineParameter']) {exit 1} else {exit 0}", "get_prereq_command": "Install-Module -Name AtomicTestHarnesses -Scope CurrentUser -Force\n"}], "inputs": {"command_line_switch_type": {"description": "The type of supported command-line switch to use", "type": "string", "default": "Hyphen"}, "encoded_command_param_variation": {"description": "The \"EncodedCommand\" parameter variation to use", "type": "string", "default": "E"}}, "cleanup": null, "executor": "powershell", "fit": "partial behavior approximation", "limitations": "Atomic defaults may fetch external content. Do not run defaults; use the separate benign plan and lab-controlled content. Same technique is not full intrusion reproduction."}

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_5d00d525ea505fab9e8d4308ac2a6463",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 7. Can the declared control observe this variant of AnyDesk installed an automatically starting service.?
Behavior: behavior_3a87a565cd2e545f8eaa52b254a80000; supporting spans: span_bc8057780dbc51f4b7e86f4a73e01948

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1219.002

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- process_creation
- service_install

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Verify telemetry with an approved benign process event in an isolated Windows VM.
- Have the analyst create a harmless command/process variant matching the relevant rule conditions, using only approved local tools and no persistence.
- Run a known benign negative control.
- Preserve raw records and separately record rule match, alert delivery, prevention and SOC handling if actually observed.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_3a87a565cd2e545f8eaa52b254a80000",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

## 8. Can the declared control observe this variant of RDP sessions carried ransomware execution.?
Behavior: behavior_4a431faf3b075841bfe83bacfd7ed92a; supporting spans: span_9a9409e03a4a508895e62df5bba7a4af

### Assumptions
- Human-led isolated lab only
- Written lab scope approved outside this application

**applicability**: windows platform declared. Technology exposure and control behavior still require tests.

**technique id**: T1021.001

### Prerequisites
- Disposable Windows lab snapshot
- Human test owner
- No production credentials or attacker callbacks

### Telemetry Checks
- logon
- process_creation

**lab scope**: Named disposable lab hosts and analyst-owned test data only

**test data**: Harmless text file / synthetic events with example.invalid; never retrieve attacker infrastructure

### Steps
- Do not execute the reported exploit, credential extraction, lateral payload or ransomware.
- Replay a separately labeled synthetic event in the local matcher or approved isolated SIEM test index.
- For actual control validation, have the control owner approve a benign vendor-supported simulation and document attempted action plus enforcement outcome.
- Record this as a telemetry/control approximation; it does not reproduce compromise or ransomware prevention.

### Expected Observables
- Process/service/session event with UTC time and stable host identity
- Required fields populated or explicit inconclusive result

**expected detection**: Evaluate named candidate rule independently from SIEM alert delivery

**expected prevention**: Unknown until attempted benign control simulation and enforcing-control outcome are evidenced

### Benign Controls
- Authorized admin equivalent
- Missing-field fixture to expose insufficient telemetry

### Stop Conditions
- Any unexpected production connection
- Unapproved privileged change
- Unexpected file modification outside lab directory

### Cleanup
- Remove only the named harmless test file
- Stop analyst-owned lab HTTP server if used
- Restore disposable snapshot for any approved configuration changes
- Preserve evidence before cleanup

### Atomic Candidates

### Limitations
- Synthetic replay is not adversary emulation
- No full ATT&CK technique coverage claim
- Missing Atomic match is an explicit catalog gap
- Dangerous stage not reproduced; use benign telemetry/control objective

**exercise designation**: coordinated

**evidence template**
```json
{
  "environment_version": 1,
  "behavior_id": "behavior_4a431faf3b075841bfe83bacfd7ed92a",
  "control_id": "",
  "control_version": "",
  "procedure": "",
  "expected": "",
  "actual": "",
  "executed_at": "UTC with offset",
  "recorded_at": "assigned by application",
  "method": "synthetic log match | lab emulation | observed SIEM alert | observed prevention | analyst attestation",
  "evidence_reference": "",
  "variant": "",
  "exercise": "coordinated or blind"
}
```

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
