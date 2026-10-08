# Supported query target and Sigma scope

The demonstration targets **Splunk raw Windows process events**, not CIM data models. The fictional Windows environment declares `process_creation` with these fields:

| Sigma field | Raw field |
|---|---|
| Image | Image |
| OriginalFileName | OriginalFileName |
| ParentImage | ParentImage |
| CommandLine | CommandLine |
| User | User |
| Computer | Computer |
| UtcTime | UtcTime |

The hunt template adds `EventCode=1` for the process-event demonstration and requires the analyst to replace `$INDEX$`, `$EARLIEST$`, `$LATEST$` with real authorized index/time values. No index name, CIM coverage, deployment or executed Splunk search is claimed. Ingestion of Sysmon fields and the chosen time window must be checked before interpreting results. Retention defaults to 30 declared days; the historical report cannot be hunted in nonexistent retained data.

pySigma parses each actual rule and the maintained Splunk backend converts it through a custom, explicit `FieldMappingTransformation` processing pipeline (`ITI explicit raw Windows field map v1`). Syntax, conversion, declared environment readiness and execution testing are independent flags. Conversion exceptions remain visible. Other behaviors receive concrete analyst procedures where this subset has no suitable query; they do not receive fabricated backend success.

Pinned subset: eight public SigmaHQ rule files, revision in `catalogs/manifest.json`. Search starts with source-cited UUID recovery and separately ranks named behavior/tool overlap. Every candidate retains actual UUID, immutable path/commit, author/license, status, logsource, fields, full condition, ATT&CK tags, limitations and reason. `source_cited_missing` means absent from the searched subset, not proof of private or nonexistent rules. Full synchronization is an explicit maintenance command; restart the app to load the new manifest. The report's former public rule repository now directs contributions to SigmaHQ.

## Synthetic evaluation contract

One reviewed fixture set supports UUID `19b08b1c-861d-4e75-a1ef-ea0c1baf202b`, **Suspicious Download Via Certutil.EXE**. Positive uses a harmless example.invalid command string (never executed), negative uses `certutil -store My`, missing-field lacks CommandLine. Results must be `match`, `no match`, `inconclusive` respectively.

The restricted matcher supports stateless named selection dictionaries, list-of-dictionaries (OR), scalar/list values, case-insensitive equality with `*`/`?` wildcard matching, `contains`, `startswith`, `endswith`, `all` value combination, boolean and/or/not/parentheses, `all of selection_*` and `1 of selection_*`. Three-valued evaluation permits a known OR branch to establish a match even if another branch is missing; unresolved required fields remain inconclusive. It rejects keyword selections, null values, regex, CIDR, base64/fieldref/other modifiers, timeframe, aggregation and correlation. It is **not a complete Sigma interpreter**. Rule parsing and conversion use maintained pySigma; the local fixture matcher is explicitly restricted application code.

No fixture pass means deployment, live alert, prevention or SOC acknowledgement. No missing-field result means a clean host. Broader detection accuracy is not measured by these tests.
