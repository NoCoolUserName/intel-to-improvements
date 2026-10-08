# Canonical schema and intake notes

Pydantic models in `iti/models.py` are version 1.0; machine-readable JSON Schema is in `docs/schemas/`. `SourceDocument.content_revision_id` identifies the raw content revision; `revision_id` identifies its parser-versioned normalized representation. Data migrations use SQLite `user_version` (currently 1). Compact JSON records are used instead of separate tables for every entity. `Context` snapshots wrap assessments/packages and are included in standalone hunt, purple-team, Sigma and coverage JSON artifacts. Improvement/test records carry their context directly.

All claims/behaviors/relationships reference exact source spans. Proposed hunt/emulation steps additionally contain assumptions and a behavior ID. Source claims, analyst inferences, proposals, unsupported and conflicting claims have distinct categories. Unsupported/conflicting behaviors cannot silently enter trusted output; they are omitted from operational plans and listed in compatibility warnings. Export readiness stays review-required. Relationships must reference known canonical entities. ATT&CK IDs/names are resolved against the pinned official dataset; deprecated/revoked or absent IDs fail validation.

Observables are not automatically indicators. Type/value deduplication preserves original defanging, occurrences, roles, context and source-supported dates. `to_ids` defaults false with a per-attribute reason. Historical malicious-role values can be represented as qualified STIX indicators; benign, victim, legitimate-tool and unknown values stay observables. No observed-data times/counts are invented from publication date.

STIX imports accept validated standard objects. The native model preserves identity/report/indicator/SCO/attack-pattern/relationship/malware/note/observed-data objects and original IDs in the source snapshot; unsupported built-in types are identified in conversion losses. A structured indicator list does not become a narrative. MISP imports preserve source event UUID and native attributes/event-report content; object-template normalization is explicitly unsupported and retained raw with a loss warning. All input bytes remain immutable locally.

Indicator CSV is UTF-8 with a header. Required columns: `type,value`; supported types `ipv4,domain,url,sha256`. Optional `role,context,first_seen,last_seen`; roles `malicious,benign,victim,legitimate_tool,unknown`. Example:

```csv
type,value,role,context,first_seen,last_seen
ipv4,198.51.100[.]42,benign,Documentation-only test address,2024-02-01,2024-02-02
```

Column mapping uses canonical-to-input names, e.g. `{"type":"Kind","value":"Indicator","role":"Meaning"}`. Set it in the Local File tab or CLI:

```sh
./scripts/iti ingest /absolute/path/indicators.csv --csv-map '{"type":"Kind","value":"Indicator"}'
```

No narrative, emulation sequence or observation count is inferred from CSV. Explicit first/last-seen strings keep their supplied precision and do not become source publication times.

Parser completeness is an enum: `complete-for-supported-content`, `partial`, `failed`, with specific gaps. There is no invented extraction-completeness percentage. Empty/image-only extraction cannot succeed as a complete read. HTML block normalization preserves heading paths and paragraph/table/code boundaries; image interpretation is unavailable. Raw-byte coordinates are not normalized Unicode coordinates. Files are limited to 5 MiB; Gmail bodies to 500,000 characters, with 25 messages maximum per file and the frozen request total limit enforced across parts.
