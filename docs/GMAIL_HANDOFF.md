# Chat-connected Gmail handoff, version 1.0

This is an intentional portable transport. The standalone app never reads Gmail, creates credentials, enumerates labels, or sends mailbox writes. Existing plugin setup is user-confirmed. A stored request freezes query, optional known label, date range, maximum messages, customer/environment versions, policy and destination. A request is not a retrieval result.

The normative validator is `GmailHandoff` in `iti/models.py`, exported in `schemas/GmailHandoff.schema.json`. Prepare a real request before importing a file; request IDs are local database identities. `runtime/gmail-request.txt` is a prepared copyable request for this build's database, and `runtime/gmail-sample.json` is clearly synthetic. To make a fresh sample against a new database, run `gmail-request`, then `gmail-sample REQUEST_ID --output FILE`.

| Field | Meaning |
|---|---|
| schema_version | `1.0` |
| request_id | Exact stored request ID; validated before any processing |
| batch_id, part | Stable returned batch identity; part 1–100 |
| requested_scope | Exact frozen query/label/date range/limit |
| context | Customer ID/version, environment ID/version, policy version reference; must equal stored request |
| retrieved_at | Actual timezone-aware retrieval timestamp |
| account | Actual returned account identity, otherwise null |
| messages | 0–25 entries and no more than the request limit across imported parts |
| counts | Returned/retrieved/failed/omitted counts when known; null otherwise |
| pagination_status | Explicit description of limit/page state, not a claim to retrieve all matches |
| limitations | Batch-wide gaps that propagate into source completeness and packages |

Message fields preserve actual message/thread IDs, account, RFC Message-ID, sender/subject/date, labels, source references, supported report serials, full returned body, part ID, representation, completeness/gaps and selected exposed attachments. Serial values must occur in supplied body content. IDs cannot contain control characters or paths. Gmail IDs are never promoted to report serials.

Representation is one of `connector-provided text`, `HTML`, `raw MIME`, `snippet`. Hashes identify exactly the preserved representation; text is not described as original email bytes. No body is replaced with an assistant summary. Snippets/truncation and missing attachments remain partial even if an imported file claims completeness. An empty body must be failed. Full-message retrieval status depends on what the plugin actually returned, not what the app wishes were present.

Attachments allow only filename, part_id, media_type, content_base64, size, sha256 and limitation. Filenames cannot traverse paths. Content is decoded with strict base64 and optional hash checking; only supported formats are parsed into child source jobs. Missing bytes remain a named gap. The importer does not follow local references, report URLs or email instructions. EML input separately preserves full raw MIME and parses preferred text or fallback HTML, quoted forwards and supported attachment parts.

Known account + message ID scopes message identity. If not exposed, preserved representation hash is used with an explicit unknown-account namespace. Each distinct request/import record retains provenance; a repeated file is idempotent. Corrected bodies create content revisions. Similar newsletters are never automatically merged or counted as independent corroboration. Multiple report serials remain associated with supported content segments; the containing newsletter is not flattened into one asserted report number.

Import validates all request/context boundaries before work. A valid partial batch can import successful messages while retaining failed-message counts. Jobs may still fail later during analysis; imported-message counts are source handoff acceptance counts, not successful AI analysis counts. The job view is authoritative for processing status.

Live acceptance requires all of: operator-scoped retrieval through the existing plugin, a preserved actual handoff, successful import, and provenance-linked processing. Retrieval, handoff processing and live model analysis are separate checks. Synthetic `.eml`/JSON fixtures prove only parser and workflow behavior. No Google Cloud project, OAuth or Gmail API setup is required or implemented.
