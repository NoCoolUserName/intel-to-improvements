# Architecture

`Source occurrence → immutable content revision → extracted document/segments → extraction revision → frozen customer assessment → package → scoped validation evidence → coverage/improvement decision`.

The application is one FastAPI process with a bounded two-thread job executor and SQLite WAL. React is built by Vite and served by the same origin. CLI and API use `Service`; no autonomous agent loop or red-team execution exists.

| Module | Responsibility |
|---|---|
| `models.py` | Versioned Pydantic contracts; JSON schemas in `docs/schemas/` |
| `store.py` | SQLite schema migration v1, immutable records/blobs, allocated identities, append-only activity triggers |
| `profiles.py` | Fictional seeds, profile history, frozen customer/environment context |
| `ingestion.py` | Selected URL fetch, article normalization, file/MIME/PDF/structured/CSV adapters |
| `analysis.py` | Exact-hash replay, bounded pattern provider, live structured-output provider and deterministic evidence/ATT&CK gates |
| `relevance.py` | Documented deterministic priority policy and per-behavior applicability |
| `detection.py` | Pinned Sigma/Atomic lookup, pySigma conversion, explicitly restricted three-valued matcher |
| `packages.py` | Human-operable hunts and safe validation proposals linked to evidence |
| `exporters.py` | STIX, native PyMISP, converter comparison, portable files/ZIP/manifests |
| `gmail.py` | Stored retrieval request + portable handoff contract; no mailbox access |
| `ledger.py` | Independent dimensions, freshness/dependency checks, history and honest timing |
| `misp.py` | Explicit optional scoped managed-event upsert, conflict/uncertain-write reconciliation |
| `evaluation.py` | Measured gold-subset evaluation, reports and dependency versions |
| `services.py`, `api.py`, `cli.py` | Shared orchestration and operator interfaces |

## Identity and revisions

`records(kind,id,data,created_at)` stores compact versioned JSON. `jobs` has a unique idempotency key, state, stage and immutable context/input snapshot. `identities` allocates UUID4 once for STIX SDOs, MISP entities and operational records. STIX SCOs use the STIX library’s prescribed content-derived identity. `activity` rejects SQL updates/deletes. `PRAGMA user_version=1` identifies the migration; existing records are not dropped on startup.

`content_revision_id` identifies immutable raw bytes for a logical document; `revision_id` identifies a parser-versioned normalized snapshot. Extraction IDs and customer assessment IDs are separate again. Thus a parser correction does not pretend the publisher changed the raw article.

The document identity is scoped to logical origin and customer/shared visibility. Exact bytes within a scope reuse content/document while retaining distinct origins; subsequent changed content at the same origin adds a revision. Near-duplicates are never merged automatically. Normalized Unicode offsets and raw-byte hashes are different coordinate spaces. Raw offsets are deliberately null when not mapped. Heading/block boundaries and stable span IDs are retained. MIME attachments carry distinct segment/part IDs; newsletter serials identify supported segments, not Gmail IDs. A newsletter may remain a container document with multiple report segments; this is not independent corroboration.

Every assessment freezes customer ID/version, environment ID/version, relevance policy, source revision, integration destination and complete profile snapshots. Private-source access and artifact routes enforce scope. Same content hash in two private customer scopes cannot reuse the other customer’s records. The React client also rejects responses for a scope switched while requests were in flight. These rules are not a substitute for authentication in a publicly hosted deployment.

## Jobs and replay

`queued → running / intake → extraction → assessment → complete (assessed)`. Package generation is a separate intentional operation. A failure stores type, message and traceback; live raw/rejected output stays local. Cancellation is checked between stages/chunks. Already-running requests may finish and their response be cached. Startup marks previously running jobs `interrupted`; operator resume returns them to `queued`. Completed source/extraction checkpoints are reused. Identical concurrent submissions share one unique job and only one claimant runs it.

Extraction cache identity includes scope, content hash, parser/prompt/schema provider mode, configured live model and catalog revisions. Live chunk keys additionally include compatible endpoint and selected spans. Replay requires an exact fixture hash. Source ingestion and customer receipt are persisted once, independent of job reruns.

Package generator revisions are immutable. Earlier failed conversion artifacts remain inspectable rather than being overwritten by a later fix. A current package uses its original assessment snapshot, even if the user is viewing a new profile version. Review flags and source gaps propagate into every exported context and manifest. Core STIX does not rely on workflow custom object types.

## Verification semantics

Evidence references, actual/expected outcomes, procedure, execution/recording timestamps, method, scope/variant and control/environment versions are required. An analyst-entered claim without actual system/lab evidence is an attestation. The app validates record completeness and transitions; it cannot authenticate the truth of an arbitrary operator-supplied external evidence URI.

Synthetic matches update only the synthetic dimension. Lab and live observations remain labeled. Prevention requires the attempted action and enforcing outcome. SOC timing requires an exercise/alert origin. Failed tests remain after passing retests. Thirty-day freshness and exact source/extraction/customer/environment/rule dependencies make earlier evidence stale after changes. Historic baseline execution retains its timestamp; a separate current confirmation time drives nonnegative receipt-to-confirmation durations. Missing endpoints produce null, never zero. No single interval is called a mean.

## Security/data flow

Source data never receives tools. Live model requests carry source-span IDs/text and a fixed extraction task; they omit customer identifiers, credentials and unrelated mail. Explicit customer policy can disable live processing. Raw snapshots and model outputs remain local. Exports are downloaded deliberately; optional MISP write uses only the destination frozen in the assessment and compares it with explicit server configuration.

Public URL requests resolve/check every address, pin the selected address during TLS/HTTP transport and recheck redirects. No environment proxy credentials are used. HTML is normalized with BeautifulSoup and displayed as text. Uploaded filenames cannot control output paths; artifact names are allowlisted. Local paths are explicit operator inputs, resolved before reading regular bounded files. Handoffs never dereference file paths or embedded report links.

## Extension points

Future work: richer extraction/evaluation and review UI, MISP MCP transport, TAXII, additional SIEM backends, Navigator exports, ticketing, optional OCR and operator-configured polling. None is represented as operational today. No app-native Gmail API/OAuth extension is part of this POC.
