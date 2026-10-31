# Local MITRE Attack Flow integration

Upstream: https://github.com/center-for-threat-informed-defense/attack-flow

Pinned revision: **5c8bf4ca9ff64ef9b55c38a2505db318750cbcda**. Builder 4.0.1; Attack Flow extension 2.0.0. `pin.json` records the source-archive and individual schema hashes. `LICENSE` is the upstream Apache-2.0 license; see the additional license notices and the root third-party notices. No MITRE endorsement is implied. No separate upstream NOTICE file was present in this revision.

## Setup and serving

Fresh setup: `./scripts/bootstrap` builds both applications. Existing installs:

```sh
./scripts/build-attack-flow
npm --prefix web ci
npm --prefix web run build
./scripts/run
```

Use the usual http://127.0.0.1:8000. Open **Purple team**, select an assessment, and generate its updated package. There is one FastAPI server. The optional acceptance server below is for testing only.

The build script verifies the archive hash, extracts only `src/attack_flow_builder/` and its required root `config/`, applies the fail-closed patch, and runs **upstream `npm ci` using its unchanged package-lock**, Vue type checking, and Vite. Dependencies and source are isolated in ignored `runtime/attack-flow-build/`; output is ignored `runtime/attack-flow-viewer/`, served at `/attack-flow-builder/`. No runtime npm process or external viewer host is used. `build.json` records upstream, schema, lock, patch, bridge and tool versions. Missing assets produce a clear UI setup error. API export generation does not need npm or the viewer build.

Build-time network access is necessary for source/dependencies. Runtime assets, settings and fonts are local. The server CSP permits only same-origin script, stylesheet, font and connection loads; the viewer has same-origin framing permission while the workbench still disallows framing. No model/provider credentials enter the iframe URL.

## Inspected upstream behavior and narrow patch

- `src/App.vue`: `src` loads a URL; `readonly` only applies alongside `src` and hides title/sidebar/edit controls.
- `Commands/FileManagement/index.ts`: requires an absolute URL, detects a STIX bundle and uses `StixToAttackFlowConverter` plus `TreeContourLayoutEngine` for horizontal progression. It did **not** fit the STIX camera.
- `vite.config.ts`: `AFB_BASE_URL=/attack-flow-builder/` supplies the subpath.
- `patch.py` awaits command groups, checks fetch status, and calls the small `bridge.ts`. The bridge waits for mounting/fonts/layout, fits real bounds and reports ready only after rendering. Messages require the same origin, parent/frame window, frame nonce and immutable package ID. It accepts only Fit requests, with no write or extraction capability.
- Disconnected actions with **no edges** use a presentation grid to avoid an unreadably tall column. The grid adds no semantic links or order. Connected/partial graphs retain upstream layout. Fit uses the visible viewport; wheel/drag retain upstream zoom/pan.
- Generator and MITRE extension identities remain in the export and author metadata; they are excluded as diagram nodes/edges. Otherwise upstream would display attribution arrows as if they were attack progression.
- Chat, AI-generation entry points, predictive/networked recommender and Atomic links are disabled. Existing workbench Atomic candidates remain the only assessed candidates. Upstream device save/export stays available in editor mode; autosave to a shared recovery bank is disabled.
- The production build excludes Vue DevTools: its pinned devtools-kit accesses Node 25's experimental `localStorage` as a browser Storage object and failed the unpatched build. This is a build-plugin change, not a change of upstream revision or dependency lock. Upstream dependencies include AI libraries but no AI path is invoked here.

## Artifact and sequence contract

`iti/attack_flow.py` creates a separate `attack-flow.json` and `attack-flow-provenance.json` from frozen package data. New package generator `packages-6-attack-flow-2` preserves historical packages. Flow validation and hashes are included in compatibility/manifest/ZIP. No changes were made to the strict core CTI validator, native MISP event, or STIX-to-MISP input.

One action is emitted per evidenced **source_reported** behavior, including environment-inapplicable behaviors and distinct occurrences with the same technique. Inferences, proposals, unsupported/conflicting assertions are retained as explicit omissions. IDs use the existing persistent UUID4 allocator scoped to extraction and frozen customer/environment context. Object versions preserve their original created timestamp. Source/extraction/package identity, evidence references and mapping/qualifier details remain portable; the sidecar carries the exact supporting spans and context. The author is **Intel to Improvements**, not the source publisher.

Directed links require existing evidence-referencing `EntityRelationship` records: `precedes`/`followed-by` are forward; `follows` reverses direction; explicitly reported `enables`/`causes` are labeled separately. Temporal order does not imply causation. Unsupported relationship kinds, nonreported relationships, self-links and cycles are omitted with reasons. Sequence integers, list order, scenario numbering and ATT&CK tactics do not create links. `start_refs` include roots of each component, not an assertion of simultaneity or a logical AND/OR. No conditions/operators are invented. No second model call is made.

The curated ActiveMQ extraction has **8 actions and no explicit inter-behavior relationships**. Its legacy sequence numbers are insufficient to justify edges, so it is intentionally unordered. Current offline/live extraction providers do not produce explicit sequence relationships; the flow generator consumes such records when present (the independently authored acceptance fixture supplies them through the canonical model). Evidence-bound relationship extraction is planned but not implemented in the existing provider.

No actions means no invalid empty STIX bundle. The manifest/provenance records the reason, and the UI displays an empty state. Unknown/partial source warnings propagate. Validation uses pinned Attack Flow + pinned STIX JSON schemas, typed reference integrity, UUID/timestamp checks and a separate STIX library parse. The registry resolves locally without HTTP. Some upstream schema dialect identifiers use HTTP; the code explicitly selects Draft 2020-12 without rewriting the pinned bytes. Schema success does not approve semantic truth.

`cti.stix21.json` remains the TIP/MISP-converter input. MISP does not receive this extension. An editor draft is not a round-trip update or review approval; download/save it separately. Existing source/customer scoping applies to every artifact GET. Package/scope changes synchronously discard the previous iframe; stale messages and fetch responses are ignored.

## Repeatable acceptance

```sh
./scripts/iti test
npm --prefix web test
npm --prefix web run build
.venv/bin/python scripts/attack-flow-smoke-fixture
.venv/bin/python scripts/attack-flow-offline-smoke
```

The last command starts an **isolated test workbench** on http://127.0.0.1:8001, with backend non-loopback DNS/connect calls denied and the normal browser same-origin CSP. Its data stays in `runtime/attack-flow-smoke`; it does not replace the owner's runtime. Stop with Ctrl-C.

Select the curated `attack-flow-sequence` assessment and open Purple team. Verify 3 actions, **CertUtil download → remote service** temporal arrow, and a disconnected AnyDesk action. Confirm initial fit, wheel zoom, drag pan, Fit view, Expand/fullscreen, JSON download, and Open in Builder. The editor must show editable Properties, no Chat, and the same package's source URL. Modify a draft title and confirm the downloaded immutable package is unchanged. Switch customer to Cedar Cloud and confirm the old diagram disappears. Inspect console and resources: only loopback loads; no model/API/catalog request. A missing build or invalid artifact must leave the human plans and downloads accessible. Frontend tests additionally exercise forged/stale bridge messages, rapid scope changes, missing build, load-without-render and timeouts.

Results and screenshots are in `validation/attack-flow/` and `VALIDATION.md`. This is local rendering/export acceptance, not defensive coverage, live-model validation or live MISP validation.

## Update / remove / deferred

To update, select a reviewed upstream commit, replace archive/schema hashes and license notices, inspect each patch anchor, rebuild with that revision's own lockfile and rerun all checks plus the real browser smoke. Bump package generator when artifact semantics change. Never backfill immutable directories. The downloaded archive is a build cache, not a branch or source checkout.

To remove the viewer, remove its bootstrap step, static mount and `AttackFlowPanel` import/render. Already-generated files remain ordinary downloadable artifacts. Removing generation requires a new package generator revision; retain archived manifests and provenance.

Deferred: evidence/scenario node navigation; candidate D3FEND defenses linked to improvements; evidence-backed coverage overlays; sequence extraction in the existing provider. No new dashboards, automated emulation, Gmail changes, chatbot, model setup, or editor-to-package approval/persistence workflow is implemented.
