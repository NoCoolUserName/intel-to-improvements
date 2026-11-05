# Frontend dependency compatibility review — PR #31

Reviewed on 2026-11-04. Integrated original Dependabot head
`46e7b7adf2f2670ebd739223fde60859bf3dbed1` with main
`a18f12ee0dff952efa064d315a08b7c60d6ac3b4` using a merge commit.
All four subsequent main commits are retained. Before this review record, the
integration differs from main only in `web/package.json` and `web/package-lock.json`.
The Sigma changes, Attack Flow security overlay, existing Undici 8.12.3 security
fix, shared workflow pins, and dependency policy are preserved.

## Dependency inventory

| Package | Previous lock | Reviewed lock |
| --- | --- | --- |
| react / react-dom | 19.3.0 | 19.3.1 |
| @testing-library/user-event | 14.6.7 | 14.6.8 |
| jsdom | 30.1.2 | 30.1.3 |
| vite | 8.3.4 | 8.3.5 |
| vitest / @vitest/mocker / @vitest/spy | 5.0.3 | 5.0.5 |
| @asamuzakjp/dom-selector | 9.2.4 | 10.0.5 |
| obug | 2.2.1 | 3.0.0 |
| @oxc-project/types | 0.153.0 | 0.156.0 |
| rolldown and all 15 optional native bindings | 1.2.13 | 1.2.16 |
| @types/estree | 1.0.9 | 1.0.10 |
| magic-string | 1.4.3 | 1.4.5 |
| postcss | 8.5.29 | 8.5.32 |

Thirty resolved package entries change version; package membership is unchanged.
Changed archives remain on registry.npmjs.org with SHA512 integrity, verified
by a clean locked installation. Optional Rolldown Linux bindings add explicit
libc selection metadata. No application scripts or configuration change.

React requirements rise from `^19.2.0` to `^19.3.1`, a minor change to the
minimum despite patch-only installed changes. React and React DOM remain matched.
This is a client-rendered createRoot application without React Server Components.
The existing React type packages pass type checking against the updated runtime.

jsdom intentionally declares dom-selector `^10.0.3`; overriding it back to 9.x
would violate its upstream dependency contract. The selector major release changes
traversal/parser internals and selector-subject extraction. The application does
not directly import those private internals. See the
[upstream 10.0.0 notes](https://github.com/asamuzaK/domSelector/releases/tag/v10.0.0).

Vitest intentionally declares obug `^3.0.0`. The
[upstream migration notes](https://github.com/sxzz/obug/releases/tag/v3.0.0)
change entry-point resolution and remove older JSR/CDN aliases. This project uses
npm and a modern Node runtime supporting package exports. The debug-enabled
Vitest check exercised its actual debug import/output path successfully.

## Validation evidence

Reused original successful PR evidence at the original Dependabot head:

- [Code quality run 41324972122](https://github.com/NoCoolUserName/intel-to-improvements/actions/runs/41324972122): frontend typecheck, all 66 tests in 11 files, production build, and configured backend/secret checks succeeded.
- [Security run 41324972172](https://github.com/NoCoolUserName/intel-to-improvements/actions/runs/41324972172): succeeded.

Focused local checks on the integrated tree, Node 24.22.1 / npm 11.9.0:

- `npm --prefix web ci --ignore-scripts --no-audit --no-fund`: clean install succeeded.
- `npm --prefix web run typecheck`: passed.
- `npm --prefix web test`: 66 passed in 11 files.
- `npm --prefix web run build`: passed; 1,928 modules transformed. Asset names
  and sizes match the original successful run (index-KF1Ot3Xk.css and
  index-oyGLkeCF.js); source application files are unchanged.
- `npm --prefix web ls --all`: passed without missing/invalid dependency contracts.
- `npm --prefix web audit --json`: zero vulnerabilities across all severity levels.
- An isolated real-jsdom probe passed 15 assertions covering class/attribute,
  :scope, :has, :nth-child, :not, matches, closest, computed styles, focus,
  form validity, invalid-selector exceptions, and XML lookup behavior.
- `DEBUG='vitest:*' npm --prefix web test -- tests/navigation.test.tsx`:
  two tests passed with actual Vitest debug output enabled.
- Public path/commit attribution validation passed for the integrated range.

No unrelated backend suite or Attack Flow browser build was manually repeated.
Pushing the updated branch will invoke the repository's existing CI; exact-head
CI conclusions must be checked before merge.

## Merge policy and limits

This is a manually reviewed update, not eligible for the patch-only controller:
React manifest minimums cross a minor boundary; dom-selector and obug cross
major boundaries; @oxc-project/types crosses a minor boundary; native binding
metadata also changes. `.github/dependency-policy.json` remains unchanged and
automatic merging remains disabled. No controller exception is introduced.

The jsdom/selector engine requirement is Node `^22.22.2 || ^24.15.0 || >=26.0.0`;
the tested Node 24.22.1 satisfies it. This review does not establish older Node
compatibility, all-platform native binding execution, real-browser rendering,
or untested selector/React APIs. DOM tests use jsdom with fixture-backed network
responses. The separate documented Python diskcache advisory remains outside
this frontend update.
