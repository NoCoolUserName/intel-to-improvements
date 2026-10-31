# Frontend checks

Use a supported even-numbered Node release, 22.22.2+ or 24.15+, and install the
locked dependencies with `npm ci` from this directory.

- `npm test`: run the Vitest suite once; this is picked up by the existing Code
  quality workflow's required `typecheck test build` configuration.
- `npm run test:watch`: rerun tests while developing.
- `npm run typecheck`: check the production TypeScript sources without emitting.
- `npm run build`: run TypeScript's build check and Vite's production build,
  including stylesheet resolution and bundling.

The suite uses React Testing Library with jsdom and authored API responses. It
checks accessible controls, customer/environment switching, late-response
isolation, evidence rendered as text, scoped export links, error reporting, and
theme persistence/fallbacks. Every test unmounts the app and restores mocks.
Unexpected API routes fail instead of silently returning an empty response.

`src/App.tsx` contains the testable application; `src/main.tsx` remains the browser
entry point, loads both stylesheets, applies the saved theme, and mounts React.
`src/vite-env.d.ts` loads Vite's asset declarations without disabling strict or
side-effect import checking.

These DOM tests complement the Python API/export tests. They are not screenshot,
layout, full accessibility-audit, or live-service tests.

CI requires all three scripts to exist and pass, and requires the committed
`package-lock.json`. Removing a script fails validation before installation;
checks cannot silently become optional. The shared workflow is pinned to
`927052f6ef9ce21c1fec280dcc87affdee1ae87a` (code-quality#3).

