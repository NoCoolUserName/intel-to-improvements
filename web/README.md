# Frontend checks

Use Node 22.12+ (matching the application's prerequisites) and install the locked
dependencies with `npm ci` from this directory.

- `npm test`: run the Vitest suite once; this is picked up by the existing Code
  quality workflow's `node-scripts: lint test build` configuration.
- `npm run test:watch`: rerun tests while developing.
- `npm run typecheck`: check the production TypeScript sources without emitting.
- `npm run build`: run TypeScript's build check and Vite's production build,
  including resolution and bundling of the actual stylesheets.

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
