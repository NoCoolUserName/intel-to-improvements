# STIX validator dependency compatibility

The application intentionally pins `stix2-validator==3.2.0`.

On 2026-10-11, Dependabot PR #2 proposed 3.3.1. Its Code quality run
38116571420 failed eight existing export/workflow tests (40 passed) with:

> Cannot locate a schema for the object's type, nor the base schema (cyber-observable-core.json).

Direct inspection of the published 3.3.1 wheel and source archive confirmed
neither contains the required schema JSON files. Building the same source
archive instead of installing the wheel therefore does not resolve this issue.
The inspected distribution hashes recorded in the Dependabot lockfile were:

- Wheel: `sha256:9dd5615524e34b15f98d565b17f33974c420b7a69350597a4f2ba955e3f489ab`
- Source: `sha256:90484bfd8f5e216a4587bb26500bb4503e320b266e3d250281e04db47cb1e441`

The correction restores the existing 3.2.0 dependency and lockfile, preserving
actual standards validation. `.github/dependabot.yml` ignores only version
3.3.1. Other dependencies and later validator releases remain eligible for
review; there is no blanket minor/major update exclusion.

Before changing the pin, run `uv sync --frozen --extra dev` and
`uv run --frozen --extra dev pytest -q`. The existing tests validate real generated
STIX bundles, reject invalid patterns, and exercise downstream MISP and workflow
exports. Do not disable schema checks or manufacture successful validation results.
