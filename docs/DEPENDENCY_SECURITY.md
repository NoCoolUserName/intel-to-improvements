# Dependency security review — 2026-10-26

This focused update fixes the available dependency advisories without changing
application behavior or dependency automation policy. It is based on main at
`cc340cc1634eb530572b5c211f69d06689c4e843`, independently of the Phase 2 PR.

| Dependency | Previous lock | Updated lock | Advisory coverage |
| --- | --- | --- | --- |
| pypdf | 6.20.0 | 6.21.2 | Nine PDF parsing/resource-exhaustion and image-decoding advisories |
| undici | 8.11.2 | 8.12.3 | Three EventSource/content-encoding denial-of-service and integrity-check advisories; frontend test dependency through jsdom |
| certifi | 2026.7.22 | 2026.10.19 | GHSA-6q48-6c7w-9gw2: affected emSign root trust |
| setuptools | 84.0.0 | 84.1.0 | GHSA-xmj3-9gf7-h52w: Windows legacy wheel-installation path traversal |

`pypdf` and the build-system `setuptools` requirements also set the patched
minimum versions. Other package versions are unchanged. Registry and lockfile
hashes were checked for the updated archives, and their dependency inventory and
license/notice references were refreshed. Existing license review limitations
remain in force.

## Remaining unpatched dependency

**diskcache 5.6.3 / CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v remains unresolved.**
The public advisory lists unsafe pickle deserialization when an attacker can
write to the cache directory. No patched release is listed; 5.6.3 remains the
latest PyPI release at this review. It is required by pySigma 1.5.1, and even the
current pySigma 2.0.1 still declares this dependency. Removing it would violate
the installed dependency contract; no library was silently removed or replaced.

In the installed pySigma source, cache construction belongs to its on-demand
MITRE ATT&CK/D3FEND downloaders. This workbench uses its bundled catalogs.
`tests/test_dependency_safety.py` runs a real local replay, Sigma conversion and
package export while rejecting every attempt to construct a `diskcache.Cache`.
This establishes non-use for that tested workflow, not a fix for the library or
a guarantee about every possible future code path. Do not enable those remote
catalog/cache loaders without reviewing this advisory and the cache-directory
trust boundary again. The advisory is not dismissed or excluded from audits.

## Audit results and limits

The GitHub integration cannot read repository Dependabot alerts (HTTP 403,
`Resource not accessible by integration`). Consequently, the previously reported
13-alert dashboard count cannot be individually reconciled or certified closed
here. Public advisory audits found **15 distinct advisories across five
packages**. These changes remove **14**; the diskcache advisory remains. The
Python advisory feed repeats that single advisory twice, so its raw result is
two vulnerability entries for one package.

Exact advisory IDs and before/after results are retained in
[`validation/dependency-security.json`](../validation/dependency-security.json).
The separately pinned upstream Attack Flow Builder dependency tree is unchanged
and is outside these two workbench lockfile audits.

- `pip-audit 2.10.1`: every one of the 89 Python package/version pairs in
  `uv.lock` was queried, including platform-specific entries and development
  dependencies. Before: 13 entries across four packages (12 distinct advisories).
  After: two duplicate entries for the one unresolved diskcache advisory.
- `npm audit`: all frontend production/development dependencies checked.
  Before: three undici advisories, propagated to jsdom/vitest in npm's summary.
  After: **zero vulnerabilities**.

Audits describe the databases available on the review date. Passing regression
or static-analysis checks does not make the remaining advisory disappear.
Default-branch alerts will only update after the dependency changes are merged
and GitHub reprocesses the dependency graph.

## Reproduce

```sh
uv sync --frozen --extra dev
npm --prefix web ci
uv run --frozen --extra dev pytest -q
npm --prefix web run typecheck
npm --prefix web test
npm --prefix web run build
npm --prefix web audit
```

For a platform-independent advisory query, export every locked package except
the local project, without executing or resolving those dependencies:

```sh
python - <<'PY' > /tmp/iti-locked-dependencies.txt
import tomllib
from pathlib import Path
lock = tomllib.loads(Path('uv.lock').read_text())
for package in sorted(lock['package'], key=lambda p: p['name']):
    if package['name'] != 'intel-to-improvements':
        print(f"{package['name']}=={package['version']}")
PY
uvx --from pip-audit==2.10.1 pip-audit \
  -r /tmp/iti-locked-dependencies.txt --no-deps --disable-pip
```

The last command intentionally returns a nonzero status while diskcache remains
affected. Do not suppress that failure or use an advisory ignore list to call
the dependency audit clean.
