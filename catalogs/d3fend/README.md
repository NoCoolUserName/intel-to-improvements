# Pinned D3FEND associations

This local snapshot contains 424 exact Enterprise ATT&CK IDs with associations to 147 D3FEND techniques. Source: [Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow/tree/5c8bf4ca9ff64ef9b55c38a2505db318750cbcda), revision `5c8bf4ca9ff64ef9b55c38a2505db318750cbcda`. `pin.json` checks the normalized catalog bytes. `catalog.json.provenance.sources` records immutable upstream URLs and SHA256 hashes of the generated enum, ATT&CK domain metadata, recommender and generator sources.

The upstream generator obtains D3FEND ATT&CK Extractor `off_to_def` associations. Its generated enum retains IDs and names, but neither definitions nor individual inference paths/effectiveness evidence. An association is a possible countermeasure requiring analyst review. Exact-ID lookup is not an exact procedure match, suitability ranking, deployed capability, prevention guarantee or coverage evidence. No parent-technique fallback is used. Enterprise IDs present without mappings, unsupported IDs/domains, unmapped behaviors, and invalid/missing catalogs have separate states. A missing association does not establish that no defense exists.

The pinned upstream source declares ATT&CK 19.1; its D3FEND ontology release/version is not recorded and remains null. Retrieval time is not a release date. Official technique references were matched by exact name to links in the official [matrix](https://d3fend.mitre.org/); its retrieval time and content hash are recorded separately. The extracted names and URLs are versioned in this catalog; the ontology version remains unknown.

## Explicit refresh

Ordinary startup, lookup, tests and package generation do not fetch anything. The transform does not execute downloaded JavaScript or run the upstream full-catalog harvester. The Builder is not required for this feature.

For the existing pin, reuse `runtime/attack-flow-build/source.tar.gz` if available. Otherwise download the exact archive from `https://codeload.github.com/center-for-threat-informed-defense/attack-flow/tar.gz/5c8bf4ca9ff64ef9b55c38a2505db318750cbcda`; the transform checks its SHA256 against `integrations/attack-flow/pin.json`. Save a fresh official matrix HTML snapshot and its actual UTC retrieval timestamp:

```sh
mkdir -p runtime/d3fend
curl --fail --location --proto '=https' --proto-redir '=https' --max-time 30 \
  https://d3fend.mitre.org/ -o runtime/d3fend/official-matrix.html
date -u +%Y-%m-%dT%H:%M:%SZ
.venv/bin/python scripts/refresh-d3fend \
  --archive runtime/attack-flow-build/source.tar.gz \
  --references runtime/d3fend/official-matrix.html \
  --retrieved-at '<actual UTC timestamp from the successful download>'
.venv/bin/python -m pytest tests/test_defenses.py -q
```

Review changes to names, IDs, mappings, official links, versions and licenses; commit both catalog and pin. The timestamp is an input, not synthesized by the transform. The raw HTML remains an ignored build input. Reproducing the exact transformation requires the recorded original snapshot; ordinary runtime reproduction needs only the checked-in normalized catalog. Review the source version and pins before adopting a new upstream revision. Original-source download access is not needed to run the demo.

Candidate snapshots and action origin metadata retain their original catalog checksum. Refreshing does not rewrite historical actions or package files. A candidate for the same assessment/behavior/defense returns the existing improvement, even if the catalog has changed. Deliberate separate follow-ups use the ordinary manual improvement form.

Licensing: `LICENSE` is Attack Flow's Apache-2.0 license. `D3FEND-LICENSE` preserves MITRE's distinct data terms, notices and disclaimer. MITRE does not endorse this application.
