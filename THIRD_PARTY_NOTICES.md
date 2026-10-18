# Third-party notices

The application's MIT license does not relicense source articles, catalogs, specifications or dependency code.

## Sharing generated packages

New packages include the application LICENSE, this notice, full bundled catalog and
integration license texts in THIRD_PARTY_LICENSES.txt, and RULE_ATTRIBUTIONS.json.
Hunt and purple-team JSON/Markdown retain candidate-rule attribution; synthetic
match messages retain the supplied rule author. Preserve supplied authors, source
links and applicable license terms when sharing derived queries. Downstream SIEM
alert templates must retain the supplied authors for messages based on DRL rule
matches; this application does not configure a live SIEM or verify those templates.
Generating a package after this update creates a new package revision and preserves
historical packages. Previously downloaded packages are not retroactively updated.

The packaged Python/JavaScript application metadata describes original application
code. Dependency code, bundled catalogs and integration assets keep their own terms.
Before redistributing an installed environment or compiled application, inventory
the exact included dependency versions and ship their required license/NOTICE files.
This repository's notices are not a complete transitive-dependency audit.

Limited attributed derivatives of publisher articles still require a valid rights
basis. Attribution and exclusion of the full article do not establish permission or
fair use. Record permission or a documented legal basis before broader redistribution;
replace a derivative fixture with an independently authored synthetic case if that
basis cannot be established.

- **The DFIR Report**, “Apache ActiveMQ Exploit Leads to LockBit Ransomware,” published 2026-02-23, analysts @malforsec, @lapadrino and @PeteO. Source: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/ . `fixtures/activemq-derived.md` is an attributed, limited developer/model-curated derivative; its text is not a complete article or screenshot. The fetched complete article remains in ignored `runtime/research/`. No private-report controls were bypassed. Publisher-supported case references TB27524 / PR39767 are distinct from the local document ID. Full source rights remain with the publisher.
- **SigmaHQ/sigma** public rule subset: exact revision, retrieval date, file paths and SHA256 values in `catalogs/manifest.json`; full original YAML author/reference metadata retained. See `catalogs/SIGMA_LICENSE` and `catalogs/SIGMA_DRL_LICENSE`. The Sigma specification, tools and detection-rule licenses differ; the bundled rule files use Detection Rule License 1.1 unless an individual rule says otherwise.
- **MITRE ATT&CK** metadata derived from the official enterprise STIX dataset at the pinned revision. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. The license and disclaimers are reproduced in `catalogs/ATTACK_LICENSE`. ATT&CK mapping does not imply complete technique coverage or MITRE endorsement.
- **Red Canary Atomic Red Team**: pinned source metadata files in `catalogs/atomic/`, with exact upstream path/commit/hash in the manifest. MIT license in `catalogs/ATOMIC_LICENSE`, copyright Red Canary, Inc. These files are inspected as catalog data; the app does not execute them. Plans replace dangerous/default external actions with bounded human-led objectives and label approximation limits.
- **Python/JavaScript dependencies** retain their licenses. Installed versions are locked in `uv.lock` / `web/package-lock.json`; selected tested versions appear in `validation/evaluation.json`. PyMISP, misp-stix, stix2, stix2-validator, pySigma and its Splunk backend are used rather than recreating their interchange formats/conversion libraries.

Official references checked during implementation:

- https://thedfirreport.com/reports/
- https://github.com/The-DFIR-Report/Sigma-Rules (public contributions now go to SigmaHQ; no private rule corpus retrieved)
- https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- https://github.com/MISP/PyMISP
- https://github.com/MISP/misp-stix
- https://attack.mitre.org/resources/attack-data-and-tools/
- https://github.com/mitre-attack/attack-stix-data
- https://sigmahq.io/docs/basics/rules.html
- https://github.com/SigmaHQ/sigma
- https://github.com/SigmaHQ/pySigma-backend-splunk
- https://github.com/redcanaryco/atomic-red-team
- https://developers.openai.com/api/docs/guides/structured-outputs

Fixture authorship: all other Markdown, CSV and MIME examples are independently authored synthetic cases. They are not real incidents. Gold labels are developer/model-curated through source inspection, not owner-reviewed and not independent human adjudication.

- **MITRE Center for Threat-Informed Defense Attack Flow**: Builder 4.0.1 and extension 2.0.0 pinned at `5c8bf4ca9ff64ef9b55c38a2505db318750cbcda`, https://github.com/center-for-threat-informed-defense/attack-flow . Apache-2.0 text retained in `integrations/attack-flow/LICENSE`. This application applies the documented local integration patch; no MITRE endorsement is implied. Upstream includes no separate NOTICE file at this revision. The whole upstream repository is not redistributed here; the build downloads a hash-verified archive and extracts only the Builder/shared config. Hashed extension/STIX schemas are retained for offline validation. Generated static output includes the license and installed dependency notices.
- **OASIS STIX JSON schemas** included with the pinned Attack Flow source: copyright OASIS Open; BSD-3-Clause notice retained as `integrations/attack-flow/OASIS-LICENSE`, retrieved from https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/LICENSE . The actual schema bytes are pinned to the Attack Flow revision, not fetched from a mutable branch at runtime.
- **Inter** and **JetBrains Mono** viewer fonts: SIL Open Font License 1.1 notices retained in `integrations/attack-flow/INTER-LICENSE` (Inter v3.19 upstream license) and `JETBRAINS-MONO-LICENSE` (official JetBrains Mono license). Fonts are served from the pinned Builder's bundled assets; no external font request occurs.

- **MITRE D3FEND / Attack Flow mapping data**: normalized exact Enterprise associations and technique names from the existing Attack Flow revision `5c8bf4ca9ff64ef9b55c38a2505db318750cbcda`. Separate Apache-2.0 and MITRE D3FEND terms are retained in `catalogs/d3fend/LICENSE` and `catalogs/d3fend/D3FEND-LICENSE`. Official matrix links were preserved as data, with supplemental source hash and actual retrieval date in `catalogs/d3fend/catalog.json`; no definitions, logos or full website HTML redistributed. Upstream does not record the mapping enum's D3FEND ontology version or release date. Sources verified: https://d3fend.mitre.org/resources/ , https://d3fend.mitre.org/resources/ontology/ , https://d3fend.mitre.org/tools/attack-extractor/ , https://d3fend.mitre.org/tou/ . Associations suggest possible defenses, not tested efficacy or endorsement.

## Vulnerability Intelligence historical examples and public data

`fixtures/vulnerability/teamcity.md` and `driver.md` are developer-authored, minimal attributed derivatives of CISA AA23-347A (2023-12-13) and CrowdStrike's BYOVD report (2023-01-10). Original linked materials retain their publishers' rights; the app license does not license their full articles/images. Full raw copies are excluded from Git. Primary URLs, document hashes, retrieval times, dates and attribution qualifiers are retained in source metadata and the demo documentation.

`fixtures/vulnerability/enrichment.json` contains selected factual records from CISA KEV, FIRST EPSS and the CVE Program's CNA records with attribution and actual snapshot dates/hashes. FIRST EPSS data is attributed to FIRST (see https://www.first.org/epss/ and its data/license terms); CISA and the originating CNA remain identified separately. These data/source notices are distinct from the application's license. No vendor logo, proprietary scanner output or real organization's asset inventory is bundled.
