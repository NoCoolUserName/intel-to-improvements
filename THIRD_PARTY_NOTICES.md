# Third-party notices

The application's MIT license does not relicense source articles, catalogs, specifications or dependency code.

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
