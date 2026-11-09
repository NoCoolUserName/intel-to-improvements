# Brotli exposure response — fictional Harborlight Capital case

## Source facts — dated publisher evidence

Google's 21 October 2026 Brotli v1.2.1 security release links CVE-2026-111497 to an out-of-bounds decoder write and possible remote code execution. This is an upstream release fact, not an inventory finding. Source: https://github.com/google/brotli/releases/tag/v1.2.1

Node.js's 21 October 2026 advisory describes CVE-2026-111497 in its bundled Brotli decoder: an application must decompress attacker-controlled Brotli data with node:zlib for the described path. Node.js calls it High and released fixes for the 22.x, 24.x and 26.x lines. Its 24.22.1 release lists the fix; 24.22.0 is the affected comparison build used in the authored asset inventory. Historical first-fixed releases are not timeless install recommendations. Sources: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases and https://nodejs.org/en/blog/release/v24.22.1

Microsoft's 25 October 2026 advisory lists CVE-2026-111497 for .NET runtime packages: the 8.0 line before 8.0.33 is affected, and 8.0.33 is listed as patched. Microsoft says self-contained applications require rebuilding and redeploying with the updated runtime. This fixture uses an authored self-contained 8.0.32 application and a separately updated 8.0.33 host; the host update cannot replace the embedded application runtime. Source: https://github.com/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9

Red Hat describes CVE-2026-111497 as a decoder flaw conditional on decompression of untrusted Brotli data. Product-specific backports must be assessed against vendor package evidence; this case makes no Red Hat package claim. Source: https://access.redhat.com/security/cve/cve-2026-111497

Datadog Security Labs reported on 29 October 2026 that it reproduced CVE-2026-111497 on Node.js 24.22.0, described automatic decoding of outbound Brotli responses by Node.js fetch, and reported confirmed exploitation in the wild as of that date. That research does not establish a Harborlight compromise, a count of exploit attempts, or a named actor. Its statement that CISA listed the CVE is secondary here: the direct feed could not be retrieved for this fixture. Source: https://securitylabs.datadoghq.com/articles/node2shell-cve-2026-111497-nodejs-brotli-decoder/

Splunk's 28 October 2026 detection story describes request-error and Linux process-image-change investigation signals. These are hypotheses requiring field coverage and benign comparisons, not definitive CVE attribution. Source: https://research.splunk.com/stories/node2shell/

## Analyst-authored questions — not source facts

The exposure leader asks where the affected decoder actually processes untrusted input, who owns patching and deployment, whether temporary controls cover inbound and outbound paths, and what measured artifact evidence could change each decision. Public severity and reported exploitation are distinct from this firm's asset priority. Investigate possible activity during the historical exposure window separately from remediation; missing telemetry is inconclusive.

Synthetic inbound hypothesis: an external request supplies Brotli-compressed input to the affected client-api decoder. T1190 is a proposed entry-path mapping, contingent on the authored route and decoding configuration; no intrusion is observed.

Synthetic outbound hypothesis: research-fetcher obtains an externally controlled Brotli response and decodes it. This is a distinct entry path; an inbound request filter does not cover it. No ATT&CK technique is asserted solely for the response decoding step.

Synthetic decoder hypothesis: the affected runtime processes attacker-controlled compressed bytes. A crash, memory disclosure or code execution is possible under the source-described flaw, but none is observed in this fictional firm. This node is a conditional processing step, not an ATT&CK technique.

Synthetic process hypothesis: if code execution occurred, a changed Linux process image or unexpected process activity could warrant investigation. T1059.004 is a conditional analyst hypothesis, not a reported attack stage. PID alone cannot distinguish process replacement from reuse; collect boot and process-start identity.

Synthetic ordering: the inbound and outbound hypotheses each precede the decoder hypothesis; the decoder hypothesis precedes the conditional process hypothesis. These two branches are authored exercise relationships, not an observed customer intrusion.

## Fictional observations and governance

All Harborlight assets, owners, routes, commits, events, retests, approvals and pipeline reports are authored synthetic data under reserved example domains. Inventory describes client-api, research-fetcher, advisor-package, reporting-service, vendor-analytics-agent and patched-reference. Affected component presence, reachable attacker-controlled decoding, unknown packaging and a source-supported patched build remain different states. Owner attestations, green runs, skipped checks and replay results cannot establish operational verification.
