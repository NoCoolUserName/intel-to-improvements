# PHP2Shell — Harborlight Capital working case

## Source review: PHP project, 21 October 2026

The PHP project identifies CVE-2026-109618 (out-of-memory corruption) and CVE-2026-109619 (stale global state) as unauthenticated remote-code-execution vulnerabilities. Fixed releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Check distribution backports and the actual serving runtime, then restart workers. The project considers mod_php highest risk; other web-serving SAPIs also require assessment. Updating is the complete remedy. Configuration changes reduce particular paths and require specialist review; a WAF or changed setting cannot establish comprehensive protection.

Primary source: https://www.php.net/archive/2026.php#2026-10-21-5

Advisories: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w and https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

## Source review: AttackIQ, 22 October 2026

AttackIQ describes a PHP2Shell assessment based on PortSwigger research. Its request probe exercises session upload-progress handling and examines response signatures. Compare target response, WAF enforcement and alert delivery independently. The probe does not demonstrate code execution or cover every attack path. A missing signature does not establish patching or protection. Record the exact content revision, route, host and control configuration when a separately authorized test is performed.

Primary source: https://www.attackiq.com/2026/10/22/php2shell/

## Source correction: Unit 42, 25 October 2026

Unit 42 retracted its October 23 exploitation update on October 25. This case does not use that retracted account as evidence of a PHP2Shell intrusion, actor attribution or post-exploitation sequence.

Primary source: https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/

## Authored investment-firm scenario — entirely synthetic

Harborlight Capital is a fictional investment firm. Its client portal receives investor documents; its research upload service handles analyst submissions; its investment reporting application publishes statements. All assets, code findings, owners, events, approvals and results below are authored demonstration data. No real firm, account, scanner or AttackIQ execution is represented.

Synthetic initial-access hypothesis: an external request reaches an affected PHP client-portal worker through the public WAF route or an overlooked direct-origin route. This maps to T1190 as an analyst proposal. The WAF blocks one authored request sample while the origin bypass remains unresolved; neither result proves complete remediation.

Synthetic execution hypothesis: after the hypothetical initial access, a PHP worker starts an unexpected Unix shell. T1059.004 is an analyst-proposed investigation step, not a reported PHP2Shell incident.

Synthetic persistence hypothesis: after that hypothetical shell, an unauthorized server-side script is written into a web-served directory. T1505.003 is a proposed investigation branch; no web shell is supplied or executed.

Synthetic collection hypothesis: after the hypothetical script, an unexpected outbound connection attempts to transfer a harmless canary from the reporting service. T1041 is a proposed investigation branch; no investor data or external destination is used.

Synthetic ordering: the initial-access hypothesis precedes the shell hypothesis; the shell hypothesis precedes the server-script hypothesis; the server-script hypothesis precedes the outbound-transfer hypothesis. These are scenario relationships only, not evidence of an observed intrusion or causation.

## Compensating-control and permanent-fix decisions

Portal engineering owns patched runtime images, worker restarts and deployment evidence. Network engineering owns WAF route coverage, origin access restrictions and decoded-body limits. SOC owns correlation of proxy request IDs, PHP worker faults, process ancestry, web-root changes and egress. Risk owns a bounded exception for the research service while patch compatibility is tested. Every temporary control has a review date, residual uncertainty and permanent patch plan. Patch claims, blocked probes, absent signatures, detection alerts and SOC response remain separate outcomes.

## Pipeline and AppSec scope

The authored SARIF review records an unpatched runtime-image assumption, a WAF origin-bypass configuration concern and a missing runtime-version release check. These are synthetic engineering observations, not actual scanner output or proof that application SAST detects a PHP engine memory-safety flaw. Authored pipeline snapshots and supplied run metadata show a skipped secret check, a failed regression, a later successful report and an external reusable workflow whose implementation remains unknown. The workflow files are inert teaching fixtures with placeholder action revisions.
