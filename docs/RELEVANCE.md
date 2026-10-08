# Relevance policy `relevance-1`

Evaluate only after source parsing and extraction. No metadata-only score can silently block a manually supplied source. Store all factors, evidence refs, explanation, source gaps and frozen context.

Priority rules in order:

1. A supported extracted technology matches a declared customer/environment technology or platform: **High**. Explicit sector mismatch cannot veto this.
2. Otherwise, a reported behavior platform matches: **Medium**, with unresolved service/exposure prerequisites.
3. No extracted behavior: **Unknown**. Insufficient text or a recognizer limitation is not Low.
4. Otherwise, a literal intelligence-requirement match supports **Medium**, with explicit platform mismatch and no invented equivalent.
5. Known behaviors on absent platforms with neither match: **Low**. Keep the source visible in All and available for manual inclusion.

Sector factor is separately `match`, `mismatch`, or `unknown`. Bounded offline recognition accepts explicit targeting wording; mere mention, source publisher, mail sender or inferred industry relationship cannot establish targeting. Live-provider outputs currently focus on bounded behaviors and do not silently infer sector targeting. Missing sector is Unknown, not a veto. Source reliability stays unassessed until independently reviewed. Recency displays source publication and incident time separately; email arrival is never substituted for either.

Fixtures: the authored healthcare report is High for the fictional financial-services Windows customer through shared ActiveMQ, despite sector mismatch. The same shared source facts are Low for the macOS/cloud customer because the Windows technologies are absent. The nontechnical note is Unknown and visible by default. A held-out cloud case also remains Unknown when the bounded recognizer misses its behavior; evaluation records the miss. This is preferable to an unjustified Low exclusion, but remains a processing limitation.

Recommended includes High/Medium/Unknown. Custom can select levels and Include Unknown; All reveals every assessed item, with filtered counts visible. Manual inclusion records reason and time. Overrides change queue selection, not source facts or evidence. Packages require an explicit generate action, including for Low sources. New profile versions or a changed policy identifier produce new immutable assessments; prior outputs and clocks remain.
