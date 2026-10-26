"""Platform-correct, human-led plans for the explicitly curated PHP2Shell case."""


def tailor(behavior, hunt, emulation):
    if not behavior.key.startswith('php2shell_'):
        return
    hunt.priority = 'high'
    hunt.hypothesis = 'Hypothetical PHP2Shell investigation: ' + behavior.text
    hunt.rationale = 'Fictional investment-portal exposure; prioritize investor documents and reporting availability without asserting compromise'
    hunt.steps = [
        {'order': 1, 'question': 'Can the retained data answer this hypothesis?',
         'procedure': 'Bound the UTC window and approved assets. Verify request ID, route, backend worker, process ancestry, file audit and egress fields with benign controls. Record retention and missing sources.',
         'on_missing': 'Inconclusive; open a telemetry improvement before interpreting absence.'},
        {'order': 2, 'question': 'Does request activity correlate with backend behavior?',
         'procedure': 'Compare WAF and direct-origin access, PHP errors/restarts, worker child processes, web-root changes and outbound sessions. Preserve exact request IDs and clock offsets. Treat malformed requests and faults as investigation leads, not proof of RCE.',
         'on_no_hit': 'Record bounded no-evidence only when source sufficiency is demonstrated.'},
        {'order': 3, 'question': 'Is there corroboration of unauthorized activity?',
         'procedure': 'Compare uploads, deployment windows and authorized administration. Escalate unexplained shell ancestry, server-script writes or egress with original evidence. No stage is inferred from a CVE mention alone.',
         'on_suspicious': 'Request approved containment and preserve evidence before patching or restarting workers.'},
    ]
    hunt.query = None
    hunt.query_origin = 'Curated portable investigation; no executable backend query or live search is claimed'
    emulation.prerequisites = ['Named isolated Linux/PHP lab and written test approval', 'Human test and control owners',
                               'Vendor content revision, maintenance window and rollback plan', 'Proxy, PHP, process, file and egress telemetry checks']
    emulation.lab_scope = 'Fictional Harborlight exercise; any actual test needs a separately approved exact asset/route scope'
    emulation.test_data = 'Authored local fixtures and a harmless canary; no investor data, exploit payload or external callback'
    if behavior.key == 'php2shell_request':
        emulation.objective = 'Evaluate the PHP2Shell request-probe evidence and compensating WAF controls'
        emulation.steps = [
            'Start offline: inspect the three authored samples in waf-results.json: blocked public route, signature through direct origin, and no signature. No HTTP request is sent by this application.',
            'For a separately approved validation, have the authorized AttackIQ operator select PHP2Shell Check (CVE-2026-109618 and CVE-2026-109619), confirm its current documentation/content revision and execute only the approved target and routes. Reference: https://www.attackiq.com/2026/10/22/php2shell/',
            'Preserve target response and request ID, WAF policy/version and enforcement event, alert delivery, route, serving runtime and worker restart evidence. Test public WAF and authorized alternate-origin paths separately; include a benign upload.',
            'Interpret independently: blocked request = this request/route was prevented; relevant signature = investigate susceptibility, not proof of RCE; no signature = inconclusive. Missing telemetry = inconclusive. A patched runtime requires separate package/serving-worker evidence.',
            'Retest permanent patch and temporary controls separately. WAF coverage, origin restrictions, request limits and egress controls reduce particular paths; record residual uncertainty, review date, owner and permanent-fix commitment.',
        ]
    else:
        emulation.objective = 'Observe an approved benign approximation of the hypothetical PHP aftermath'
        emulation.steps = [
            'Use the authored scenario as a hypothesis only; no source-backed PHP2Shell intrusion chain is claimed.',
            'In a disposable Linux test environment, have the lab owner select a benign local process, temporary inert text file or loopback canary transfer appropriate to this behavior. Do not introduce a web shell, persistence or exploit.',
            'Preserve process ancestry, file or network records plus the exact procedure. Check a benign comparison and a deliberately missing-field fixture.',
            'Record telemetry, rule match, actual alert delivery, enforcement and SOC handling separately, only when evidenced. Missing observations remain inconclusive.',
        ]
    emulation.expected_observables = ['Proxy request ID and route correlated to PHP worker and response',
                                      'Linux process/file/egress records appropriate to the selected hypothesis',
                                      'Exact control version, UTC times, benign comparison and preserved evidence hashes']
    emulation.expected_detection = 'Unknown until a named rule and its actual alert delivery are separately evidenced'
    emulation.expected_prevention = 'One blocked request establishes only its tested route/variant; comprehensive protection remains unknown'
    emulation.cleanup = ['Preserve evidence and hashes first', 'Remove only named benign lab artifacts and stop the owned loopback canary service',
                         'Restore the disposable lab snapshot and verify normal benign uploads']
    emulation.atomic_candidates = []
    emulation.limitations = ['Hypothetical chain, not a reported compromise', 'AttackIQ content is referenced; this app has no AttackIQ integration or execution',
                            'The probe does not prove RCE; absent signatures do not prove safety',
                            'No exact Atomic procedure selected for this curated scenario', 'All preloaded results are authored synthetic examples']
