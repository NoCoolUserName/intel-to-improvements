"""Bounded investigation and benign validation for the curated Brotli case."""


def tailor(behavior, hunt, emulation):
    if not behavior.key.startswith('brotli_'):
        return
    path = behavior.key.removeprefix('brotli_')
    hunt.priority = 'high'
    hunt.question = 'What evidence supports or limits this fictional Brotli path?'
    hunt.hypothesis = 'Hypothetical ' + path + ' path: ' + behavior.text
    hunt.rationale = 'Dated source facts plus authored asset observations; no customer intrusion asserted'
    hunt.scope = 'Fictional Harborlight assets only; bound UTC window to actual retained data before any real search'
    hunt.required_fields = ['asset_id', 'event_time', 'boot_id', 'process_start', 'pid'] if path == 'process' else (
        ['destination', 'content_encoding', 'decoder_error', 'event_time'] if path == 'outbound' else
        ['request_id', 'route', 'content_encoding', 'status', 'decoder_error', 'event_time'])
    hunt.field_mapping = {field: 'Map to approved source field before any query' for field in hunt.required_fields}
    hunt.steps = [
        {'order': 1, 'question': 'Is telemetry sufficient for this asset and window?',
         'procedure': 'Verify source collection, retention, clock alignment and required fields using an ordinary Brotli or authorized process control.',
         'on_missing': 'Inconclusive. Record the gap and owner action; do not conclude no compromise.'},
        {'order': 2, 'question': 'Does activity warrant investigation?',
         'procedure': ('Compare fetched-response decoder activity and external destinations; inbound request filters do not cover this path.' if path == 'outbound' else
                       'Compare process image, PID, process start and boot identity; distinguish authorized exec and PID reuse.' if path == 'process' else
                       'Correlate Brotli-bearing requests with decoder errors, crashes, resource anomalies and subsequent workload events.'),
         'on_no_hit': 'Only a bounded no-match statement is possible after telemetry sufficiency is shown.'},
        {'order': 3, 'question': 'Are signals benign or corroborated?',
         'procedure': 'Compare ordinary Brotli traffic, benign truncated inputs, approved process execution and deployment windows; preserve raw events and uncertainty.',
         'on_suspicious': 'Escalate to the investigation owner with original records; a header, error or crash alone is not CVE attribution.'},
    ]
    hunt.query = None
    hunt.query_origin = 'Hand-authored investigation procedure; no SIEM query executed or correlation rule claimed'
    hunt.negative_controls = ['Ordinary Brotli response/request', 'Benign truncated input', 'Authorized process execution', 'Deliberately missing telemetry']
    hunt.branches['missing_telemetry'] = 'Inconclusive; preserve gap and request collection/retention evidence'
    hunt.closure = 'Record bounded findings and unresolved historical exposure; patch verification does not resolve prior compromise'
    emulation.objective = 'Human-led benign validation of the ' + path + ' assumption'
    emulation.prerequisites = ['Written approval and exact asset/route scope outside this application',
                              'Engineering and evidence-review owners', 'Named benign input only',
                              'Declared response, application and process telemetry with retention check']
    emulation.lab_scope = 'Synthetic replay by default; any real test requires separately approved isolated lab scope'
    emulation.test_data = 'events.json authored replay and harmless valid/truncated Brotli samples only; no exploit bytes or external targets'
    emulation.steps = [
        'Inspect the authored positive, negative and missing-telemetry replay records; no network or decoder attack is run.',
        'Have engineering establish package branch/version, embedded runtime, built image and running artifact identity before a fix conclusion.',
        'Validate inbound request filtering and outbound response decoding independently with benign data in an approved lab.',
        'Preserve exact configuration, test time, expected/actual result, control version and benign comparison; an absent signal is inconclusive without telemetry proof.',
    ]
    emulation.expected_observables = hunt.required_fields
    emulation.expected_detection = 'Unknown until reviewed draft detection is deployed, fields exist and actual alert delivery is evidenced'
    emulation.expected_prevention = 'Benign path/control behavior only; no CVE immunity or exploit prevention established'
    emulation.atomic_candidates = []
    emulation.limitations = ['No exploit payload, memory-corruption probe, malware or automatic offensive execution',
                            'No actual SIEM search, scanner, patch deployment or production security verification',
                            'Authored replay may test interpretation, not detection effectiveness']
