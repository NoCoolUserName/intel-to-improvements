"""Bounded offline SARIF 2.1.0 normalization. URIs are never dereferenced."""
import json
import math
import re
from pathlib import Path
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry
from .store import canonical, uid

MAX_BYTES = 4 * 1024 * 1024
MAX_RESULTS = 1000
NORMALIZER_VERSION = 'sarif-normalizer-2'
MAX_MESSAGE_CHARS = 32768
MESSAGE_TOKEN = re.compile(r'\{\{|\}\}|\{([0-9]+)\}')
SCHEMA = json.loads((Path(__file__).parent / 'schemas/sarif-2.1.0.json').read_text())
VALIDATOR = Draft7Validator(SCHEMA, registry=Registry(), format_checker=FormatChecker(formats=["date-time"]))
LIMITATIONS = [
    'Scanner reports are not independently validated vulnerabilities.',
    'Scan completeness, exploitability, reachability, ownership and business impact are unknown.',
    'Import performs no scanning, remediation, verification or enterprise risk scoring.',
    'Absence from a later report never closes a finding.',
    'Artifact URIs are untrusted evidence text; no files or remote resources are read.',
    'Optional content is retained in original evidence; only documented fields are normalized.',
]


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('Duplicate JSON object keys are not supported')
        out[key] = value
    return out


def parse(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('SARIF upload limit is 4 MiB')
    try:
        document = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise ValueError('Malformed or excessively nested UTF-8 JSON') from None
    stack = [(document, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if depth > 32 or count > 200000:
            raise ValueError('SARIF structure exceeds depth 32 or 200000 nodes')
        if isinstance(value, str):
            if len(value) > 32768 or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise ValueError('SARIF string exceeds 32768 characters or contains invalid Unicode')
        elif isinstance(value, (dict, list)):
            if len(value) > 1000:
                raise ValueError('SARIF collection exceeds 1000 entries')
            stack.extend((v, depth + 1) for v in (list(value.keys()) + list(value.values()) if isinstance(value, dict) else value))
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError('Nonfinite JSON numbers are not supported')
    if not isinstance(document, dict) or document.get('version') != '2.1.0':
        raise ValueError('SARIF version must be 2.1.0')
    # Do not echo untrusted report contents in validation errors or logs.
    error = next(VALIDATOR.iter_errors(document), None)
    if error:
        raise ValueError('Invalid SARIF structure (schema constraint: ' + str(error.validator) + ')')
    runs = document.get('runs')
    if runs is None or len(runs) > 100:
        raise ValueError('SARIF requires an array of at most 100 runs')
    if sum(len(r.get('results', [])) for r in runs) > MAX_RESULTS:
        raise ValueError('SARIF limit is 1000 total results')
    return document


def rule_for(run, result):
    reference = result.get('rule', {})
    component = run['tool']['driver']
    selector = reference.get('toolComponent', {})
    extensions = run['tool'].get('extensions', [])
    if selector:
        candidates = [component] + extensions
        if 'index' in selector:
            index = selector['index']
            if index < -1 or index >= len(extensions):
                raise ValueError('Unresolved rule tool component index')
            candidates = [component if index == -1 else extensions[index]]
        candidates = [c for c in candidates if all(c.get(k) == selector[k] for k in ('name', 'guid') if k in selector)]
        if len(candidates) != 1:
            raise ValueError('Ambiguous or unresolved rule tool component')
        component = candidates[0]
    rules = component.get('rules', [])
    ids = [v for v in (result.get('ruleId'), reference.get('id')) if v is not None]
    indexes = [v for v in (result.get('ruleIndex'), reference.get('index')) if v is not None and v != -1]
    if len(set(ids)) > 1 or len(set(indexes)) > 1:
        raise ValueError('Conflicting rule references')
    rule = {}
    if indexes:
        if indexes[0] >= len(rules):
            raise ValueError('Unresolved rule index')
        rule = rules[indexes[0]]
        if ids and rule['id'] != ids[0]:
            raise ValueError('Rule ID and index disagree')
    elif ids or reference.get('guid'):
        matches = [r for r in rules if (not ids or r['id'] == ids[0]) and (not reference.get('guid') or r.get('guid') == reference['guid'])]
        if len(matches) > 1:
            raise ValueError('Ambiguous rule reference')
        rule = matches[0] if matches else {}
    if reference.get('guid') and rule.get('guid') != reference['guid']:
        raise ValueError('Unresolved rule GUID')
    return rule, (ids[0] if ids else rule.get('id')), component


def identifiers(value, pattern):
    """Literal identifiers only in explicit metadata, never inferred from rule names."""
    return sorted(set(re.findall(pattern, canonical(value), flags=re.I)), key=str.upper)


def resolve_message(message, rule, component, gaps):
    """SARIF 3.11.5/3.11.7/3.11.11; substitute once, never interpret arguments."""
    template = message.get('text') or message.get('markdown')
    if template is None and message.get('id'):
        referenced = rule.get('messageStrings', {}).get(message['id']) or component.get('globalMessageStrings', {}).get(message['id'], {})
        template = referenced.get('text') or referenced.get('markdown')
    if template is None:
        return None
    args = message.get('arguments', [])
    pieces = []
    length = position = 0
    for token in MESSAGE_TOKEN.finditer(template):
        replacement = token[0][0]  # Doubled braces represent one literal brace.
        if token[1] is not None:
            digits = token[1].lstrip('0') or '0'
            # Avoid converting attacker-controlled, arbitrarily long integers.
            index = int(digits) if len(digits) <= len(str(len(args))) else len(args)
            if index < len(args):
                replacement = args[index]
            else:
                replacement = token[0]
                gaps.append('Message placeholder has no supplied argument; placeholder retained')
        prefix = template[position:token.start()]
        length += len(prefix) + len(replacement)
        if length > MAX_MESSAGE_CHARS:
            gaps.append('Message substitution exceeds limit; original template retained')
            return template
        pieces.extend((prefix, replacement))
        position = token.end()
    if length + len(template) - position > MAX_MESSAGE_CHARS:
        gaps.append('Message substitution exceeds limit; original template retained')
        return template
    pieces.append(template[position:])
    return ''.join(pieces)


def normalize(document, scope, operator, source_hash):
    findings = []
    normalized_bytes = 0
    warnings = list(LIMITATIONS)
    for ri, run in enumerate(document['runs']):
        driver = run['tool']['driver']
        invocations = run.get('invocations', [])
        status = 'unknown'
        if invocations:
            failed = any(i.get('executionSuccessful') is False or i.get('exitCode', 0) != 0 or i.get('executionNotifications') or i.get('toolExecutionNotifications') for i in invocations)
            status = 'failed or incomplete' if failed else ('reported success' if all(i.get('executionSuccessful') is True for i in invocations) else 'unknown')
        run_warnings = []
        supported_run = {'tool','results','automationDetails','invocations','versionControlProvenance','properties','artifacts','$schema'}
        for key in sorted(set(run) - supported_run):
            run_warnings.append('Run field retained in evidence, not interpreted: ' + key)
        if run.get('externalPropertyFileReferences'):
            run_warnings.append('External properties are not loaded; report may be incomplete')
        if 'results' not in run:
            run_warnings.append('Results absent; scan completeness unknown')
        warnings.extend(f'Run {ri}: {w}' for w in run_warnings)
        timestamps = [{k: i[k] for k in ('startTimeUtc','endTimeUtc') if k in i} for i in invocations]
        reported_context = run.get('versionControlProvenance', [])
        for index, result in enumerate(run.get('results', [])):
            rule, rule_id, component = rule_for(run, result)
            gaps = list(run_warnings)
            for key in sorted(set(result) - {'rule','ruleId','ruleIndex','message','level','locations','fingerprints','partialFingerprints','properties'}):
                gaps.append('Result field retained in evidence, not interpreted: ' + key)
            locations = []
            for location in result.get('locations', []):
                physical = location.get('physicalLocation', {})
                artifact = dict(physical.get('artifactLocation', {}))
                if 'index' in artifact and artifact['index'] >= 0:
                    artifacts = run.get('artifacts', [])
                    if artifact['index'] >= len(artifacts):
                        raise ValueError('Unresolved artifact index')
                    declared = artifacts[artifact['index']].get('location', {})
                    if 'uri' not in artifact and 'uri' in declared:
                        artifact = declared | artifact
                locations.append({'artifact': artifact, 'region': physical.get('region', {}), 'logical_locations': location.get('logicalLocations', [])})
                if artifact.get('uriBaseId'):
                    gaps.append('URI base retained but not resolved')
            level = result.get('level')
            level_source = 'result.level' if level is not None else None
            if level is None:
                level = rule.get('defaultConfiguration', {}).get('level')
                if level is not None:
                    level_source = 'rule.defaultConfiguration.level (run overrides not evaluated)'
                    if any(i.get('ruleConfigurationOverrides') for i in invocations):
                        level = None
                        level_source = None
                        gaps.append('Rule configuration overrides are not evaluated; level unknown')
            metadata = {'rule.properties': rule.get('properties', {}), 'result.properties': result.get('properties', {})}
            message = result['message']
            resolved_message = resolve_message(message, rule, component, gaps)
            fp, partial = result.get('fingerprints', {}), result.get('partialFingerprints', {})
            # Partial fingerprints need locations too; no context means no cross-document correlation.
            identity_context = {'operator': operator, 'reported': reported_context}
            has_context = bool(operator.get('repository') or operator.get('application') or reported_context)
            basis = 'fingerprints' if fp else ('partial fingerprints plus locations' if partial else 'rule, tool, locations and message fallback')
            key = [scope['customer_id'], scope['environment_id'], identity_context, driver['name'], component['name'], rule_id]
            key += [fp] if fp else [partial, locations, None if partial else message]
            if not has_context or not rule_id or (not fp and not locations):
                key += [source_hash, ri, index]
                basis += '; document-local because correlation context is incomplete'
            for field, value in {'rule metadata': rule, 'rule identifier': rule_id, 'scanner version': driver.get('version'), 'scanner level': level, 'source location': locations, 'scan timestamp': any(timestamps), 'repository/commit from SARIF': reported_context}.items():
                if not value:
                    gaps.append('Missing or unresolved: ' + field)
            if resolved_message is None:
                gaps.append('Missing or unresolved: resolved message')
            synthetic_basis = []
            if operator.get('synthetic'):
                synthetic_basis.append('operator supplied')
            if document.get('properties', {}).get('synthetic') is True or run.get('properties', {}).get('synthetic') is True:
                synthetic_basis.append('SARIF properties.synthetic')
            findings.append(dict(logical_id=uid('app_logical', *key), identity_basis=basis, reported_context=reported_context,
                scanner={k: driver[k] for k in ('name','version','semanticVersion','guid','informationUri') if k in driver} | {'rule_component': component['name']},
                run_index=ri, result_index=index, run_id=run.get('automationDetails'), rule_id=rule_id, rule_metadata=rule,
                message=message, resolved_message=resolved_message, scanner_level=level, level_source=level_source,
                severity_metadata=metadata, cwes=[v.upper() for v in identifiers(metadata, r'(?<![\w-])CWE-\d+(?![\w-])')],
                cves=[v.upper() for v in identifiers(metadata, r'(?<![\w-])CVE-\d{4}-\d{4,19}(?![\w-])')],
                locations=locations, fingerprints=fp, partial_fingerprints=partial, scan_timestamps=timestamps,
                invocation_status=status, synthetic=bool(synthetic_basis), synthetic_basis=synthetic_basis, warnings=sorted(set(gaps))))
            normalized_bytes += len(canonical(findings[-1]).encode())
            if normalized_bytes > 16 * 1024 * 1024:
                raise ValueError('Normalized SARIF exceeds 16 MiB; split the report')
    return findings, warnings
