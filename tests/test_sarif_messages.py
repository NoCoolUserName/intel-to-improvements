"""Message regressions through the actual SARIF API and immutable store."""
import copy
import json

import pytest
from fastapi.testclient import TestClient

from iti.api import create_app
from iti.store import canonical, digest, uid

SCOPE = {'customer_id': 'fictional-bank', 'environment_id': 'windows-ad'}
OTHER = {'customer_id': 'fictional-cloud', 'environment_id': 'mac-cloud'}
LOOKUPS = ['text', 'rule-id', 'rule-index', 'rule-guid', 'driver-global',
           'extension-rule', 'extension-global']


def report(template, arguments, lookup='text'):
    rule = {'id': 'synthetic/message', 'guid': '12345678-1234-4234-8234-123456789abc'}
    component = {'name': 'Synthetic scanner', 'rules': [rule]}
    tool = {'driver': component}
    result = {'ruleId': rule['id'], 'message': {'arguments': arguments},
              'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'synthetic.txt'},
                                                 'region': {'startLine': 1}}}]}
    template_value = {'text': template, 'markdown': 'Unused Markdown'}
    if lookup.startswith('extension-'):
        tool = {'driver': {'name': 'Synthetic driver'}, 'extensions': [component]}
        result['rule'] = {'index': 0, 'toolComponent': {'index': 0}}
    if lookup == 'text':
        # Direct plain text takes precedence over both Markdown and ID lookup.
        result['message'].update(text=template, markdown='Unused Markdown', id='message')
        rule['messageStrings'] = {'message': {'text': 'Unused referenced message'}}
    else:
        result['message']['id'] = 'message'
        if lookup.endswith('global'):
            component['globalMessageStrings'] = {'message': template_value}
        else:
            rule['messageStrings'] = {'message': template_value}
            component['globalMessageStrings'] = {'message': {'text': 'Unused global message'}}
        if lookup == 'rule-index':
            result.pop('ruleId')
            result['ruleIndex'] = 0
        elif lookup == 'rule-guid':
            result.pop('ruleId')
            result['rule'] = {'guid': rule['guid']}
    return {'version': '2.1.0', 'properties': {'synthetic': True},
            'runs': [{'tool': tool, 'results': [result]}]}


def preview(client, raw, scope=SCOPE):
    response = client.post('/api/application-findings/preview', data=scope,
                           files={'file': ('synthetic-message.sarif', raw)})
    assert response.status_code == 200, response.json()
    return response.json()


def confirm(client, p, scope=SCOPE):
    response = client.post('/api/application-findings/confirm', json=scope | {'preview_id': p['id']})
    assert response.status_code == 200, response.json()
    return response.json()


def inspect(client, finding_id, scope=SCOPE):
    response = client.get('/api/application-findings/' + finding_id, params=scope)
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize('lookup', LOOKUPS)
@pytest.mark.parametrize('template,arguments,expected', [
    ('Value {0} reached {1}', ['user_input', 'eval'], 'Value user_input reached eval'),
    ('Literal {{0}}; value {0}', ['SAFE_MARKER'], 'Literal {0}; value SAFE_MARKER'),
    ('Repeat {0}/{0}; pair {{{1}}}; literal {{0}}; close }}; open {{',
     ['<script>alert(1)</script> {1}', 'SAFE_MARKER'],
     'Repeat <script>alert(1)</script> {1}/<script>alert(1)</script> {1}; '
     'pair {SAFE_MARKER}; literal {0}; close }; open {'),
], ids=['direct-arguments', 'escaped-braces', 'repeated-literal-arguments'])
def test_messages_through_preview_confirm_and_detail(service, lookup, template, arguments, expected):
    document = report(template, arguments, lookup)
    original = copy.deepcopy(document['runs'][0]['results'][0]['message'])
    raw = json.dumps(document, indent=2).encode()
    with TestClient(create_app(service), base_url='http://localhost') as client:
        p = preview(client, raw)
        assert p['findings'][0]['resolved_message'] == expected
        assert p['normalizer'] == 'sarif-normalizer-2'
        batch = confirm(client, p)
        detail = inspect(client, batch['finding_ids'][0])
        assert detail['finding']['resolved_message'] == expected
        assert detail['finding']['message'] == original
        assert detail['import']['normalizer'] == p['normalizer']
        assert detail['source']['sha256'] == digest(raw)
        assert client.get('/api/application-findings/sources/' + detail['source']['id'], params=SCOPE).content == raw
        rows = client.get('/api/application-findings', params=SCOPE).json()['findings']
        assert rows == [detail['finding']]
        assert confirm(client, preview(client, raw))['duplicate']
        assert service.store.all('application_finding') == rows
        assert inspect(client, rows[0]['id']) == detail


@pytest.mark.parametrize('lookup', ['text', 'rule-id'])
@pytest.mark.parametrize('template,arguments,expected,warning', [
    ('Escaped {{0}} and {{}}', [], 'Escaped {0} and {}', None),
    ('{0}', [''], '', None),
    ('{0}{0}', ['x' * 16384], 'x' * 32768, None),
    ('{0}x', ['x' * 32768], '{0}x', 'substitution exceeds limit'),
    ('{{0}}{0}{0}', ['x' * 16384], '{{0}}{0}{0}', 'substitution exceeds limit'),
    ('Unknown {9}; known {0}', ['safe'], 'Unknown {9}; known safe', 'no supplied argument'),
    ('{' + '9' * 16000 + '}', [], '{' + '9' * 16000 + '}', 'no supplied argument'),
    ('{0.__class__} {name} {0:>10} {0}', ['literal'],
     '{0.__class__} {name} {0:>10} literal', None),
], ids=['escaped-only', 'empty-argument', 'exact-limit', 'trailing-over-limit',
        'escaped-over-limit', 'missing-argument', 'long-index', 'unsupported-format'])
def test_message_bounds_and_literal_arguments(service, lookup, template, arguments, expected, warning):
    with TestClient(create_app(service), base_url='http://localhost') as client:
        p = preview(client, json.dumps(report(template, arguments, lookup)).encode())
        finding = p['findings'][0]
        assert finding['resolved_message'] == expected
        assert len(finding['resolved_message']) <= 32768
        if warning:
            assert any(warning in w for w in finding['warnings'])
        else:
            assert not any(w.startswith('Message ') or 'resolved message' in w for w in finding['warnings'])
        batch = confirm(client, p)
        saved = inspect(client, batch['finding_ids'][0])['finding']
        assert saved['resolved_message'] == expected
        assert saved['warnings'] == finding['warnings']


@pytest.mark.parametrize('version', [None, 'sarif-normalizer-1', 'unknown-normalizer'])
def test_confirmation_rejects_previews_from_another_normalizer(service, version):
    with TestClient(create_app(service), base_url='http://localhost') as client:
        p = preview(client, json.dumps(report('Value {0}', ['safe'])).encode())
        if version is None:
            p.pop('normalizer')  # Original v1 previews did not record their version.
        else:
            p['normalizer'] = version
        service.store.put('application_preview', p['id'], p)
        response = client.post('/api/application-findings/confirm', json=SCOPE | {'preview_id': p['id']})
        assert response.status_code == 422 and 'normalizer changed' in response.json()['detail']
        assert not service.store.all('application_batch')
        assert not service.store.all('application_finding')
        assert not service.store.history(SCOPE['customer_id'] + ':' + SCOPE['environment_id'])


def test_reimport_preserves_legacy_records_and_logical_identity(service):
    raw = json.dumps(report('Value {0}', ['corrected'])).encode()
    with TestClient(create_app(service), base_url='http://localhost') as client:
        p = preview(client, raw)
        # Seed a historical v1 import using the established persisted identity contract.
        batch_id = uid('app_batch', p['context'], digest(raw), p['operator_context'], 'sarif-normalizer-1')
        old = p['findings'][0] | {'id': uid('app_finding', batch_id, 0, 0), 'batch_id': batch_id,
                                'resolved_message': 'Value {0}', 'imported_at': '2026-01-01T00:00:00+00:00'}
        batch = {k: p[k] for k in ('context', 'operator_context', 'source_id', 'source_sha256', 'warnings', 'runs')}
        batch.update(id=batch_id, imported_at=old['imported_at'], normalizer='sarif-normalizer-1',
                     finding_ids=[old['id']], scan_completeness='unknown')
        source = {'id': p['source_id'], 'context': p['context'], 'sha256': digest(raw),
                  'reference': 'blob:' + digest(raw), 'byte_length': len(raw), 'recorded_at': old['imported_at']}
        historical = [('application_finding', old), ('application_batch', batch), ('application_source', source)]
        for kind, row in historical:
            service.store.put(kind, row['id'], row, immutable=True)
        previous = inspect(client, old['id'])
        governance_path = '/api/application-findings/' + old['id'] + '/governance'
        context = client.get(governance_path, params=SCOPE).json()['context']
        decision = client.post('/api/application-findings/' + old['id'] + '/review', json={
            'context': context, 'review': {'reviewer': 'Synthetic reviewer',
            'disposition': 'Applicable / remediation warranted', 'reason': 'Historical synthetic review'}})
        assert decision.status_code == 200
        review = copy.deepcopy(service.store.all('appsec_review'))
        imported = confirm(client, p)
        assert imported['id'] != batch_id and not imported['duplicate']
        current = inspect(client, imported['finding_ids'][0])
        assert current['finding']['logical_id'] == old['logical_id']
        assert current['finding']['resolved_message'] == 'Value corrected'
        assert current['source'] == previous['source']
        assert inspect(client, old['id']) == previous
        for kind, row in historical:
            with service.store.connect() as c:
                saved = c.execute('SELECT data FROM records WHERE kind=? AND id=?', (kind, row['id'])).fetchone()[0]
            assert saved == canonical(row)
        assert service.store.all('appsec_review') == review
        governance = client.get(governance_path, params=SCOPE).json()
        assert governance['disposition'] == 'Needs review' and governance['reviews'][0]['stale']
        assert not governance['verification']['can_close']
        assert confirm(client, preview(client, raw))['id'] == imported['id']
        assert len(service.store.all('application_finding')) == 2
        other = preview(client, raw, OTHER)
        assert other['batch_id'] != imported['id']
        assert other['findings'][0]['logical_id'] != old['logical_id']
        assert client.post('/api/application-findings/confirm', json=OTHER | {'preview_id': p['id']}).status_code == 404
        assert client.get('/api/application-findings/' + old['id'], params=OTHER).status_code == 404
        assert client.get('/api/application-findings/sources/' + source['id'], params=OTHER).status_code == 404
