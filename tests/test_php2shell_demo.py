import json
import pytest
from fastapi.testclient import TestClient
from iti import attack_flow, ledger, php2shell_demo as demo
from iti.api import create_app
from iti.store import canonical


def state(store):
    with store.connect() as connection:
        return [tuple(row) for row in connection.execute('SELECT * FROM records ORDER BY kind,id')]


def test_connected_case_preserves_existing_records_and_reopening_edits(service):
    before = state(service.store)
    result = demo.load(service)
    after = state(service.store)
    assert set(before).issubset(set(after))
    assert len(result['stops']) == 12
    assert result['checks']['d3fend_candidates'] > 0
    assert result['checks']['operational_tests_executed'] is False
    customer = service.store.get('customer', demo.CUSTOMER)
    assert customer['sector'] == 'financial-services' and 'Harborlight Capital' in customer['name']
    assert customer['allow_live_processing'] is False
    assessment = service.store.get('assessment', result['assessment_id'])
    coverage = ledger.view(service.store, assessment)
    assert coverage['metrics']['customer_first_receipt'] and len(coverage['rows']) == 4
    assert assessment['source']['gaps'] and assessment['relevance']['rank'] == 'High'
    assert len(assessment['extraction']['behaviors']) == 4
    assert all(b['kind'] == 'analyst_inference' for b in assessment['extraction']['behaviors'])
    package = service.store.get('package', result['package_id'])
    assert len(package['hunts']) == len(package['emulations']) == 4
    assert 'AttackIQ' in ' '.join(package['emulations'][0]['steps'])
    assert all('Windows' not in canonical(plan) for plan in package['emulations'])
    flow = json.loads((service.store.root / 'artifacts' / result['package_id'] / 'attack-flow.json').read_text())
    assert attack_flow.validate_bundle(flow)['valid']
    assert len([o for o in flow['objects'] if o['type'] == 'attack-action']) == 4
    assert 'HYPOTHETICAL' in next(o for o in flow['objects'] if o['type'] == 'attack-flow')['description']
    assert len(result['vulnerability_decisions']) == 2
    assert len(result['finding_ids']) == 4 and len(result['pipeline_snapshot_ids']) == 2
    assert len(service.store.all('pipeline_execution')) == 2
    states = [{v['state'] for v in e['controls'].values()} for e in service.store.all('pipeline_execution')]
    assert 'Reported failed' in states[0] and 'Reported skipped' in states[0]
    assert 'Reported successful' in states[1] and 'Reported skipped' in states[1]
    assert service.store.all('appsec_exception_request') and service.store.all('appsec_exception_decision')
    assert all(e['kind'] == 'synthetic fixture replay' for t in service.store.all('test') for e in t['evidence'])
    assert all(t['method'] not in ('observed prevention', 'observed SIEM alert') for t in service.store.all('test'))
    customer['priorities'].append('Operator edit must survive')
    service.store.put('customer', demo.CUSTOMER, customer)
    snapshot = state(service.store)
    assert demo.load(service) == result
    assert state(service.store) == snapshot


def test_failed_staging_and_reserved_customer_never_replace_user_work(service, monkeypatch):
    before = state(service.store)
    def fail(builder):
        builder.store.put('customer', demo.CUSTOMER, {'id': demo.CUSTOMER})
        raise ValueError('authored staging failure')
    monkeypatch.setattr(demo, 'build', fail)
    with pytest.raises(ValueError, match='staging failure'):
        demo.load(service)
    assert state(service.store) == before
    service.store.put('customer', demo.CUSTOMER, {'id': demo.CUSTOMER, 'name': 'Operator-owned profile'})
    with pytest.raises(ValueError, match='refusing to overwrite'):
        demo.load(service)
    assert service.store.get('customer', demo.CUSTOMER)['name'] == 'Operator-owned profile'


def test_scenario_export_is_explicit_and_api_keeps_scope_origin_and_file_limits(service):
    client = TestClient(create_app(service), base_url='http://127.0.0.1')
    assert client.get('/api/demos/php2shell').json() is None
    assert client.post('/api/demos/php2shell', headers={'Origin': 'https://example.invalid'}).status_code == 403
    result = client.post('/api/demos/php2shell').json()
    assert client.get('/api/demos/php2shell').json() == result
    assert client.get('/api/demos/php2shell/files/dossier.md').status_code == 200
    assert client.get('/api/demos/php2shell/files/unknown.txt').status_code == 404
    package = service.store.get('package', result['package_id'])
    package['source']['metadata'].pop('synthetic_scenario')
    _, _, status = attack_flow.export(service.store, package)
    assert status['status'] == 'empty'  # ordinary inferences still cannot masquerade as reported actions
    assert client.get('/api/pipeline-assurance/' + result['pipeline_snapshot_ids'][0],
        params={'customer_id': 'fictional-bank', 'environment_id': 'windows-ad'}).status_code == 404
