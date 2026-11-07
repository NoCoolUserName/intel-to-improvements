import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from iti import appsec, attack_flow, brotli_demo as demo, vulnerabilities as vi
from iti.api import create_app
from iti.store import digest


def state(store):
    with store.connect() as db:
        return [tuple(r) for r in db.execute('SELECT * FROM records ORDER BY kind,id')]


def test_explicit_load_is_atomic_idempotent_and_scoped(service):
    before = state(service.store)
    assert service.store.maybe('working_case_demo', demo.VERSION) is None
    result = demo.load(service)
    assert set(before).issubset(set(state(service.store)))
    assert result['id'] == demo.VERSION and len(result['stops']) == 13
    assert result['checks']['attack_flow']['validation']['valid']
    assert len(result['relations']['asset_to_exposure']) == 6
    assert vi.workspace(service, 'fictional-bank', 'windows-ad')['items'] == []
    profile = service.store.get('customer', demo.CUSTOMER)
    profile['priorities'].append('Operator edit survives')
    service.store.put('customer', demo.CUSTOMER, profile)
    edited = state(service.store)
    assert demo.load(service) == result
    assert state(service.store) == edited


def test_distinct_asset_judgments_and_qualified_results(service):
    result = demo.load(service)
    rel = result['relations']
    decisions = {asset: service.store.get('vulnerability_decision', id)
                 for asset, id in rel['asset_to_decision'].items()}
    assert decisions['client-api']['response'] == vi.EXPEDITE
    assert decisions['research-fetcher']['response'] == vi.EXPEDITE
    assert decisions['advisor-package']['response'] == vi.EXPEDITE
    assert decisions['reporting-service']['response'] == vi.PRIORITIZE
    assert decisions['reporting-service']['asset']['applicability'] == 'confirmed affected'
    assert decisions['reporting-service']['asset']['reachability'] == 'not reachable'
    assert decisions['vendor-analytics-agent']['response'] == vi.INVESTIGATE
    assert decisions['patched-reference']['response'] == vi.NOT_APPLICABLE
    assert '24.22.1' in decisions['patched-reference']['asset']['observed_version']
    assert set(rel['asset_to_vulnerability_action']) == set(decisions) - {'patched-reference'}
    ctx = decisions['advisor-package']['context']
    advisor = vi.verification(service.store, ctx, decisions['advisor-package']['asset'])
    client = vi.verification(service.store, ctx, decisions['client-api']['asset'])
    assert advisor['tests'][-1]['result'] == 'failed'
    assert advisor['verified_at'] is None
    assert client['tests'][-1]['result'] == 'passed'
    assert client['verified_at'] is None  # authored replay never becomes operational remediation
    assert all(t['evidence'][0]['kind'] != 'live system' for t in advisor['tests'] + client['tests'])


def test_evidence_links_exports_pipeline_and_appsec_history(service):
    result = demo.load(service)
    rel = result['relations']
    source = service.store.get('source', rel['source_revision'])
    assert digest((demo.FIXTURES / 'dossier.md').read_bytes()) == source['content_hash']
    assert source['metadata']['retrieval']['representation'].startswith('Selected text')
    assert all(s.get('excerpt_sha256') == digest(s['excerpt'].encode()) for s in result['sources'] if 'excerpt' in s)
    assert not any(s['id'] == 'S9' and s.get('excerpt_sha256') for s in result['sources'])
    package = service.store.get('package', result['package_id'])
    assert len(package['hunts']) == len(package['emulations']) == 4
    assert all(h['query'] is None for h in package['hunts'])
    root = service.store.root / 'artifacts' / result['package_id']
    flow = json.loads((root / 'attack-flow.json').read_text())
    assert attack_flow.validate_bundle(flow)['valid']
    assert 'HYPOTHETICAL SYNTHETIC' in next(o for o in flow['objects'] if o['type'] == 'attack-flow')['description']
    assert len([o for o in flow['objects'] if o['type'] == 'attack-action']) == 4
    app_tests = rel['rule_to_appsec_tests']
    success = service.store.get('test', app_tests['demo/brotli-runtime-evidence'][-1])
    failure = service.store.get('test', app_tests['demo/self-contained-package'][-1])
    assert success['result'] == 'passed' and success['assurance'] == 'synthetic/lab evidence reviewed'
    assert failure['result'] == 'failed'
    finding = service.store.get('application_finding', rel['rule_to_finding']['demo/self-contained-package'])
    action = service.store.get('improvement', rel['rule_to_appsec_action']['demo/self-contained-package'])
    assert action['status'] == 'retest requested'  # revised green pipeline does not close the finding
    assert appsec.verification(service.store, finding, action)['status'] == 'Retest failed'
    assert service.store.all('appsec_exception_request') and service.store.all('appsec_exception_decision')
    executions = service.store.all('pipeline_execution')
    assert len(executions) == 2
    assert any(v['state'] == 'Reported skipped' for v in executions[0]['controls'].values())
    assert any(v['state'] == 'Reported successful' for v in executions[1]['controls'].values())
    assert result['checks']['operational_tests_executed'] is False


def test_exception_expires_as_of_injected_clock_without_fix(service, monkeypatch):
    result = demo.load(service)
    finding = service.store.get('application_finding', result['relations']['rule_to_finding']['demo/outbound-control-scope'])
    before = appsec.view(service.store, finding)
    assert before['exceptions'][0]['status'] == 'active operator-recorded acceptance; finding remains'
    review_by = before['exceptions'][0]['review_by']
    future = (appsec.dt(review_by) + timedelta(seconds=1)).isoformat()
    monkeypatch.setattr(appsec, 'now', lambda: future)
    after = appsec.view(service.store, finding)
    assert after['exceptions'][0]['status'] == 'expired'
    assert after['action'] is None


def test_missing_synthetic_attachment_invalidates_success(service):
    result = demo.load(service)
    rel = result['relations']
    rule = 'demo/brotli-runtime-evidence'
    finding = service.store.get('application_finding', rel['rule_to_finding'][rule])
    action = service.store.get('improvement', rel['rule_to_appsec_action'][rule])
    assert appsec.verification(service.store, finding, action)['status'].startswith('Evidence-reviewed successful retest')
    test = service.store.get('test', rel['rule_to_appsec_tests'][rule][-1])
    evidence = service.store.get('appsec_evidence', test['measurement']['evidence_ids'][0])
    (service.store.root / 'blobs' / evidence['sha256']).unlink()
    outcome = appsec.verification(service.store, finding, action)
    assert outcome['status'] == 'Stale evidence; renewed review/retest required'
    assert any('Supporting evidence missing' in reason for reason in outcome['history'][-1]['stale_reasons'])


def test_failed_stage_or_changed_curated_input_cannot_publish(service, monkeypatch, tmp_path):
    before = state(service.store)
    def fail(builder):
        builder.store.put('customer', demo.CUSTOMER, {'id': demo.CUSTOMER})
        raise ValueError('staged failure')
    original = demo.build
    monkeypatch.setattr(demo, 'build', fail)
    with pytest.raises(ValueError, match='staged failure'):
        demo.load(service)
    assert state(service.store) == before
    monkeypatch.setattr(demo, 'build', original)
    changed = tmp_path / 'changed'
    changed.mkdir()
    for name in demo.FILES:
        (changed / name).write_bytes((demo.FIXTURES / name).read_bytes())
    (changed / 'dossier.md').write_text((changed / 'dossier.md').read_text() + '\nChanged content.\n')
    monkeypatch.setattr(demo, 'FIXTURES', changed)
    with pytest.raises(ValueError, match='exact versioned dossier'):
        demo.load(service)
    assert state(service.store) == before


def test_api_origin_scope_and_downloads(service):
    client = TestClient(create_app(service), base_url='http://127.0.0.1')
    assert client.get('/api/demos/brotli').json() is None
    assert client.post('/api/demos/brotli', headers={'Origin': 'https://example.invalid'}).status_code == 403
    result = client.post('/api/demos/brotli').json()
    assert client.get('/api/demos/brotli').json() == result
    assert client.get('/api/demos/brotli/files/inventory.json').status_code == 200
    assert client.get('/api/demos/brotli/files/unknown').status_code == 404
    assert client.get('/api/demos/brotli/manifest.json').json()['relations'] == result['relations']
    assert 'Synthetic' in client.get('/api/demos/brotli/summary.md').text or 'synthetic' in client.get('/api/demos/brotli/summary.md').text
    assert client.get('/api/assessments/' + result['assessment_id'], params={'customer_id': 'fictional-bank', 'environment_id': 'windows-ad'}).status_code == 404
