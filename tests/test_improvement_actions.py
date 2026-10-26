import json
import pytest
from fastapi.testclient import TestClient
from iti.api import create_app
from iti import improvement_actions, php2shell_demo
from iti.models import ImprovementAction
from iti import ledger


def frozen_records(store):
    with store.connect() as c:
        return [tuple(r) for r in c.execute('SELECT * FROM records ORDER BY kind,id')], c.execute('SELECT count(*) FROM activity').fetchone()[0]


def test_projection_reuses_all_three_origins_without_writes(service):
    demo = php2shell_demo.load(service)
    before = frozen_records(service.store)
    client = TestClient(create_app(service), base_url='http://127.0.0.1')
    params = {'customer_id': demo['customer_id'], 'environment_id': demo['environment_id']}
    result = client.get('/api/improvements', params=params)
    assert result.status_code == 200
    rows = result.json()['rows']
    assert len(rows) == 9 and {r['origin_kind'] for r in rows} == {'AppSec', 'Vulnerability', 'Intelligence case'}
    for row in rows:
        assert row['customer_id'] == demo['customer_id'] and row['environment_id'] == demo['environment_id']
        detail = client.get('/api/improvements/' + row['id'], params=params).json()
        assert detail['action'] == service.store.get('improvement', row['id'])
        assert detail['reference']['action_id'] == row['id']
        if row['origin_kind'] == 'Vulnerability':
            assert row['outcome'] == 'attestation / synthetic or lab evidence only'
        elif row['origin_kind'] == 'Intelligence case':
            assert row['outcome'] == 'No action-linked retest recorded'  # unlinked behavior tests are not action verification
        else:
            assert row['outcome'] == 'No retest evidence'
    assert frozen_records(service.store) == before


def test_scope_and_missing_origins_never_leak_another_case(service, assessed):
    action = ledger.improve(service.store, assessed, ImprovementAction(behavior_id=assessed['extraction']['behaviors'][0]['id'],
        owner='Synthetic case owner', priority='high', rationale='Authored gap', proposed_change='Review control settings', retest='Review actual evidence'))
    client = TestClient(create_app(service), base_url='http://localhost')
    other = {'customer_id': 'fictional-cloud', 'environment_id': 'mac-cloud'}
    assert client.get('/api/improvements', params=other).json()['rows'] == []
    assert client.get('/api/improvements/' + action['id'], params=other).status_code == 404
    assert client.get('/api/improvements', params={'customer_id': 'fictional-cloud', 'environment_id': 'windows-ad'}).status_code == 422
    # A scoped action with a broken or foreign reference remains inspectable without opening the foreign record.
    copy = action | {'id': 'orphan', 'context': {
        'customer_id': 'fictional-cloud', 'environment_id': 'mac-cloud', 'customer_version': 1, 'environment_version': 1}}
    service.store.put('improvement', copy['id'], copy)
    projected = client.get('/api/improvements/orphan', params=other).json()
    assert projected['reference'] is None and projected['source'] is None
    assert assessed['source']['title'] not in json.dumps(projected)
    assert projected['action']['id'] == 'orphan'


def test_bounded_list_fails_closed_instead_of_truncating(service, assessed, monkeypatch):
    ledger.improve(service.store, assessed, ImprovementAction(behavior_id=assessed['extraction']['behaviors'][0]['id'],
        owner='Synthetic owner', priority='medium', rationale='Fixture rationale', proposed_change='Fixture change', retest='Fixture retest'))
    monkeypatch.setattr(improvement_actions, 'LIMIT', 0)
    with pytest.raises(ValueError, match='not truncated'):
        improvement_actions.workspace(service.store, 'fictional-bank', 'windows-ad')
