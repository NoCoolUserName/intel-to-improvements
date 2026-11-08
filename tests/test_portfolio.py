import copy
from fastapi.testclient import TestClient
from iti.api import create_app
from iti.portfolio import dashboard


def test_dashboard_groups_revisions_and_includes_every_customer(service):
    customers = service.store.all('customer')
    first, second = customers[:2]
    for customer in (first, second):
        service.submit(customer['id'], customer['environments'][0]['id'], 'offline', 'case', 'no-ioc', background=False)
    assessment = service.store.all('assessment')[0]
    newer = copy.deepcopy(assessment)
    newer.update(id='newer-assessment', created_at='2099-01-01T00:00:00+00:00')
    service.store.put('assessment', newer['id'], newer)
    ctx = assessment['context']
    action = dict(id='case-action', context=ctx, scope=':'.join((ctx['customer_id'], ctx['environment_id'], assessment['source']['id'])), status='retest requested', owner='Unassigned')
    service.store.put('improvement', action['id'], action)
    before = service.store.all('assessment')
    result = dashboard(service.store)
    assert len(result['cases']) == 2
    assert result['revision_count'] == 3
    assert result['cases'][0]['id'] == 'newer-assessment'
    assert result['cases'][0]['open_actions'] == 1
    assert {s['customer_id'] for s in result['scopes']} == {c['id'] for c in customers}
    scope = next(s for s in result['scopes'] if (s['customer_id'], s['environment_id']) == (ctx['customer_id'], ctx['environment_id']))
    assert scope['open_actions'] == scope['unassigned_actions'] == scope['retest_actions'] == 1
    assert service.store.all('assessment') == before
    client = TestClient(create_app(service), base_url='http://localhost')
    response = client.get('/api/exposure-overview/portfolio')
    assert response.status_code == 200
    assert len(response.json()['cases']) == 2
