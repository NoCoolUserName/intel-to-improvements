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


def test_priority_summary_preserves_reviewed_override_and_missing_severity():
    from iti.portfolio import priority_rows
    decision = dict(id='d1', series_id='series', context={'customer_id':'a','environment_id':'e'}, cve='CVE-2026-0001',
                    response='Expedite remediation/mitigation', reason_codes=[{'explanation':'Affected and reachable'}],
                    credible_exploitation=True, asset={'asset_id':'app','logical_id':'asset','evidence_kind':'synthetic fixture'},
                    verification={'status':'not tested'}, created_at='2026-11-08T00:00:00Z')
    review = dict(decision_id='d1', response='Investigate applicability/exposure', reason='Confirm deployed artifact first')
    row = priority_rows([decision], [review])[0]
    assert row['response'] == review['response'] and row['proposed_response'] == decision['response']
    assert row['reviewed'] and row['rationale'] == review['reason']
    assert row['severity'] == 'Severity not available' and row['validation'] == 'not tested'
    assert row['synthetic']
    newer = decision | {'id':'d2'}
    row = priority_rows([decision,newer], [review])[0]
    assert row['id'] == 'd2' and not row['reviewed']


def test_dashboard_validation_is_readonly_and_does_not_invent_execution(service):
    from iti import exposure_demo
    exposure_demo.load(service)
    with service.store.connect() as c:
        before = [tuple(r) for r in c.execute('SELECT * FROM records ORDER BY kind,id')]
        activity = c.execute('SELECT count(*) FROM activity').fetchone()[0]
    result = dashboard(service.store)
    assert result['priorities'] == []  # Reading the dashboard must not generate decisions.
    assert any(r['outcome'] == 'No recorded validation' and not r['recorded'] for r in result['validation'])
    assert any(r['outcome'] == 'Retest failed' and r['synthetic'] for r in result['validation'])
    assert all(r['outcome'] for r in result['validation'])
    with service.store.connect() as c:
        assert before == [tuple(r) for r in c.execute('SELECT * FROM records ORDER BY kind,id')]
        assert activity == c.execute('SELECT count(*) FROM activity').fetchone()[0]
