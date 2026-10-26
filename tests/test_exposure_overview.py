import copy
import json
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from iti.api import create_app
from iti import exposure_overview as eo, exposure_demo, appsec, profiles, vulnerabilities as vi
from iti.models import CustomerProfile, EnvironmentProfile
from iti.store import now
from test_appsec import Workflow



def metrics(data): return {m['id']:m['value'] for m in data['metrics']}
def show(service,c='fictional-bank',e='windows-ad'): return eo.overview(service.store,c,e)


def test_demo_reconciles_readonly_idempotent_and_qualified(service):
    scope=exposure_demo.load(service)
    with service.store.connect() as c:
        before=[tuple(r) for r in c.execute('SELECT * FROM records ORDER BY kind,id')]
        activity=c.execute('SELECT count(*) FROM activity').fetchone()[0]
    d=show(service,scope['customer_id'],scope['environment_id']);m=metrics(d)
    assert d['raw_appsec_occurrences']==11 and m['appsec']==10
    assert m['affected']==1 and m['potential']==1 and m['mentions']==1
    assert m['unreviewed']==2 and m['applicable']==8
    assert m['work']==5 and m['overdue']==5 and m['fix']==3
    assert m['verification:Synthetic AppSec evidence reviewed']==1
    assert m['verification:Operational infrastructure remediation']==0
    assert m['verification:Retest failed']==1 and m['verification:Retest inconclusive']==1
    assert m['verification:Stale evidence']==1
    for status in ['active operator-recorded acceptance; finding remains','expired','unapproved request']:
        assert m['exception:'+status]==1
    ids={r['id'] for r in d['rows']}
    for metric in d['metrics']:
        assert metric['value']==len(set(metric['record_ids']))
        assert set(metric['record_ids'])<=ids
        assert metric['population_count']==len([r for r in d['rows'] if r['entity']==metric['population']])
        assert metric['definition'] and metric['exclusions']
    assert d['timing'][0]['sample_count']==1
    assert d['timing'][2]['median_seconds'] is None
    with service.store.connect() as c:
        assert before==[tuple(r) for r in c.execute('SELECT * FROM records ORDER BY kind,id')]
        assert activity==c.execute('SELECT count(*) FROM activity').fetchone()[0]
    assert exposure_demo.load(service)==scope
    assert not show(service)['rows']


@pytest.mark.parametrize('disposition',[appsec.APPLICABLE,appsec.DUPLICATE,'Not applicable','False positive (reviewed determination)','Needs further investigation'])
def test_triage_identity_and_exclusions(service,disposition):
    f=Workflow(service)
    f.review(disposition=disposition,**({'duplicate_of':f.other['id']} if disposition==appsec.DUPLICATE else {}))
    d=show(service);r=next(r for r in d['rows'] if r['reference'].get('finding_id')==f.f['id'])
    assert r['status']==disposition
    assert r['outstanding']==(disposition in (appsec.APPLICABLE,'Needs further investigation'))
    f.newer();d=show(service)
    assert metrics(d)['appsec']==2 and metrics(d)['unreviewed']==2


@pytest.mark.parametrize('result,method,expected',[
    ('passed','version/configuration evidence','Synthetic AppSec evidence reviewed'),
    ('failed','version/configuration evidence','Retest failed'),
    ('inconclusive','version/configuration evidence','Retest inconclusive'),
    ('passed','analyst attestation','Attestation only')])
def test_current_retest_classes(service,result,method,expected):
    f=Workflow(service);f.ready();f.retest(result=result,method=method)
    assert metrics(show(service))['verification:'+expected]==1
    assert show(service)['timing'][0]['sample_count']==0 # not closed
    if result=='passed' and method!='analyst attestation':
        f.action(status='closed');assert metrics(show(service))['work']==0
        f.retest(result='failed');assert metrics(show(service))['work']==1
        assert metrics(show(service))['verification:Retest failed']==1
        assert show(service)['timing'][0]['median_seconds'] is None


def test_missing_evidence_and_changed_implementation_invalidate(service):
    f=Workflow(service);f.ready();f.retest();f.action(status='closed')
    evidence=f.store.all('appsec_evidence')[0]
    (f.store.root/'blobs'/evidence['sha256']).unlink()
    d=show(service)
    assert metrics(d)['verification:Stale evidence']==1 and metrics(d)['work']==1
    assert d['timing'][0]['median_seconds'] is None


@pytest.mark.parametrize('delta,expected',[(0,0),(-1,1),(1,0),(None,None)])
def test_recorded_targets_utc_boundary(service,monkeypatch,delta,expected):
    f=Workflow(service);f.review();a=f.action()
    fixed='2026-10-26T00:00:00+00:00';monkeypatch.setattr(eo,'now',lambda:fixed)
    plan=a['remediation']|{'target_date':(appsec.dt(fixed)+timedelta(days=delta)).date().isoformat() if delta is not None else None}
    f.action(remediation=plan)
    row=next(r for r in show(service)['rows'] if r['entity']=='action')
    assert row['overdue_days']==expected


@pytest.mark.parametrize('value,expected',[(None,'Unknown'),(0,'0–7 days'),(7,'0–7 days'),(8,'8–30 days'),(30,'8–30 days'),(31,'31–60 days'),(60,'31–60 days'),(61,'61–90 days'),(90,'61–90 days'),(91,'Over 90 days')])
def test_age_bands(value,expected): assert eo.band(value)==expected


def test_missing_future_and_timezone_clocks():
    assert eo.days(None,now()) is None
    assert eo.days('not a date',now()) is None
    assert eo.days('2026-10-26T01:00:00+02:00','2026-10-26T00:00:00Z')==0
    assert eo.days('2027-01-01T00:00:00Z','2026-01-01T00:00:00Z') is None
    assert eo.days('2026-01-01','2026-01-02T00:00:00Z') is None


def test_scope_limits_api_and_host_controls(service,monkeypatch):
    Workflow(service)
    c=CustomerProfile(id='same-customer',name='Fictional second customer',sector='technology',environments=[EnvironmentProfile(id='a',name='A',platforms=['linux']),EnvironmentProfile(id='b',name='B',platforms=['linux'])])
    profiles.save(service.store,c)
    with TestClient(create_app(service),base_url='http://localhost') as client:
        assert not client.get('/api/exposure-overview',params={'customer_id':c.id,'environment_id':'a'}).json()['rows']
        assert client.get('/api/exposure-overview',params={'customer_id':c.id,'environment_id':'windows-ad'}).status_code==422
        assert client.get('/api/exposure-overview',params={'customer_id':'absent','environment_id':'a'}).status_code==404
        assert client.get('/api/exposure-overview?customer_id=fictional-bank&environment_id=windows-ad',headers={'Origin':'https://evil.example'}).status_code==403
        monkeypatch.setattr(eo,'LIMIT',1)
        r=client.get('/api/exposure-overview?customer_id=fictional-bank&environment_id=windows-ad')
        assert r.status_code==422 and 'not truncated' in r.json()['detail']


@pytest.mark.parametrize('decision',['approved','rejected','revoked'])
def test_exception_latest_decision_expiry_and_profile_change(service,monkeypatch,decision):
    f=Workflow(service);f.review();ctx=profiles.context(f.store,'fictional-bank','windows-ad').model_dump()
    end=appsec.dt(now())+timedelta(days=1)
    req=appsec.request_exception(f.store,f.f,ctx,{'requester':'Requester','justification':'Authored justification','residual_risk':'Remains unresolved','review_by':end.isoformat()})
    appsec.decide_exception(f.store,f.f,ctx,req['id'],{'authority':'Authority','decision':decision,'reason':'Recorded decision'})
    d=show(service);expected='active operator-recorded acceptance; finding remains' if decision=='approved' else decision
    assert metrics(d)['exception:'+expected]==1
    assert metrics(d)['outstanding']==2
    monkeypatch.setattr(eo,'now',lambda:end.isoformat())
    assert metrics(show(service))['exception:expired']==1
    monkeypatch.setattr(eo,'now',now)
    profiles.save(f.store,CustomerProfile.model_validate(f.store.get('customer','fictional-bank')))
    assert metrics(show(service))['exception:stale; renewed decision required']==1


def test_infrastructure_revisions_distinct_assets_and_operational_qualification(service):
    ctx=profiles.context(service.store,'fictional-bank','windows-ad').model_dump()
    value={'asset_id':'asset-a','product':'Authored product','observed_version':'1','cve':'CVE-2025-12345','finding_id':'one','owner':'Asset team','observed_at':now(),'evidence_reference':'authored:test','applicability':'confirmed affected','applicability_reason':'Authored test condition only','evidence_kind':'analyst assessment'}
    first=vi.observe(service.store,ctx,value)
    second=vi.observe(service.store,ctx,value|{'finding_id':'two'})
    vi.observe(service.store,ctx,value|{'asset_id':'asset-b','applicability':'needs verification'})
    assert first['logical_id']==second['logical_id']
    assert metrics(show(service))['affected']==1 and metrics(show(service))['potential']==1
    d=vi.workspace(service,'fictional-bank','windows-ad')['items'][0]['decisions'][0]
    vi.review(service.store,d['id'],'fictional-bank','windows-ad',{'reason':'Authored scope review','reviewer':'Reviewer'})
    from iti.models import ImprovementAction
    from iti import ledger
    a=ledger.improve(service.store,vi.subject(service.store,d['id'],'fictional-bank','windows-ad'),ImprovementAction(vulnerability_assessment_id=d['id'],owner='Owner',priority='medium',rationale='Authored rationale',proposed_change='Authored fix',retest='Authored retest',remediation={'review_date':'2026-01-01','residual_uncertainty':'Unknown','permanent_fix':'Authored fix','source_references':'authored:test'}))
    infra_test(service,d,a)
    result=show(service)
    assert metrics(result)['verification:Operational infrastructure remediation']==1
    assert result['timing'][2]['sample_count']==1
    assert next(r for r in result['rows'] if r['entity']=='action')['target_date'] is None
    evidence=service.store.all('vulnerability_evidence')[0]
    path=service.store.root/'blobs'/evidence['sha256'];raw=path.read_bytes();path.unlink()
    assert metrics(show(service))['verification:Stale evidence']==1
    assert show(service)['timing'][2]['median_seconds'] is None
    path.write_bytes(raw)
    infra_test(service,d,a,result='failed')
    assert metrics(show(service))['verification:Retest failed']==1
    assert show(service)['timing'][2]['median_seconds'] is None
    changed=copy.deepcopy(a);changed['proposed_change']='Changed implementation';service.store.put('improvement',a['id'],changed)
    assert metrics(show(service))['verification:Stale evidence']==1


def infra_test(service,d,action,result='passed'):
    from iti.models import TestRun as Verification
    from iti import ledger
    evidence=vi.capture_evidence(service.store,d['context'],'authored.txt',b'Authored validation fixture, not operational evidence','live system')
    test=Verification(vulnerability_assessment_id=d['id'],environment_version=d['context']['environment_version'],control_id='Authored scanner',control_version='1',procedure='Authored procedure',expected='Authored fixed version',actual='Authored result',executed_at=now(),method='reliable rescan',result=result,dimension='remediation',scope=d['asset']['asset_id'],variant='Authored version evidence',improvement_id=action['id'],measurement={'asset_id':d['asset']['asset_id'],'observed_value':'Authored fixed version','acceptance_basis':'Authored criteria'},evidence=[{'id':evidence['id'],'reference':evidence['reference'],'sha256':evidence['sha256'],'description':'Authored test only','kind':'live system'}])
    return ledger.record_test(service.store,vi.subject(service.store,d['id'],d['context']['customer_id'],d['context']['environment_id']),test)


def test_same_customer_environments_stay_distinct(service):
    from iti import application_findings as af
    c=CustomerProfile.model_validate(service.store.get('customer','fictional-bank'))
    c.environments.append(EnvironmentProfile(id='second',name='Second lab',platforms=['linux']))
    profiles.save(service.store,c)
    flow=Workflow(service)
    p=af.preview(service.store,'fictional-bank','second',flow.raw,{'application':'Synthetic app','repository':'synthetic/repo'})
    af.confirm(service.store,p['id'],'fictional-bank','second')
    a,b=show(service),show(service,e='second')
    assert metrics(a)['appsec']==metrics(b)['appsec']==2
    assert not {r['id'] for r in a['rows']} & {r['id'] for r in b['rows']}


def test_attachment_budget_fails_explicitly(service,monkeypatch):
    f=Workflow(service);f.ready();f.retest()
    monkeypatch.setattr(eo,'EVIDENCE_LIMIT',1)
    with pytest.raises(ValueError,match='not truncated'):show(service)


def test_expired_retest_and_missing_action_clock(service,monkeypatch):
    f=Workflow(service);f.ready();f.retest();f.action(status='closed')
    monkeypatch.setattr(eo,'now',lambda:(appsec.dt(now())+timedelta(days=31)).isoformat())
    assert metrics(show(service))['verification:Stale evidence']==1
    a=f.store.all('improvement')[0];a['opened_at']=None;f.store.put('improvement',a['id'],a)
    assert metrics(show(service))['age:Unknown']==1


def test_orphan_action_visible_without_verification(service):
    f=Workflow(service);f.ready()
    with f.store.connect() as c:c.execute("DELETE FROM records WHERE kind='application_finding'")
    d=show(service)
    assert metrics(d)['work']==1
    assert d['rows'][0]['verification']=='Unknown; origin unavailable'
