import json
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from iti import application_findings as af, appsec, profiles
from iti.api import create_app
from iti.models import CustomerProfile
from iti.store import ROOT, now, digest

C='fictional-bank'; E='windows-ad'


class Workflow:
    def __init__(self, service):
        self.store=service.store
        self.client=TestClient(create_app(service),base_url='http://localhost')
        self.raw=(ROOT/'fixtures/application-findings/codeql.sarif.json').read_bytes()
        p=af.preview(self.store,C,E,self.raw,{'application':'Synthetic app','repository':'synthetic/repo'})
        af.confirm(self.store,p['id'],C,E)
        self.f=p['findings'][0];self.other=p['findings'][1]
        self.query={'customer_id':C,'environment_id':E}
    def get(self):
        r=self.client.get('/api/application-findings/'+self.f['id']+'/governance',params=self.query)
        assert r.status_code==200,r.text
        return r.json()
    def post(self,path,body,code=200,ctx=None):
        r=self.client.post('/api/application-findings/'+self.f['id']+path,json={'context':ctx or self.get()['context'],**body})
        assert r.status_code==code,r.text
        return r.json()
    def review(self,**changes):
        return self.post('/review',{'review':{'reviewer':'Security reviewer','disposition':appsec.APPLICABLE,'reason':'Reviewed synthetic source and applicability','evidence_ids':[self.f['source_id']],**changes}})
    def action(self,code=200,**changes):
        g=self.get();old=g['action']
        value={'owner':'Engineering team','priority':'medium','rationale':'Correct reviewed finding','proposed_change':'Apply the reviewed change','retest':'Inspect version and relevant behavior','remediation':{'security_reviewer':'Security reviewer','expected_result':'Finding cause removed','implementation_ref':'fix-commit-1','implementation_claim':'Developer reports the fix'},'status':'open'}
        if old:value.update({k:old[k] for k in value});value['id']=old['id']
        value.update(changes)
        return self.post('/action',{'review_id':g['reviews'][-1]['id'],'actor':'Engineering owner','reason':'Recorded implementation change or reopening','expected_updated_at':old['updated_at'] if old else None,'action':value},code)
    def evidence(self,kind='synthetic/lab evidence',name='test.txt',raw=b'Synthetic technical evidence',code=200):
        r=self.client.post('/api/application-findings/'+self.f['id']+'/attachments',data={'context':json.dumps(self.get()['context']),'kind':kind,'description':'Authored evidence only'},files={'file':(name,raw)})
        assert r.status_code==code,r.text
        return r.json()
    def retest(self,code=200,**changes):
        g=self.get();e=self.evidence()
        value={'action_id':g['action']['id'],'review_id':g['reviews'][-1]['id'],'implementation_ref':'fix-commit-1','finding_context_hash':g['dependencies']['finding_context_hash'],'reviewer':'Evidence reviewer','judgment':'Reviewed supplied evidence, synthetic only','procedure':'Inspect authored result and benign control','expected':'Authored fix present','actual':'Authored fix observed','executed_at':now(),'result':'passed','method':'version/configuration evidence','evidence_ids':[e['id']],**changes}
        return self.post('/retest',{'retest':value},code)
    def ready(self):
        self.review();self.action();self.action(status='retest requested')
    def newer(self):
        doc=json.loads(self.raw);doc['runs'][0]['results'][0]['message']['text']='New contradictory reported evidence'
        p=af.preview(self.store,C,E,json.dumps(doc).encode(),{'application':'Synthetic app','repository':'synthetic/repo'})
        af.confirm(self.store,p['id'],C,E)
        assert p['findings'][0]['logical_id']==self.f['logical_id']
        return p['findings'][0]


@pytest.fixture
def flow(service):return Workflow(service)


def test_triage_default_explicit_idempotence_history(flow):
    assert flow.get()['disposition']=='Needs review'
    review=flow.review()
    assert flow.get()['disposition']==appsec.APPLICABLE
    assert flow.review()['id']==review['id']
    p=af.preview(flow.store,C,E,flow.raw,{'application':'Synthetic app','repository':'synthetic/repo'});af.confirm(flow.store,p['id'],C,E)
    assert len(flow.get()['reviews'])==1
    flow.review(disposition='Needs further investigation')
    assert flow.get()['reviews'][-1]['previous_disposition']==appsec.APPLICABLE
    flow.post('/review',{'review':{'reviewer':'Reviewer','disposition':'Not applicable','reason':'  '}},422)
    assert len(flow.get()['reviews'])==2


def test_duplicate_links_reject_self_cycles_and_cross_scope(flow):
    flow.review(disposition=appsec.DUPLICATE,duplicate_of=flow.other['id'])
    original=flow.f;flow.f=flow.other
    flow.post('/review',{'review':{'reviewer':'Reviewer','disposition':appsec.DUPLICATE,'reason':'Explicit duplicate','duplicate_of':original['id']}},422)
    flow.post('/review',{'review':{'reviewer':'Reviewer','disposition':appsec.DUPLICATE,'reason':'Explicit duplicate','duplicate_of':flow.f['id']}},422)
    p=af.preview(flow.store,'fictional-cloud','mac-cloud',flow.raw,{})
    af.confirm(flow.store,p['id'],'fictional-cloud','mac-cloud')
    flow.post('/review',{'review':{'reviewer':'Reviewer','disposition':appsec.DUPLICATE,'reason':'Explicit duplicate','duplicate_of':p['findings'][0]['id']}},404)


def test_action_ledger_origin_history_and_forgery(flow):
    flow.review();action=flow.action()
    assert flow.store.get('improvement',action['id'])==action
    assert action['behavior_id'] is None and action['vulnerability_assessment_id'] is None
    assert action['origin']['finding_id']==flow.f['id'] and action['origin']['source_sha256']==flow.f['source_sha256']
    flow.action(code=422,origin={'kind':'application_finding','finding_id':'forged'})
    flow.action(code=422,owner='')
    flow.action(code=422,proposed_change=' ')
    flow.action(code=422,retest='')
    flow.action(code=422,id='foreign-action')
    updated=flow.action(status='retest requested')
    assert updated['origin']==action['origin']
    assert flow.get()['verification']['can_close'] is False
    flow.action(code=422,status='closed')
    assert len([r for r in flow.get()['history'] if r['kind'].startswith('improvement_')])==2
    stale={'review_id':flow.get()['reviews'][-1]['id'],'actor':'Owner','reason':'Outdated edit','expected_updated_at':action['updated_at'],'action':{'id':action['id'],'owner':'Owner','priority':'low','rationale':'Reason','proposed_change':'Change','retest':'Retest','remediation':action['remediation']}}
    flow.post('/action',stale,422)


def test_concurrent_action_creation_is_idempotent(flow):
    review=flow.review();ctx=flow.get()['context']
    body={'review_id':review['id'],'actor':'Owner','reason':'Create bounded action','action':{'owner':'Owner','priority':'medium','rationale':'Reason','proposed_change':'Change','retest':'Retest','remediation':{'security_reviewer':'Security','expected_result':'Fixed cause'}}}
    with ThreadPoolExecutor(max_workers=4) as pool:
        result=list(pool.map(lambda _:flow.post('/action',body,ctx=ctx),range(4)))
    assert len({r['id'] for r in result})==1
    assert len(flow.store.all('improvement'))==1


@pytest.mark.parametrize('result,method,expected', [('failed','version/configuration evidence','Retest failed'),('inconclusive','version/configuration evidence','Retest inconclusive'),('passed','analyst attestation','Fix attested; verification pending')])
def test_outcomes_never_imply_independent_verification(flow,result,method,expected):
    flow.ready();flow.retest(result=result,method=method)
    g=flow.get();assert g['verification']['status']==expected
    assert not g['verification']['independent_operational_verification']
    flow.action(code=422,status='closed')


def test_successful_review_close_failed_retest_and_explicit_reopen(flow):
    flow.ready();flow.retest()
    assert flow.get()['verification']['can_close']
    flow.action(status='closed')
    assert flow.get()['lifecycle']=='Closed with reviewed supporting evidence'
    flow.retest(result='failed')
    assert flow.get()['lifecycle']=='Reopen/review required; prior closure is historical'
    assert len(flow.get()['verification']['history'])==2
    flow.action(status='open')
    assert flow.get()['lifecycle']=='Reopened'
    assert not flow.get()['verification']['can_close']


def test_new_finding_stales_review_and_closed_outcome(flow):
    flow.ready();flow.retest();action=flow.action(status='closed');old=flow.f
    new=flow.newer()
    assert flow.get()['disposition']=='Needs review'
    assert flow.get()['reviews'][0]['stale']
    assert not flow.get()['verification']['can_close']
    flow.post('/review',{'review':{'reviewer':'Reviewer','reason':'Old input','disposition':appsec.APPLICABLE}},422)
    flow.f=new;flow.review();reopened=flow.action(status='open')
    assert reopened['origin']==action['origin'] and reopened['origin']['finding_id']==old['id']


def test_changed_profile_and_implementation_stale_evidence(flow):
    flow.ready();flow.retest();ctx=flow.get()['context']
    changed=flow.action(proposed_change='Different implementation')
    assert not flow.get()['verification']['can_close']
    flow.retest();assert flow.get()['verification']['can_close']
    customer=CustomerProfile.model_validate(flow.store.get('customer',C));profiles.save(flow.store,customer)
    assert flow.get()['disposition']=='Needs review'
    assert not flow.get()['verification']['can_close']
    flow.post('/review',{'review':{'reviewer':'Reviewer','reason':'Stale context','disposition':appsec.APPLICABLE}},422,ctx=ctx)
    assert changed['origin']==flow.get()['action']['origin']


def test_missing_forged_cross_finding_and_old_evidence(flow,monkeypatch):
    flow.ready()
    flow.retest(code=422,evidence_ids=[])
    flow.retest(code=404,evidence_ids=['forged'])
    flow.retest(code=422,implementation_ref='different-commit')
    flow.retest(code=422,finding_context_hash='forged-context')
    original=flow.f;flow.f=flow.other;e=flow.evidence();flow.f=original
    flow.retest(code=422,evidence_ids=[e['id']])
    flow.retest(executed_at=(appsec.dt(now())-timedelta(days=31)).isoformat())
    assert not flow.get()['verification']['can_close']
    flow.action(code=422,status='closed')
    flow.retest()
    flow.retest(code=422,executed_at=(appsec.dt(now())-timedelta(days=2)).isoformat())


def test_sarif_absence_incomplete_and_context_mismatch(flow):
    flow.ready()
    doc=json.loads(flow.raw);doc['runs'][0]['results']=[];doc['runs'][0]['invocations']=[{'executionSuccessful':False}]
    p=af.preview(flow.store,C,E,json.dumps(doc).encode(),{'application':'Synthetic app','repository':'synthetic/repo'})
    af.confirm(flow.store,p['id'],C,E)
    flow.retest(code=422,method='reliable rescan',basis='SARIF absence',sarif_batch_id=p['batch_id'])
    flow.retest(method='reliable rescan',basis='SARIF absence',result='inconclusive',sarif_batch_id=p['batch_id'])
    assert flow.get()['verification']['status']=='Retest inconclusive'
    p=af.preview(flow.store,C,E,json.dumps(doc).encode(),{'repository':'different/repo'});af.confirm(flow.store,p['id'],C,E)
    flow.retest(code=422,method='reliable rescan',result='inconclusive',sarif_batch_id=p['batch_id'])
    flow.retest(code=422,method='reliable rescan')
    flow.retest(code=422,method='targeted human-led test')


def test_exceptions_separate_decisions_expiry_and_no_mutations(flow,monkeypatch):
    source=flow.store.get('application_finding',flow.f['id'])
    future=(appsec.dt(now())+timedelta(days=7)).isoformat()
    request={'requester':'Engineering requester','justification':'Bounded business need','residual_risk':'Reported issue remains','compensating_controls':'Claimed test-only control','review_by':future,'evidence_ids':[flow.f['source_id']]}
    r=flow.post('/exceptions',{'request':request})
    assert flow.get()['exceptions'][0]['status']=='unapproved request'
    flow.post('/exceptions',{'request':request|{'decision':'approved'}},422)
    flow.post('/exception-decisions',{'request_id':r['id'],'decision':{'authority':'Engineering requester','decision':'approved','reason':'Self approval'}},422)
    flow.post('/exception-decisions',{'request_id':r['id'],'decision':{'authority':'Named risk authority','decision':'approved','reason':'Explicit operator-recorded decision'}})
    assert flow.get()['exceptions'][0]['status'].startswith('active')
    monkeypatch.setattr(appsec,'now',lambda:(appsec.dt(future)+timedelta(seconds=1)).isoformat())
    assert flow.get()['exceptions'][0]['status']=='expired'
    assert flow.store.get('application_finding',flow.f['id'])==source
    assert flow.get()['action'] is None and not flow.get()['verification']['can_close']
    flow.post('/exceptions',{'request':request|{'residual_risk':' '}},422)


def test_exception_decision_scope_and_newer_evidence(flow):
    r=flow.post('/exceptions',{'request':{'requester':'Owner','justification':'Reason','residual_risk':'Still open risk','review_by':(appsec.dt(now())+timedelta(days=7)).isoformat()}})
    body={'request_id':r['id'],'decision':{'authority':'Authority','decision':'approved','reason':'Reviewed decision'}}
    original=flow.f;flow.f=flow.other;flow.post('/exception-decisions',body,422);flow.f=original
    flow.f=flow.newer();flow.post('/exception-decisions',body,422)
    assert flow.get()['exceptions'][0]['status'].startswith('stale')


@pytest.mark.parametrize('name,raw', [('../escape.txt',b'x'),('bad\\file.txt',b'x'),('huge.txt',b'x'*(2*1024*1024+1)),('empty.txt',b'')])
def test_evidence_limits(flow,name,raw):
    flow.evidence(name=name,raw=raw,code=422)
    assert not flow.store.all('appsec_evidence')


def test_evidence_integrity_download_and_scope(flow):
    raw=b'<script>alert(1)</script> file:///etc/passwd $(echo unsafe)'
    e=flow.evidence(raw=raw);assert e['sha256']==digest(raw)
    path='/api/application-findings/'+flow.f['id']+'/attachments/'+e['id']
    response=flow.client.get(path,params=flow.query)
    assert response.content==raw and 'attachment' in response.headers['content-disposition']
    assert flow.client.get(path,params={'customer_id':'fictional-cloud','environment_id':'mac-cloud'}).status_code==404
    assert flow.client.get('/api/application-findings/'+flow.f['id']+'/governance',params={'customer_id':'fictional-cloud','environment_id':'mac-cloud'}).status_code==404
    flow.ready();(flow.store.root/'blobs'/e['sha256']).write_bytes(b'changed')
    flow.retest(code=422,evidence_ids=[e['id']])


def test_atomic_ledger_and_history_failure(flow):
    flow.review()
    with flow.store.connect() as c:
        c.execute("CREATE TRIGGER fail_appsec_event BEFORE INSERT ON activity WHEN NEW.kind='improvement_open' BEGIN SELECT RAISE(ABORT,'synthetic rollback'); END")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):flow.action()
    assert not flow.store.all('improvement')


def test_demo_cases_and_repeat_preserves_edits(service):
    from iti import appsec_demo
    result=appsec_demo.load(service)
    assert appsec_demo.load(service)==result
    def view(label):
        f=service.store.get('application_finding',result['cases'][label])
        return appsec.view(service.store,f)
    assert view('A')['lifecycle']=='Closed with reviewed supporting evidence'
    assert view('A')['verification']['history'][-1]['assurance']=='synthetic/lab evidence reviewed'
    assert view('B')['action']['status']=='in progress'
    assert view('B')['disposition']=='Needs review'
    assert view('C-active')['exceptions'][0]['status'].startswith('active')
    assert view('C-expired')['exceptions'][0]['status']=='expired'
    assert view('C-unapproved')['exceptions'][0]['status']=='unapproved request'
    assert 'Reopen/review required' in view('D')['lifecycle']
    assert [r['result'] for r in view('D')['verification']['history']]==['passed','failed']
    assert not service.store.all('vulnerability_exposure') and not service.store.all('assessment')


def test_changed_evidence_integrity_invalidates_closure(flow):
    flow.ready();test=flow.retest();flow.action(status='closed')
    sha=test['evidence'][0]['sha256'];(flow.store.root/'blobs'/sha).write_bytes(b'corrupt')
    assert not flow.get()['verification']['can_close']
    assert 'historical' in flow.get()['lifecycle']


def test_changed_commit_context_never_inherits_closed_success(flow):
    flow.ready();flow.retest();flow.action(status='closed')
    p=af.preview(flow.store,C,E,flow.raw,{'application':'Synthetic app','repository':'synthetic/repo','commit':'different-commit'})
    af.confirm(flow.store,p['id'],C,E)
    assert p['findings'][0]['logical_id']!=flow.f['logical_id']
    assert flow.get()['disposition']=='Needs review'
    assert not flow.get()['verification']['can_close']
    assert flow.get()['dependencies']['changed_context_batches']==[p['batch_id']]


def test_same_customer_other_environment_cannot_reuse_origin(flow):
    from iti.models import EnvironmentProfile
    customer=CustomerProfile.model_validate(flow.store.get('customer',C))
    customer.environments.append(EnvironmentProfile(id='other-env',name='Other environment',platforms=['linux']))
    profiles.save(flow.store,customer)
    query={'customer_id':C,'environment_id':'other-env'}
    assert flow.client.get('/api/application-findings/'+flow.f['id']+'/governance',params=query).status_code==404
    flow.post('/review',{'review':{'reviewer':'Reviewer','reason':'Cross env','disposition':appsec.APPLICABLE}},404,ctx=appsec.versions(profiles.context(flow.store,C,'other-env').model_dump()))


def test_retest_predating_changed_implementation_is_historical(flow):
    flow.ready();earlier=now();flow.action(proposed_change='Changed implementation after earlier test')
    flow.retest(executed_at=earlier)
    assert not flow.get()['verification']['can_close']
    assert any('predates' in s for s in flow.get()['verification']['history'][-1]['stale_reasons'])


def test_review_and_exception_endpoints_keep_origin_protection(flow):
    response=flow.client.post('/api/application-findings/'+flow.f['id']+'/review',headers={'Origin':'https://external.invalid'},json={})
    assert response.status_code==403
    response=flow.client.post('/api/appsec/demo',headers={'Sec-Fetch-Site':'cross-site'})
    assert response.status_code==403
    flow.review();g=flow.get()
    flow.post('/action',{'review_id':'forged-review','actor':'Owner','reason':'Forged approval','action':{'owner':'Owner','priority':'medium','rationale':'Reason','proposed_change':'Change','retest':'Retest','remediation':{'security_reviewer':'Security','expected_result':'Fixed cause'}}},422)
    assert flow.get()['history']==g['history']


def test_ledger_boundary_rejects_inconsistent_test_fields(flow):
    from iti.models import TestRun
    from iti import ledger
    flow.ready();saved=flow.retest(result='failed')
    test=TestRun.model_validate({k:v for k,v in saved.items() if k in TestRun.model_fields})
    test.result='passed'
    ctx=profiles.context(flow.store,C,E).model_dump()
    subject=appsec.subject(flow.store,flow.f,appsec.versions(ctx))
    with pytest.raises(ValueError,match='disagree'):ledger.record_test(flow.store,subject,test)
    assert flow.get()['verification']['status']=='Retest failed'


def test_supplied_technical_evidence_is_not_labeled_lab_execution(flow):
    doc=json.loads(flow.raw);doc.pop('properties')
    p=af.preview(flow.store,C,E,json.dumps(doc).encode(),{'application':'Synthetic app','repository':'synthetic/repo'})
    af.confirm(flow.store,p['id'],C,E);flow.f=p['findings'][0]
    assert not flow.f['synthetic']
    flow.ready();e=flow.evidence(kind='supplied configuration/version evidence')
    result=flow.retest(evidence_ids=[e['id']])
    assert result['evidence'][0]['kind']=='supplied evidence'
    assert result['assurance']=='supplied evidence reviewed; not independently verified'
    assert not flow.get()['verification']['independent_operational_verification']


def test_supplied_evidence_cannot_enter_legacy_verification(service,assessed):
    from iti import ledger
    from iti.models import TestRun
    test=TestRun(behavior_id=assessed['extraction']['behaviors'][0]['id'],environment_version=assessed['context']['environment_version'],control_id='example',control_version='1',procedure='Authored test',expected='Expected',actual='Actual',executed_at=now(),method='analyst attestation',result='passed',dimension='detection',scope='Synthetic scope',variant='Synthetic example',evidence=[{'id':'example','reference':'example','description':'Supplied only','kind':'supplied evidence'}])
    with pytest.raises(ValueError,match='restricted to AppSec'):ledger.record_test(service.store,assessed,test)
