import copy,json,time
from datetime import datetime,timezone,timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from iti.models import CustomerProfile,TestRun as ValidationRun,EvidenceAttachment,ImprovementAction
from iti.store import uid,now
from iti import profiles,relevance,ledger,detection,analysis

def test_relevance_shared_facts_two_customers(service):
    j=service.submit('fictional-bank','windows-ad','offline','case','no-ioc',shared=True,background=False);a=service.store.get('assessment',j['data']['assessment_id'])
    j2=service.submit('fictional-cloud','mac-cloud','offline','source',a['source']['revision_id'],background=False);b=service.store.get('assessment',j2['data']['assessment_id'])
    assert a['extraction']==b['extraction'];assert a['relevance']['rank']=='High' and b['relevance']['rank']=='Low'
    assert a['relevance']['sector']['status']=='mismatch';assert 'ActiveMQ' in a['relevance']['technology_matches']

def test_unknown_visible_and_insufficient(service):
    j=service.submit('fictional-bank','windows-ad','offline','case','insufficient',background=False);a=service.store.get('assessment',j['data']['assessment_id']);p=service.generate(a['id'],'fictional-bank')
    assert a['relevance']['rank']=='Unknown' and relevance.visible('Unknown') and not relevance.visible('Low') and relevance.visible('Low','All')
    assert not p['hunts'] and not p['emulations']

def test_changed_customer_during_job_frozen(service,monkeypatch):
    import threading
    entered=threading.Event();release=threading.Event();original=analysis.OfflineProvider.extract
    def slow(self,source,store,cancel):entered.set();release.wait(5);return original(self,source,store,cancel)
    monkeypatch.setattr(analysis.OfflineProvider,'extract',slow)
    j=service.submit('fictional-bank','windows-ad','offline','text','CertUtil downloaded a payload.')
    assert entered.wait(5)
    c=CustomerProfile.model_validate(service.store.get('customer','fictional-bank'));c.misp_destination='https://changed.example';profiles.save(service.store,c)
    release.set()
    for _ in range(100):
        r=service.job(j['id'])
        if r['state'] in ('complete','failed'):break
        time.sleep(.02)
    assert r['state']=='complete',r
    a=service.store.get('assessment',r['data']['assessment_id']);assert a['context']['customer_version']==1 and a['context']['destination'] is None
    with pytest.raises(KeyError):service.scoped('assessment',a['id'],'fictional-cloud')

def test_concurrent_idempotency(service,monkeypatch):
    calls=[];old=analysis.OfflineProvider.extract
    def track(*a,**k):calls.append(1);time.sleep(.03);return old(*a,**k)
    monkeypatch.setattr(analysis.OfflineProvider,'extract',track)
    def submit(_):return service.submit('fictional-bank','windows-ad','offline','text','CertUtil downloaded a payload.',background=False)
    with ThreadPoolExecutor(max_workers=5) as ex:jobs=list(ex.map(submit,range(5)))
    assert len({j['id'] for j in jobs})==1 and len(calls)==1

def test_live_missing_failure_resume_checkpoint(service,monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY',raising=False);monkeypatch.delenv('OPENAI_MODEL',raising=False)
    j=service.submit('fictional-bank','windows-ad','live','text','CertUtil downloaded a payload.',background=False)
    assert j['state']=='failed' and 'unavailable' in j['data']['error']['message'];source=j['data']['source_revision']
    assert service.resume(j['id'],background=False)['data']['source_revision']==source
    assert not service.store.all('extraction')
    assert len(service.store.all('failure'))==2

def test_replay_rejects_changed_content(service):
    j=service.submit('fictional-bank','windows-ad','replay','text','CertUtil downloaded NEW facts.',background=False)
    assert j['state']=='failed' and 'exact-content replay' in j['data']['error']['message']

def test_restart_cancel_no_corruption(service,monkeypatch):
    class Dummy:
        def submit(self,*a):pass
    monkeypatch.setattr('iti.services.EXECUTOR',Dummy())
    j=service.submit('fictional-bank','windows-ad','offline','text','AnyDesk was installed on Windows.')
    assert service.cancel(j['id'])['state']=='cancelled';assert service.resume(j['id'],background=False)['state']=='complete'
    service.update(j['id'],state='running');service.restart();assert service.job(j['id'])['state']=='interrupted'
    assert service.resume(j['id'],background=False)['state']=='complete'

def test_sigma_positive_negative_missing_and_unsupported():
    result=detection.fixture_test('19b08b1c-861d-4e75-a1ef-ea0c1baf202b')
    assert [x['result'] for x in result['cases'].values()]==['match','no match','inconclusive']
    for mod in ['re','cidr','base64offset','fieldref']:
        with pytest.raises(detection.UnsupportedSigma):detection.compile_subset({'detection':{'selection':{'CommandLine|'+mod:'a'},'condition':'selection'}})
    with pytest.raises(detection.UnsupportedSigma):detection.compile_subset({'detection':{'selection':{'x':'a'},'condition':'selection | count() > 2'}})

def test_catalog_integrity_and_conversion(assessed):
    from pathlib import Path
    from iti.store import ROOT,digest
    for entry in detection.MANIFEST['files']:assert digest((ROOT/entry['path']).read_bytes())==entry['sha256']
    assert assessed['retrieval']['searched_rules']==8
    assert '19b08b1c-861d-4e75-a1ef-ea0c1baf202b' in assessed['retrieval']['source_cited_found']
    assert any(c['syntax_valid'] and c['conversion_supported'] for c in assessed['candidates'])
    assert not any(c['execution_tested'] for c in assessed['candidates'])

def test_ledger_synthetic_never_live(service,assessed):
    b=assessed['extraction']['behaviors'][1];c=assessed['candidates'][0]
    t=ValidationRun(behavior_id=b['id'],environment_version=1,control_id=c['id'],control_version=c['source']['sha256'],procedure='fixture',expected='match',actual='match',executed_at=now(),method='synthetic log match',result='passed',dimension='detection',scope='authored event',variant='positive',evidence=[EvidenceAttachment(id='e',reference='fixture:1',description='actual test',kind='synthetic fixture replay')])
    ledger.record_test(service.store,assessed,t);v=ledger.view(service.store,assessed);row=next(r for r in v['rows'] if r['behavior_id']==b['id'])
    assert row['synthetic_result']=='passed' and row['detection_test']=='not tested' and row['prevention_test']=='not tested' and row['soc_response']=='not tested'
    assert v['metrics']['source_ingestion_to_live_detection_seconds'] is None
    with pytest.raises(ValueError):ValidationRun.model_validate(t.model_dump()|{'dimension':'prevention'})

def test_failure_retest_stale_baseline_clocks(service,assessed):
    b=assessed['extraction']['behaviors'][0];past=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    common=dict(behavior_id=b['id'],environment_version=1,control_id='owned-control',control_version='v1',procedure='approved observation',expected='alert',actual='observed',executed_at=now(),method='observed SIEM alert',dimension='detection',scope='single lab-designated live-system variant',variant='one variant',evidence=[EvidenceAttachment(id='e',reference='immutable-evidence:1',description='operator evidence',kind='live system')])
    ledger.record_test(service.store,assessed,ValidationRun(**common,result='failed'))
    ledger.record_test(service.store,assessed,ValidationRun(**(common|{'executed_at':past}),result='passed',baseline=True,control_deployed_at=past))
    v=ledger.view(service.store,assessed);assert len(v['tests'])==2;assert v['rows'][0]['coverage_classification']=='existing coverage confirmed after receipt';assert v['metrics']['customer_receipt_to_live_detection_confirmation_seconds']>=0
    assert v['tests'][1]['executed_at']==past
    c=CustomerProfile.model_validate(service.store.get('customer','fictional-bank'));profiles.save(service.store,c)
    v=ledger.view(service.store,assessed);assert all(t['stale'] for t in v['tests']);assert v['metrics']['source_ingestion_to_live_detection_seconds'] is None

def test_improvement_history(service,assessed):
    action=ImprovementAction(behavior_id=assessed['extraction']['behaviors'][0]['id'],owner='Lab owner',priority='high',rationale='missing telemetry',proposed_change='enable logging',retest='repeat harmless variant')
    a=ledger.improve(service.store,assessed,action);action.id=a['id'];action.status='deployed';b=ledger.improve(service.store,assessed,action)
    assert a['opened_at']==b['opened_at'] and b['deployed_at']
    assert len(service.store.history(ledger.scope_key(assessed)))==2
    with service.store.connect() as c:
        with pytest.raises(Exception,match='append-only'):c.execute('DELETE FROM activity')

def test_new_gap_remediated_history_and_nonnegative_clock(service,assessed):
    b=assessed['extraction']['behaviors'][0]
    action=ImprovementAction(behavior_id=b['id'],owner='Lab control owner',priority='high',rationale='gap confirmed',proposed_change='deploy reviewed control',retest='controlled approved simulation')
    original=ledger.improve(service.store,assessed,action);action.status='deployed';changed=ledger.improve(service.store,assessed,action)
    t=ValidationRun(behavior_id=b['id'],environment_version=1,control_id='local-control',control_version='v2',procedure='approved scoped test',expected='SIEM alert',actual='alert observed',executed_at=now(),method='observed SIEM alert',dimension='detection',result='passed',scope='single system',variant='benign variation',evidence=[EvidenceAttachment(id='e',reference='record:observed-1',description='Operator-provided live evidence reference',kind='live system')],control_deployed_at=changed['deployed_at'],improvement_id=changed['id'])
    ledger.record_test(service.store,assessed,t);v=ledger.view(service.store,assessed)
    assert v['rows'][0]['coverage_classification']=='coverage changed after gap; variant verified'
    assert v['metrics']['customer_receipt_to_live_detection_confirmation_seconds']>=0
    assert original['opened_at']==changed['opened_at']

def test_fabricated_rule_atomic_and_unsupported_claim_omission(service,assessed):
    from iti.exporters import stix_export
    from iti.models import Extraction
    import json
    with pytest.raises(ValueError,match='not in pinned'):detection.fixture_test('00000000-0000-4000-8000-000000000000')
    ex=Extraction.model_validate(assessed['extraction'])
    atomic=detection.atomic_candidates(next(b for b in ex.behaviors if b.key=='certutil'))
    assert atomic and all(x['guid'] and x['revision']==detection.MANIFEST['revisions']['atomic'] for x in atomic)
    package=service.generate(assessed['id'],'fictional-bank');package=copy.deepcopy(package);package['extraction']['behaviors'][0]['kind']='unsupported'
    text,validation,omissions=stix_export(service.store,package)
    assert omissions and package['extraction']['behaviors'][0]['id'] in omissions[0]

def test_tampered_live_response_rejected_and_saved(service,monkeypatch):
    import openai
    from types import SimpleNamespace
    from iti.analysis import LivePayload,LiveFinding
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-test-key');monkeypatch.setenv('OPENAI_MODEL','fixture-client-not-a-real-model')
    class Responses:
        def parse(self,**kwargs):
            f=LiveFinding(text='Unsupported',evidence=['invented-span'],quote='not in source',kind='source_reported',qualifier=None,platform='windows',technique_id=None,technology=[],telemetry=[],rationale='fabricated')
            return SimpleNamespace(status='completed',output_parsed=LivePayload(findings=[f],abstentions=[]),usage=None,model_dump=lambda **k:{'status':'synthetic response'})
    monkeypatch.setattr(openai,'OpenAI',lambda **kwargs:SimpleNamespace(responses=Responses()))
    j=service.submit('fictional-bank','windows-ad','live','text','CertUtil downloaded a payload.',background=False)
    assert j['state']=='failed' and 'support gate' in j['data']['error']['message']
    assert service.store.all('rejected_output') and service.store.all('model_response')

def test_live_refusal_visible_no_fallback(service,monkeypatch):
    import openai
    from types import SimpleNamespace
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-test-key');monkeypatch.setenv('OPENAI_MODEL','fixture-client-not-a-real-model')
    class Responses:
        def parse(self,**kwargs):return SimpleNamespace(status='incomplete',output_parsed=None,usage=None,model_dump=lambda **k:{'status':'incomplete','reason':'synthetic truncation'})
    monkeypatch.setattr(openai,'OpenAI',lambda **kwargs:SimpleNamespace(responses=Responses()))
    j=service.submit('fictional-bank','windows-ad','live','text','CertUtil downloaded a payload.',background=False)
    assert j['state']=='failed' and not service.store.all('extraction') and service.store.all('model_response')
