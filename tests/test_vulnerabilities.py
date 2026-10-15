import csv
import io
import json
from datetime import datetime,timezone,timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from iti import vulnerabilities as vi, vulnerability_enrichment as enrichment, vulnerability_demo, profiles, ledger
from iti.api import create_app
from iti.store import ROOT,now,uid,canonical
from iti.models import ImprovementAction,TestRun as Verification,CustomerProfile

@pytest.fixture
def demo(service):return vulnerability_demo.load(service)['workspace']

def team(workspace):return next(i for i in workspace['items'] if i['cve']=='CVE-2023-42793')
def current(service):return vi.workspace(service,'fictional-software','software-lab')
def decision(workspace):return team(workspace)['decisions'][0]
def scope():return {'customer_id':'fictional-software','environment_id':'software-lab'}
def review(service,d,**changes):return vi.review(service.store,d['id'],'fictional-software','software-lab',value={'reason':'Reviewed source and scoped evidence','reviewer':'Authored fixture analyst',**changes})
def make_action(service,d,**updates):
    action=ImprovementAction(vulnerability_assessment_id=d['id'],owner='Build owner',priority='high',rationale='Reviewed source/exposure finding',proposed_change='Apply vendor supported fix',retest='Preserve rescan and build configuration',
      remediation={'review_date':'2026-10-20','residual_uncertainty':'Prior compromise unknown','permanent_fix':'Apply supported patch','source_references':'https://www.cisa.gov/'},**updates)
    return ledger.improve(service.store,vi.subject(service.store,d['id'],'fictional-software','software-lab'),action)
def test_record(service,d,action,kind='synthetic fixture replay',method='reliable rescan',result='passed',**updates):
    evidence=vi.capture_evidence(service.store,d['context'],'authored-result.json',b'{"authored_fixture":"not a real scanner result"}',kind)
    values={'vulnerability_assessment_id':d['id'],'environment_version':d['context']['environment_version'],'control_id':'authored scanner','control_version':'1',
      'procedure':'Authored test procedure','expected':'Supported patched version','actual':'Authored outcome','executed_at':now(),'method':method,'result':result,'dimension':'remediation',
      'scope':d['asset']['asset_id'],'variant':'version configuration','improvement_id':action['id'],'measurement':{'asset_id':d['asset']['asset_id'],'observed_value':'example fixed version','acceptance_basis':'Authored test expectation'},
      'evidence':[{'id':evidence['id'],'reference':evidence['reference'],'sha256':evidence['sha256'],'description':'Authored test only','kind':kind}],**updates}
    return ledger.record_test(service.store,vi.subject(service.store,d['id'],'fictional-software','software-lab'),Verification(**values))
test_record.__test__=False

def test_literal_mention_dedup_exact_offsets_no_exploitation(service):
    j=service.submit('fictional-bank','windows-ad','offline','text','Actor Example mentioned separately. cve-2023-42793, CVE-2023-42793. No exploitation established. CVE-2023-42793BAD is not a valid token.',background=False)
    w=vi.workspace(service,'fictional-bank','windows-ad');i=w['items'][0]
    assert len(w['items'])==1 and not i['assertions']
    assert len(i['mentions'][0]['occurrences'])==2
    for o in i['mentions'][0]['occurrences']:assert i['mentions'][0]['source']['normalized'][o['start']:o['end']]==o['literal']
    assert not i['decisions'][0]['credible_exploitation'] and i['decisions'][0]['response']==vi.INVESTIGATE
    receipt=i['metrics']['receipt_at'];service.resume(j['id'],background=False)
    assert vi.workspace(service,'fictional-bank','windows-ad')['items'][0]['metrics']['receipt_at']==receipt

def test_demo_dates_uncertainty_byovd_and_contrast(service,demo):
    t=team(demo);assert [d['response'] for d in t['decisions']]==[vi.EXPEDITE,vi.INVESTIGATE]
    assert t['assertions'][0]['event_time']=='late September 2023'
    assert t['mentions'][0]['source']['published_at']=='2023-12-13'
    driver=next(i for i in demo['items'] if i['cve']=='CVE-2015-2291')
    assert driver['assertions'][0]['classification']=='attempted exploitation'
    assert 'Low-confidence' in driver['assertions'][0]['attribution_qualifier']
    assert driver['assets'][0]['association']=='potential attack path'
    assert driver['assets'][0]['applicability']=='needs verification'
    before=len(service.store.all('vulnerability_exposure'));vulnerability_demo.load(service)
    assert len(service.store.all('vulnerability_exposure'))==before

def test_assertion_requires_actual_cve_actor_alias_event_spans(service,demo):
    a=team(demo)['assertions'][0];value={k:v for k,v in a.items() if k in vi.VulnerabilityAssertion.model_fields}
    for changes,match in [({'evidence':['fake']},'Dangling'),({'actor':'Invented Actor'},'Named actor'),({'aliases':['invented alias']},'alias'),({'event_time':'2099-01-01'},'event wording')]:
        with pytest.raises(ValueError,match=match):vi.assert_source(service.store,a['context'],value|changes)
    assert not vi.workspace(service,'fictional-bank','windows-ad')['items']
    with pytest.raises(ValueError,match='not associated'):vi.assert_source(service.store,profiles.context(service.store,'fictional-bank','windows-ad').model_dump(),value)

def test_low_epss_unknown_actor_and_unverified_controls_do_not_cancel(service,demo):
    d=decision(demo);a=d['asset'];assertion=d['assertions'][0]
    vals={k:v for k,v in assertion.items() if k in vi.VulnerabilityAssertion.model_fields};vals.update(actor=None,aliases=[],actor_evidence=[],supersedes=assertion['id'])
    vi.assert_source(service.store,d['context'],vals)
    service.store.put('vulnerability_enrichment','low',{'id':'low','cve':d['cve'],'provider':'epss','status':'available','retrieved_at':now(),'value':{'probability':0.0001,'percentile':0.01,'data_date':now()[:10]}})
    values={k:v for k,v in a.items() if k in vi.ExposureObservation.model_fields};values['control_claim']='Firewall protects everything (not tested)'
    vi.observe(service.store,d['context'],values)
    new=decision(current(service));assert new['response']==vi.EXPEDITE and new['enrichment']['epss']['value']['probability']==0.0001
    assert new['previous_id'] and {'assertions','exposure','enrichment'}.issubset(new['changed_inputs'])

def test_csv_preview_duplicate_error_frozen_context_and_customer_scope(service,demo):
    ctx=demo['context'];out=io.StringIO();row={k:v for k,v in team(demo)['assets'][0].items() if k in vi.ExposureObservation.model_fields and v is not None and k!='schema_version'}
    writer=csv.DictWriter(out,fieldnames=row);writer.writeheader();writer.writerow(row)
    p=vi.preview_csv(service.store,ctx,out.getvalue());assert not p['errors'] and p['rows'][0]['duplicate']
    before=len(service.store.all('vulnerability_exposure'));vi.import_csv(service.store,p['id'],'fictional-software','software-lab');assert len(service.store.all('vulnerability_exposure'))==before
    writer.writerow(row);assert vi.preview_csv(service.store,ctx,out.getvalue())['errors']
    with pytest.raises(KeyError):vi.import_csv(service.store,p['id'],'fictional-bank','windows-ad')
    c=CustomerProfile.model_validate(service.store.get('customer',ctx['customer_id']));profiles.save(service.store,c)
    result=vi.import_csv(service.store,p['id'],'fictional-software','software-lab');assert result['context']['customer_version']==1
    new=decision(current(service));assert new['context']['customer_version']==2 and new['response']==vi.INVESTIGATE
    assert new['asset']['assessment_stale']

def test_unknown_not_safe_and_driver_absence_guard(service,demo):
    row=next(i for i in demo['items'] if i['cve']=='CVE-2015-2291')['assets'][0]
    values={k:v for k,v in row.items() if k in vi.ExposureObservation.model_fields}
    for state in ['assessed not affected','confirmed affected']:
        with pytest.raises(ValueError,match='Driver absence'):vi.observe(service.store,demo['context'],values|{'applicability':state})
    values={k:v for k,v in team(demo)['assets'][1].items() if k in vi.ExposureObservation.model_fields}
    vi.observe(service.store,demo['context'],values|{'applicability':'assessed not affected','assessment_basis':'version evidence','applicability_reason':'Reviewed synthetic configuration explicitly establishes exclusion','evidence_reference':'synthetic:version-evidence'})
    assert team(current(service))['decisions'][1]['response']==vi.NOT_APPLICABLE

def test_reviews_override_history_stale_proposal_and_commitment_retained(service,demo):
    d=decision(demo);review(service,d)
    assert decision(current(service))['id']==d['id'] # ordinary acceptance must not cause revision churn
    values={k:v for k,v in d['asset'].items() if k in vi.ExposureObservation.model_fields}
    vi.observe(service.store,d['context'],values|{'applicability':'assessed not affected','applicability_reason':'Authored new version evidence supports exclusion'})
    new=decision(current(service));assert new['response']==vi.EXPEDITE and new['unconstrained_proposal']==vi.NOT_APPLICABLE
    with pytest.raises(ValueError,match='changed'):review(service,d)
    r=review(service,new,disposition='override',response=vi.NOT_APPLICABLE,reason='Explicitly release prior commitment on new exclusion evidence')
    final=decision(current(service));assert final['id']==new['id'] # reviewing does not invalidate its own proposal
    assert r['response']==vi.NOT_APPLICABLE
    assert service.store.get('vulnerability_review',r['id'])['decision_id']==new['id']
    assert service.store.get('vulnerability_decision',d['id'])['response']==vi.EXPEDITE

def test_actions_use_existing_ledger_no_fake_behavior_idempotent_history(service,demo):
    d=decision(demo)
    with pytest.raises(ValueError,match='Accept or override'):make_action(service,d)
    review(service,d)
    with ThreadPoolExecutor(max_workers=4) as pool:actions=list(pool.map(lambda _:make_action(service,d),range(5)))
    assert len({a['id'] for a in actions})==1
    a=actions[0];assert a['behavior_id'] is None and a['origin']['kind']=='vulnerability_decision'
    fields={k:v for k,v in a.items() if k in ImprovementAction.model_fields};fields['status']='closed'
    ledger.improve(service.store,vi.subject(service.store,d['id'],'fictional-software','software-lab'),ImprovementAction(**fields))
    assert decision(current(service))['verification']['verified_at'] is None
    assert len(service.store.history(ledger.scope_key(vi.subject(service.store,d['id'],'fictional-software','software-lab'))))==2
    with pytest.raises(KeyError):vi.subject(service.store,d['id'],'fictional-bank','windows-ad')

def test_synthetic_lab_attestation_and_failed_retests_never_live(service,demo):
    d=decision(demo);review(service,d);a=make_action(service,d)
    for kind,method in [('synthetic fixture replay','reliable rescan'),('lab execution','version/configuration evidence'),('analyst attestation','analyst attestation'),('live system','reliable rescan')]:
        test_record(service,d,a,kind,method)
        # Even deliberately mislabeled live evidence cannot turn a synthetic asset into operational verification.
        assert decision(current(service))['verification']['verified_at'] is None
    with pytest.raises(ValueError,match='Synthetic match'):test_record(service,d,a,method='synthetic log match')
    test_record(service,d,a,result='failed')
    tests=decision(current(service))['verification']['tests'];assert len(tests)==5 and tests[-1]['result']=='failed'
    assert team(current(service))['metrics']['outcomes'][0]['confirmed_exposure_to_verified_seconds'] is None

def test_operational_verification_requires_bytes_context_and_stales_on_change(service,demo):
    base=decision(demo);values={k:v for k,v in base['asset'].items() if k in vi.ExposureObservation.model_fields}
    # Authored regression simulates operational records; not reported as live acceptance evidence.
    vi.observe(service.store,base['context'],values|{'asset_id':'authored-operational-schema','evidence_kind':'scanner supplied','finding_id':'TEST-ONLY'})
    d=team(current(service))['decisions'][-1];review(service,d);a=make_action(service,d)
    test_record(service,d,a,kind='live system',result='failed');assert team(current(service))['decisions'][-1]['verification']['status']=='failed'
    t=test_record(service,d,a,kind='live system');new=team(current(service))['decisions'][-1]
    assert new['verification']['status']=='verified remediation'
    assert team(current(service))['metrics']['outcomes'][-1]['confirmed_exposure_to_verified_seconds']>=0
    assert len(new['verification']['tests'])==2
    fields={k:v for k,v in a.items() if k in ImprovementAction.model_fields};fields['proposed_change']='Different implementation under review'
    ledger.improve(service.store,vi.subject(service.store,d['id'],'fictional-software','software-lab'),ImprovementAction(**fields))
    assert team(current(service))['decisions'][-1]['verification']['status']=='stale'
    assert service.store.get('test',t['id'])['actual']=='Authored outcome'

def test_evidence_and_mitigation_validation(service,demo):
    d=decision(demo);review(service,d);a=make_action(service,d)
    with pytest.raises(ValueError,match='residual risk'):test_record(service,d,a,dimension='mitigation')
    with pytest.raises(ValueError,match='approval'):test_record(service,d,a,method='targeted human-led test')
    with pytest.raises(ValueError,match='Attach the actual'):test_record(service,d,a,evidence=[{'id':'fake','reference':'invented:/result','sha256':'a'*64,'description':'claim','kind':'live system'}])
    e=vi.capture_evidence(service.store,d['context'],'result.txt',b'authored evidence','synthetic fixture replay')
    with pytest.raises(KeyError):vi.scoped(service.store,'vulnerability_evidence',e['id'],'fictional-bank','windows-ad')
    with pytest.raises(ValueError,match='filename'):vi.capture_evidence(service.store,d['context'],'../bad',b'x','live system')

def test_enrichment_schema_missing_dates_cache_different_cves_and_failure(service):
    cves=['CVE-2023-42793','CVE-2015-2291'];calls=[]
    raw=json.dumps({'catalogVersion':'test','dateReleased':now(),'count':1,'vulnerabilities':[{'cveID':cves[0],'dateAdded':'2023-10-04','dueDate':'2023-10-25','product':'TeamCity','vendorProject':'JetBrains','requiredAction':'Vendor guidance'}]}).encode()
    def fetch(url):
        calls.append(url)
        if url==enrichment.KEV:return raw,{'origin':url}
        raise OSError('Authored unavailable provider')
    enrichment.refresh(service.store,[cves[0]],fetch)
    enrichment.refresh(service.store,[cves[1]],fetch)
    assert calls.count(enrichment.KEV)==1
    assert enrichment.latest(service.store,cves[1])['kev']['value']['listed'] is False
    assert enrichment.latest(service.store,cves[0])['epss']['value'] is None
    with pytest.raises(ValueError):enrichment.parse('epss',json.dumps({'status':'OK','status-code':200,'data':[{'cve':cves[0],'epss':-1,'percentile':0.5,'date':'2023-01-01'}]}),cves)
    with pytest.raises(ValueError,match='count mismatch'):enrichment.parse('kev',raw.replace(b'"count": 1',b'"count": 2'),cves)

def test_stale_and_unavailable_enrichment_remains_dated(service,demo):
    cve='CVE-2024-99999';old=(datetime.now(timezone.utc)-timedelta(days=20)).isoformat()
    service.store.put('vulnerability_enrichment','old',{'id':'old','cve':cve,'provider':'epss','status':'available','retrieved_at':old,'value':{'probability':0.5,'data_date':old[:10]}})
    assert enrichment.latest(service.store,cve)['epss']['status']=='stale'
    service.store.put('vulnerability_enrichment','failed',{'id':'failed','cve':cve,'provider':'epss','status':'unavailable','retrieved_at':now(),'value':None,'reason':'Timeout'})
    r=enrichment.latest(service.store,cve)['epss'];assert r['status']=='unavailable' and r['last_available']['stale'] and r['value'] is None

def test_api_scope_origin_upload_and_persistence(service,demo):
    client=TestClient(create_app(service),base_url='http://localhost');query='?customer_id=fictional-software&environment_id=software-lab';d=decision(demo)
    assert client.get('/api/vulnerabilities'+query).status_code==200
    wrong={'customer_id':'fictional-bank','environment_id':'windows-ad','review':{'reviewer':'Fixture','reason':'Wrong customer request'}}
    assert client.post('/api/vulnerabilities/decisions/'+d['id']+'/review',json=wrong).status_code==404
    assert client.post('/api/vulnerabilities/exposures',headers={'Origin':'https://attacker.example'},json={}).status_code==403
    r=client.post('/api/vulnerabilities/evidence',data=scope()|{'kind':'synthetic fixture replay'},files={'file':('result.txt',b'authored result')});assert r.status_code==200
    assert client.get('/api/vulnerabilities/evidence/'+r.json()['id']+query).content==b'authored result'
    assert client.get('/api/vulnerabilities/evidence/'+r.json()['id']+'?customer_id=fictional-bank&environment_id=windows-ad').status_code==404
    from iti.services import Service
    reopened=Service(service.store);assert decision(current(reopened))['id']==d['id']

def test_commitment_deadline_survives_new_observation(service,demo):
    d=decision(demo);data={k:v for k,v in d['asset'].items() if k in vi.ExposureObservation.model_fields}
    first=vi.observe(service.store,d['context'],data|{'commitment_response':vi.EXPEDITE,'commitment_deadline':'2026-10-20','commitment_reason':'Authored policy commitment'})
    second=vi.observe(service.store,d['context'],data|{'observed_version':'new observation'})
    assert second['commitment_deadline']==first['commitment_deadline']
    assert decision(current(service))['deadline']=='2026-10-20'

def test_source_revision_and_profile_change_preserve_receipt_and_prior_decisions(service,demo):
    before=team(demo);ctx=demo['context']
    c=CustomerProfile.model_validate(service.store.get('customer',ctx['customer_id']));profiles.save(service.store,c)
    after=team(current(service));assert after['metrics']['receipt_at']==before['metrics']['receipt_at']
    assert after['decisions'][0]['context']['customer_version']==2
    assert service.store.get('vulnerability_decision',before['decisions'][0]['id'])['context']['customer_version']==1
    assert after['decisions'][0]['response']==vi.INVESTIGATE

def test_changed_finding_is_revision_of_same_asset_and_absence_is_not_exclusion(service,demo):
    d=decision(demo);a=d['asset'];values={k:v for k,v in a.items() if k in vi.ExposureObservation.model_fields}
    revised=vi.observe(service.store,d['context'],values|{'finding_id':'NEW-SCANNER-FINDING','observed_version':'new unknown observation','applicability':'needs verification'})
    assert revised['logical_id']==a['logical_id'] and revised['previous_id']==a['id']
    assert len(vi.current_exposures(service.store,d['context'],d['cve']))==2
    with pytest.raises(ValueError,match='changed'):review(service,d)
    with pytest.raises(ValueError,match='absence alone'):vi.observe(service.store,d['context'],values|{'assessment_basis':'software absence only','applicability':'assessed not affected'})

def test_action_link_retains_origin_and_rejects_other_asset(service,demo):
    d=decision(demo);review(service,d);action=make_action(service,d)
    values={k:v for k,v in d['asset'].items() if k in vi.ExposureObservation.model_fields}
    vi.observe(service.store,d['context'],values|{'control_claim':'A changed unverified control claim'})
    updated=decision(current(service));review(service,updated)
    client=TestClient(create_app(service),base_url='http://localhost')
    result=client.post('/api/vulnerabilities/decisions/'+updated['id']+'/link',json=scope()|{'action_id':action['id'],'reason':'Retain original implementation and review the revised evidence'})
    assert result.status_code==200
    assert service.store.get('improvement',action['id'])['assessment_id']==d['id']
    other=team(current(service))['decisions'][1];review(service,other)
    rejected=client.post('/api/vulnerabilities/decisions/'+other['id']+'/link',json=scope()|{'action_id':action['id'],'reason':'Invalid different asset link'})
    assert rejected.status_code==422 and 'same asset/CVE' in rejected.json()['detail']
