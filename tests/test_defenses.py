import copy
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from iti import defenses, ledger
from iti.api import create_app
from iti.models import ImprovementAction, TestRun as RunRecord
from iti.store import digest, now

def selected(service, assessed):
    response=defenses.suggestions(service.store,assessed)
    row=next(r for r in response['behaviors'].values() if r['attack_id']=='T1105')
    return response,row['candidates'][0]

def action(candidate, **updates):
    return ImprovementAction(**(candidate['prefill']|{'owner':'Lab control owner'}|updates))

def reference(candidate):
    return {'snapshot_id':candidate['snapshot_id'],'candidate_id':candidate['id']}

def test_real_exact_mappings_provenance_and_offline(service,assessed,monkeypatch):
    monkeypatch.setattr(socket,'create_connection',lambda *a,**k:pytest.fail('Runtime lookup attempted networking'))
    a,c=selected(service,assessed)
    candidates=a['behaviors'][c['behavior_id']]['candidates']
    assert [x['d3fend_id'] for x in candidates]==['D3-APCA','D3-CSPP','D3-NTCD','D3-NTF','D3-NTSA','D3-OTF','D3-PHDURA','D3-PMAD','D3-RPA','D3-RTSD','D3-UGLPA']
    assert c['name']=='Application Protocol Command Analysis'
    assert c['reference']=='https://d3fend.mitre.org/technique/d3f:ApplicationProtocolCommandAnalysis'
    assert c['catalog']['revision']=='5c8bf4ca9ff64ef9b55c38a2505db318750cbcda'
    assert c['catalog']['ontology_version'] is None and c['mapping_basis']=='analyst_proposed'
    assert len(c['catalog']['catalog_sha256'])==64 and c['evidence']
    assert defenses.suggestions(service.store,assessed)==a
    assert all(x['improvement'] is None for x in candidates)

def test_empty_unsupported_subtechnique_and_catalog_errors(service,assessed,tmp_path):
    a=copy.deepcopy(assessed);b=a['extraction']['behaviors'][0]
    for tid,state in [(None,'no_attack_mapping'),('T1027.003','no_catalog_mapping'),('T1006','no_catalog_mapping'),('T9999.123','unsupported_id'),('T0800','unsupported_id'),('AML.T0000','unsupported_id')]:
        b['technique_id']=tid;r=defenses.assess(a)['behaviors'][b['id']]
        assert r['state']==state and not r['candidates']
    catalog,_=defenses.load_catalog()
    assert catalog['mappings'].get('T1027') # child must not inherit this real parent mapping
    assert defenses.assess(a,tmp_path)['state']=='catalog_unavailable'
    (tmp_path/'catalog.json').write_text('{}');(tmp_path/'pin.json').write_text('{"sha256":"bad"}')
    assert defenses.assess(a,tmp_path)['state']=='catalog_unavailable'
    changed=copy.deepcopy(catalog);changed['mappings']['T1105']=['D3-FAKE']
    raw=json.dumps(changed).encode();(tmp_path/'catalog.json').write_bytes(raw)
    (tmp_path/'pin.json').write_text(json.dumps({'sha256':digest(raw),'revision':catalog['provenance']['revision']}))
    assert defenses.assess(a,tmp_path)['state']=='catalog_unavailable'

def test_create_retry_concurrent_freezes_origin_and_does_not_verify(service,assessed):
    _,c=selected(service,assessed);before=ledger.view(service.store,assessed)
    def create(_):return ledger.improve(service.store,assessed,action(c,proposed_change='Enable the reviewed lab control',retest='Lab A; expected blocked action; collect control event'),reference(c))
    with ThreadPoolExecutor(max_workers=6) as pool:rows=list(pool.map(create,range(10)))
    assert len({r['id'] for r in rows})==1 and len(service.store.all('improvement'))==1
    row=rows[0];assert row['proposed_change']=='Enable the reviewed lab control'
    assert row['origin']['evidence']==c['evidence'] and row['origin']['catalog']==c['catalog']
    assert row['context']==assessed['context'] and row['assessment_id']==assessed['id']
    assert row['status']=='open' and not row['deployed_at']
    after=ledger.view(service.store,assessed)
    for key in ['rows','counts','metrics','tests']:assert before[key]==after[key]
    assert len([e for e in after['history'] if e['kind']=='improvement_open'])==1
    assert selected(service,assessed)[1]['improvement']=={'id':row['id'],'status':'open'}

def test_manual_compatibility_updates_retest_and_origin_tampering(service,assessed):
    _,c=selected(service,assessed)
    manual=ledger.improve(service.store,assessed,action(c));assert manual['origin'] is None
    created=ledger.improve(service.store,assessed,action(c),reference(c))
    fields={k:v for k,v in created.items() if k in ImprovementAction.model_fields}
    fields.pop('origin') # legacy clients may omit it; server must preserve it
    fields.update(status='deployed',owner='Edited control owner',retest='Revised plan')
    updated=ledger.improve(service.store,assessed,ImprovementAction(**fields))
    assert updated['origin']==created['origin'] and updated['opened_at']==created['opened_at']
    assert updated['owner']=='Edited control owner' and updated['context']==created['context']
    bad=fields|{'origin':created['origin']|{'d3fend_id':'D3-FAKE'}}
    with pytest.raises(ValueError,match='altered'):ledger.improve(service.store,assessed,ImprovementAction(**bad))
    with pytest.raises(ValueError,match='not trusted'):ledger.improve(service.store,assessed,action(c,origin=created['origin']))
    t=RunRecord(behavior_id=c['behavior_id'],environment_version=1,control_id='reviewed-control',control_version='v1',
      procedure='Authored attestation only',expected='Review required',actual='Plan reviewed',executed_at=now(),
      method='analyst attestation',result='inconclusive',dimension='detection',scope='authored lab',variant='variant A',
      improvement_id=created['id'],evidence=[{'id':'attestation','reference':'authored:test','description':'Fixture attestation','kind':'analyst attestation'}])
    ledger.record_test(service.store,assessed,t)
    assert service.store.get('improvement',created['id'])['origin']==created['origin']
    fields['status']='closed'
    ledger.improve(service.store,assessed,ImprovementAction(**fields))
    metrics=ledger.view(service.store,assessed)['metrics']
    assert metrics['source_ingestion_to_live_detection_seconds'] is None
    assert metrics['source_ingestion_to_live_prevention_seconds'] is None

def test_scope_membership_and_api_guard(service,assessed):
    _,c=selected(service,assessed)
    with TestClient(create_app(service),base_url='http://127.0.0.1') as client:
        url='/api/assessments/'+assessed['id']+'/defenses'
        assert client.get(url,params={'customer_id':'fictional-cloud','environment_id':'windows-ad'}).status_code!=200
        assert client.get(url,params={'customer_id':'fictional-bank','environment_id':'wrong'}).status_code!=200
        body={'customer_id':'fictional-bank','environment_id':'wrong','candidate_ref':reference(c),'action':action(c).model_dump()}
        assert client.post('/api/ledger/'+assessed['id']+'/improve',json=body).status_code!=200
        body['environment_id']='windows-ad';body['action']['behavior_id']=assessed['extraction']['behaviors'][0]['id']
        assert client.post('/api/ledger/'+assessed['id']+'/improve',json=body).status_code==422
        body['action']=action(c).model_dump();body['candidate_ref']['candidate_id']='forged'
        assert client.post('/api/ledger/'+assessed['id']+'/improve',json=body).status_code==422
        body['candidate_ref']=reference(c)
        assert client.post('/api/ledger/'+assessed['id']+'/improve',json=body).status_code==200
    other=copy.deepcopy(assessed);other['id']='another-assessment'
    with pytest.raises(ValueError,match='mismatch'):ledger.improve(service.store,other,action(c),reference(c))

def test_catalog_change_preserves_snapshots_actions_and_package(service,assessed,monkeypatch,tmp_path):
    package=service.generate(assessed['id'],'fictional-bank')
    root=service.store.root/'artifacts'/package['id'];before={p.name:digest(p.read_bytes()) for p in root.iterdir()}
    snap,c=selected(service,assessed);created=ledger.improve(service.store,assessed,action(c),reference(c))
    catalog,checksum=defenses.load_catalog();changed=copy.deepcopy(catalog)
    changed['provenance']['transformation_version']='authored-test-revision'
    original=defenses.load_catalog
    monkeypatch.setattr(defenses,'load_catalog',lambda directory=None:(changed,digest('authored changed catalog')))
    newer,c2=selected(service,assessed)
    assert newer['snapshot_id']!=snap['snapshot_id'] and c2['id']!=c['id']
    assert c2['improvement']['id']==created['id']
    assert ledger.improve(service.store,assessed,action(c2),reference(c2))==created
    assert service.store.get('defense_snapshot',snap['snapshot_id'])['catalog']['catalog_sha256']==checksum
    monkeypatch.setattr(defenses,'load_catalog',lambda directory=None:(_ for _ in ()).throw(defenses.CatalogError('Unavailable')))
    assert defenses.suggestions(service.store,assessed)['state']=='catalog_unavailable'
    # A previously displayed, valid frozen selection remains usable despite current catalog failure.
    assert ledger.improve(service.store,assessed,action(c),reference(c))==created
    assert before=={p.name:digest(p.read_bytes()) for p in root.iterdir()}
    monkeypatch.setattr(defenses,'load_catalog',original)

def test_duplicate_catalog_rows_stable_and_frozen_profile(service,assessed,monkeypatch):
    catalog,checksum=defenses.load_catalog();catalog['mappings']['T1105']*=2
    monkeypatch.setattr(defenses,'load_catalog',lambda directory=None:(catalog,checksum))
    _,c=selected(service,assessed)
    ids=[x['id'] for x in defenses.assess(assessed)['behaviors'][c['behavior_id']]['candidates']]
    assert len(ids)==len(set(ids))==11
    customer=service.store.get('customer','fictional-bank');customer['version']+=1;service.store.put('customer',customer['id'],customer)
    row=ledger.improve(service.store,assessed,action(c),reference(c))
    assert row['context']['customer_version']==1
