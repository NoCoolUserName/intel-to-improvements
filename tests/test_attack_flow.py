"""Focused schema/provenance/ordering/isolation regression checks, not broad accuracy claims."""
import copy
import json
import zipfile
import pytest
from fastapi.testclient import TestClient
from iti import attack_flow, exporters, packages
from iti.api import create_app
from iti.models import EntityRelationship
from iti.store import digest, uid, now


def frozen(assessed):
    return copy.deepcopy(assessed) | {'id': 'test-package', 'assessment_id': assessed['id'], 'created_at': now()}


def relationship(package, source, target, kind='precedes', evidence=None):
    # Independent authored evidence for a directed temporal relation; not derived from sequence numbers.
    text = 'In the authored lab narrative, the download happened before remote service execution. It did not establish causation.'
    sid = 'authored-relationship-span'
    if not any(s['id']==sid for s in package['source']['spans']):
        start=len(package['source']['normalized'])
        package['source']['normalized']+=text
        package['source']['spans'].append({'id':sid,'revision_id':package['source']['revision_id'],'text':text,'start':start,'end':start+len(text)})
    rel=EntityRelationship(id='test-relationship',text=text,source_ref=source,target_ref=target,
                           relationship=kind,evidence=evidence if evidence is not None else [sid],
                           confidence_rationale='Independently authored temporal fixture').model_dump()
    package['extraction']['relationships'].append(rel)
    return rel


def test_flow_sequence_evidence_direction_stability_and_frozen_provenance(service, assessed):
    p=frozen(assessed);left=p['extraction']['behaviors'][1];right=p['extraction']['behaviors'][4]
    relationship(p,left['id'],right['id'])
    text,prov,status=attack_flow.export(service.store,p);bundle=json.loads(text)
    assert attack_flow.validate_bundle(bundle)['valid']
    actions={a['behavior_id']:a['action_id'] for a in prov['actions']}
    byid={o['id']:o for o in bundle['objects']}
    assert byid[actions[left['id']]]['effect_refs']==[actions[right['id']]]
    assert 'effect_refs' not in byid[actions[right['id']]]
    assert prov['edges'][0]['evidence'][0]['text'].startswith('In the authored lab')
    assert 'causation not established' in prov['edges'][0]['semantics']
    assert status['ordering']=='partial' and status['edges']==1
    assert prov['context']['customer_id']=='fictional-bank' and prov['package_id']==p['id']
    assert prov['source_hash']==p['source']['content_hash'] and prov['extraction_id']==p['extraction']['id']
    assert byid[byid[actions[left['id']]]['created_by_ref']]['name']=='Intel to Improvements'
    assert byid[actions[left['id']]]['technique_id']==left['technique_id']
    assert prov['actions'][1]['mapping_basis']==left['mapping_basis']
    assert attack_flow.export(service.store,p)[0]==text
    # Editing current customer cannot change the frozen export.
    customer=service.store.get('customer','fictional-bank');customer['version']+=1
    service.store.put('customer',customer['id'],customer)
    assert attack_flow.export(service.store,p)[0]==text
    p['extraction']['relationships'][0].update(relationship='follows',source_ref=right['id'],target_ref=left['id'])
    assert attack_flow.export(service.store,p)[1]['edges'][0]['source_behavior']==left['id']


def test_unknown_order_repeated_technique_and_inapplicable_actions(service,assessed):
    p=frozen(assessed)
    repeated=copy.deepcopy(p['extraction']['behaviors'][1]);repeated.update(id='distinct-occurrence',text='A second reported download in a separate occurrence.',sequence=999)
    p['extraction']['behaviors'].append(repeated)
    p['coverage']=[dict(r,applicability='not applicable') for r in p['coverage']]
    text,prov,status=attack_flow.export(service.store,p)
    actions=[o for o in json.loads(text)['objects'] if o['type']=='attack-action']
    assert len(actions)==9 and status['ordering']=='unordered' and status['edges']==0
    assert len([a for a in actions if a.get('technique_id')==repeated['technique_id']])==2
    assert all('effect_refs' not in a for a in actions)
    flow=next(o for o in json.loads(text)['objects'] if o['type']=='attack-flow')
    assert len(flow['start_refs'])==9
    assert 'not simultaneous or AND/OR' in flow['description']
    assert {a['behavior_id'] for a in prov['actions']}=={b['id'] for b in p['extraction']['behaviors']}


def test_empty_unsupported_partial_and_cyclic_order(service,assessed):
    p=frozen(assessed)
    for b in p['extraction']['behaviors']:b['kind']='analyst_inference'
    text,prov,status=attack_flow.export(service.store,p)
    assert text is None and status['status']=='empty' and status['validation'] is None
    assert len(prov['omissions'])==8
    p=frozen(assessed);p['source']['completeness']='partial';p['source']['gaps']=['missing attachment']
    a,b=p['extraction']['behaviors'][:2]
    relationship(p,a['id'],b['id']);relationship(p,b['id'],a['id'])
    text,prov,status=attack_flow.export(service.store,p)
    assert status['edges']==0 and status['source_gaps']==['missing attachment']
    assert 'missing attachment' in text and any('Cyclic' in x['reason'] for x in prov['omissions'])
    p['extraction']['relationships'][1]['kind']='analyst_inference'
    assert attack_flow.export(service.store,p)[2]['edges']==1


def test_reject_dangling_spans_refs_ids_invalid_mapping_schema(service,assessed):
    p=frozen(assessed);a,b=p['extraction']['behaviors'][:2]
    relationship(p,a['id'],b['id'],evidence=['made-up-span'])
    with pytest.raises(ValueError,match='evidence'):attack_flow.export(service.store,p)
    p=frozen(assessed);text,_,_=attack_flow.export(service.store,p);valid=json.loads(text)
    action=next(o for o in valid['objects'] if o['type']=='attack-action')
    action['effect_refs']=['attack-action--00000000-0000-4000-8000-000000000000']
    with pytest.raises(ValueError,match='Dangling'):attack_flow.validate_bundle(valid)
    action.pop('effect_refs');action['id']='attack-action--fabricated'
    with pytest.raises(ValueError):attack_flow.validate_bundle(valid)
    valid=json.loads(text);next(o for o in valid['objects'] if o['type']=='attack-flow')['start_refs']=[]
    with pytest.raises(Exception):attack_flow.validate_bundle(valid)
    p['extraction']['behaviors'][0]['technique_id']='T99999'
    with pytest.raises(ValueError,match='not in pinned'):attack_flow.export(service.store,p)


def test_package_manifest_zip_history_and_cti_misp_unchanged(service,assessed):
    # Preserve a real previous package shape without generating a fake backfilled file.
    old=copy.deepcopy(assessed)|{'id':uid('package',assessed['id'],'packages-5'),'assessment_id':assessed['id'],'artifacts':{'names':['hunt.md']}}
    service.store.put('package',old['id'],old,immutable=True)
    p=service.generate(assessed['id'],'fictional-bank');root=service.store.root/'artifacts'/p['id']
    assert p['id']!=old['id'] and service.store.get('package',old['id'])==old
    assert 'attack-flow.json' in p['artifacts']['names']
    manifest=json.loads((root/'manifest.json').read_text())
    assert manifest['artifacts']['attack-flow.json']==digest((root/'attack-flow.json').read_bytes())
    assert manifest['validation']['attack_flow']['validation']['valid']
    with zipfile.ZipFile(root/'package.zip') as z:assert z.read('attack-flow.json')==(root/'attack-flow.json').read_bytes()
    assert exporters.validate_stix((root/'cti.stix21.json').read_text())['valid']
    assert exporters.validate_misp(json.loads((root/'cti.misp.json').read_text()))
    assert exporters.stix_export(service.store,p)[0]==(root/'cti.stix21.json').read_text()
    assert exporters.misp_export(service.store,p)[0]==(root/'cti.misp.json').read_text()
    assert 'attack-action' not in (root/'cti.stix21.json').read_text()
    assert json.loads((root/'purple-team.json').read_text())['scenarios']==p['emulations']
    assert service.generate(assessed['id'],'fictional-bank')==p


def test_scoped_downloads_viewer_csp_and_empty_package(service,assessed):
    p=service.generate(assessed['id'],'fictional-bank')
    with TestClient(create_app(service),base_url='http://127.0.0.1') as c:
        path='/api/artifacts/'+p['id']+'/attack-flow.json'
        assert c.get(path,params={'customer_id':'fictional-bank','environment_id':'windows-ad'}).status_code==200
        assert c.get(path,params={'customer_id':'fictional-cloud','environment_id':'windows-ad'}).status_code==404
        assert c.get(path,params={'customer_id':'fictional-bank','environment_id':'mac-cloud'}).status_code==404
        assert c.get('/api/attack-flow/viewer').status_code==200
        response=c.get('/attack-flow-builder/')
        if response.status_code==200:
            assert "frame-ancestors 'self'" in response.headers['content-security-policy']
            assert "connect-src 'self'" in response.headers['content-security-policy']
            assert '/attack-flow-builder/assets/' in response.text
        else:assert response.status_code==503
        assert "frame-ancestors 'none'" in c.get('/health').headers['content-security-policy']
    job=service.submit('fictional-bank','windows-ad','offline','case','insufficient',background=False)
    empty=service.generate(job['data']['assessment_id'],'fictional-bank')
    assert empty['artifacts']['validation']['attack_flow']['status']=='empty'
    assert 'attack-flow.json' not in empty['artifacts']['names']
