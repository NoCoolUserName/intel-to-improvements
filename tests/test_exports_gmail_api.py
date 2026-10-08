import copy,json,base64
from datetime import datetime,timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from iti.models import GmailScope,CustomerProfile
from iti import gmail,profiles,exporters,misp
from iti.store import now,ROOT,uid

def test_exports_valid_stable_no_ioc(service,assessed):
    p=service.generate(assessed['id'],'fictional-bank');root=service.store.root/'artifacts'/p['id']
    stix=(root/'cti.stix21.json').read_text();native=json.loads((root/'cti.misp.json').read_text())
    assert exporters.validate_stix(stix)['valid'];assert exporters.validate_misp(native);assert native['Event']['published'] is False and native['Event']['distribution']=='0'
    assert all(not a['to_ids'] for a in native['Event']['Attribute'])
    assert p['artifacts']['validation']['converter']['status']=='completed'
    assert service.generate(assessed['id'],'fictional-bank')['id']==p['id']
    j=service.submit('fictional-bank','windows-ad','offline','case','no-ioc',background=False);n=service.generate(j['data']['assessment_id'],'fictional-bank')
    b=json.loads((service.store.root/'artifacts'/n['id']/'cti.stix21.json').read_text())
    assert not any(o['type']=='indicator' for o in b['objects']) and any(o['type']=='attack-pattern' for o in b['objects']) and n['hunts']
    with pytest.raises(KeyError):service.scoped('package',p['id'],'fictional-cloud')

def test_stix_import_preserves_ids_and_invalid_patterns(service,assessed):
    from iti.ingestion import ingest
    p=service.generate(assessed['id'],'fictional-bank');data=(service.store.root/'artifacts'/p['id']/'cti.stix21.json').read_bytes();s=ingest(service.store,data,'bundle.json','stix','fictional-bank')
    orig=json.loads(data);assert {o['id'] for o in orig['objects']}=={o['id'] for o in s.imported_objects}
    bad=json.loads(data);indicator=next(o for o in bad['objects'] if o['type']=='indicator');indicator['pattern']='INVALID PATTERN'
    with pytest.raises(Exception):ingest(service.store,json.dumps(bad).encode(),'bad.json','stix-bad','shared')

def test_misp_input_preserves_attributes(service,assessed):
    from iti.ingestion import ingest
    p=service.generate(assessed['id'],'fictional-bank');raw=(service.store.root/'artifacts'/p['id']/'cti.misp.json').read_bytes();s=ingest(service.store,raw,'event.json','misp','shared')
    assert any('166.62.100.52' in x.text for x in s.spans) and s.metadata['source_event_uuid']

@pytest.fixture
def request_sample(service):
    req=gmail.prepare(service.store,'fictional-bank','windows-ad',GmailScope(query='label:Research newer_than:30d',max_messages=2));return req,gmail.sample(req)

def test_gmail_preview_import_idempotent_frozen(service,request_sample):
    req,h=request_sample;raw=json.dumps(h);preview=gmail.preview(service.store,raw,'fictional-bank')
    assert preview['messages'][0]['completeness']=='partial';assert 'TB10001' in preview['messages'][0]['body']
    c=CustomerProfile.model_validate(service.store.get('customer','fictional-bank'));profiles.save(service.store,c)
    r=gmail.process(service,raw,'fictional-bank',background=False);r2=gmail.process(service,raw,'fictional-bank',background=False)
    assert r['counts']['new_imported']==1 and r2['counts']['duplicate']==1
    job=service.job(r['results'][0]['job_id']);assert job['state']=='complete' and job['data']['context']['customer_version']==1
    a=service.store.get('assessment',job['data']['assessment_id']);assert a['source']['completeness']=='partial';assert 'original email' in a['source']['hash_basis']
    p=service.generate(a['id'],'fictional-bank');assert p['source']['gaps'] and p['relevance']['uncertainty']
    assert set(s['value'] for s in a['source']['serials'])=={'TB10001','TB10002'}

def test_gmail_context_snippets_counts_paths(service,request_sample):
    req,h=request_sample
    wrong=copy.deepcopy(h);wrong['context']['customer_id']='fictional-cloud'
    with pytest.raises(ValueError,match='context'):gmail.preview(service.store,json.dumps(wrong),'fictional-bank')
    with pytest.raises(ValueError,match='another customer'):gmail.preview(service.store,json.dumps(h),'fictional-cloud')
    bad=copy.deepcopy(h);bad['messages'][0]['attachments'][0]={'filename':'../../secret.txt','content_base64':base64.b64encode(b'x').decode()}
    with pytest.raises(ValueError,match='traversal'):gmail.preview(service.store,json.dumps(bad),'fictional-bank')
    short=copy.deepcopy(h);short['messages'][0]['representation']='snippet';short['messages'][0]['completeness']='complete-for-supported-content'
    p=gmail.preview(service.store,json.dumps(short),'fictional-bank');assert p['messages'][0]['completeness']=='partial'
    assert p['counts']['omitted'] is None

def test_gmail_split_limit_partial_failures_attachments(service,request_sample):
    req,h=request_sample
    h['messages'][0]['attachments']=[{'filename':'attached report.txt','part_id':'a1','content_base64':base64.b64encode(b'AnyDesk was installed on Windows.').decode()}]
    failed=copy.deepcopy(h['messages'][0]);failed.update(message_id='failure-id',body='',completeness='failed',report_serials=[],attachments=[]);h['messages'].append(failed)
    r=gmail.process(service,json.dumps(h),'fictional-bank',background=False);assert r['counts']['failed']==1 and len(r['results'][0]['attachment_jobs'])==1
    part=copy.deepcopy(h);part['part']=2;part['messages']=[copy.deepcopy(h['messages'][0])];part['messages'][0]['message_id']='third-message'
    gmail.process(service,json.dumps(part),'fictional-bank',background=False)
    part['part']=3;part['messages'][0]['message_id']='fourth-message'
    with pytest.raises(ValueError,match='limit'):gmail.process(service,json.dumps(part),'fictional-bank')

def test_api_origin_upload_scope_and_all_handoff_transports(service,request_sample,tmp_path):
    from iti.api import create_app
    req,h=request_sample;raw=json.dumps(h);file=tmp_path/'Gmail handoff ü.json';file.write_text(raw)
    with TestClient(create_app(service),base_url='http://127.0.0.1') as client:
        assert client.get('/health').status_code==200
        assert client.post('/api/ingest',headers={'Origin':'https://evil.example'},json={}).status_code==403
        assert client.get('/health',headers={'Host':'evil.example'}).status_code==400
        assert client.post('/api/gmail/preview',json={'customer_id':'fictional-bank','json':raw}).status_code==200
        assert client.post('/api/gmail/preview',json={'customer_id':'fictional-bank','path':str(file)}).status_code==200
        assert client.post('/api/gmail/upload',data={'customer_id':'fictional-bank'},files={'file':('handoff.json',raw,'application/json')}).status_code==200
        assert client.post('/api/upload',data={'customer_id':'fictional-bank','environment_id':'windows-ad'},files={'file':('../../evil.txt',b'text')}).status_code==422
        assert client.post('/api/gmail/process',json={'customer_id':'fictional-bank','json':raw}).status_code==200
    assert file.read_text()==raw

class FakeMISP:
    def __init__(self):self.events={};self.creates=0;self.updates=0;self.timeout=False
    def search(self,**kwargs):return [{'Event':copy.deepcopy(self.events[kwargs['uuid']])}] if kwargs['uuid'] in self.events else []
    def add_event(self,payload,**kwargs):
        ev=copy.deepcopy(payload['Event']);self.events[ev['uuid']]=ev;self.creates+=1
        if self.timeout:self.timeout=False;raise TimeoutError('write completed but reply lost')
        return {'Event':ev}
    def update_event(self,payload,**kwargs):self.events[payload['Event']['uuid']]=copy.deepcopy(payload['Event']);self.updates+=1;return payload
    def get_event(self,uuid,**kwargs):return {'Event':copy.deepcopy(self.events[uuid])}
    def get_version(self):return {'version':'synthetic-test-instance'}

def test_misp_upsert_timeout_reconcile_preserve_and_conflict(service,monkeypatch):
    c=CustomerProfile.model_validate(service.store.get('customer','fictional-bank'));c.misp_destination='https://misp.example.invalid';profiles.save(service.store,c)
    j=service.submit(c.id,'windows-ad','replay','case','activemq-derived',background=False);p=service.generate(j['data']['assessment_id'],c.id);client=FakeMISP();client.timeout=True
    with pytest.raises(ValueError,match='uncertain'):misp.import_event(service.store,p,client)
    result=misp.import_event(service.store,p,client);assert result['status']=='reconciled after uncertain write' and client.creates==1
    event=next(iter(client.events.values()));event['Attribute'].append({'uuid':'analyst-uuid','type':'comment','value':'Keep this analyst note','to_ids':False})
    misp.import_event(service.store,p,client);assert client.creates==1 and any(a['uuid']=='analyst-uuid' for a in next(iter(client.events.values()))['Attribute'])
    event=next(iter(client.events.values()));event['info']='Analyst changed managed info'
    with pytest.raises(ValueError,match='changed remotely'):misp.import_event(service.store,p,client)

def test_misp_scoped_identity_profile_revision(service):
    j=service.submit('fictional-bank','windows-ad','replay','case','activemq-derived',background=False);a=service.generate(j['data']['assessment_id'],'fictional-bank')
    first=json.loads((service.store.root/'artifacts'/a['id']/'cti.misp.json').read_text())['Event']['uuid']
    c=CustomerProfile.model_validate(service.store.get('customer','fictional-bank'));profiles.save(service.store,c)
    j=service.submit('fictional-bank','windows-ad','replay','source',a['source']['revision_id'],background=False);b=service.generate(j['data']['assessment_id'],'fictional-bank')
    second=json.loads((service.store.root/'artifacts'/b['id']/'cti.misp.json').read_text())['Event']['uuid'];assert first==second
