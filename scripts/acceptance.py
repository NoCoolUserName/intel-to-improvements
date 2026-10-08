"""Read/write local API smoke path; records actual synthetic execution, never live coverage."""
import json,time,sys
from pathlib import Path
import httpx
base='http://127.0.0.1:8000';client=httpx.Client(base_url=base,timeout=45);results=[]
def get(path):
 r=client.get(path);r.raise_for_status();return r.json()
def post(path,data):
 r=client.post(path,json=data);r.raise_for_status();return r.json()
assert get('/health')['status']=='ok';results.append('health')
boot=get('/api/bootstrap');assert len(boot['customers'])>=2;results.append('profiles')
j=post('/api/ingest',{'customer_id':'fictional-bank','environment_id':'windows-ad','mode':'replay','kind':'case','value':'activemq-derived'})
for _ in range(80):
 j=next(x for x in get('/api/jobs?customer_id=fictional-bank') if x['id']==j['id'])
 if j['state'] in ('complete','failed'):break
 time.sleep(.05)
assert j['state']=='complete',j;aid=j['data']['assessment_id'];a=get('/api/assessments/'+aid+'?customer_id=fictional-bank&environment_id=windows-ad');assert len(a['extraction']['behaviors'])==8;results.append('replay ingestion, assessment, evidence')
p=post('/api/assessments/'+aid+'/generate',{'customer_id':'fictional-bank'});results.append('package generation')
for name in p['artifacts']['names']:
 r=client.get('/api/artifacts/'+p['id']+'/'+name,params={'customer_id':'fictional-bank','environment_id':'windows-ad'});assert r.status_code==200 and len(r.content)>10
results.append('all artifact downloads and ZIP')
r=client.get('/api/artifacts/'+p['id']+'/cti.misp.json',params={'customer_id':'fictional-cloud','environment_id':'mac-cloud'});assert r.status_code==404;results.append('cross-customer artifact rejection')
candidate=next(c for c in a['candidates'] if c['id']=='19b08b1c-861d-4e75-a1ef-ea0c1baf202b')
s=post('/api/ledger/'+aid+'/synthetic',{'customer_id':'fictional-bank','behavior_id':candidate['behavior_id'],'rule_id':candidate['id']});assert [x['result'] for x in s['cases'].values()]==['match','no match','inconclusive'];results.append('actual synthetic positive/negative/missing-field execution')
l=get('/api/ledger/'+aid+'?customer_id=fictional-bank&environment_id=windows-ad');assert l['counts']['live_detection_passed']==0 and l['metrics']['source_ingestion_to_live_detection_seconds'] is None;results.append('synthetic remains separate from live coverage')
action=post('/api/ledger/'+aid+'/improve',{'customer_id':'fictional-bank','action':{'behavior_id':candidate['behavior_id'],'owner':'Fictional lab owner','priority':'medium','status':'open','rationale':'Local API acceptance: demonstrate the improvement workflow. No production gap is asserted.','proposed_change':'Verify the raw-event field map against an approved lab source before deployment','retest':'Collect actual lab evidence and compare positive, benign and missing-field variants'}});results.append('improvement recorded with scope and retest')
req=post('/api/gmail/prepare',{'customer_id':'fictional-bank','environment_id':'windows-ad','scope':{'query':'subject:synthetic-acceptance-only','max_messages':1}});sample=get('/api/gmail/sample/'+req['id']+'?customer_id=fictional-bank');preview=post('/api/gmail/preview',{'customer_id':'fictional-bank','json':json.dumps(sample)});assert preview['messages'][0]['completeness']=='partial';imported=post('/api/gmail/process',{'customer_id':'fictional-bank','json':json.dumps(sample)});assert imported['counts']['new_imported']==1;again=post('/api/gmail/process',{'customer_id':'fictional-bank','json':json.dumps(sample)});assert again['counts']['duplicate']==1;results.append('synthetic Gmail request / preview / process / idempotent reimport')
from datetime import datetime,timezone
report={'executed_at':datetime.now(timezone.utc).isoformat(),'transport':'actual local HTTP API, not browser automation','checks':results,'assessment_id':aid,'package_id':p['id'],'synthetic_test_results':s,'live_coverage_confirmed':False,'browser_screenshot':'NOT RUN: IAB unavailable; native Chrome access rejected by Computer Use permissions','gmail_live_retrieval':'NOT RUN: no operator retrieval scope supplied'}
Path('validation/api-acceptance.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
