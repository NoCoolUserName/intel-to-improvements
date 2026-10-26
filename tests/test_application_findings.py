import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from iti import application_findings as af, profiles
from iti.application_sarif import parse, MAX_BYTES
from iti.api import create_app
from iti.models import CustomerProfile
from iti.store import ROOT, digest

SCOPE = {'customer_id': 'fictional-bank', 'environment_id': 'windows-ad'}
OTHER = {'customer_id': 'fictional-cloud', 'environment_id': 'mac-cloud'}


def fixture(name='codeql'):
    return (ROOT / 'fixtures/application-findings' / (name + '.sarif.json')).read_bytes()


def preview(service, raw=None, **operator):
    return af.preview(service.store, 'fictional-bank', 'windows-ad', raw or fixture(), operator)


def confirm(service, p):
    return af.confirm(service.store, p['id'], 'fictional-bank', 'windows-ad')


@pytest.mark.parametrize('name', ['codeql','semgrep'])
def test_real_api_import_and_immutable_evidence(service, name):
    client = TestClient(create_app(service), base_url='http://localhost')
    raw = fixture(name)
    p = client.post('/api/application-findings/preview', data=SCOPE | {'application':'Synthetic app'}, files={'file':('example.sarif',raw)}).json()
    assert not service.store.all('application_finding')
    assert len(p['findings']) == 2
    assert all(r['cwes'] == ['CWE-079'] and r['cves'] == [] and r['synthetic'] for r in p['findings'])
    response = client.post('/api/application-findings/confirm', json=SCOPE | {'preview_id':p['id']})
    assert response.status_code == 200
    batch = response.json()
    rows = client.get('/api/application-findings', params=SCOPE).json()['findings']
    assert len(rows) == 2 and rows[0]['logical_id'] != rows[1]['logical_id']
    detail = client.get('/api/application-findings/'+rows[0]['id'], params=SCOPE).json()
    assert detail['finding']['verification'] == 'scanner reported; not independently validated'
    assert detail['import']['scan_completeness'] == 'unknown'
    assert detail['source']['sha256'] == digest(raw)
    source_path = '/api/application-findings/sources/'+detail['source']['id']
    downloaded = client.get(source_path, params=SCOPE)
    assert downloaded.content == raw and 'attachment' in downloaded.headers['content-disposition']
    for path in [source_path, '/api/application-findings/'+rows[0]['id'], '/api/application-findings/imports/'+batch['id']]:
        assert client.get(path, params=OTHER).status_code == 404
    for kind in ['vulnerability_exposure','improvement','test','assessment']:
        assert service.store.all(kind) == []
    assert rows[0]['scanner_level'] == ('warning' if name == 'codeql' else None)
    assert ('rule.properties' in rows[0]['severity_metadata'])
    assert client.post('/api/application-findings/confirm',json=SCOPE|{'preview_id':p['id'],'findings':[]}).status_code == 422
    assert client.post('/api/application-findings/preview',data=SCOPE,files={'file':('x',raw)},headers={'Origin':'https://evil.invalid'}).status_code == 403


def test_idempotence_concurrency_new_evidence_and_scope(service):
    p = preview(service, repository='repo')
    with ThreadPoolExecutor(max_workers=4) as pool:
        batches = list(pool.map(lambda _: confirm(service,p), range(4)))
    assert sum(not b['duplicate'] for b in batches) == 1
    first = service.store.all('application_finding')
    again = preview(service, repository='repo')
    assert confirm(service,again)['duplicate']
    document = json.loads(fixture()); document['runs'][0]['results'] = document['runs'][0]['results'][:1]
    newer = preview(service, json.dumps(document).encode(), repository='repo'); confirm(service,newer)
    after = service.store.all('application_finding')
    assert len(after) == 3
    assert all(r in after for r in first)
    assert newer['findings'][0]['logical_id'] == p['findings'][0]['logical_id']
    assert not any('status' in r or 'fixed' in r for r in after)
    other = af.preview(service.store, 'fictional-cloud','mac-cloud',fixture(),{'repository':'repo'})
    assert other['findings'][0]['logical_id'] != p['findings'][0]['logical_id']
    with pytest.raises(KeyError): af.confirm(service.store, p['id'], 'fictional-cloud','mac-cloud')
    assert af.workspace(service.store,'fictional-cloud','mac-cloud')['findings'] == []


def test_stale_expired_forged_preview_and_blob_integrity(service):
    p = preview(service)
    with pytest.raises(KeyError): af.confirm(service.store, 'app_preview_forged', 'fictional-bank','windows-ad')
    customer = CustomerProfile.model_validate(service.store.get('customer','fictional-bank'))
    profiles.save(service.store, customer)
    with pytest.raises(ValueError, match='Profile changed'): confirm(service,p)
    p = preview(service)
    service.store.put('application_preview',p['id'],p|{'expires_at':(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()})
    with pytest.raises(ValueError, match='expired'): confirm(service,p)
    p = preview(service)
    (service.store.root/'blobs'/p['source_sha256']).write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='integrity'): confirm(service,p)
    assert not service.store.all('application_batch') and not service.store.all('application_finding')


def test_multiple_runs_rule_references_and_message_resolution(service):
    doc = json.loads(fixture()); run = doc['runs'][0]
    second = copy.deepcopy(run); doc['runs'].append(second)
    second['tool']['driver']['rules'][0]['id'] = 'different-rule'
    for result in second['results']:
        result.pop('ruleId'); result['rule'] = {'index':0}
    second['tool']['driver']['rules'][0]['messageStrings']={'example':{'text':'Reported {0}'}}
    second['results'][0]['message']={'id':'example','arguments':['text <script>']}
    p = preview(service,json.dumps(doc).encode())
    assert [r['run_index'] for r in p['findings']] == [0,0,1,1]
    assert p['findings'][2]['rule_id'] == 'different-rule'
    assert p['findings'][2]['resolved_message'] == 'Reported text <script>'
    second['tool']['extensions']=[{'name':'extension','rules':[{'id':'extension-rule'}]}]
    second['results'][0]['rule']={'index':0,'toolComponent':{'index':0}}
    assert preview(service,json.dumps(doc).encode())['findings'][2]['rule_id']=='extension-rule'
    run['results'][0]['ruleId']='conflict'
    with pytest.raises(ValueError,match='disagree'): preview(service,json.dumps(doc).encode())


@pytest.mark.parametrize('raw', [b'{',b'[]',b'{"version":"2.0"}',b'{"version":"2.1.0","version":"2.1.0"}',b'['*2000+b']'*2000,b' '* (MAX_BYTES+1)])
def test_invalid_input_no_partial_storage(service, raw):
    with pytest.raises(ValueError): preview(service,raw)
    assert not service.store.all('application_preview')
    assert not list((service.store.root/'blobs').iterdir())


@pytest.mark.parametrize('change', ['results','type','string','depth','nan','surrogate','index'])
def test_structural_limits(service, change):
    doc = json.loads(fixture()); run = doc['runs'][0]
    if change=='results': run['results'] *= 501
    if change=='type': run['results'][0]['locations']='wrong'
    if change=='string': run['results'][0]['message']['text']='x'*32769
    if change=='depth':
        value={}
        for _ in range(35): value={'x':value}
        run['properties']=value
    if change=='nan': run['properties']={'x':float('nan')}
    if change=='surrogate': run['properties']={'x':'\ud800'}
    if change=='index': run['results'][0]['ruleIndex']=10
    with pytest.raises(ValueError): preview(service,json.dumps(doc).encode())
    assert not service.store.all('application_preview')


def test_unsafe_uris_and_failed_invocation_are_evidence_only(service):
    doc = json.loads(fixture('semgrep')); run = doc['runs'][0]
    run['invocations']=[{'executionSuccessful':False,'exitCode':1,'startTimeUtc':'2026-01-01T00:00:00Z'}]
    run['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']='file:///etc/passwd'
    run['results'][1]['locations'][0]['physicalLocation']['artifactLocation']['uri']='javascript:alert(1)'
    run['results'][0]['message']['text']='<script>alert(1)</script> $(touch /tmp/nope)'
    run['results'][0]['properties']={'cve':'CVE-2026-12345'}
    p=preview(service,json.dumps(doc).encode()); confirm(service,p)
    r=p['findings'][0]
    assert r['invocation_status']=='failed or incomplete'
    assert r['scanner_level'] is None and r['level_source'] is None
    assert r['cves']==['CVE-2026-12345']
    assert r['scan_timestamps']==[{'startTimeUtc':'2026-01-01T00:00:00Z'}]
    assert '<script>' in r['message']['text']
    assert r['locations'][0]['artifact']['uri']=='file:///etc/passwd'
    assert not service.store.all('test')


def test_missing_fallback_and_artifact_reference(service):
    doc=json.loads(fixture('semgrep')); run=doc['runs'][0]
    run['artifacts']=[{'location':{'uri':'relative/path.txt'}}]
    r=run['results'][1]; r['locations'][0]['physicalLocation']['artifactLocation']={'index':0}
    p=preview(service,json.dumps(doc).encode(),repository='repo')
    assert p['findings'][1]['locations'][0]['artifact']['uri']=='relative/path.txt'
    assert 'fallback' in p['findings'][1]['identity_basis']
    assert p['findings'][1]['warnings']
    run.pop('results')
    p=preview(service,json.dumps(doc).encode()); batch=confirm(service,p)
    assert not batch['finding_ids'] and batch['scan_completeness']=='unknown'
    assert any('Results absent' in w for w in batch['warnings'])


def test_transaction_rollback(service):
    p=preview(service)
    with service.store.connect() as c:
        c.execute("CREATE TRIGGER reject_app BEFORE INSERT ON records WHEN NEW.kind='application_finding' BEGIN SELECT RAISE(ABORT,'test failure'); END;")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError): confirm(service,p)
    assert not service.store.all('application_batch') and not service.store.all('application_source')


def test_default_driver_reference_and_explicit_unknowns(service):
    doc=json.loads(fixture('semgrep')); run=doc['runs'][0]
    run['results'][0]['rule']={'index':0,'toolComponent':{'index':-1}}
    run['invocations']=[{'executionSuccessful':True}]
    p=preview(service,json.dumps(doc).encode())
    assert p['findings'][0]['invocation_status']=='reported success'
    assert p['findings'][0]['scan_timestamps']==[{}]
    assert p['findings'][0]['scanner_level'] is None
    run['invocations'][0]['executionSuccessful']=False
    assert preview(service,json.dumps(doc).encode())['findings'][0]['invocation_status']=='failed or incomplete'


def test_bounded_message_expansion_and_invalid_timestamps(service):
    doc=json.loads(fixture()); run=doc['runs'][0]
    run['tool']['driver']['rules'][0]['messageStrings']={'x':{'text':'{0}'*1000}}
    run['results'][0]['message']={'id':'x','arguments':['x'*32768]}
    p=preview(service,json.dumps(doc).encode())
    assert len(p['findings'][0]['resolved_message'])==3000
    assert any('substitution exceeds' in w for w in p['findings'][0]['warnings'])
    run['invocations']=[{'executionSuccessful':True,'startTimeUtc':'not-a-date'}]
    with pytest.raises(ValueError,match='structure'):preview(service,json.dumps(doc).encode())


def test_upload_size_api_and_limit_boundary(service):
    client=TestClient(create_app(service),base_url='http://localhost')
    response=client.post('/api/application-findings/preview',data=SCOPE,files={'file':('large.json',b' '*(MAX_BYTES+1))})
    assert response.status_code==422 and '4 MiB' in response.json()['detail']
    doc=json.loads(fixture()); doc['runs'][0]['results']*=500
    assert len(parse(json.dumps(doc).encode())['runs'][0]['results'])==1000
    assert not service.store.all('application_preview')
