import copy
import json
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
import yaml
from fastapi.testclient import TestClient
from iti.api import create_app
from iti import pipeline as p, pipeline_config as config, pipeline_execution as execution, profiles, exposure_overview
from iti.models import CustomerProfile
from iti.store import ROOT, digest, now

C='fictional-bank'; E='windows-ad'; S={'customer_id':C,'environment_id':E}
OP={'repository':'synthetic/juniper','ref':'main','commit':'a'*40,'synthetic':True}
FIX=ROOT/'fixtures/pipeline'

def upload(service,names=('good.yml',)):
    preview=p.preview(service.store,C,E,[(name,(FIX/name).read_bytes()) for name in names],OP)
    return p.confirm(service.store,preview['id'],C,E)

def data():return json.loads((FIX/'run.json').read_bytes())

def observation(snapshot,check,job=None):
    return next(r for r in snapshot['observations'] if r['check_id']==check and (job is None or r['job_key']==job))


def test_real_preview_confirm_sources_idempotence_revisions_and_dashboard_unchanged(service):
    before=exposure_overview.overview(service.store,C,E)
    with TestClient(create_app(service),base_url='http://localhost') as client:
        files=[('files',(n,(FIX/n).read_bytes(),'application/yaml')) for n in ('good.yml','concerns.yml','shared.yml')]
        r=client.post('/api/pipeline-assurance/preview',data=S|OP,files=files)
        assert r.status_code==200,r.text
        preview=r.json();assert not service.store.all('pipeline_snapshot')
        r=client.post('/api/pipeline-assurance/confirm',json=S|{'preview_id':preview['id']})
        assert r.status_code==200,r.text
        snapshot=r.json();assert len(snapshot['files'])==3
        detail=client.get('/api/pipeline-assurance/'+snapshot['id'],params=S).json()
        assert not detail['executions']
        assert client.get('/api/pipeline-assurance',params=S).json()['snapshots'][0]['id']==snapshot['id']
        for file in snapshot['files']:
            response=client.get('/api/pipeline-assurance/sources/'+file['source_id'],params=S)
            assert response.content==(FIX/file['filename']).read_bytes()
            assert digest(response.content)==file['sha256']
        assert client.post('/api/pipeline-assurance/confirm',json=S|{'preview_id':preview['id']}).json()['duplicate']
        newer=p.preview(service.store,C,E,[('good.yml',(FIX/'revised/good.yml').read_bytes())],OP)
        saved=p.confirm(service.store,newer['id'],C,E)
        assert saved['id']!=snapshot['id']
        assert client.get('/api/pipeline-assurance/'+snapshot['id'],params=S).json()==detail
        wrong={'customer_id':'fictional-cloud','environment_id':'mac-cloud'}
        for path in ['/api/pipeline-assurance/'+snapshot['id'],'/api/pipeline-assurance/sources/'+snapshot['files'][0]['source_id']]:assert client.get(path,params=wrong).status_code==404
        assert client.post('/api/pipeline-assurance/confirm',json=wrong|{'preview_id':preview['id']}).status_code==404
        assert client.post('/api/pipeline-assurance/confirm',json=S|{'preview_id':'forged'}).status_code==404
        assert client.post('/api/pipeline-assurance/confirm',headers={'Origin':'https://evil.example'},json=S|{'preview_id':preview['id']}).status_code==403
    after=exposure_overview.overview(service.store,C,E)
    assert before['rows']==after['rows'] and before['metrics']==after['metrics']
    assert not service.store.all('improvement') and not service.store.all('application_finding')


def test_on_booleans_locations_and_loader_isolation():
    doc,locations=config.parse((FIX/'good.yml').read_bytes())
    assert doc['on']==['push','pull_request'] and True not in doc
    assert doc['jobs']['sast']['steps'][0]['with']['persist-credentials'] is False
    assert locations['jobs.sast.steps.2.uses']>0
    assert yaml.safe_load('on: push')=={True:'push'} # Existing consumers are unchanged.


@pytest.mark.parametrize('raw',[
    b'on: push\non: pull_request\njobs: {}',
    b'on: push\njobs:\n  test:\n    steps: [a, b]',
    b'on: push\njobs: &x {test: *x}',
    b'!!python/object/apply:os.system ["echo never"]',
    b'!!custom {on: push, jobs: {}}',
    b'on: [push\njobs: {}',
    b'on: push\njobs: {}\n---\non: push\njobs: {}',
    b'\xff',
    b'on: true\njobs: {}',
    ('x: '+ '['*25+'0'+']'*25).encode(),
    ('x: '+ 'a'*32769).encode(),
    b'x: '+b'a'*(512*1024),
    b'on: push\njobs: {test: {uses: "foo/bar@v1", steps: []}}',
])
def test_reject_unsafe_malformed_and_pathological_yaml(raw):
    with pytest.raises(ValueError):config.parse(raw)


@pytest.mark.parametrize('name',['../good.yml','/tmp/good.yml','a\\good.yml','.github/workflows/good.yml','http://evil/good.yml','bad.txt'])
def test_unsafe_filenames(name):
    with pytest.raises(ValueError):config.filename(name)


def test_failed_multiple_file_import_has_no_partial_records_or_blobs(service):
    prior=set((service.store.root/'blobs').iterdir())
    with pytest.raises(ValueError):p.preview(service.store,C,E,[('good.yml',(FIX/'good.yml').read_bytes()),('bad.yml',b'on: [')],OP)
    assert not service.store.all('pipeline_preview') and not service.store.all('pipeline_source')
    assert set((service.store.root/'blobs').iterdir())==prior
    with pytest.raises(ValueError):p.preview(service.store,C,E,[('good.yml',b'a')]*21,OP)
    with pytest.raises(ValueError):p.preview(service.store,C,E,[(str(i)+'.yml',b'x'*(512*1024)) for i in range(9)],OP)


def test_supported_checks_and_reusable_unknowns(service):
    good=upload(service)
    assert observation(good,'configured_sast')['state']=='Observed configured'
    assert observation(good,'checkout_credentials')['state']=='Observed configured'
    assert observation(good,'merge_enforcement')['state']=='Unknown'
    writes=[r for r in good['observations'] if r['category']=='Permissions' and isinstance(r['evidence'],dict) and r['evidence'].get('security-events')=='write']
    assert writes and all(r['state']=='Requires manual review' for r in writes)
    concern=upload(service,('concerns.yml',))
    assert observation(concern,'event_shell_interpolation')['state']=='Potential concern'
    assert observation(concern,'declared_permissions')['state']=='Potential concern'
    assert observation(concern,'control_gate')['state']=='Potential concern'
    assert observation(concern,'trigger_trust_boundary')['state']=='Requires manual review'
    shared=upload(service,('shared.yml',))
    assert observation(shared,'delegated_controls')['state']=='Unknown'
    assert all(r['state']=='Unknown' for r in shared['observations'] if r['check_id'].startswith('coverage_'))
    assert not any(r['state']=='Not observed in supplied scope' for r in shared['observations'])


@pytest.mark.parametrize('reference,state',[
    ('actions/checkout@'+'a'*40,'Observed configured'),('actions/checkout@v4','Potential concern'),
    ('./local/action','Requires manual review'),('docker://alpine@sha256:'+'a'*64,'Observed configured'),
    ('docker://alpine:latest','Requires manual review'),('${{ inputs.action }}','Unknown'),
    ('javascript:alert(1)','Unknown')])
def test_reference_forms(reference,state):assert config.uses_state(reference)[0]==state


def test_lint_and_echo_are_not_sast_and_local_definition_is_bounded(service):
    raw=b'on: push\njobs:\n  lint:\n    steps:\n      - run: ruff check .\n      - run: echo semgrep ci\n  shared:\n    uses: ./.github/workflows/local.yml\n'
    local=b'on: workflow_call\njobs:\n  scanning:\n    steps:\n      - run: semgrep ci\n'
    preview=p.preview(service.store,C,E,[('caller.yml',raw),('local.yml',local)],OP)
    rows=preview['payload']['observations']
    assert next(r for r in rows if r['check_id']=='delegated_controls')['state']=='Requires manual review'
    assert len([r for r in rows if r['check_id']=='configured_sast'])==1
    assert not any(r['check_id']=='configured_sast' and r['workflow'].endswith('caller.yml') for r in rows)


def test_stale_context_expiry_version_and_hash_rollback(service):
    preview=p.preview(service.store,C,E,[('good.yml',(FIX/'good.yml').read_bytes())],OP)
    broken=copy.deepcopy(preview);broken['expires_at']=(__import__('datetime').datetime.now(__import__('datetime').timezone.utc)-timedelta(hours=1)).isoformat()
    service.store.put('pipeline_preview',preview['id'],broken)
    with pytest.raises(ValueError,match='expired'):p.confirm(service.store,preview['id'],C,E)
    service.store.put('pipeline_preview',preview['id'],preview)
    source=preview['payload']['files'][0];(service.store.root/'blobs'/source['sha256']).write_bytes(b'corrupt')
    with pytest.raises(ValueError,match='integrity'):p.confirm(service.store,preview['id'],C,E)
    assert not service.store.all('pipeline_snapshot') and not service.store.all('pipeline_source')
    profiles.save(service.store,CustomerProfile.model_validate(service.store.get('customer',C)))
    with pytest.raises(ValueError,match='Stale'):p.confirm(service.store,preview['id'],C,E)


def test_concurrent_repeat_confirmation(service):
    preview=p.preview(service.store,C,E,[('good.yml',(FIX/'good.yml').read_bytes())],OP)
    with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:p.confirm(service.store,preview['id'],C,E),range(4)))
    assert sum(not r['duplicate'] for r in results)==1
    assert len(service.store.all('pipeline_snapshot'))==1


def test_execution_preview_confirm_reported_states_and_original_bytes(service):
    snapshot=upload(service)
    raw=(FIX/'run.json').read_bytes()
    with TestClient(create_app(service),base_url='http://localhost') as client:
        r=client.post('/api/pipeline-assurance/execution-preview',data=S|{'snapshot_id':snapshot['id']},files={'file':('run.json',raw)})
        assert r.status_code==200,r.text
        preview=r.json();assert not service.store.all('pipeline_execution')
        reported=client.post('/api/pipeline-assurance/confirm',json=S|{'preview_id':preview['id']}).json()
        states=reported['controls']
        assert states[observation(snapshot,'configured_sast')['id']]['state']=='Reported successful'
        assert states[observation(snapshot,'configured_secrets_scanning')['id']]['state']=='Reported skipped'
        assert states[observation(snapshot,'configured_regression_tests')['id']]['state']=='Reported failed'
        assert not reported['independently_verified']
        assert client.get('/api/pipeline-assurance/sources/'+reported['source_id'],params=S).content==raw
        repeated=p.preview_execution(service.store,C,E,snapshot['id'],raw)
        assert p.confirm(service.store,repeated['id'],C,E)['duplicate']
        incomplete=p.preview_execution(service.store,C,E,snapshot['id'],(FIX/'incomplete.json').read_bytes())
        saved=p.confirm(service.store,incomplete['id'],C,E)
        assert saved['controls'][observation(snapshot,'configured_sast')['id']]['state']=='Incomplete'
        assert len(p.detail(service.store,snapshot['id'],C,E)['executions'])==2


@pytest.mark.parametrize('change', ['repository','commit','branch','path','attempt','job_attempt','job_run','timestamp','duplicate_job','missing_step','duplicate_step_name','run_conclusion_missing','noncomplete_conclusion'])
def test_execution_mismatch_and_unknowns(service,change):
    snapshot=upload(service);doc=data()
    if change=='repository':doc['workflow_run']['repository']['full_name']='other/repo'
    if change=='commit':doc['workflow_run']['head_sha']='b'*40
    if change=='branch':doc['workflow_run']['head_branch']='different'
    if change=='path':doc['workflow_run']['path']='.github/workflows/other.yml'
    if change=='attempt':doc['workflow_run'].pop('run_attempt')
    if change=='job_attempt':doc['jobs']['jobs'][0].pop('run_attempt')
    if change=='job_run':doc['jobs']['jobs'][0]['run_id']=999
    if change=='timestamp':doc['jobs']['jobs'][0]['started_at']='2026-01-01'
    if change=='duplicate_job':doc['jobs']['jobs'][1]['id']=doc['jobs']['jobs'][0]['id']
    if change=='missing_step':doc['jobs']['jobs'][0].pop('steps')
    if change=='duplicate_step_name':doc['jobs']['jobs'][0]['steps'].append(doc['jobs']['jobs'][0]['steps'][0]|{'number':4})
    if change=='run_conclusion_missing':doc['workflow_run']['conclusion']=None
    if change=='noncomplete_conclusion':doc['workflow_run']['status']='in_progress'
    if change in ('missing_step','duplicate_step_name','run_conclusion_missing'):
        result=execution.parse(json.dumps(doc).encode(),snapshot)
        assert result['controls'][observation(snapshot,'configured_sast')['id']]['state'] in ('Unknown / no evidence','Incomplete')
    else:
        with pytest.raises(ValueError):p.preview_execution(service.store,C,E,snapshot['id'],json.dumps(doc).encode())
        assert not service.store.all('pipeline_execution')


@pytest.mark.parametrize('conclusion,expected',[('cancelled','Reported cancelled'),('neutral','Unknown / no evidence'),('timed_out','Reported failed')])
def test_non_success_outcomes(service,conclusion,expected):
    snapshot=upload(service);doc=data();job=doc['jobs']['jobs'][0];job['conclusion']=conclusion;job['steps'][0]['conclusion']=conclusion
    r=execution.parse(json.dumps(doc).encode(),snapshot)
    assert r['controls'][observation(snapshot,'configured_sast')['id']]['state']==expected


def test_execution_bound_and_missing_commit(service):
    snap=upload(service)
    for raw in [b'{',b'{"jobs":{},"jobs":{}}',b'x'*(execution.MAX_EXECUTION+1)]:
        with pytest.raises(ValueError):execution.parse(raw,snap)
    snap['operator_context']['commit']=None
    with pytest.raises(ValueError,match='commit'):execution.parse((FIX/'run.json').read_bytes(),snap)


def test_permissions_override_inheritance_dates_and_shell_masking(service):
    raw=b'''on: workflow_run
permissions: write-all
env: {RELEASE_DATE: 2026-01-01}
jobs:
  inherited:
    steps:
      - run: semgrep ci || true
  restricted:
    permissions: {contents: read}
    if: "${{ github.event_name == 'push' }}"
    steps:
      - name: Check
        run: npm audit
'''
    snap=p.preview(service.store,C,E,[('checks.yml',raw)],OP)['payload']
    assert snap['files'][0]['document']['env']['RELEASE_DATE']=='2026-01-01'
    rows=snap['observations']
    inherited=next(r for r in rows if r['job_key']=='inherited')
    assert inherited['state']=='Potential concern' and inherited['key']=='permissions' and inherited['line']==2
    assert next(r for r in rows if r['key']=='jobs.restricted.permissions')['state']=='Observed configured'
    assert [r['state'] for r in rows if r['check_id']=='control_gate']==['Potential concern','Requires manual review']
    assert observation(snap,'trigger_trust_boundary')['state']=='Requires manual review'


@pytest.mark.parametrize('change',['path_type','job_before_run','step_before_job','step_after_job','matrix','missing_name','missing_time','version'])
def test_execution_chronology_unknown_binding_and_preview_version(service,change):
    snapshot=upload(service);doc=data()
    if change=='path_type':doc['workflow_run']['path']=[]
    if change=='job_before_run':doc['jobs']['jobs'][0]['started_at']='2025-01-01T00:00:00Z'
    if change=='step_before_job':doc['jobs']['jobs'][0]['steps'][0]['started_at']='2025-01-01T00:00:00Z'
    if change=='step_after_job':doc['jobs']['jobs'][0]['steps'][0]['completed_at']='2027-01-01T00:00:00Z'
    if change in ('matrix','missing_name'):
        raw=(FIX/'good.yml').read_bytes()
        raw=raw.replace(b'    name: Synthetic SAST',b'    strategy: {matrix: {os: [ubuntu-latest]}}\n    name: Synthetic SAST') if change=='matrix' else raw.replace(b'      - name: Analyze CodeQL\n        uses:',b'      - uses:')
        snapshot=p.preview(service.store,C,E,[('good.yml',raw)],OP)['payload']
    if change=='missing_time':doc['jobs']['jobs'][0]['steps'][0].pop('completed_at')
    if change in ('matrix','missing_name','missing_time'):
        result=execution.parse(json.dumps(doc).encode(),snapshot)
        assert result['controls'][observation(snapshot,'configured_sast')['id']]['state']=='Unknown / no evidence'
    elif change=='version':
        preview=p.preview_execution(service.store,C,E,snapshot['id'],json.dumps(doc).encode())
        service.store.put('pipeline_preview',preview['id'],preview|{'rule_version':'older'})
        with pytest.raises(ValueError,match='rule version'):p.confirm(service.store,preview['id'],C,E)
    else:
        with pytest.raises(ValueError):p.preview_execution(service.store,C,E,snapshot['id'],json.dumps(doc).encode())
    assert not service.store.all('pipeline_execution')



def test_bounded_mapping_keys_and_unambiguous_source_locations():
    raw=b'on: push\njobs: {scan: {steps: [{run: semgrep ci}]}}\n"jobs.scan.steps.0.run": misleading\n'
    document,locations=config.parse(raw)
    assert locations['jobs.scan.steps.0.run']==2
    assert locations['["jobs.scan.steps.0.run"]']==3
    with pytest.raises(ValueError,match='mapping keys'):
        config.parse(b'a'*257+b': value\n'+raw)
    with pytest.raises(ValueError,match='location'):
        config.parse(('a'*250+': {') .encode()*10 + b'value: x'+b'}'*10)
