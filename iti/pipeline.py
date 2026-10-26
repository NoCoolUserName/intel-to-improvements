"""Immutable scoped manual configuration/run imports using the existing store."""
import json
import secrets
from datetime import datetime,timezone,timedelta
from . import profiles, pipeline_config as config, pipeline_execution as execution
from .pipeline_models import PipelineContext, VERSION, LIMITATIONS
from .application_findings import scoped, in_scope
from .store import TransactionStore, uid, digest, canonical, now


def preview(store,customer,environment,uploads,operator):
    ctx=profiles.context(store,customer,environment).model_dump()
    operator=PipelineContext.model_validate(operator).model_dump()
    if not 1<=len(uploads)<=20 or sum(len(raw) for _,raw in uploads)>config.MAX_TOTAL:raise ValueError('Snapshot limit: 20 files and 4 MiB aggregate')
    files=[];paths=set()
    for name,raw in uploads:
        path=config.filename(name)
        if path in paths:raise ValueError('Duplicate workflow filename')
        paths.add(path)
        doc,locations=config.parse(raw)
        files.append({'filename':name,'path':path,'sha256':digest(raw),'byte_length':len(raw),'document':doc,'locations':locations})
    files.sort(key=lambda f:f['path'])
    if sum(len(j.get('steps',[])) for f in files for j in f['document']['jobs'].values())>1000:raise ValueError('Snapshot limit is 1000 total steps')
    observations=config.assess(files)
    id=uid('pipeline_snapshot',ctx,operator,[(f['path'],f['sha256']) for f in files],VERSION)
    for observation in observations:observation.update(snapshot_id=id,assessed_at=now(),customer_id=customer,environment_id=environment,repository=operator['repository'])
    for f in files:f['source_id']=uid('pipeline_source',customer,environment,f['path'],f['sha256'])
    payload={'id':id,'context':ctx,'operator_context':operator,'files':files,'observations':observations,'rule_version':VERSION,'limitations':LIMITATIONS,'assessment_at':now()}
    if len(canonical(payload).encode())>16*1024*1024:raise ValueError('Normalized assessment exceeds 16 MiB')
    for _,raw in uploads:store.blob(raw)
    return save_preview(store,payload,'pipeline_snapshot')


def preview_execution(store,customer,environment,snapshot_id,raw):
    snapshot=scoped(store,'pipeline_snapshot',snapshot_id,customer,environment)
    ctx=profiles.context(store,customer,environment).model_dump()
    if ctx!=snapshot['context']:raise ValueError('Profile changed; import configuration in the current context before attaching execution')
    parsed=execution.parse(raw,snapshot)
    sha=digest(raw);source_id=uid('pipeline_source',customer,environment,'execution.json',sha)
    payload=parsed|{'id':uid('pipeline_execution',snapshot_id,sha,VERSION),'snapshot_id':snapshot_id,'context':ctx,'source_sha256':sha,'source_id':source_id,'rule_version':VERSION,'byte_length':len(raw)}
    if len(canonical(payload).encode())>8*1024*1024:raise ValueError('Normalized execution metadata exceeds 8 MiB')
    store.blob(raw)
    return save_preview(store,payload,'pipeline_execution')


def save_preview(store,payload,kind):
    row={'id':'pipeline_preview_'+secrets.token_hex(24),'context':payload['context'],'kind':kind,'payload':payload,'rule_version':VERSION,'recorded_at':now(),'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}
    store.put('pipeline_preview',row['id'],row,immutable=True)
    return row|{'already_imported':store.maybe(kind,payload['id']) is not None}


def confirm(store,preview_id,customer,environment):
    p=scoped(store,'pipeline_preview',preview_id,customer,environment)
    with store.connect() as connection:
        connection.execute('BEGIN IMMEDIATE');tx=TransactionStore(store,connection)
        if p['rule_version']!=VERSION or p['context']!=profiles.context(tx,customer,environment).model_dump():raise ValueError('Stale profile or rule version; preview again')
        if datetime.now(timezone.utc)>datetime.fromisoformat(p['expires_at']):raise ValueError('Preview expired; preview again')
        row=p['payload'];prior=tx.maybe(p['kind'],row['id'])
        if prior:return prior|{'duplicate':True}
        sources=row['files'] if p['kind']=='pipeline_snapshot' else [{'filename':'execution.json','sha256':row['source_sha256'],'source_id':row['source_id'],'byte_length':row['byte_length']}]
        for f in sources:
            if digest((store.root/'blobs'/f['sha256']).read_bytes())!=f['sha256']:raise ValueError('Pipeline source integrity check failed')
        timestamp=now()
        for f in sources:
            source={'id':f['source_id'],'context':p['context'],'filename':f['filename'],'sha256':f['sha256'],'byte_length':f['byte_length'],'recorded_at':timestamp}
            tx.put('pipeline_source',source['id'],source,immutable=True)
        row=row|{'imported_at':timestamp}
        tx.put(p['kind'],row['id'],row,immutable=True)
        tx.event(p['kind']+'_imported',customer+':'+environment,{'id':row['id'],'rule_version':VERSION})
        return row|{'duplicate':False}


def workspace(store,customer,environment):
    ctx=profiles.context(store,customer,environment).model_dump()
    snapshots=[r for r in store.all('pipeline_snapshot') if in_scope(r,customer,environment)]
    # Return summaries; full definitions stay behind scoped inspection.
    return {'context':ctx,'snapshots':[{k:r[k] for k in ('id','operator_context','imported_at','rule_version')}|{'workflows':[f['path'] for f in r['files']],'observation_count':len(r['observations'])} for r in snapshots]}


def detail(store,id,customer,environment):
    snapshot=scoped(store,'pipeline_snapshot',id,customer,environment)
    return {'snapshot':snapshot,'executions':[r for r in store.all('pipeline_execution') if in_scope(r,customer,environment) and r['snapshot_id']==id]}
