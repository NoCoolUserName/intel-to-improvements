import json,os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request,HTTPException,UploadFile,File,Form
from fastapi.responses import FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .services import Service
from .store import ROOT,now,uid
from .models import CustomerProfile,GmailScope,TestRun,ImprovementAction,EvidenceAttachment,SECTORS
from . import profiles,gmail,ledger,detection,misp,ingestion,defenses

def create_app(service=None):
    svc=service or Service()
    @asynccontextmanager
    async def lifespan(app):svc.restart();yield
    app=FastAPI(title='Intel to Improvements',version='0.1.0',lifespan=lifespan)
    app.state.service=svc
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['127.0.0.1','localhost','[::1]'])
    @app.middleware('http')
    async def local_only(request,call_next):
        origin=request.headers.get('origin');host=request.headers.get('host')
        if origin and origin not in (f'http://{host}',f'https://{host}'):return JSONResponse({'detail':'Cross-origin requests rejected; use the loopback app'},status_code=403)
        if request.headers.get('sec-fetch-site')=='cross-site':return JSONResponse({'detail':'Cross-site requests rejected'},status_code=403)
        if int(request.headers.get('content-length','0'))>6*1024*1024:return JSONResponse({'detail':'Request exceeds 6 MiB'},status_code=413)
        if request.method in ('POST','PUT','PATCH'):
            chunks=[];total=0
            async for chunk in request.stream():
                total+=len(chunk)
                if total>6*1024*1024:return JSONResponse({'detail':'Request exceeds 6 MiB'},status_code=413)
                chunks.append(chunk)
            request._body=b''.join(chunks)
        if request.url.path.startswith('/attack-flow-builder/') and not (ROOT/'runtime/attack-flow-viewer/index.html').is_file():
            return JSONResponse({'detail':'Local Attack Flow viewer not built; run ./scripts/build-attack-flow'},status_code=503)
        response=await call_next(request)
        builder=request.url.path.startswith('/attack-flow-builder/')
        frame_policy="'self'" if builder else "'none'"
        response.headers.update({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':f"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors {frame_policy}"})
        return response
    @app.exception_handler(ValueError)
    async def bad(request,exc):return JSONResponse({'detail':str(exc)},status_code=422)
    @app.exception_handler(KeyError)
    async def missing(request,exc):return JSONResponse({'detail':str(exc)},status_code=404)
    @app.exception_handler(OSError)
    async def os_error(request,exc):return JSONResponse({'detail':str(exc)},status_code=422)
    @app.get('/health')
    def health():return {'status':'ok','version':'0.1.0','mode':'local single operator','utc':now()}
    @app.get('/api/bootstrap')
    def bootstrap():return {'customers':svc.store.all('customer'),'sectors':SECTORS,'templates':[profiles.WINDOWS.model_dump(),profiles.MAC.model_dump()],'cases':[{'id':'activemq-derived','title':'ActiveMQ → LockBit','description':'Limited attributed DFIR Report case · exact-content replay'},{'id':'no-ioc','title':'Zero IOCs','description':'Authored healthcare / shared technology case'},{'id':'insufficient','title':'Insufficient intelligence','description':'Authored nontechnical source; no justified emulation'},{'id':'held-out','title':'Held-out change case','description':'Authored negation / benign indicators fixture'}],'capabilities':readiness(svc.store)}
    @app.post('/api/customers')
    def save_customer(c:CustomerProfile):
        saved=profiles.save(svc.store,c)
        prior=svc.assessments(c.id);latest={}
        for a in prior:latest[(a['source']['id'],a['context']['environment_id'])]=a
        for (_,env_id),a in latest.items():
            if env_id in {e.id for e in saved.environments}:
                svc.submit(c.id,env_id,a['extraction']['mode'],'source',a['source']['revision_id'])
        return saved.model_dump()
    @app.get('/api/reports')
    def reports(limit:int=15):return ingestion.list_reports(limit)
    @app.post('/api/ingest')
    def ingest(body:dict):return svc.submit(body['customer_id'],body['environment_id'],body.get('mode','offline'),body['kind'],body['value'],name=body.get('name'),shared=body.get('shared',False),metadata={'column_mapping':body.get('column_mapping')} if body.get('column_mapping') else None)
    @app.post('/api/upload')
    async def upload(customer_id:str=Form(),environment_id:str=Form(),mode:str=Form('offline'),csv_mapping:str=Form(''),file:UploadFile=File()):
        content=await file.read(ingestion.MAX_BYTES+1)
        if not file.filename or Path(file.filename).name!=file.filename or '\\' in file.filename:raise ValueError('Unsafe upload filename')
        return svc.submit(customer_id,environment_id,mode,'upload',content,name=file.filename,metadata={'column_mapping':json.loads(csv_mapping)} if csv_mapping else None)
    @app.get('/api/jobs')
    def jobs(customer_id:str):return svc.jobs(customer_id)
    @app.post('/api/jobs/{id}/{action}')
    def job_action(id:str,action:str,body:dict):
        j=svc.job(id)
        if j['data']['context']['customer_id']!=body['customer_id']:raise KeyError('Job not found')
        if action=='cancel':return svc.cancel(id)
        if action=='resume':return svc.resume(id)
        if action=='reanalyze':return svc.reanalyze(id,body.get('mode'))
        raise ValueError('Unknown job action')
    @app.get('/api/assessments')
    def assessments(customer_id:str,environment_id:str):
        return [a for a in svc.assessments(customer_id) if a['context']['environment_id']==environment_id]
    @app.get('/api/assessments/{id}')
    def assessment(id:str,customer_id:str,environment_id:str):return svc.scoped('assessment',id,customer_id,environment_id)
    @app.post('/api/assessments/{id}/generate')
    def generate(id:str,body:dict):return svc.generate(id,body['customer_id'])
    @app.post('/api/assessments/{id}/override')
    def override(id:str,body:dict):
        a=svc.scoped('assessment',id,body['customer_id'])
        if not body.get('reason','').strip():raise ValueError('Override reason required')
        r={'assessment_id':id,'context':a['context'],'reason':body['reason'],'include':bool(body.get('include',True)),'at':now()}
        svc.store.put('override',id,r);svc.store.event('relevance_override',body['customer_id'],r);return r
    @app.get('/api/overrides')
    def overrides(customer_id:str):return [o for o in svc.store.all('override') if o['context']['customer_id']==customer_id]
    @app.get('/api/packages')
    def package_list(customer_id:str,environment_id:str):return [p for p in svc.store.all('package') if p['context']['customer_id']==customer_id and p['context']['environment_id']==environment_id]
    @app.get('/api/artifacts/{id}/{name}')
    def artifact(id:str,name:str,customer_id:str,environment_id:str):
        p=svc.scoped('package',id,customer_id,environment_id)
        if name not in p['artifacts']['names']:raise KeyError('Artifact not found')
        return FileResponse(svc.store.root/'artifacts'/id/name,filename=name)
    @app.get('/api/ledger/{id}')
    def coverage(id:str,customer_id:str,environment_id:str):
        a=svc.scoped('assessment',id,customer_id,environment_id)
        return ledger.view(svc.store,a)
    @app.post('/api/ledger/{id}/test')
    def test(id:str,body:dict):return ledger.record_test(svc.store,svc.scoped('assessment',id,body['customer_id']),TestRun.model_validate(body['test']))
    @app.post('/api/ledger/{id}/improve')
    def improve(id:str,body:dict):
        if body.get('candidate_ref') and not body.get('environment_id'):raise ValueError('Selected environment required for defense suggestion')
        a=svc.scoped('assessment',id,body['customer_id'],body.get('environment_id'))
        return ledger.improve(svc.store,a,ImprovementAction.model_validate(body['action']),body.get('candidate_ref'))
    @app.get('/api/assessments/{id}/defenses')
    def defensive_candidates(id:str,customer_id:str,environment_id:str):
        return defenses.suggestions(svc.store,svc.scoped('assessment',id,customer_id,environment_id))
    @app.post('/api/ledger/{id}/synthetic')
    def synthetic(id:str,body:dict):
        a=svc.scoped('assessment',id,body['customer_id']);rule_id=body['rule_id'];b=body['behavior_id']
        if not any(c['id']==rule_id and c['behavior_id']==b for c in a['candidates']):raise ValueError('Rule not associated with behavior')
        result=detection.fixture_test(rule_id);blob=svc.store.blob(json.dumps(result).encode());executed=now()
        for variant,case in result['cases'].items():
            expected={'positive':'match','negative':'no match','missing-field':'inconclusive'}[variant]
            t=TestRun(behavior_id=b,environment_version=a['context']['environment_version'],control_id=rule_id,control_version=result['rule_version'],procedure='Restricted Sigma matcher on '+variant+' authored event',expected=expected,actual=case['result'],executed_at=executed,method='synthetic log match',result='inconclusive' if case['result']=='inconclusive' else ('passed' if case['result']==expected else 'failed'),dimension='detection',scope='local authored synthetic fixtures only',variant=variant,evidence=[EvidenceAttachment(id=uid('attachment',blob),reference='blob:'+blob,sha256=blob,description='Actual local matcher result, including original input event',kind='synthetic fixture replay')])
            ledger.record_test(svc.store,a,t)
        return result
    @app.post('/api/gmail/prepare')
    def prepare(body:dict):return gmail.prepare(svc.store,body['customer_id'],body['environment_id'],GmailScope.model_validate(body['scope']))
    @app.get('/api/gmail/requests')
    def requests(customer_id:str):return [r for r in svc.store.all('gmail_request') if r['context']['customer_id']==customer_id]
    @app.get('/api/gmail/imports')
    def imports(customer_id:str):return [r for r in svc.store.all('gmail_import') if r['context']['customer_id']==customer_id]
    @app.get('/api/gmail/sample/{id}')
    def sample(id:str,customer_id:str):
        r=svc.store.get('gmail_request',id)
        if r['context']['customer_id']!=customer_id:raise KeyError('Request not found')
        return gmail.sample(r)
    def handoff_bytes(body):
        if body.get('path'):return ingestion.read_path(body['path'])[0]
        return body['json']
    @app.post('/api/gmail/preview')
    def gmail_preview(body:dict):return gmail.preview(svc.store,handoff_bytes(body),body['customer_id'])
    @app.post('/api/gmail/process')
    def gmail_process(body:dict):return gmail.process(svc,handoff_bytes(body),body['customer_id'],body.get('mode','offline'))
    @app.post('/api/gmail/upload')
    async def gmail_upload(customer_id:str=Form(),file:UploadFile=File()):
        raw=await file.read(ingestion.MAX_BYTES+1);return gmail.preview(svc.store,raw,customer_id)
    @app.post('/api/misp/{id}')
    def misp_import(id:str,body:dict):return misp.import_event(svc.store,svc.scoped('package',id,body['customer_id']))
    @app.get('/api/misp/results')
    def misp_results(customer_id:str):
        packages={p['id'] for p in svc.store.all('package') if p['context']['customer_id']==customer_id}
        return [r for r in svc.store.all('misp_sync') if r['package_id'] in packages]
    @app.get('/api/evaluation')
    def evaluation():
        p=ROOT/'validation/evaluation.json';return json.loads(p.read_text()) if p.exists() else {'status':'NOT RUN','command':'./scripts/iti eval'}
    from .vulnerability_api import register
    register(app,svc)
    from .application_api import register as register_application_findings
    register_application_findings(app,svc)
    viewer=ROOT/'runtime/attack-flow-viewer'
    @app.get('/api/attack-flow/viewer')
    def viewer_status():
        available=(viewer/'index.html').is_file() and (viewer/'build.json').is_file()
        return {'available':available,'reason':None if available else 'Build the local viewer with ./scripts/build-attack-flow, restart the app, then retry.'}
    # Mount even before build so completing setup does not require an app restart.
    app.mount('/attack-flow-builder',StaticFiles(directory=viewer,html=True,check_dir=False),name='attack-flow-builder')
    dist=ROOT/'web/dist'
    if dist.exists():
        app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
        @app.get('/favicon.svg', include_in_schema=False)
        def favicon():return FileResponse(dist/'favicon.svg',media_type='image/svg+xml')
        @app.get('/apple-touch-icon.png', include_in_schema=False)
        def touch_icon():return FileResponse(dist/'apple-touch-icon.png',media_type='image/png')
        @app.get('/')
        def index():return FileResponse(dist/'index.html')
    else:
        @app.get('/')
        def unbuilt():return {'message':'Frontend not built. Run ./scripts/bootstrap then ./scripts/run'}
    return app

def readiness(store=None):
    from .store import Store
    store=store or Store();live_extractions=[e for e in store.all('extraction') if e.get('mode')=='live'];misp_reads=[r for r in store.all('misp_sync') if r.get('status') in ('readback matched','reconciled after uncertain write')]
    measured=(ROOT/'validation/evaluation.json').exists()
    return [{'capability':'Existing Gmail plugin','implemented':True,'fixture_tested':None,'live_tested':'user-confirmed configured and tested','status':'Assisted handoff; no in-app mailbox connectivity'}, {'capability':'Selected Gmail handoff','implemented':True,'fixture_tested':measured,'live_tested':False,'status':'NOT RUN until scoped retrieval and import recorded'}, {'capability':'Live AI extraction','implemented':True,'fixture_tested':measured,'live_tested':bool(live_extractions),'status':'Successful structured request recorded; evaluate general extraction separately' if live_extractions else 'Configured; acceptance pending' if os.getenv('OPENAI_API_KEY') and os.getenv('OPENAI_MODEL') else 'NOT VERIFIED — API key/model unavailable'}, {'capability':'Native MISP export / converter','implemented':True,'fixture_tested':measured,'live_tested':False,'status':'See each package compatibility report'}, {'capability':'MISP import/readback','implemented':True,'fixture_tested':measured,'live_tested':bool(misp_reads),'status':'Actual readback result recorded; inspect differences' if misp_reads else 'Configured; live check pending' if os.getenv('MISP_URL') and os.getenv('MISP_API_KEY') else 'NOT RUN — instance credentials unavailable'}, {'capability':'Synthetic Sigma evaluation','implemented':True,'fixture_tested':measured,'live_tested':False,'status':'One rule, three authored variants; no live SIEM'}]
app=create_app()
