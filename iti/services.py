import json,os,traceback,threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .store import Store,ROOT,uid,digest,canonical,now
from .models import SourceDocument,Extraction,Context
from . import profiles,ingestion,analysis,relevance,detection,packages,exporters
EXECUTOR=ThreadPoolExecutor(max_workers=2,thread_name_prefix='iti-job')

class Service:
    def __init__(self,store=None):
        self.store=store or Store();profiles.seed(self.store)
    def restart(self):
        with self.store.connect() as c:c.execute("UPDATE jobs SET state='interrupted',updated_at=? WHERE state='running'",(now(),))
    def jobs(self,customer):
        with self.store.connect() as c:rows=c.execute('SELECT * FROM jobs ORDER BY updated_at DESC').fetchall()
        return [dict(r)|{'data':json.loads(r['data'])} for r in rows if json.loads(r['data'])['context']['customer_id']==customer]
    def job(self,id):
        with self.store.connect() as c:r=c.execute('SELECT * FROM jobs WHERE id=?',(id,)).fetchone()
        if not r:raise KeyError('Job not found')
        return dict(r)|{'data':json.loads(r['data'])}
    def update(self,id,state=None,stage=None,updates=None):
        with self.store.connect() as c:
            r=c.execute('SELECT * FROM jobs WHERE id=?',(id,)).fetchone();d=json.loads(r['data']);d.update(updates or {})
            c.execute('UPDATE jobs SET state=?,stage=?,data=?,updated_at=? WHERE id=?',(state or r['state'],stage or r['stage'],canonical(d),now(),id))
    def submit(self,customer,environment,mode,kind,value,name=None,shared=False,background=True,metadata=None,frozen_context=None):
        if mode not in ('replay','offline','live'):raise ValueError('Invalid processing mode')
        ctx=frozen_context or profiles.context(self.store,customer,environment)
        if mode=='live' and not ctx.customer_snapshot.allow_live_processing:raise ValueError('Customer policy prohibits live external processing')
        scope='shared' if shared else customer
        payload={'kind':kind,'value':value,'name':name,'scope':scope,'metadata':metadata or {}}
        if kind=='path':
            data,actual=ingestion.read_path(value);payload={'kind':'bytes','blob':self.store.blob(data),'name':Path(actual).name,'origin':actual,'scope':scope,'metadata':metadata or {}}
        elif kind in ('text','upload'):
            data=value.encode() if isinstance(value,str) else value
            if len(data)>ingestion.MAX_BYTES:raise ValueError('Input exceeds 5 MiB')
            payload={'kind':'bytes','blob':self.store.blob(data),'name':name or 'pasted.txt','origin':(metadata or {}).get('origin') or ('upload:'+Path(name).name if name else 'pasted:'+digest(data)),'scope':scope,'metadata':metadata or {}}
        elif kind=='case':
            if value not in ('activemq-derived','no-ioc','insufficient','held-out','held-out-cloud'):raise ValueError('Unknown fixture')
            path=ROOT/'fixtures'/f'{value}.md';data=path.read_bytes()
            meta={'title':{'activemq-derived':'ActiveMQ → LockBit · DFIR Report derived case','no-ioc':'Zero IOCs · authored healthcare case','insufficient':'Insufficient intelligence · authored note','held-out':'Held-out · changed facts and negation','held-out-cloud':'Held-out cloud account activity'}[value],'fixture':True}
            if value=='activemq-derived':meta|={'publisher':'The DFIR Report','authors':['@malforsec','@lapadrino','@PeteO'],'published_at':'2026-02-23','publication_precision':'day','incident_time':'mid-February 2024; recurrence 18 days later','incident_precision':'approximate month and relative interval','title':'ActiveMQ → LockBit · limited derived case','gaps':['Limited developer-curated derivative, not the full report; original contains image-only evidence','C2 address discrepancy .52 versus .62 requires source review']}
            payload={'kind':'bytes','blob':self.store.blob(data),'name':path.name,'origin':ingestion.DFIR_URL+'#limited-derived' if value=='activemq-derived' else 'authored-fixture:'+value,'scope':scope,'metadata':meta}
            if mode=='replay' and value!='activemq-derived': mode='offline'
        elif kind=='source':
            source=self.store.get('source',value)
            if source['scope'] not in ('shared',customer):raise ValueError('Source belongs to another customer')
        elif kind!='url':raise ValueError('Unsupported input mode')
        key=uid('jobkey',ctx.model_dump(),mode,payload,analysis.PROMPT_VERSION,ingestion.PARSER_VERSION,detection.MANIFEST['revisions'])
        id=uid('job',key);data={'context':ctx.model_dump(),'mode':mode,'input':payload,'created_at':now(),'cancel_requested':False}
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            exists=c.execute('SELECT 1 FROM jobs WHERE unique_key=?',(key,)).fetchone()
            pending=c.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0]
            if not exists and pending>=32:raise ValueError('Job queue full (32 active/pending); wait or cancel a job')
            c.execute('INSERT OR IGNORE INTO jobs VALUES(?,?,?,?,?,?)',(id,key,'queued','intake',canonical(data),now()))
        if background:EXECUTOR.submit(self.run,id)
        else:self.run(id)
        return self.job(id)
    def cancel(self,id):
        job=self.job(id)
        if job['state'] in ('complete','cancelled'):return job
        self.update(id,state='cancelled' if job['state']!='running' else None,updates={'cancel_requested':True});return self.job(id)
    def resume(self,id,background=True):
        job=self.job(id)
        if job['state'] not in ('failed','cancelled','interrupted'):return job
        self.update(id,state='queued',updates={'cancel_requested':False,'previous_error':job['data'].get('error'),'error':None})
        if background:EXECUTOR.submit(self.run,id)
        else:self.run(id)
        return self.job(id)
    def reanalyze(self,id,mode,background=True):
        job=self.job(id);data=job['data']
        if job['state'] not in ('failed','cancelled','interrupted'):raise ValueError('Only a failed, cancelled, or interrupted job can be reanalyzed here')
        if mode not in ('offline','live'):raise ValueError('Choose local or model API analysis for a saved report')
        if not data.get('source_revision'):raise ValueError('This job has no saved source; submit the source again')
        ctx=Context.model_validate(data['context'])
        result=self.submit(ctx.customer_id,ctx.environment_id,mode,'source',data['source_revision'],background=background,frozen_context=ctx)
        self.store.event('analysis_restarted',ctx.customer_id,{'previous_job':id,'job':result['id'],'source_revision':data['source_revision'],'mode':mode})
        return result
    def run(self,id):
        with self.store.connect() as c:
            changed=c.execute("UPDATE jobs SET state='running' WHERE id=? AND state='queued'",(id,)).rowcount
        if not changed:return
        try:
            job=self.job(id);data=job['data'];ctx=Context.model_validate(data['context']);inp=data['input']
            def check():
                if self.job(id)['data'].get('cancel_requested'):raise InterruptedError('Cancelled at checkpoint; completed stages retained')
            check()
            if not data.get('source_revision'):
                if inp['kind']=='source':source=SourceDocument.model_validate(self.store.get('source',inp['value']))
                else:
                    if inp['kind']=='url':
                        content,meta=ingestion.fetch(inp['value']);name='selected-report.pdf' if 'pdf' in meta['content_type'] else 'selected-report.html';origin=inp['value']
                    else:content=(self.store.root/'blobs'/inp['blob']).read_bytes();meta=inp['metadata'];name=inp['name'];origin=inp['origin']
                    source=ingestion.ingest(self.store,content,name,origin,inp['scope'],metadata=meta,extra_gaps=meta.get('gaps',[]),occurrence_key=meta.get('occurrence_key'))
                if source.completeness=='failed':raise ValueError('No supported content extracted; see source gaps')
                self.store.clock('customer_receipt',uid('receipt',ctx.customer_id,source.id))
                self.update(id,stage='extraction',updates={'source_revision':source.revision_id});data=self.job(id)['data']
            source=SourceDocument.model_validate(self.store.get('source',data['source_revision']));check()
            cachekey=uid('extraction',source.scope,source.content_hash,ingestion.PARSER_VERSION,analysis.PROMPT_VERSION,data['mode'],os.getenv('OPENAI_MODEL') if data['mode']=='live' else None,os.getenv('OPENAI_BASE_URL') if data['mode']=='live' else None,digest(canonical(Extraction.model_json_schema())),detection.MANIFEST['revisions'])
            cached=self.store.maybe('extraction_cache',cachekey)
            if cached and cached['source_revision']==source.revision_id:ex=Extraction.model_validate(cached)
            else:
                provider={'replay':analysis.ReplayProvider,'offline':analysis.OfflineProvider,'live':analysis.LiveProvider}[data['mode']]()
                ex=provider.extract(source,self.store,cancel=lambda:self.job(id)['data'].get('cancel_requested',False));analysis.validate_evidence(ex,source)
                self.store.put('extraction_cache',cachekey,ex.model_dump(),immutable=True);self.store.put('extraction',ex.id,ex.model_dump(),immutable=True)
            self.update(id,stage='assessment',updates={'extraction_id':ex.id});check()
            assessment=self.assess(source,ex,ctx)
            self.update(id,state='complete',stage='assessed',updates={'assessment_id':assessment['id'],'completed_at':now()})
        except InterruptedError as e:self.update(id,state='cancelled',updates={'error':str(e)})
        except Exception as e:
            error={'type':type(e).__name__,'message':str(e),'code':getattr(e,'code',None),'traceback':traceback.format_exc(),'at':now()};self.store.put('failure',uid('failure',id,now()),error,immutable=True);self.update(id,state='failed',updates={'error':error})
    def assess(self,source,ex,ctx):
        aid=uid('assessment',source.revision_id,ex.id,ctx.model_dump())
        previous=self.store.maybe('assessment',aid)
        if previous:return previous
        rel=relevance.relevance(ex,source,ctx);coverage=relevance.applicability(ex,ctx);candidates,retrieval=detection.assess(ex,ctx)
        assessment={'id':aid,'source':source.model_dump(),'extraction':ex.model_dump(),'context':ctx.model_dump(),'relevance':rel,'coverage':[r.model_dump() for r in coverage],'candidates':[r.model_dump() for r in candidates],'retrieval':retrieval,'created_at':now()}
        self.store.put('assessment',aid,assessment,immutable=True);self.store.event('assessment_ready',ctx.customer_id,{'assessment':aid,'source_revision':source.revision_id});return assessment
    def assessments(self,customer):return [a for a in self.store.all('assessment') if a['context']['customer_id']==customer]
    def scoped(self,kind,id,customer,environment=None):
        row=self.store.get(kind,id)
        if row['context']['customer_id']!=customer or environment and row['context']['environment_id']!=environment:raise KeyError('Not found in selected customer/environment')
        return row
    def generate(self,assessment_id,customer):
        with self.store.lock('package:'+assessment_id):
            return self._generate(assessment_id,customer)
    def _generate(self,assessment_id,customer):
        a=self.scoped('assessment',assessment_id,customer);pid=uid('package',a['id'],'packages-5')
        existing=self.store.maybe('package',pid)
        if existing:return existing
        from .models import CoverageAssessment,DetectionCandidate
        ex=Extraction.model_validate(a['extraction']);source=SourceDocument.model_validate(a['source']);ctx=Context.model_validate(a['context'])
        rows=[CoverageAssessment.model_validate(r) for r in a['coverage']];cs=[DetectionCandidate.model_validate(r) for r in a['candidates']]
        hunts,emulations=packages.generate(ex,source,ctx,rows,cs)
        p=a|{'id':pid,'assessment_id':a['id'],'created_at':now(),'mode':ex.mode,'hunts':[x.model_dump() for x in hunts],'emulations':[x.model_dump() for x in emulations],'coverage':[r.model_dump() for r in rows]}
        p['manifest']={'schema_version':'1.0','application':'0.1.0','package_id':pid,'assessment_id':a['id'],'context':a['context'],'source_revision':source.revision_id,'content_revision_id':source.content_revision_id,'source_hash':source.content_hash,'normalized_hash':digest(source.normalized),'extraction_id':ex.id,'mode':ex.mode,'provider':ex.provider,'model':ex.model,'prompt_version':analysis.PROMPT_VERSION,'provider_implementation_hash':digest((ROOT/'iti/analysis.py').read_bytes()),'extraction_schema_hash':digest(canonical(Extraction.model_json_schema())),'parser_version':ingestion.PARSER_VERSION,'catalogs':detection.MANIFEST,'created_at':p['created_at'],'environment_hash':digest(canonical(a['context']['environment_snapshot'])),'review_status':ex.review_status,'live_splunk':'NOT RUN','live_model':'completed' if ex.mode=='live' else 'NOT RUN','live_misp':'NOT RUN','source_gaps':source.gaps}
        artifacts=exporters.export_package(self.store,p);p['artifacts']=artifacts
        self.store.put('package',pid,p,immutable=True);self.store.event('package_ready',customer,{'package':pid,'assessment':a['id']});return p
