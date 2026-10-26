"""Explicit isolated leadership examples; all claims and evidence are synthetic."""
import json
from datetime import timedelta
from . import profiles, application_findings as af, appsec, ledger, vulnerabilities as vi
from .models import CustomerProfile, EnvironmentProfile, ImprovementAction
from .store import now

CUSTOMER='fictional-leadership-demo'
ENVIRONMENT='leadership-lab'


def load(service):
    store=service.store
    with store.lock('leadership-demo'):
        previous=store.maybe('exposure_demo','phase3')
        if previous:return previous
        if store.maybe('customer',CUSTOMER):raise ValueError('Leadership demo customer already exists without a completed marker; use an isolated store')
        profiles.save(store,CustomerProfile(id=CUSTOMER,name='Juniper Software · synthetic leadership demo',sector='technology',environments=[EnvironmentProfile(id=ENVIRONMENT,name='Leadership lab · synthetic',platforms=['linux'])]))
        ctx=profiles.context(store,CUSTOMER,ENVIRONMENT).model_dump()
        at=appsec.dt(now())
        cases=['unreviewed','open','pending','failed','inconclusive','reviewed','stale','active','expired','unapproved']
        results=[{'ruleId':'synthetic/'+case,'message':{'text':'Authored leadership example: '+case},'fingerprints':{'synthetic/v1':case},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'synthetic.txt'},'region':{'startLine':i+1}}}]} for i,case in enumerate(cases)]
        doc={'version':'2.1.0','properties':{'synthetic':True},'runs':[{'tool':{'driver':{'name':'Synthetic leadership fixture'}},'results':results}]}
        operator={'application':'Juniper authored application','repository':'synthetic/leadership','synthetic':True}
        p=af.preview(store,CUSTOMER,ENVIRONMENT,json.dumps(doc).encode(),operator);af.confirm(store,p['id'],CUSTOMER,ENVIRONMENT)
        for case,f in zip(cases,p['findings']):
            if case=='unreviewed':continue
            with appsec.transaction(store) as tx:
                review=appsec.review(tx,f,ctx,{'reviewer':'Synthetic security reviewer','disposition':appsec.APPLICABLE,'reason':'Authored applicability for a fictional management demonstration'})
                if case in ('active','expired','unapproved'):
                    request=appsec.request_exception(tx,f,ctx,{'requester':'Synthetic engineering requester','justification':'Authored bounded business justification','residual_risk':'Synthetic finding remains unresolved','review_by':(at+timedelta(days=-1 if case=='expired' else 5)).isoformat()})
                    if case!='unapproved':appsec.decide_exception(tx,f,ctx,request['id'],{'authority':'Synthetic accepting authority','decision':'approved','reason':'Operator-recorded synthetic approval'})
                    continue
                subject=appsec.subject(tx,f,appsec.versions(ctx))
                command={'review_id':review['id'],'actor':'Synthetic engineering owner','reason':'Authored demonstration commitment','expected_updated_at':None}
                subject['appsec_command']=command
                action=ImprovementAction(owner='Synthetic application engineering',priority='medium',rationale='Correct authored finding',proposed_change='Authored change only',retest='Inspect authored result and benign control',remediation={'security_reviewer':'Synthetic security reviewer','expected_result':'Authored cause removed','target_date':(at-timedelta(days=2)).date().isoformat(),'implementation_ref':'synthetic-change','implementation_claim':'Developer attests to authored implementation'})
                saved=ledger.improve(tx,subject,action)
                if case=='open':continue
                action.id=saved['id'];action.status='retest requested';command['expected_updated_at']=saved['updated_at'];saved=ledger.improve(tx,subject,action)
                if case=='pending':continue
                evidence=appsec.capture_evidence(tx,f,ctx,'synthetic.txt',b'Authored result; no actual scanner or application test executed.','synthetic/lab evidence','Synthetic result for dashboard semantics')
                appsec.retest(tx,subject,{'action_id':saved['id'],'review_id':review['id'],'implementation_ref':'synthetic-change','finding_context_hash':appsec.context_hash(f),'reviewer':'Synthetic evidence reviewer','judgment':'Accept only as an authored synthetic result','procedure':'Read authored result','expected':'Authored cause removed','actual':'Authored '+case+' result','executed_at':now(),'result':case if case in ('failed','inconclusive') else 'passed','method':'version/configuration evidence','evidence_ids':[evidence['id']]})
                if case in ('reviewed','stale'):
                    action.status='closed';command['expected_updated_at']=saved['updated_at'];ledger.improve(tx,subject,action)
        doc['runs'][0]['results']=[r for r in results if r['ruleId']=='synthetic/stale']
        doc['runs'][0]['results'][0]['message']['text']='Later synthetic contradictory occurrence'
        p=af.preview(store,CUSTOMER,ENVIRONMENT,json.dumps(doc).encode(),operator);af.confirm(store,p['id'],CUSTOMER,ENVIRONMENT)
        doc['runs'][0]['results']=[]
        p=af.preview(store,CUSTOMER,ENVIRONMENT,json.dumps(doc).encode(),operator);af.confirm(store,p['id'],CUSTOMER,ENVIRONMENT)
        for asset,applicability in [('synthetic-build-01','confirmed affected'),('synthetic-build-02','needs verification')]:
            vi.observe(store,ctx,{'asset_id':asset,'cve':'CVE-2023-42793','product':'Synthetic build service','observed_version':'unknown','finding_id':asset,'owner':'Synthetic infrastructure engineering','observed_at':now(),'evidence_reference':'synthetic:leadership','evidence_kind':'synthetic fixture','applicability':applicability,'applicability_reason':'Authored fictional assessment; no actual asset scanned'})
        # A separate source-only CVE illustrates that mention does not imply exposure.
        job=service.submit(CUSTOMER,ENVIRONMENT,'offline','text','Synthetic leadership example mentions CVE-2025-12345 only; no asset applicability is established.',background=False,name='synthetic-leadership.txt',metadata={'fixture':True})
        if job['state']!='complete':raise ValueError('Synthetic source ingestion did not complete')
        vi.sync_sources(service,ctx)
        result={'customer_id':CUSTOMER,'environment_id':ENVIRONMENT,'synthetic':True,'created_at':now()}
        store.put('exposure_demo','phase3',result,immutable=True)
        return result
