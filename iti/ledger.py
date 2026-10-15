from datetime import datetime,timezone,timedelta
from .models import TestRun,ImprovementAction
from .store import uid,now,digest,canonical
FRESHNESS_DAYS=30

def dt(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
def seconds(start,end):return max(0,(dt(end)-dt(start)).total_seconds()) if start and end else None

def dependency(assessment,behavior_id):
    return {'source_revision':assessment['source']['revision_id'],'extraction_id':assessment['extraction']['id'],'customer_version':assessment['context']['customer_version'],'environment_version':assessment['context']['environment_version'],'rules':{r['id']:r['source']['sha256'] for r in assessment['candidates'] if r['behavior_id']==behavior_id}}
def scope_key(assessment):
    c=assessment['context'];return ':'.join([c['customer_id'],c['environment_id'],assessment['source']['id']])

def record_test(store,assessment,test):
    ids={b['id'] for b in assessment['extraction']['behaviors']}
    if test.behavior_id not in ids:raise ValueError('Behavior does not belong to assessment')
    if test.environment_version!=assessment['context']['environment_version']:raise ValueError('Environment version mismatch')
    if dt(test.executed_at)>datetime.now(timezone.utc)+timedelta(minutes=5):raise ValueError('Execution time cannot be in the future')
    if test.dimension.startswith('soc_') and dt(test.executed_at)<dt(test.exercise_event_at):raise ValueError('SOC outcome cannot precede exercise event')
    if test.method in ('observed SIEM alert','observed prevention') and not any(e.kind in ('live system','lab execution') for e in test.evidence):raise ValueError('Observed outcome requires live-system or lab execution evidence; assertion alone is an attestation')
    if test.method=='synthetic log match' and any(e.kind!='synthetic fixture replay' for e in test.evidence):raise ValueError('Synthetic method requires synthetic evidence labeling')
    if test.method=='lab emulation' and not any(e.kind=='lab execution' for e in test.evidence):raise ValueError('Lab method requires lab evidence')
    if test.improvement_id:
        action=store.get('improvement',test.improvement_id)
        if action['scope']!=scope_key(assessment) or action['behavior_id']!=test.behavior_id:raise ValueError('Retest improvement scope mismatch')
    matched=next((r for r in assessment['candidates'] if r['id']==test.control_id),None)
    if matched and test.method!='analyst attestation' and test.control_version!=matched['source']['sha256']:raise ValueError('Rule version differs from assessed candidate; reassess the changed rule before recording verification')
    test.id=store.identity('test:'+uid('test',scope_key(assessment),now(),test.model_dump_json()));test.recorded_at=now()
    record=test.model_dump()|{'context':assessment['context'],'document_id':assessment['source']['id'],'assessment_id':assessment['id'],'dependencies':dependency(assessment,test.behavior_id),'confirmed_at':now()}
    store.put('test',test.id,record,immutable=True);store.event('test_executed',scope_key(assessment),record)
    if test.baseline:store.event('baseline_assessed',scope_key(assessment),{'test_id':test.id,'confirmed_at':record['confirmed_at'],'original_execution_time':test.executed_at})
    return record

def improve(store,assessment,action,candidate_ref=None):
    # Serializes retries and simultaneous submissions across threads/processes.
    with store.lock('improvement:'+scope_key(assessment)):
        return _improve(store,assessment,action,candidate_ref)

def _improve(store,assessment,action,candidate_ref):
    from . import defenses
    if action.behavior_id not in {b['id'] for b in assessment['extraction']['behaviors']}:raise ValueError('Unknown behavior')
    context=assessment['context'];origin_assessment=assessment['id']
    if action.id:
        old=store.get('improvement',action.id)
        if old['scope']!=scope_key(assessment):raise ValueError('Improvement customer/environment mismatch')
        if candidate_ref:raise ValueError('Existing action cannot acquire a new candidate origin')
        if old.get('origin') and (old['origin']['assessment_id']!=assessment['id'] or old['behavior_id']!=action.behavior_id):raise ValueError('Frozen defense action assessment/behavior mismatch')
        if action.origin is not None and action.origin!=old.get('origin'):raise ValueError('Improvement origin cannot be altered')
        action.origin=old.get('origin');context=old['context'];origin_assessment=old.get('assessment_id',assessment['id'])
        action.opened_at=old['opened_at']
        action.deployed_at=old.get('deployed_at') or action.deployed_at
    else:
        if action.origin is not None:raise ValueError('Client-supplied origin is not trusted; select a stored candidate')
        if candidate_ref:
            action.origin=defenses.resolve_origin(store,assessment,action.behavior_id,candidate_ref)
            action.id=uid('improvement',assessment['id'],context['customer_id'],context['environment_id'],action.behavior_id,action.origin['d3fend_id'])
            prior=store.maybe('improvement',action.id)
            if prior:return prior
            if action.status!='open' or action.deployed_at:raise ValueError('New candidate improvement must start open and undeployed')
        else:action.id=store.identity('improvement:'+scope_key(assessment)+':'+now())
        action.opened_at=now()
    if action.status=='deployed' and not action.deployed_at:action.deployed_at=now()
    row=action.model_dump()|{'context':context,'scope':scope_key(assessment),'assessment_id':origin_assessment}
    store.put('improvement',action.id,row);store.event('improvement_'+action.status.replace(' ','_'),scope_key(assessment),row)
    return row

def view(store,assessment):
    import copy
    # Packages have their own creation clock. Always assess against the original
    # persisted assessment, including when a CLI caller supplies a package.
    if assessment.get('assessment_id'):
        assessment=store.get('assessment',assessment['assessment_id'])
    scope=scope_key(assessment);c=assessment['context'];rows=copy.deepcopy(assessment['coverage'])
    tests=[t for t in store.all('test') if t['document_id']==assessment['source']['id'] and t['context']['customer_id']==c['customer_id'] and t['context']['environment_id']==c['environment_id']]
    current=store.get('customer',c['customer_id']);env=next((e for e in current['environments'] if e['id']==c['environment_id']),None)
    receipt=store.get('customer_receipt',uid('receipt',c['customer_id'],assessment['source']['id']))['at']
    ingestion=store.get('source_ingestion',assessment['source']['id'])['at']
    verified_detection=None;verified_prevention=None
    for t in tests:
        reasons=[]
        if t['dependencies']!=dependency(assessment,t['behavior_id']):reasons.append('Source/extraction/profile/rule dependency changed')
        if current['version']!=c['customer_version'] or not env or env['version']!=c['environment_version']:reasons.append('Current customer/environment has a newer version')
        if datetime.now(timezone.utc)-dt(t['executed_at'])>timedelta(days=FRESHNESS_DAYS):reasons.append('Evidence older than 30-day freshness policy')
        t['stale']=bool(reasons);t['stale_reasons']=reasons
        row=next((r for r in rows if r['behavior_id']==t['behavior_id']),None)
        if not row:continue
        if t['method']=='synthetic log match':row['synthetic_result']='stale' if reasons else t['result'];continue
        if t['method']=='analyst attestation':row.setdefault('attestations',[]).append(t['id']);continue
        dim={'telemetry':'telemetry_readiness','detection':'detection_test','prevention':'prevention_test','soc_acknowledged':'soc_response','soc_response':'soc_response','deployment':'deployment'}[t['dimension']]
        label='stale' if reasons else t['result'];evidence_scope='live' if any(e['kind']=='live system' for e in t['evidence']) else 'lab'
        row[dim]=label+' ('+evidence_scope+')'
        if not reasons and t['result']=='passed':
            if t['baseline'] and t['control_deployed_at'] and dt(t['control_deployed_at'])<=dt(receipt):row['coverage_classification']='existing coverage confirmed after receipt'
            elif t['improvement_id'] and t['control_deployed_at'] and dt(t['control_deployed_at'])>=dt(receipt):row['coverage_classification']='coverage changed after gap; variant verified'
            if t['dimension']=='detection' and evidence_scope=='live':verified_detection=t['confirmed_at'] if verified_detection is None else min(verified_detection,t['confirmed_at'])
            if t['dimension']=='prevention' and evidence_scope=='live':verified_prevention=t['confirmed_at'] if verified_prevention is None else min(verified_prevention,t['confirmed_at'])
    counts={k:sum(r['applicability']==k for r in rows) for k in ['applicable','unknown','not applicable']}
    counts.update({'failed':sum('failed' in r['detection_test'] or r['synthetic_result']=='failed' for r in rows),'untested':sum(r['detection_test']=='not tested' for r in rows),'stale':sum('stale' in r['detection_test'] or r['synthetic_result']=='stale' for r in rows),'live_detection_passed':sum(r['detection_test']=='passed (live)' and r['applicability']=='applicable' for r in rows)})
    packages=[p for p in store.all('package') if p['source']['id']==assessment['source']['id'] and p['context']['customer_id']==c['customer_id'] and p['context']['environment_id']==c['environment_id']]
    first_package=min((p['created_at'] for p in packages),default=None)
    assessments=[a for a in store.all('assessment') if a['source']['id']==assessment['source']['id'] and a['context']['customer_id']==c['customer_id'] and a['context']['environment_id']==c['environment_id']]
    first_assessment=min((a['created_at'] for a in assessments),default=None)
    return {'rows':rows,'tests':tests,'improvements':[i for i in store.all('improvement') if i['scope']==scope],'history':sorted(store.history(scope)+store.history(assessment['source']['id']),key=lambda e:e['seq']),'counts':counts,'live_detection_percent':round(100*counts['live_detection_passed']/counts['applicable'],1) if counts['applicable'] else None,'metrics':{'source_first_ingestion':ingestion,'customer_first_receipt':receipt,'first_package_ready':first_package,'assessment_ready':assessment['created_at'],'first_assessment_ready':first_assessment,'customer_receipt_to_first_assessment_seconds':seconds(receipt,first_assessment),'source_ingestion_to_package_seconds':seconds(ingestion,first_package),'customer_receipt_to_assessment_seconds':seconds(receipt,assessment['created_at']),'source_ingestion_to_live_detection_seconds':seconds(ingestion,verified_detection),'source_ingestion_to_live_prevention_seconds':seconds(ingestion,verified_prevention),'customer_receipt_to_live_detection_confirmation_seconds':seconds(receipt,verified_detection),'customer_receipt_to_live_prevention_confirmation_seconds':seconds(receipt,verified_prevention),'soc_timings':[{'test_id':t['id'],'seconds':seconds(t.get('exercise_event_at'),t['executed_at']),'scope':t['method'],'exercise':t['exercise']} for t in tests if t['dimension'].startswith('soc_') and not t['stale']],'synthetic_timings':'Excluded from live operational metrics','policy':'30-day freshness plus exact source/extraction/customer/environment/rule dependency match; current confirmation and original execution clocks retained'}}
