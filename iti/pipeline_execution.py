"""Strict manual matching of supplied REST run/jobs responses; no network access."""
import json
from datetime import datetime

MAX_EXECUTION=2*1024*1024


def parse(raw,snapshot):
    if not raw or len(raw)>MAX_EXECUTION:raise ValueError('Execution JSON must be nonempty and at most 2 MiB')
    def pairs(values):
        row={}
        for k,v in values:
            if k in row:raise ValueError('Duplicate JSON keys unsupported')
            row[k]=v
        return row
    try:doc=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs)
    except (ValueError,UnicodeError,RecursionError):raise ValueError('Malformed execution JSON') from None
    stack=[(doc,0)];count=0
    while stack:
        value,depth=stack.pop();count+=1
        if depth>24 or count>50000:raise ValueError('Execution structure exceeds limits')
        if isinstance(value,str) and (len(value)>32768 or any(0xD800<=ord(c)<=0xDFFF for c in value)):raise ValueError('Execution string exceeds limits')
        if isinstance(value,(dict,list)):
            if len(value)>1000:raise ValueError('Execution collection exceeds 1000 entries')
            stack.extend((v,depth+1) for v in (list(value.keys())+list(value.values()) if isinstance(value,dict) else value))
        if isinstance(value,float):raise ValueError('Execution metadata requires integers, not floating point numbers')
    if not isinstance(doc,dict) or set(doc)!={'workflow_run','jobs'}:raise ValueError('Expected workflow_run and jobs REST response envelope')
    run=doc['workflow_run'];job_response=doc['jobs']
    if not isinstance(run,dict) or not isinstance(job_response,dict):raise ValueError('Invalid run/jobs structures')
    def integer(value):return type(value) is int and value>0
    if not integer(run.get('id')) or not integer(run.get('run_attempt')):raise ValueError('Positive run ID and explicit run_attempt required')
    op=snapshot['operator_context']
    if not isinstance(run.get('repository'),dict) or run['repository'].get('full_name')!=op['repository']:raise ValueError('Run repository does not match operator-provided snapshot repository')
    if not op.get('commit') or not isinstance(run.get('head_sha'),str) or run['head_sha'].lower()!=op['commit'].lower():raise ValueError('Run commit must exactly match a snapshot with an explicit commit SHA')
    def branch(value):return value.removeprefix('refs/heads/') if isinstance(value,str) else None
    if branch(run.get('head_branch'))!=branch(op['ref']):raise ValueError('Run ref does not match snapshot ref')
    path=run.get('path')
    if not isinstance(path,str) or path not in {f['path'] for f in snapshot['files']}:raise ValueError('Run workflow path is not in the supplied snapshot')
    jobs=job_response.get('jobs');total=job_response.get('total_count')
    if not isinstance(jobs,list) or len(jobs)>200 or type(total) is not int or total<len(jobs):raise ValueError('Jobs response requires total_count and at most 200 jobs')
    warnings=[]
    if total!=len(jobs):warnings.append('Partial jobs response; omitted jobs remain unknown')
    def times(record,fields):
        parsed={}
        for field in fields:
            value=record.get(field)
            if value is None:continue
            try:
                parsed[field]=datetime.fromisoformat(value.replace('Z','+00:00'))
                if parsed[field].tzinfo is None:raise ValueError()
            except (ValueError,AttributeError):raise ValueError('Execution timestamps require valid timezone-aware ISO values') from None
        if 'completed_at' in parsed and 'started_at' in parsed and parsed['completed_at']<parsed['started_at']:raise ValueError('Completion precedes execution start')
        if 'updated_at' in parsed and 'created_at' in parsed and parsed['updated_at']<parsed['created_at']:raise ValueError('Run update precedes creation')
    def status(record):
        if record.get('status') not in ('queued','in_progress','completed','waiting','requested','pending'):raise ValueError('Unsupported execution status')
        if record.get('conclusion') not in (None,'success','failure','skipped','cancelled','timed_out','neutral','action_required','stale','startup_failure'):raise ValueError('Unsupported execution conclusion')
        if record['status']!='completed' and record.get('conclusion') is not None:raise ValueError('Incomplete execution cannot have a completed conclusion')
    status(run);times(run,('created_at','updated_at','run_started_at'))
    seen=set();step_count=0
    for job in jobs:
        if not isinstance(job,dict) or not integer(job.get('id')) or job['id'] in seen:raise ValueError('Jobs require unique positive IDs')
        seen.add(job['id'])
        if job.get('run_id')!=run['id'] or type(job.get('run_id')) is not int or type(job.get('run_attempt')) is not int or job.get('run_attempt')!=run['run_attempt']:raise ValueError('Job run ID/attempt does not match; explicit run_attempt required')
        if 'head_sha' in job and job['head_sha']!=run['head_sha']:raise ValueError('Job head SHA differs from run')
        if not isinstance(job.get('name'),str) or not job['name']:raise ValueError('Job name required')
        status(job);times(job,('started_at','completed_at'))
        if job.get('started_at') and run.get('run_started_at') and datetime.fromisoformat(job['started_at'].replace('Z','+00:00'))<datetime.fromisoformat(run['run_started_at'].replace('Z','+00:00')):raise ValueError('Job starts before supplied run start')
        steps=job.get('steps',[])
        if not isinstance(steps,list):raise ValueError('Job steps must be a list')
        step_count+=len(steps)
        if step_count>1000:raise ValueError('Execution limit is 1000 total steps')
        numbers=set()
        for step in steps:
            if not isinstance(step,dict) or not integer(step.get('number')) or step['number'] in numbers or not isinstance(step.get('name'),str):raise ValueError('Steps require unique positive numbers and names')
            numbers.add(step['number']);status(step);times(step,('started_at','completed_at'))
            for field in ('started_at','completed_at'):
                if step.get(field) and job.get(field):
                    step_time=datetime.fromisoformat(step[field].replace('Z','+00:00'));job_time=datetime.fromisoformat(job[field].replace('Z','+00:00'))
                    if field=='started_at' and step_time<job_time or field=='completed_at' and step_time>job_time:raise ValueError('Step time is outside supplied job execution')
    matches={}
    for control in snapshot['observations']:
        state='Unknown / no evidence';reason='No uniquely associated named security step in supplied metadata'
        if control['workflow']==path and control['execution_matchable']:
            candidates=[j for j in jobs if j['name']==control['job_name']]
            if len(candidates)==1:
                job=candidates[0]
                steps=[s for s in job.get('steps',[]) if s['name']==control['step_name']]
                if run['status']!='completed' or not run.get('conclusion'):state='Incomplete';reason='Workflow run is incomplete'
                elif job.get('conclusion') in ('skipped','cancelled'):
                    state='Reported '+job['conclusion'];reason='Associated job did not execute successfully'
                elif len(steps)==1:
                    step=steps[0]
                    if job['status']!='completed' or step['status']!='completed' or not step.get('conclusion') or not job.get('conclusion'):state='Incomplete'
                    elif step['conclusion']=='success':
                        state='Reported successful' if job.get('conclusion')=='success' and step.get('started_at') and step.get('completed_at') and job.get('started_at') and job.get('completed_at') else 'Unknown / no evidence'
                    elif step['conclusion'] in ('failure','timed_out','startup_failure'):state='Reported failed'
                    elif step['conclusion'] in ('skipped','cancelled'):state='Reported '+step['conclusion']
                    else:state='Unknown / no evidence'
                    reason='Exact literal job and unique step name match in supplied metadata; authenticity, scanner coverage and effectiveness remain unknown'
        matches[control['id']]={'state':state,'reason':reason}
    return {'workflow_run':run,'jobs':job_response,'controls':matches,'warnings':warnings,'provenance':'SUPPLIED EXECUTION METADATA; not independently authenticated','independently_verified':False}
