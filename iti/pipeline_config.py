"""Bounded non-executing YAML assessment; no action/expression resolution."""
import re
import json
import yaml
from yaml.nodes import MappingNode, SequenceNode, ScalarNode
from .pipeline_models import Observation, VERSION, LIMITATIONS
from .store import uid

MAX_FILE=512*1024
MAX_TOTAL=4*1024*1024

class WorkflowLoader(yaml.SafeLoader):
    pass
# YAML 1.2 boolean spelling: do not turn GitHub's `on` into a boolean key.
WorkflowLoader.yaml_implicit_resolvers={k:[(tag,pattern) for tag,pattern in values if tag not in ('tag:yaml.org,2002:bool','tag:yaml.org,2002:timestamp')] for k,values in yaml.SafeLoader.yaml_implicit_resolvers.items()}
WorkflowLoader.add_implicit_resolver('tag:yaml.org,2002:bool',re.compile(r'^(?:true|false|True|False|TRUE|FALSE)$'),list('tTfF'))


def filename(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_. -]{1,190}\.ya?ml',value) or value.startswith('.'):
        raise ValueError('Use a plain workflow filename ending in .yml or .yaml; paths are not accepted')
    return '.github/workflows/'+value


def parse(raw):
    if not raw or len(raw)>MAX_FILE: raise ValueError('Workflow must be nonempty and at most 512 KiB')
    try:
        text=raw.decode('utf-8-sig')
        count=depth=documents=0
        for event in yaml.parse(text,Loader=WorkflowLoader):
            count+=1
            if isinstance(event,yaml.AliasEvent) or getattr(event,'anchor',None): raise ValueError('YAML anchors/aliases are unsupported; supply expanded configuration')
            if isinstance(event,yaml.DocumentStartEvent): documents+=1
            if isinstance(event,(yaml.MappingStartEvent,yaml.SequenceStartEvent)): depth+=1
            if isinstance(event,(yaml.MappingEndEvent,yaml.SequenceEndEvent)): depth-=1
            if depth>24 or count>20000 or documents>1: raise ValueError('YAML exceeds depth 24, 20000 events or one document')
            if isinstance(event,yaml.ScalarEvent) and (len(event.value)>32768 or any(0xD800<=ord(c)<=0xDFFF for c in event.value)): raise ValueError('YAML string limit is 32768 valid Unicode characters')
        loader=WorkflowLoader(text)
        locations={}
        try:
            node=loader.get_single_node()
            def visit(n,path):
                location='.'.join(str(k) if not isinstance(k,str) or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*',k) else '['+json.dumps(k,ensure_ascii=False)+']' for k in path)
                if len(location)>2048:raise ValueError('YAML source location exceeds 2048 characters')
                locations[location]=n.start_mark.line+1
                if isinstance(n,MappingNode):
                    if n.tag!='tag:yaml.org,2002:map':raise ValueError('Unsupported YAML mapping tag')
                    if len(n.value)>200:raise ValueError('YAML mapping limit is 200 entries')
                    values={}
                    for key,value in n.value:
                        if not isinstance(key,ScalarNode) or key.tag!='tag:yaml.org,2002:str':raise ValueError('YAML mapping keys must be unambiguous strings')
                        k=key.value
                        if len(k)>256:raise ValueError('YAML mapping keys exceed 256 characters')
                        if k in values or k=='<<':raise ValueError('Duplicate keys and merge keys are unsupported')
                        values[k]=visit(value,path+[k])
                    return values
                if isinstance(n,SequenceNode):
                    if n.tag!='tag:yaml.org,2002:seq':raise ValueError('Unsupported YAML sequence tag')
                    if len(n.value)>200:raise ValueError('YAML sequence limit is 200 entries')
                    return [visit(v,path+[i]) for i,v in enumerate(n.value)]
                if not isinstance(n,ScalarNode) or n.tag not in {'tag:yaml.org,2002:str','tag:yaml.org,2002:bool','tag:yaml.org,2002:int','tag:yaml.org,2002:float','tag:yaml.org,2002:null'}:raise ValueError('Unsupported YAML type/tag')
                value=loader.construct_object(n)
                if isinstance(value,float):
                    import math
                    if not math.isfinite(value):raise ValueError('Nonfinite YAML numbers unsupported')
                return value
            document=visit(node,[]) if node else None
        finally: loader.dispose()
    except (yaml.YAMLError,UnicodeError,RecursionError,OverflowError):
        raise ValueError('Malformed or unsupported workflow YAML') from None
    validate(document)
    return document,locations


def validate(doc):
    if not isinstance(doc,dict) or not isinstance(doc.get('jobs'),dict) or not doc['jobs'] or len(doc['jobs'])>100:raise ValueError('Workflow requires 1–100 jobs')
    triggers=doc.get('on')
    if not isinstance(triggers,(str,list,dict)) or (isinstance(triggers,list) and any(not isinstance(x,str) for x in triggers)):raise ValueError('Workflow on must be an event name, list or mapping')
    if isinstance(triggers,dict) and any(v is not None and not isinstance(v,dict) for v in triggers.values()):raise ValueError('Event configuration must be a mapping or null')
    def permissions(value):
        if value is None:return
        if isinstance(value,str) and value in ('read-all','write-all'):return
        if not isinstance(value,dict) or any(v not in ('read','write','none') for v in value.values()):raise ValueError('Unsupported permissions structure')
    permissions(doc.get('permissions'))
    for key,job in doc['jobs'].items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*',key) or not isinstance(job,dict):raise ValueError('Invalid job mapping')
        permissions(job.get('permissions'))
        if 'uses' in job and ('steps' in job or not isinstance(job['uses'],str)):raise ValueError('Reusable jobs require a string uses and cannot also contain steps')
        steps=job.get('steps',[])
        if 'uses' not in job and not steps:raise ValueError('Job requires nonempty steps or a reusable workflow reference')
        if not isinstance(steps,list):raise ValueError('Job steps must be a list')
        for step in steps:
            if not isinstance(step,dict) or ('uses' in step and 'run' in step):raise ValueError('Ambiguous workflow step')
            if not step.get('uses') and not step.get('run'):raise ValueError('Step requires a nonempty uses or run string')
            for field in ('uses','run','name'):
                if field in step and not isinstance(step[field],str):raise ValueError('Step uses/run/name must be strings')
            if 'with' in step and not isinstance(step['with'],dict):raise ValueError('Step with must be a mapping')
        for container in [job,*steps]:
            if 'if' in container and not isinstance(container['if'],(str,bool)):raise ValueError('Unsupported conditional type')
            if 'continue-on-error' in container and not isinstance(container['continue-on-error'],(str,bool)):raise ValueError('Unsupported continue-on-error type')
        if 'name' in job and not isinstance(job['name'],str):raise ValueError('Job name must be a string')


def uses_state(value):
    if value.startswith('./'):return 'Requires manual review','Local reference; supplied definitions only, no filesystem access'
    if value.startswith('docker://'):
        if re.fullmatch(r'docker://[^\s@]+@sha256:[0-9a-fA-F]{64}',value):return 'Observed configured','Container digest reference is immutable syntax; image trust is not established'
        return 'Requires manual review','Container reference lacks a supported immutable digest; image is not inspected'
    match=re.fullmatch(r'([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s]+)',value)
    if not match:return 'Unknown','Unsupported action reference form; no resolution attempted'
    if re.fullmatch(r'[0-9a-fA-F]{40}',match[2]):return 'Observed configured','Full commit-SHA reference; legitimacy and content are not independently validated'
    return 'Potential concern','Mutable external tag/ref; consider an approved immutable reference'


def control(step):
    uses=step.get('uses','').split('@')[0].lower()
    if uses=='github/codeql-action/analyze' or uses=='semgrep/semgrep-action':return 'SAST'
    if uses=='gitleaks/gitleaks-action':return 'Secrets scanning'
    if uses=='actions/dependency-review-action':return 'Dependency review'
    # Only direct command invocations at a line start; names in comments/echo are not controls.
    for line in step.get('run','').splitlines():
        for pattern,kind in [(r'semgrep\s+(?:ci|scan)\b','SAST'),(r'gitleaks\s+(?:detect|protect|git|dir)\b','Secrets scanning'),(r'(?:pip-audit|npm\s+audit)\b','Dependency vulnerability scanning'),(r'(?:(?:python3?\s+-m\s+)?pytest|npm\s+test|go\s+test|cargo\s+test|dotnet\s+test)\b','Regression tests')]:
            if re.match(r'^\s*'+pattern,line):return kind
    return None


def assess(files):
    rows=[]
    by_path={f['path']:f for f in files}
    for f in files:
        doc,locations,path=f['document'],f['locations'],f['path']
        def add(check,category,key,state,reason,evidence,**binding):
            row=Observation(id=uid('pipeline_control',path,check,key),check_id=check,category=category,description=check.replace('_',' '),state=state,workflow=path,key=key,line=locations.get(key),evidence=evidence,reason=reason,limitations=LIMITATIONS,**binding).model_dump()
            rows.append(row)
        def permission(value,key):
            state='Unknown' if value is None else 'Potential concern' if value=='write-all' else 'Requires manual review' if isinstance(value,dict) and 'write' in value.values() else 'Observed configured'
            add('declared_permissions','Permissions',key,state,'Absent permissions leave defaults unknown; explicit job permissions override workflow declarations. Narrow writes can be legitimate. Effective token permissions and policy remain unknown.',value)
        permission(doc.get('permissions'),'permissions')
        triggers=doc['on']; events=[triggers] if isinstance(triggers,str) else list(triggers)
        sensitive=any(e in events for e in ('pull_request_target','workflow_run'))
        add('trigger_trust_boundary','Execution context','on','Requires manual review' if sensitive else 'Observed configured','Sensitive event context requires review of which content is executed; no exploitability inferred.' if sensitive else 'Declared trigger scope only; expressions and branch/path filters are not evaluated.',triggers)
        add('merge_enforcement','Enforcement','on','Unknown','Workflow YAML does not establish branch protection, required checks or bypass policy.',None)
        found=set(); delegated=any('uses' in j for j in doc['jobs'].values())
        for job_id,job in doc['jobs'].items():
            prefix='jobs.'+job_id
            permission(job.get('permissions',doc.get('permissions')),prefix+'.permissions')
            if 'permissions' not in job:
                rows[-1].update(key='permissions',line=locations.get('permissions'),job_key=job_id,evidence={'inherited_from':'workflow permissions','declaration':doc.get('permissions')})
            if 'uses' in job:
                reference=job['uses'];state,reason=uses_state(reference)
                add('reusable_reference','Dependencies',prefix+'.uses',state,reason,reference)
                target=by_path.get(reference[2:]) if reference.startswith('./') else None
                target_on=target['document']['on'] if target else None
                callable_target=target and ('workflow_call'==target_on or isinstance(target_on,(list,dict)) and 'workflow_call' in target_on)
                add('delegated_controls','Security testing',prefix+'.uses','Requires manual review' if callable_target else 'Unknown',
                    'Included local workflow definition is assessed separately. Its call inputs, secrets, nested delegation and execution are not resolved.' if callable_target else 'Referenced but uninspected reusable workflow; downstream security coverage is unknown, not absent.',{'reference':reference,'included_definition':target['path'] if callable_target else None})
            steps=job.get('steps',[])
            for i,step in enumerate(steps):
                key=prefix+'.steps.'+str(i)
                if 'uses' in step:
                    state,reason=uses_state(step['uses']);add('action_reference','Dependencies',key+'.uses',state,reason,step['uses'])
                    if step['uses'].split('@')[0].lower()=='actions/checkout':
                        options=step.get('with',{});persist=options.get('persist-credentials')
                        add('checkout_credentials','Credentials',key+'.with','Observed configured' if persist is False or persist=='false' else 'Potential concern' if persist is True or persist=='true' else 'Unknown',
                            'Explicit persistence disabled only for this checkout.' if persist is False or persist=='false' else 'Persistence is enabled or unspecified/dynamic; necessity and token privileges require review.',{'persist-credentials':persist,'token_supplied':'token' in options})
                        if sensitive and 'ref' in options:
                            add('privileged_checkout_ref','Execution context',key+'.with','Requires manual review','Sensitive trigger with explicit checkout ref; review whether untrusted head content is executed. Data flow is not established.',{'ref':options['ref'],'events':events})
                run=step.get('run','')
                if re.search(r'\$\{\{\s*github\.event\.(?:pull_request|issue|comment|head_commit|commits)\b',run):
                    add('event_shell_interpolation','Execution context',key+'.run','Potential concern','Direct event-field interpolation in supplied shell text warrants trust-boundary review; no shell is executed and exploitation is not established.',run)
                kind=control(step)
                if not kind:continue
                found.add(kind)
                conditional='if' in job or 'if' in step or 'strategy' in job
                masks_failure=bool(re.search(r'\|\|\s*(?:true|:)(?:\s|$)|\bset\s+\+e\b|\bexit\s+0\b',run))
                nonblocking=masks_failure or job.get('continue-on-error',False) is not False or step.get('continue-on-error',False) is not False
                job_name=job.get('name',job_id);step_name=step.get('name')
                bind=bool(step_name and '${{' not in step_name and '${{' not in job_name and 'strategy' not in job and sum(j.get('name',k)==job_name for k,j in doc['jobs'].items())==1 and sum(s.get('name')==step_name for s in steps)==1)
                add('configured_'+kind.lower().replace(' ','_'),'Security testing',key,'Observed configured',
                    kind+' invocation is present in configuration; actual execution, coverage and effectiveness are unknown.',{'uses':step.get('uses'),'run':step.get('run')},job_key=job_id,job_name=job_name,step_name=step_name,step_number=i+1,execution_matchable=bind)
                add('control_gate','Enforcement',key,'Potential concern' if nonblocking else 'Requires manual review' if conditional else 'Observed configured',
                    'Failure continuation, shell failure masking or dynamic continuation requires review.' if nonblocking else 'Conditional/matrix execution can skip or vary this control.' if conditional else 'No explicit failure continuation; configured failure propagation only. Shell error handling and merge enforcement remain unverified.',
                    {'job_if':job.get('if'),'step_if':step.get('if'),'job_continue_on_error':job.get('continue-on-error'),'step_continue_on_error':step.get('continue-on-error'),'needs':job.get('needs'),'strategy':job.get('strategy')})
        for kind in ('SAST','Secrets scanning','Dependency vulnerability scanning','Regression tests'):
            if kind not in found:add('coverage_'+kind.lower().replace(' ','_'),'Security testing','jobs','Unknown' if delegated else 'Not observed in supplied scope',
                'Delegated definitions may contain this control; no absence conclusion is supported.' if delegated else 'No supported direct invocation recognized in these supplied steps. Arbitrary scripts, local actions and other control tools are not analyzed.',kind)
    if len(rows)>5000:raise ValueError('Pipeline assessment exceeds 5000 observations')
    return rows
