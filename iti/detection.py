import json, re, fnmatch
import yaml
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from .models import DetectionCandidate
from .store import ROOT,digest

MANIFEST=json.loads((ROOT/'catalogs/manifest.json').read_text())
def catalog():
    rows=[]
    for entry in MANIFEST['files']:
        if entry['kind']=='sigma':
            raw=(ROOT/entry['path']).read_text(); rule=yaml.safe_load(raw)
            rows.append((rule,raw,entry))
    return rows

def required_fields(det):
    result=set()
    def walk(v):
        if isinstance(v,dict):
            for k,x in v.items(): result.add(k.split('|')[0]); walk(x) if isinstance(x,dict) else None
        elif isinstance(v,list):
            for x in v: walk(x)
    for k,v in det.items():
        if k not in ('condition','timeframe'): walk(v)
    return sorted(result)

def convert(raw,field_map):
    collection=SigmaCollection.from_yaml(raw)
    pipeline=ProcessingPipeline(name='ITI explicit raw Windows field map v1',items=[ProcessingItem(identifier='iti_fields',transformation=FieldMappingTransformation(field_map))])
    return SplunkBackend(processing_pipeline=pipeline).convert(collection)

def assess(extraction,context):
    candidates=[]; rows=catalog(); found={str(r['id']) for r,_,_ in rows}
    retrieval={'searched_rules':len(rows),'revision':MANIFEST['revisions']['sigma'],'scope':MANIFEST['sigma_scope'],'source_cited_found':[x for x in extraction.cited_rules if x in found],'source_cited_missing':[x for x in extraction.cited_rules if x not in found],'missing_explanation':'Absent from this pinned subset; public/private/removed availability is not inferred','rejected':[]}
    env=context.environment_snapshot
    for b in extraction.behaviors:
        terms={'certutil':['certutil'],'anydesk':['anydesk'],'java_shell':['java','shell'],'powershell':['powershell','gzip'],'lsass':['lsass'],'remote_service':['service'],'rdp':['rdp'],'activemq':['activemq']}.get(b.key,b.technology)
        scored=[]
        for rule,raw,entry in rows:
            hay=(rule.get('title','')+' '+rule.get('description','')).lower()
            score=sum(t.lower() in hay for t in terms)
            if not score: continue
            scored.append((score,rule,raw,entry))
        for _,rule,raw,entry in sorted(scored,key=lambda x:-x[0])[:3]:
            syntax=True; query=None; error=None
            try: SigmaCollection.from_yaml(raw)
            except Exception as e: syntax=False; error=str(e)
            if syntax:
                try: query=' OR '.join('('+q+')' for q in convert(raw,env.field_map))
                except Exception as e: error=f'{type(e).__name__}: {e}'
            fields=required_fields(rule['detection']); category=rule['logsource'].get('category','unknown')
            available=env.telemetry.get(category,[]); missing=[f for f in fields if f not in available]
            ready=rule['logsource'].get('product') in env.platforms and not missing and category in env.telemetry
            strong=b.key=='certutil' and rule['id']=='19b08b1c-861d-4e75-a1ef-ea0c1baf202b'
            candidates.append(DetectionCandidate(id=str(rule['id']),title=rule['title'],behavior_id=b.id,evidence=b.evidence,retrieval='source-cited' if str(rule['id']) in extraction.cited_rules else 'independent local lexical search',match='strong' if strong else 'partial',explanation='Matches named utility and download switches; actual command-line switch variant still needs evidence' if strong else 'Named tool overlap; exact switches/variant may not match the report. Review before deployment.',source=entry|{'commit':MANIFEST['revisions']['sigma'],'sha256':digest(raw)},status=rule.get('status','unknown'),author=rule.get('author','unknown'),license=rule.get('license','Detection Rule License 1.1 (repository license)'),logsource=rule['logsource'],fields=fields,condition=rule['detection'],attack_tags=rule.get('tags',[]),limitations=['Catalog subset only','Conversion does not establish live Splunk execution','Legitimate administrator activity may match'],environment_fit=('Declared fields available; live telemetry not checked' if ready else 'Missing/inapplicable logsource or fields: '+', '.join(missing or [category])),syntax_valid=syntax,conversion_supported=query is not None,environment_ready=ready,query=query,conversion_error=error))
        selected={c.id for c in candidates if c.behavior_id==b.id}
        retrieval['rejected'] += [{'behavior':b.id,'rule':str(r['id']),'reason':'No tool/behavior match in bounded lexical search or lower ranked beyond 3 candidates'} for r,_,_ in rows if str(r['id']) not in selected]
    return candidates,retrieval

class UnsupportedSigma(ValueError): pass

def tri_and(values): return False if False in values else (None if None in values else True)
def tri_or(values): return True if True in values else (None if None in values else False)
def compile_subset(rule):
    det=rule.get('detection',{}); condition=det.get('condition')
    if not isinstance(condition,str) or 'timeframe' in det: raise UnsupportedSigma('Only one stateless boolean condition supported')
    def check(v):
        if isinstance(v,list):
            if not v: raise UnsupportedSigma('Empty selection')
            for x in v: check(x)
        elif isinstance(v,dict):
            for field,value in v.items():
                mods=field.split('|')[1:]
                if any(m not in ('contains','endswith','startswith','all') for m in mods) or len(set(mods)&{'contains','endswith','startswith'})>1: raise UnsupportedSigma('Unsupported modifier: '+field)
                vals=value if isinstance(value,list) else [value]
                if any(not isinstance(x,(str,int,bool)) for x in vals): raise UnsupportedSigma('Only string/integer/bool values supported')
        else: raise UnsupportedSigma('Keyword/raw selection unsupported')
    for k,v in det.items():
        if k!='condition': check(v)
    def expand(m):
        names=[k for k in det if k!='condition' and fnmatch.fnmatchcase(k,m[2])]
        if not names: raise UnsupportedSigma('Condition wildcard matches no selection')
        return '('+(' and ' if m[1]=='all' else ' or ').join(names)+')'
    expr=re.sub(r'\b(all|1) of ([\w*]+)',expand,condition)
    tokens=re.findall(r'[\w]+|[()]',expr)
    if re.sub(r'[\w\s()]','',expr): raise UnsupportedSigma('Unsupported condition expression')
    def evaluate(event):
        missing=set()
        def match(v):
            if isinstance(v,list): return tri_or([match(x) for x in v])
            groups=[]
            for field,value in v.items():
                name,*mods=field.split('|')
                if name not in event: missing.add(name);groups.append(None);continue
                actual=str(event[name]).lower(); vals=value if isinstance(value,list) else [value]
                checks=[]
                for x in vals:
                    target=str(x).lower()
                    if 'contains' in mods: ok=target in actual
                    elif 'endswith' in mods: ok=actual.endswith(target)
                    elif 'startswith' in mods: ok=actual.startswith(target)
                    else: ok=fnmatch.fnmatchcase(actual,target)
                    checks.append(ok)
                groups.append(tri_and(checks) if 'all' in mods else tri_or(checks))
            return tri_and(groups)
        values={k:match(v) for k,v in det.items() if k!='condition'}; pos=0
        def atom():
            nonlocal pos
            if pos>=len(tokens): raise UnsupportedSigma('Incomplete condition')
            t=tokens[pos];pos+=1
            if t=='not':
                x=atom();return None if x is None else not x
            if t=='(':
                x=disjunction()
                if pos>=len(tokens) or tokens[pos]!=')': raise UnsupportedSigma('Unbalanced condition')
                pos+=1;return x
            if t not in values: raise UnsupportedSigma('Unknown condition selector '+t)
            return values[t]
        def conjunction():
            nonlocal pos
            x=atom()
            while pos<len(tokens) and tokens[pos]=='and': pos+=1;x=tri_and([x,atom()])
            return x
        def disjunction():
            nonlocal pos
            x=conjunction()
            while pos<len(tokens) and tokens[pos]=='or': pos+=1;x=tri_or([x,conjunction()])
            return x
        result=disjunction()
        if pos!=len(tokens): raise UnsupportedSigma('Trailing unsupported tokens')
        return {'result':'match' if result is True else 'no match' if result is False else 'inconclusive','missing_fields':sorted(missing),'method':'synthetic log match','scope':'restricted stateless Sigma semantics; no SIEM, deployment, prevention or SOC validation'}
    evaluate({}) # Validate complete condition even before first real event.
    return evaluate

def fixture_test(rule_id):
    row=next((r for r,_,_ in catalog() if str(r['id'])==rule_id),None)
    if not row: raise ValueError('Rule not in pinned subset')
    if rule_id!='19b08b1c-861d-4e75-a1ef-ea0c1baf202b': raise ValueError('Authored fixture set supports only CertUtil download rule; other rules need their own reviewed fixtures')
    evaluate=compile_subset(row)
    fixtures={'positive':{'Image':r'C:\Windows\System32\certutil.exe','OriginalFileName':'CertUtil.exe','CommandLine':'certutil.exe -urlcache -split -f https://example.invalid/harmless.txt harmless.txt'},'negative':{'Image':r'C:\Windows\System32\certutil.exe','OriginalFileName':'CertUtil.exe','CommandLine':'certutil.exe -store My'},'missing-field':{'Image':r'C:\Windows\System32\certutil.exe','OriginalFileName':'CertUtil.exe'}}
    return {'rule_id':rule_id,'rule_version':next(e['sha256'] for r,_,e in catalog() if str(r['id'])==rule_id),'cases':{name:evaluate(event)|{'event':event} for name,event in fixtures.items()},'executed_live':False}

def atomic_candidates(behavior):
    results=[]
    for entry in MANIFEST['files']:
        if entry['kind']!='atomic': continue
        doc=yaml.safe_load((ROOT/entry['path']).read_text())
        if doc['attack_technique']!=behavior.technique_id: continue
        for test in doc['atomic_tests']:
            if behavior.platform not in test['supported_platforms']: continue
            relevant=(behavior.key=='certutil' and 'certutil' in (test['name']+' '+test['description']).lower()) or (behavior.key=='powershell' and 'encoded' in test['name'].lower())
            if relevant:
                results.append({'guid':test['auto_generated_guid'],'name':test['name'],'path':entry['upstream_path'],'url':entry['url'],'revision':MANIFEST['revisions']['atomic'],'platforms':test['supported_platforms'],'prerequisites':test.get('dependencies',[]),'inputs':test.get('input_arguments',{}),'cleanup':test.get('executor',{}).get('cleanup_command'),'executor':test.get('executor',{}).get('name'),'fit':'partial behavior approximation','limitations':'Atomic defaults may fetch external content. Do not run defaults; use the separate benign plan and lab-controlled content. Same technique is not full intrusion reproduction.'})
    return results[:2]
