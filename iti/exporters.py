import copy
import json, re, zipfile, io
from datetime import datetime,timezone
import stix2
from stix2patterns.validator import run_validator
from stix2validator import validate_string,ValidationOptions
from pymisp import MISPEvent
from .store import uid,canonical,digest,now
from .models import SourceDocument,Extraction
from .analysis import validate_evidence

def validate_stix(text):
    bundle=stix2.parse(text,allow_custom=False)
    if bundle.type!='bundle': raise ValueError('Expected STIX Bundle')
    result=validate_string(text,ValidationOptions(version='2.1',strict=False))
    errors=[str(e) for e in (result.errors or [])]; warnings=[str(w) for w in (result.warnings or [])]
    ids={o.id for o in bundle.objects}
    for obj in bundle.objects:
        if obj.type=='indicator': errors.extend(run_validator(obj.pattern,'2.1'))
        for key in ('object_refs','source_ref','target_ref','created_by_ref'):
            refs=obj.get(key,[]); refs=[refs] if isinstance(refs,str) else refs
            for ref in refs:
                if ref not in ids: errors.append(f'Dangling {key}: {ref}')
    if errors: raise ValueError('STIX validation failed: '+str(errors))
    return {'valid':True,'objects':len(ids),'warnings':warnings,'patterns_valid':True,'references_valid':True}

def stix_export(store,package):
    source=SourceDocument.model_validate(package['source']);ex=Extraction.model_validate(package['extraction']);validate_evidence(ex,source)
    # Imported standard objects preserve original IDs/content, including source identity.
    objects=[stix2.parse(o,allow_custom=False) for o in source.imported_objects if o.get('type') not in ('csv','misp-attribute','ip-dst','sha256','domain') and '--' in o.get('id','')]
    timestamp=package['created_at'].replace('+00:00','Z'); base=source.id; store.put('stix_created',base,{'at':timestamp},immutable=True); created=min(store.get('stix_created',base)['at'].replace('+00:00','Z'),timestamp)
    def sid(key,typ):return store.identity('stix:'+base+':'+key,typ)
    identity=stix2.Identity(id=sid('publisher','identity'),name=source.publisher or 'Supplied source (publisher unknown)',identity_class='organization',created=created,modified=timestamp)
    objects.append(identity);refs=[];omissions=[]
    for b in ex.behaviors:
        if b.kind in ('unsupported','conflicting'):omissions.append(f'{b.id}: unsupported/conflicting assertion omitted');continue
        external=[{'source_name':'MITRE ATT&CK','external_id':b.technique_id,'url':'https://attack.mitre.org/techniques/'+b.technique_id.replace('.','/')+'/'}] if b.technique_id else []
        ap=stix2.AttackPattern(id=sid(b.id,'attack-pattern'),name=b.technique_name or b.text[:120],description=b.text+'\nEvidence: '+', '.join(b.evidence)+'\nMapping: '+b.mapping_basis+'; '+(b.qualifier or ''),created=created,modified=timestamp,external_references=external or None,created_by_ref=identity.id)
        objects.append(ap);refs.append(ap.id)
    for o in ex.observables:
        if o.type=='ipv4': sco=stix2.IPv4Address(value=o.value);prop='ipv4-addr:value'
        elif o.type=='domain':sco=stix2.DomainName(value=o.value);prop='domain-name:value'
        elif o.type=='url':sco=stix2.URL(value=o.value);prop='url:value'
        else:sco=stix2.File(hashes={'SHA-256':o.value});prop="file:hashes.'SHA-256'"
        objects.append(sco);refs.append(sco.id)
        if o.maliciousness_asserted and o.role=='malicious':
            escaped=o.value.replace('\\','\\\\').replace("'","\\'"); pattern=f"[{prop} = '{escaped}']"
            if run_validator(pattern,'2.1'):raise ValueError('Invalid generated indicator pattern')
            indicator=stix2.Indicator(id=sid(o.id,'indicator'),name='Historical source-reported '+o.type,description=o.context+'\nNot an automatic block recommendation. Review historical significance. Evidence: '+', '.join(o.evidence),pattern=pattern,pattern_type='stix',valid_from=timestamp,created=created,modified=timestamp,created_by_ref=identity.id)
            objects.extend([indicator,stix2.Relationship(id=sid(o.id+'based-on','relationship'),relationship_type='based-on',source_ref=indicator.id,target_ref=sco.id,created=created,modified=timestamp)]);refs.append(indicator.id)
    # Report published is required in STIX. Unknown source publication uses a Grouping instead.
    external=[{'source_name':source.publisher or 'supplied source','url':source.origin}] if source.origin.startswith(('http://','https://')) else []
    desc='Source context; '+source.completeness+'. '+ ' '.join(source.gaps)+'\nIncident time: '+(source.incident_time or 'unknown')+'\nSource document: '+source.id+'\nSerials: '+', '.join(s['value'] for s in source.serials)
    refs=refs or [identity.id]
    if source.published_at:
        published=source.published_at[:10]+'T00:00:00Z' if len(source.published_at)==10 else source.published_at.replace('+00:00','Z')
        report=stix2.Report(id=sid('report','report'),name=source.title,description=desc+'\nPublication precision: '+source.publication_precision,report_types=['threat-report'],published=published,object_refs=refs,created=created,modified=timestamp,external_references=external or None,created_by_ref=identity.id)
    else:report=stix2.Grouping(id=sid('grouping','grouping'),name=source.title,description=desc,context='suspicious-activity',object_refs=refs,created=created,modified=timestamp,external_references=external or None)
    objects.append(report)
    # De-duplicate SCOs / imported identities without rewriting imported versions.
    unique={o.id:o for o in objects}; text=stix2.Bundle(id=store.identity('bundle:'+package['id'],'bundle'),objects=list(unique.values())).serialize(pretty=True)
    return text,validate_stix(text),omissions

def misp_export(store,package):
    source=package['source'];context=package['context'];ex=package['extraction']
    key='misp:'+context['customer_id']+':'+(context['destination'] or 'local-export')+':'+source['id']
    event=MISPEvent();event.uuid=store.identity(key);event.info=source['title'];event.distribution=0;event.published=False;event.analysis=0;event.threat_level_id=4
    # Event date is package-context date, explicitly not intrusion date.
    event.date=package['created_at'][:10]
    event.add_tag('iti:mode='+ex['mode'])
    for obs in ex['observables']:
        attr=event.add_attribute({'ipv4':'ip-dst','domain':'domain','url':'url','sha256':'sha256'}[obs['type']],obs['value'],uuid=store.identity(key+':'+obs['id']),to_ids=obs['to_ids'],distribution=0,comment=f'Role: {obs["role"]}. {obs["to_ids_reason"]} Evidence: {", ".join(obs["evidence"])}')
    if source['origin'].startswith(('http://','https://')):event.add_attribute('link',source['origin'],uuid=store.identity(key+':source-link'),to_ids=False,distribution=0,comment='Source report URL; never an IOC')
    context_text=f'Source: {source["origin"]}\nDocument: {source["id"]}\nPublished: {source["published_at"]} ({source["publication_precision"]})\nIncident: {source["incident_time"] or "unknown"}\nCompleteness: {source["completeness"]}; gaps: {source["gaps"]}\nCustomer assessment: {context["customer_id"]} v{context["customer_version"]}, {context["environment_id"]} v{context["environment_version"]}\nMode: {ex["mode"]}\nEvent date is package creation date, not an inferred observation. MISP analysis=0 does not describe AI/test completion.\n'
    for b in ex['behaviors']:
        if b['kind'] in ('unsupported','conflicting'):continue
        context_text+=f'\n- {b["text"]} ATT&CK {b["technique_id"]} ({b["mapping_basis"]}). Evidence {b["evidence"]}. {b["qualifier"] or ""}'
    context_text+='\nImported source event identity: '+str(source['metadata'].get('source_event_uuid','not a MISP input'))
    context_text+='\n\nReview warnings: '+ '; '.join(ex['warnings'])
    event.add_event_report(name='Intel to Improvements source and assessment context',content=context_text,uuid=store.identity(key+':context'),distribution=0)
    result=json.loads(event.to_json());wrapped={'Event':result}
    validate_misp(wrapped)
    return json.dumps(wrapped,indent=2,ensure_ascii=False),{'valid':True,'attributes':len(result.get('Attribute',[])),'native':'PyMISP event + bundled schema-lax.json; EventReport checked by PyMISP models','live_import':'NOT RUN'}

def validate_misp(obj):
    event=MISPEvent();event.load(copy.deepcopy(obj));event.to_json()
    import pymisp,jsonschema
    from pathlib import Path
    schema=json.loads((Path(pymisp.__file__).parent/'data/schema-lax.json').read_text())
    jsonschema.validate(obj,schema)
    # PyMISP load validates attribute types; enforce application sharing invariants too.
    ev=obj['Event']
    if ev.get('published') not in (False,0,'0'):raise ValueError('Export must remain unpublished')
    if int(ev['distribution'])!=0:raise ValueError('Export must remain organization-only')
    for a in ev.get('Attribute',[]):
        if int(a.get('distribution',0))!=0:raise ValueError('Child sharing must be organization-only')
    for report in ev.get('EventReport',[]):
        if int(report.get('distribution',0))!=0:raise ValueError('Event report sharing must be organization-only')
    return True

def convert_compare(stix_text,native):
    try:
        from misp_stix_converter import ExternalSTIX2toMISPParser
        parser=ExternalSTIX2toMISPParser();parser.load_stix_bundle(stix2.parse(stix_text));parser.parse_stix_bundle()
        events=getattr(parser,'misp_events',None) or [parser.misp_event]
        if isinstance(events,MISPEvent):events=[events]
        converted=[json.loads(e.to_json()) for e in events]
        native_ev=json.loads(native)['Event']; values={a['value'] for a in native_ev.get('Attribute',[]) if a['type']!='link'}
        got={a['value'] for ev in converted for a in ev.get('Attribute',[])}
        object_values={a['value'] for ev in converted for o in ev.get('Object',[]) for a in o.get('Attribute',[])}
        missing=values-(got|object_values)
        clusters=[c for ev in converted for g in ev.get('Galaxy',[]) for c in g.get('GalaxyCluster',[])]
        original=json.loads(stix_text);behavior_objects=[o for o in original['objects'] if o['type']=='attack-pattern']
        preserved_behaviors=[o['id'] for o in behavior_objects if any(c.get('uuid')==o['id'].split('--',1)[1] or c.get('value')==o['name'] for c in clusters)]
        native_context=[r.get('content','') for r in native_ev.get('EventReport',[])]
        converted_context=[r.get('content','') for ev in converted for r in ev.get('EventReport',[])]
        return {'status':'completed','library':'misp-stix','events':len(converted),'native_values':sorted(values),'missing_values':sorted(missing),'preserved_values':sorted(values & (got|object_values)),'behavior_comparison':{'source_attack_patterns':len(behavior_objects),'preserved_by_identity_or_name':len(preserved_behaviors),'missing_ids':[o['id'] for o in behavior_objects if o['id'] not in preserved_behaviors],'note':'ATT&CK cluster/name retention is not preservation of exact procedure semantics'},'native_eventreport_exactly_preserved':all(x in converted_context for x in native_context),'behavior_context':'Native EventReport and converted objects differ; inspect converted export. No universal compatibility claim.','warnings':str(getattr(parser,'warnings',{})),'errors':str(getattr(parser,'errors',{})),'live_misp_import':'NOT RUN'},json.dumps(converted,indent=2)
    except Exception as e:return {'status':'failed','error':f'{type(e).__name__}: {e}','live_misp_import':'NOT RUN'},None

def export_package(store,package):
    from .packages import render_markdown
    stix,sv,omissions=stix_export(store,package);misp,mv=misp_export(store,package)
    conversion,converted=convert_compare(stix,misp)
    from . import attack_flow
    flow,flow_provenance,flow_status=attack_flow.export(store,package)
    compatibility={'stix':sv,'native_misp':mv,'converter':conversion,'omissions':omissions+package['source']['conversion_losses'],'review_warnings':package['extraction']['warnings'],'readiness':'review required','attack_flow':flow_status,'claim':'Validated serialization is not semantic truth or universal TIP compatibility'}
    data={'cti.stix21.json':stix,'cti.misp.json':misp,'hunt.json':json.dumps({'context':package['context'],'source_gaps':package['source']['gaps'],'hunts':package['hunts']},indent=2),'purple-team.json':json.dumps({'context':package['context'],'source_gaps':package['source']['gaps'],'scenarios':package['emulations']},indent=2),'hunt.md':render_markdown('Evidence-led hunt package',package,'hunts'),'purple-team.md':render_markdown('Human-led controlled validation plan',package,'emulations'),'compatibility.json':json.dumps(compatibility,indent=2),'evidence.json':json.dumps({'source':package['source'],'extraction':package['extraction']},indent=2),'coverage.json':json.dumps({'context':package['context'],'source_revision':package['source']['revision_id'],'rows':package['coverage']},indent=2),'sigma.json':json.dumps({'context':package['context'],'candidates':package['candidates'],'retrieval':package['retrieval']},indent=2)}
    if flow:data['attack-flow.json']=flow
    data['attack-flow-provenance.json']=json.dumps(flow_provenance,indent=2,ensure_ascii=False)
    if converted:data['misp-converted.json']=converted
    manifest=package['manifest']|{'artifacts':{k:digest(v) for k,v in data.items()},'validation':compatibility}
    data['manifest.json']=json.dumps(manifest,indent=2)
    # Immutable package directory, content allocated for this package only.
    out=store.root/'artifacts'/package['id'];out.mkdir(exist_ok=True)
    for name,content in data.items():(out/name).write_text(content)
    with zipfile.ZipFile(out/'package.zip','w',compression=zipfile.ZIP_DEFLATED) as z:
        for name in data:z.write(out/name,name)
    return {'names':list(data)+['package.zip'],'validation':compatibility,'manifest':manifest}
