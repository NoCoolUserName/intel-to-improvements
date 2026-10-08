"""Explicit upsert to a configured destination. Never publish or synchronize."""
import os,json,copy
from .store import canonical,digest,now,uid
from .exporters import validate_misp

def managed_projection(event,uuids,report_uuids):
    ev=event.get('Event',event)
    return {'uuid':ev.get('uuid'),'info':ev.get('info'),'published':bool(ev.get('published')),'distribution':str(ev.get('distribution')),'attributes':sorted([{'uuid':a.get('uuid'),'type':a['type'],'value':a['value'],'to_ids':bool(a.get('to_ids')),'comment':a.get('comment',''),'distribution':str(a.get('distribution','5'))} for a in ev.get('Attribute',[]) if a.get('uuid') in uuids],key=lambda x:x['uuid']),'reports':sorted([{'uuid':r.get('uuid'),'content':r.get('content'),'name':r.get('name'),'distribution':str(r.get('distribution','5'))} for r in ev.get('EventReport',[]) if r.get('uuid') in report_uuids],key=lambda x:x['uuid']),'tags':sorted(t['name'] for t in ev.get('Tag',[]) if t['name'].startswith('iti:'))}

def import_event(store,package,client=None):
    destination=package['context']['destination'];url=os.getenv('MISP_URL');key=os.getenv('MISP_API_KEY')
    if not destination:raise ValueError('Set this customer’s MISP destination before assessment/package creation; destination is frozen per job')
    if client is None:
        if not url or not key:raise ValueError('MISP live import NOT RUN: configure MISP_URL and MISP_API_KEY')
        if destination.rstrip('/')!=url.rstrip('/'):raise ValueError('Configured MISP URL differs from frozen customer destination')
        from pymisp import PyMISP
        client=PyMISP(url,key,ssl=True,timeout=(10,45))
    native=json.loads((store.root/'artifacts'/package['id']/'cti.misp.json').read_text());validate_misp(native);event=native['Event'];uuid=event['uuid'];managed={a['uuid'] for a in event.get('Attribute',[])};reports={r['uuid'] for r in event.get('EventReport',[])}
    iid=uid('misp-import',package['context']['customer_id'],destination,package['source']['id']);previous=store.maybe('misp_sync',iid)
    found=client.search(controller='events',uuid=uuid,pythonify=False)
    if isinstance(found,dict) and 'response' in found:found=found['response']
    if isinstance(found,dict) and found.get('errors'):raise ValueError('MISP lookup failed: '+str(found['errors']))
    if not isinstance(found,list):raise ValueError('Unexpected MISP search response; refusing write')
    if len(found)>1:raise ValueError('Multiple remote events share stable identity; manual reconciliation required')
    expected=managed_projection(native,managed,reports)
    if found:
        remote=client.get_event(uuid,pythonify=False);remote_ev=remote.get('Event',remote)
        prior_managed=set(previous.get('managed_attributes',[])) if previous else managed;prior_reports=set(previous.get('managed_reports',[])) if previous else reports
        projection=managed_projection(remote,prior_managed,prior_reports)
        if previous and previous.get('status')=='uncertain' and managed_projection(remote,managed,reports)==previous['expected']:
            result=previous|{'status':'reconciled after uncertain write','readback':managed_projection(remote,managed,reports),'differences':[],'at':now()};store.put('misp_sync',iid,result);return result
        if previous and previous.get('status')=='uncertain' and not previous.get('readback') and managed_projection(remote,managed,reports)!=previous['expected']:raise ValueError('Uncertain initial write returned differing managed data; inspect remote event before any retry')
        if previous and previous.get('readback') and projection!=previous['readback']:raise ValueError('Managed fields changed remotely; preserving analyst edits. Resolve conflict before retry.')
        if not previous and managed_projection(remote,managed,reports)!=expected:raise ValueError('Existing event has no local ownership/readback baseline; refusing blind replacement')
        # Preserve unrelated attributes, reports, tags and fields. Replace only app-managed content.
        merged=copy.deepcopy(remote_ev)
        merged.update({k:event[k] for k in ('info','published','distribution')})
        merged['Attribute']=[a for a in remote_ev.get('Attribute',[]) if a.get('uuid') not in prior_managed]+event.get('Attribute',[])
        merged['EventReport']=[r for r in remote_ev.get('EventReport',[]) if r.get('uuid') not in prior_reports]+event.get('EventReport',[])
        merged['Tag']=[t for t in remote_ev.get('Tag',[]) if not t['name'].startswith('iti:')]+event.get('Tag',[])
        payload={'Event':merged};operation='update'
    else:payload=native;operation='create'
    pending={'id':iid,'status':'uncertain','expected':expected,'managed_attributes':sorted(managed),'managed_reports':sorted(reports),'destination':destination,'event_uuid':uuid,'package_id':package['id'],'at':now(),'readback':previous.get('readback') if previous else None}
    # Save BEFORE write; any timeout is reconciled by stable UUID before another write.
    store.put('misp_sync',iid,pending)
    try:
        response=client.update_event(payload,pythonify=False) if operation=='update' else client.add_event(payload,pythonify=False)
        if isinstance(response,dict) and response.get('errors'):raise ValueError(str(response['errors']))
        actual=client.get_event(uuid,pythonify=False);projection=managed_projection(actual,managed,reports)
        differences=[k for k in expected if expected[k]!=projection[k]]
        version=client.get_version();result=pending|{'status':'readback matched' if not differences else 'readback differences','operation':operation,'readback':projection,'differences':differences,'misp_version':version,'at':now()}
        store.put('misp_sync',iid,result);store.event('misp_readback',package['context']['customer_id'],result);return result
    except Exception as e:
        store.put('misp_sync',iid,pending|{'error':str(e)});raise ValueError('MISP write outcome uncertain; retry first reconciles stable UUID. '+str(e)) from e
