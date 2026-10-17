"""Local, exact-ID D3FEND suggestions. Associations never assert implemented protection."""
import copy
import json
import re
from pathlib import Path
from .store import ROOT, canonical, digest, now, uid

CATALOG_DIR = ROOT/'catalogs/d3fend'
VERSION = 'defense-candidates-1'

class CatalogError(ValueError):
    pass

def load_catalog(directory=None):
    root = Path(directory or CATALOG_DIR)
    try:
        raw = (root/'catalog.json').read_bytes()
        pin = json.loads((root/'pin.json').read_text())
        if len(raw) > 2*1024*1024 or digest(raw) != pin['sha256']:
            raise ValueError('checksum or size mismatch')
        data = json.loads(raw)
        if data['schema_version'] != '1.0' or data['provenance']['domain'] != 'enterprise-attack':
            raise ValueError('unsupported catalog schema/domain')
        if data['provenance']['revision'] != pin['revision']:
            raise ValueError('revision mismatch')
        for tid in data['supported_ids']:
            if not re.fullmatch(r'T\d{4}(?:\.\d{3})?', tid):
                raise ValueError('invalid ATT&CK ID')
        for did, row in data['techniques'].items():
            if not re.fullmatch(r'D3-[A-Z0-9]+', did) or row['id'] != did or not row['name'].strip():
                raise ValueError('invalid defensive technique')
            if not re.fullmatch(r'https://d3fend\.mitre\.org/(?:technique/d3f:[A-Za-z0-9-]+/?|resources/)', row['reference']):
                raise ValueError('invalid official reference')
        for tid, ids in data['mappings'].items():
            if tid not in data['supported_ids'] or not isinstance(ids, list) or any(d not in data['techniques'] for d in ids):
                raise ValueError('invalid mapping reference')
        return data, digest(raw)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise CatalogError('D3FEND catalog missing or invalid: '+str(exc)) from exc

def assess(assessment, directory=None):
    """Create a frozen suggestion revision independently of immutable operational packages."""
    result = {'version':VERSION,'assessment_id':assessment['id'],'context':copy.deepcopy(assessment['context']),
              'source_revision':assessment['source']['revision_id'],'extraction_id':assessment['extraction']['id'],
              'source_gaps':assessment['source']['gaps'],'behaviors':{}}
    try:
        catalog, checksum = load_catalog(directory)
    except CatalogError as exc:
        return result | {'state':'catalog_unavailable','message':str(exc),'snapshot_id':None}
    provenance = copy.deepcopy(catalog['provenance']) | {'catalog_sha256':checksum,'generator':VERSION}
    result.update(state='ready',catalog=provenance,snapshot_id=uid('defenses',assessment['id'],checksum,VERSION))
    coverage = {r['behavior_id']:r for r in assessment['coverage']}
    for b in assessment['extraction']['behaviors']:
        tid = b.get('technique_id')
        row = {'behavior_id':b['id'],'attack_id':tid,'mapping_basis':b.get('mapping_basis'),
               'qualifier':b.get('qualifier'),'extraction_confidence':b.get('extraction_confidence'),
               'confidence_rationale':b.get('confidence_rationale'),'applicability':copy.deepcopy(coverage.get(b['id'],{})),
               'suitability':'Analyst review required; declared telemetry and products do not establish this capability.',
               'candidates':[]}
        if not tid:
            row.update(state='no_attack_mapping',message='This behavior has no ATT&CK mapping.')
        elif tid not in catalog['supported_ids']:
            row.update(state='unsupported_id',message='ID/domain not supported by this pinned enterprise catalog. No parent substitution.')
        elif not catalog['mappings'].get(tid):
            row.update(state='no_catalog_mapping',message='No mapping available in this catalog for '+tid+'. This does not mean no defense exists.')
        else:
            row.update(state='candidates',message='Exact ATT&CK lookup; defensive suitability needs analyst review.')
            for did in sorted(set(catalog['mappings'][tid])):
                c = {'id':uid('defense',result['snapshot_id'],b['id'],did),'assessment_id':assessment['id'],
                     'snapshot_id':result['snapshot_id'],'behavior_id':b['id'],'attack_id':tid,
                     'd3fend_id':did,**copy.deepcopy(catalog['techniques'][did]),
                     'mapping_basis':b.get('mapping_basis'),'qualifier':b.get('qualifier'),
                     'extraction_confidence':b.get('extraction_confidence'),'confidence_rationale':b.get('confidence_rationale'),
                     'evidence':list(b['evidence']),'catalog':provenance,
                     'explanation':f'The pinned catalog associates {tid} with {did} {catalog["techniques"][did]["name"]}. This is a possible countermeasure, not an exact procedure match or verified protection.'}
                # The upstream technique ID must not replace the application candidate identity.
                c['id'] = uid('defense',result['snapshot_id'],b['id'],did)
                c['prefill'] = {'behavior_id':b['id'],'priority':'high','status':'open',
                    'proposed_change':f'Assess and, if suitable, implement {did} {c["name"]}. Specify the named control and concrete configuration before deployment.',
                    'rationale':f'Behavior ({b["kind"]}): {b["text"]}\nSource evidence: {", ".join(b["evidence"])}. ATT&CK {tid}; mapping basis: {b.get("mapping_basis")}; qualifier: {b.get("qualifier") or "none recorded"}.\nSeparate catalog-derived suggestion: {c["explanation"]}',
                    'retest':f'Name the control/version and approved environment scope for {did}. Define the behavior variant, expected telemetry and detection/prevention outcomes, and a benign control. Preserve timestamped test evidence and actual results; record failure or missing telemetry honestly. A saved or deployed improvement does not verify protection.'}
                row['candidates'].append(c)
        result['behaviors'][b['id']] = row
    return result

def suggestions(store, assessment):
    result = assess(assessment)
    if result['snapshot_id']:
        store.put('defense_snapshot',result['snapshot_id'],result | {'created_at':now()},immutable=True)
        result = store.get('defense_snapshot',result['snapshot_id'])
    # Current action status is a separate projection; never mutate the frozen candidate record.
    actions = {(i['behavior_id'],i['origin']['d3fend_id']):i for i in store.all('improvement')
               if i.get('origin') and i['origin'].get('assessment_id')==assessment['id'] and i['context']==assessment['context']}
    for row in result['behaviors'].values():
        for c in row['candidates']:
            i = actions.get((c['behavior_id'],c['d3fend_id']))
            c['improvement'] = {'id':i['id'],'status':i['status']} if i else None
    return result

def resolve_origin(store, assessment, behavior_id, reference):
    if set(reference) != {'snapshot_id','candidate_id'}:
        raise ValueError('Supply only the stored snapshot and candidate identifiers')
    snap = store.get('defense_snapshot',reference['snapshot_id'])
    if snap['assessment_id']!=assessment['id'] or snap['context']!=assessment['context']:
        raise ValueError('Defense candidate assessment/customer/environment mismatch')
    candidates = snap['behaviors'].get(behavior_id,{}).get('candidates',[])
    c = next((c for c in candidates if c['id']==reference['candidate_id']),None)
    if not c:
        raise ValueError('Defense candidate does not belong to this behavior/assessment')
    return {'kind':'d3fend_candidate','candidate_id':c['id'],'snapshot_id':snap['snapshot_id'],
            'assessment_id':assessment['id'],'behavior_id':behavior_id,'attack_id':c['attack_id'],
            'd3fend_id':c['d3fend_id'],'name':c['name'],'reference':c['reference'],
            'catalog':copy.deepcopy(c['catalog']),'evidence':list(c['evidence']),
            'source_revision':snap['source_revision'],'extraction_id':snap['extraction_id'],
            'mapping_basis':c['mapping_basis'],'qualifier':c['qualifier'],
            'extraction_confidence':c['extraction_confidence'],'confidence_rationale':c['confidence_rationale'],
            'explanation':c['explanation'],'candidate_sha256':digest(canonical(c))}
