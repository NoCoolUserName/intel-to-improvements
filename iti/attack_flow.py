"""Separate Attack Flow export. No inference, no model calls, no change to core CTI.

Only explicit source-reported EntityRelationships can create directed action edges.
Legacy sequence integers, extraction order and ATT&CK order are never evidence.
"""
import copy
import json
from datetime import datetime, timezone
from functools import lru_cache
from uuid import UUID

import jsonschema
import stix2
from referencing import Registry
from referencing.jsonschema import DRAFT202012

from .store import ROOT, canonical, digest
from .models import SourceDocument, Extraction
from .analysis import validate_evidence, resolve_attack

DIRECTORY = ROOT / 'integrations/attack-flow'
PIN = json.loads((DIRECTORY / 'pin.json').read_text())
EXTENSION = 'extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4'
VERSION = 'attack-flow-2'
# Exact meanings only; all other relationships are retained as omissions.
DIRECTIONS = {'precedes': False, 'followed-by': False, 'follows': True,
              'enables': False, 'causes': False}


@lru_cache(maxsize=1)
def schemas():
    registry = Registry()
    documents = {}
    for name, expected_hash in PIN['schemas'].items():
        raw = (DIRECTORY / 'schemas' / name).read_bytes()
        if digest(raw) != expected_hash:
            raise ValueError('Pinned Attack Flow schema hash mismatch: ' + name)
        document = json.loads(raw)
        documents[name] = document
        if '$schema' in document:
            resource = DRAFT202012.create_resource(document)
            uri = document.get('$id', 'urn:iti:schema:' + name)
            registry = registry.with_resource(uri, resource)
            if name == 'attack-flow-schema-2.0.0.json':
                registry = registry.with_resource('https://center-for-threat-informed-defense.github.io/attack-flow/stix/' + name, resource)
    return documents, registry


def validate_bundle(bundle):
    """Pinned offline schema validation plus typed-reference/timestamp checks.

    allow_custom is isolated here: jsonschema validates every extension object.
    Existing exporters.validate_stix remains strict and is never used for this bundle.
    """
    documents, registry = schemas()
    if bundle.get('type') != 'bundle' or not bundle.get('objects'):
        raise ValueError('Attack Flow requires a nonempty STIX bundle')
    objects = bundle['objects']
    by_id = {o['id']: o for o in objects}
    if len(by_id) != len(objects):
        raise ValueError('Duplicate Attack Flow object IDs')
    if len([o for o in objects if o['type'] == 'attack-flow']) != 1:
        raise ValueError('Exactly one attack-flow required')
    if EXTENSION not in by_id:
        raise ValueError('Attack Flow extension-definition missing')
    mapping = {'identity': 'oasis-open/sdos/identity.json',
               'extension-definition': 'oasis-open/common/extension-definition.json',
               'attack-flow': 'attack-flow-schema-2.0.0.json',
               'attack-action': 'attack-flow-schema-2.0.0.json'}
    for obj in [bundle] + objects:
        prefix, suffix = obj['id'].split('--', 1)
        if prefix != obj['type'] or UUID(suffix).version != 4:
            raise ValueError('Invalid allocated STIX ID: ' + obj['id'])
        if obj is bundle:
            continue
        if obj['type'] not in mapping:
            raise ValueError('Unsupported object in generated Attack Flow: ' + obj['type'])
        jsonschema.Draft202012Validator(documents[mapping[obj['type']]], registry=registry,
                                       format_checker=jsonschema.FormatChecker()).validate(obj)
        created = datetime.fromisoformat(obj['created'].replace('Z', '+00:00'))
        modified = datetime.fromisoformat(obj['modified'].replace('Z', '+00:00'))
        if modified < created:
            raise ValueError('STIX modified time precedes created time')
        for key, allowed in [('created_by_ref', {'identity'}), ('start_refs', {'attack-action'}),
                             ('effect_refs', {'attack-action'})]:
            refs = obj.get(key, [])
            if isinstance(refs, str): refs = [refs]
            for ref in refs:
                if ref not in by_id or by_id[ref]['type'] not in allowed:
                    raise ValueError('Dangling or wrong-type ' + key + ': ' + ref)
        for ref in obj.get('extensions', {}):
            if ref != EXTENSION:
                raise ValueError('Unexpected Attack Flow extension')
    stix2.parse(json.dumps(bundle), allow_custom=True)
    return {'valid': True, 'schema': 'Attack Flow 2.0.0 + pinned STIX 2.1 schemas',
            'schema_revision': PIN['revision'], 'references_valid': True,
            'objects': len(objects), 'semantic_review': 'required', 'misp_import': 'not used'}


def export(store, package):
    source = SourceDocument.model_validate(package['source'])
    extraction = Extraction.model_validate(package['extraction'])
    validate_evidence(extraction, source)
    spans = {s.id: s for s in source.spans}
    supported = [b for b in extraction.behaviors if b.kind == 'source_reported' and b.evidence]
    omissions = [{'id': b.id, 'reason': 'Not an evidenced source-reported action; retained in evidence.json for review'}
                 for b in extraction.behaviors if b not in supported]
    provenance = {
        'generator': VERSION, 'upstream_revision': PIN['revision'], 'extension_version': '2.0.0',
        'source_document_id': source.id, 'source_revision_id': source.revision_id,
        'source_hash': source.content_hash, 'extraction_id': extraction.id,
        'package_id': package['id'], 'assessment_id': package['assessment_id'],
        'context': {k: package['context'][k] for k in ('customer_id', 'customer_version', 'environment_id', 'environment_version')},
        'source_completeness': source.completeness, 'source_gaps': source.gaps,
        'mode': extraction.mode, 'review_status': 'Generated — review required',
        'edge_policy': 'Explicit source-reported relationships only; temporal order does not establish causation. Sequence integers and array order ignored.',
        'actions': [], 'edges': [], 'omissions': omissions,
    }
    status = {'generator': VERSION, 'upstream_revision': PIN['revision'], 'review_status': provenance['review_status'],
              'source_completeness': source.completeness, 'source_gaps': source.gaps,
              'actions': len(supported), 'edges': 0, 'omissions': omissions}
    if not supported:
        status.update(status='empty', reason='No evidenced source-reported actions in this extraction. Inferences, proposals and unsupported assertions are not reported attack actions.', validation=None)
        return None, provenance, status
    # Allocated once for this frozen extraction + customer/environment context. Stable on rerun.
    key = 'attack-flow:' + extraction.id + ':' + digest(canonical(package['context']))
    def sid(part, typ): return store.identity(key + ':' + part, typ)
    stamp = datetime.fromisoformat(package['created_at'].replace('Z', '+00:00')).astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    store.put('attack_flow_created', key, {'at': stamp}, immutable=True)
    created = min(store.get('attack_flow_created', key)['at'], stamp)
    creator_id = sid('generator', 'identity')
    common = {'spec_version': '2.1', 'created': created, 'modified': stamp, 'created_by_ref': creator_id}
    extension = {'extensions': {EXTENSION: {'extension_type': 'new-sdo'}}}
    objects = copy.deepcopy(schemas()[0]['attack-flow-extension-2.0.0.json']['objects'])
    objects.append(dict(common, type='identity', id=creator_id, name='Intel to Improvements', identity_class='system', description='Application-generated representation of source intelligence; not the original publisher.'))
    by_behavior = {}
    for behavior in supported:
        refs = [{'source_name': 'iti:behavior', 'external_id': behavior.id}]
        refs += [{'source_name': 'iti:evidence-span', 'external_id': s} for s in behavior.evidence]
        description = 'Mapping: ' + behavior.mapping_basis + '. Certainty: ' + behavior.extraction_confidence + '.'
        if behavior.qualifier: description += '\n' + behavior.qualifier
        description += '\nSource reliability: ' + behavior.source_reliability + '. Full evidence: attack-flow-provenance.json.'
        obj = dict(common, **extension, type='attack-action', id=sid(behavior.id, 'attack-action'),
                   name=behavior.text[:160], description=description, external_references=refs)
        if behavior.technique_id and behavior.mapping_basis != 'none':
            resolve_attack(behavior.technique_id)
            obj['technique_id'] = behavior.technique_id
        by_behavior[behavior.id] = obj
        objects.append(obj)
        provenance['actions'].append({'action_id': obj['id'], 'behavior_id': behavior.id,
                                      'evidence': [spans[s].model_dump() for s in behavior.evidence],
                                      'mapping_basis': behavior.mapping_basis, 'qualifier': behavior.qualifier,
                                      'extraction_confidence': behavior.extraction_confidence,
                                      'confidence_rationale': behavior.confidence_rationale,
                                      'source_reliability': behavior.source_reliability,
                                      'sequence_annotation_ignored': behavior.sequence})
    edges = []
    for rel in extraction.relationships:
        reason = None
        if rel.kind != 'source_reported' or not rel.evidence:
            reason = 'Relationship is not an evidenced source report'
        elif rel.relationship not in DIRECTIONS:
            reason = 'Relationship has no supported directed sequence semantics'
        elif rel.source_ref not in by_behavior or rel.target_ref not in by_behavior:
            reason = 'Relationship endpoints are not exported reported actions'
        elif rel.source_ref == rel.target_ref:
            reason = 'Self-sequence is ambiguous; separate action occurrences required'
        if reason:
            omissions.append({'id': rel.id, 'reason': reason})
            continue
        left, right = rel.source_ref, rel.target_ref
        if DIRECTIONS[rel.relationship]: left, right = right, left
        edges.append({'relationship_id': rel.id, 'source_behavior': left, 'target_behavior': right,
                      'source_action': by_behavior[left]['id'], 'target_action': by_behavior[right]['id'],
                      'semantics': 'source-reported causation/enablement' if rel.relationship in ('causes', 'enables') else 'reported temporal order; causation not established',
                      'assertion': rel.text, 'qualifier': rel.qualifier,
                      'evidence': [spans[s].model_dump() for s in rel.evidence]})
    # Cyclic ordering contradicts this first, acyclic flow representation. Retain evidence; don't invent a break.
    import graphlib
    dependencies = {b: set() for b in by_behavior}
    for edge in edges: dependencies[edge['target_behavior']].add(edge['source_behavior'])
    try: list(graphlib.TopologicalSorter(dependencies).static_order())
    except graphlib.CycleError:
        omissions.extend({'id': e['relationship_id'], 'reason': 'Cyclic sequence requires review; ordering edges omitted'} for e in edges)
        edges = []
    targets = set()
    for edge in edges:
        obj = by_behavior[edge['source_behavior']]
        obj['effect_refs'] = sorted(set(obj.get('effect_refs', []) + [edge['target_action']]))
        obj['description'] += '\nOutgoing link: ' + edge['semantics'] + '. ' + edge['assertion'] + '\nRelationship evidence: ' + ', '.join(s['id'] for s in edge['evidence'])
        targets.add(edge['target_action'])
    provenance['edges'] = edges
    linked = {e[k] for e in edges for k in ('source_behavior', 'target_behavior')}
    unordered = [b.id for b in supported if b.id not in linked]
    order = 'unordered' if not edges else 'partial' if unordered or source.gaps or omissions else 'supported relationships only'
    note = 'Reported actions; ' + order + '. Entry points include independently unordered components, not simultaneous or AND/OR actions. Temporal arrows do not establish causation. All actions require source review; human validation scenarios are scoped separately.'
    flow = dict(common, **extension, type='attack-flow', id=sid('flow', 'attack-flow'), name=source.title,
                scope='other', description=note + '\nSource: ' + source.origin + '\nSource document: ' + source.id + '\nSource revision: ' + source.revision_id + '\nExtraction: ' + extraction.id + '\nPackage: ' + package['id'] + '\nCompleteness: ' + source.completeness + '; ' + '; '.join(source.gaps),
                start_refs=[o['id'] for o in by_behavior.values() if o['id'] not in targets],
                external_references=[{'source_name': 'iti:source-revision', 'external_id': source.revision_id}, {'source_name': 'iti:extraction', 'external_id': extraction.id}, {'source_name': 'iti:package', 'external_id': package['id']}])
    objects.append(flow)
    bundle = {'type': 'bundle', 'id': sid('bundle', 'bundle'), 'objects': objects}
    validation = validate_bundle(bundle)
    status.update(status='generated', edges=len(edges), ordering=order, unordered_behavior_ids=unordered,
                  explanation=note, validation=validation, flow_id=flow['id'])
    return json.dumps(bundle, indent=2, ensure_ascii=False), provenance, status
