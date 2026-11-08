"""Read-only system dashboard over saved cases and existing exposure projections."""
from collections import defaultdict
from .exposure_overview import overview
from .store import now


def dashboard(store):
    customers = store.all('customer')
    assessments = store.all('assessment')
    actions = store.all('improvement')
    if len(assessments) + len(actions) > 10000:
        raise ValueError('Dashboard limit: more than 10000 case revisions and actions; totals unavailable')
    latest = {}
    for assessment in assessments:
        ctx = assessment['context']
        key = (ctx['customer_id'], ctx['environment_id'], assessment['source']['id'])
        if key not in latest or assessment.get('created_at', '') >= latest[key].get('created_at', ''):
            latest[key] = assessment
    grouped = defaultdict(list)
    for action in actions:
        ctx = action.get('context', {})
        if ctx.get('customer_id') and ctx.get('environment_id'):
            grouped[ctx['customer_id'], ctx['environment_id']].append(action)
    scopes = {}
    for customer in customers:
        for env in customer['environments']:
            key = (customer['id'], env['id'])
            scopes[key] = dict(customer_id=key[0], environment_id=key[1], customer_name=customer['name'], environment_name=env['name'])
    cases = []
    for (customer, environment, source), assessment in latest.items():
        ctx = assessment['context']
        key = (customer, environment)
        if key not in scopes:
            scopes[key] = dict(customer_id=customer, environment_id=environment,
                               customer_name=ctx.get('customer_snapshot', {}).get('name', customer),
                               environment_name=ctx.get('environment_snapshot', {}).get('name', environment))
        linked = [a for a in grouped[key] if a.get('scope') == ':'.join((customer, environment, source))]
        metadata = assessment['source'].get('metadata', {})
        cases.append(dict(id=assessment['id'], customer_id=customer, environment_id=environment,
                          title=assessment['source']['title'], updated_at=assessment.get('created_at'),
                          relevance=assessment.get('relevance', {}).get('rank', 'Unknown'),
                          synthetic=bool(metadata.get('fixture') or metadata.get('synthetic')),
                          open_actions=sum(a['status'] != 'closed' for a in linked)))
    validation = []
    for key, scope in scopes.items():
        scoped_actions = grouped[key]
        scope.update(cases=sum((c['customer_id'], c['environment_id']) == key for c in cases),
                     open_actions=sum(a['status'] != 'closed' for a in scoped_actions),
                     unassigned_actions=sum(a['status'] != 'closed' and (not a.get('owner', '').strip() or a['owner'].lower() == 'unassigned') for a in scoped_actions),
                     retest_actions=sum(a['status'] in ('deployed', 'retest requested') for a in scoped_actions))
        try:
            projection = overview(store, *key)
            metrics = {m['id']: m['value'] for m in projection['metrics']}
            for row in projection['rows']:
                if row['entity'] != 'exposure':
                    continue
                linked_ids = {a['action_id'] for a in projection['rows'] if a.get('exposure_id') == row['id'] and a.get('action_id')}
                plans = [{'owner': a['owner'], 'retest': a.get('retest', ''), 'rationale': a.get('rationale', '')} for a in scoped_actions if a['id'] in linked_ids]
                validation.append(dict(plans=plans, id=row['id'], customer_id=key[0], environment_id=key[1],
                                       label=row['label'], origin=row['origin'], owner=row['owner'],
                                       outcome=row['verification'] if row.get('test_id') else 'No recorded validation',
                                       recorded=bool(row.get('test_id')), synthetic=row['synthetic'],
                                       reference=row['reference'], tested_at=row.get('last_retest_at')))

            scope.update(outstanding=metrics['outstanding'], overdue=metrics['overdue'],
                         needs_review=metrics['unreviewed'] + metrics['potential'],
                         appsec=metrics['appsec'], affected=metrics['affected'], error=None)
        except (KeyError, ValueError, OSError) as error:
            scope.update(outstanding=None, overdue=None, needs_review=None, appsec=None, affected=None, error=str(error))
    from . import ledger
    for assessment in latest.values():
        ctx = assessment['context']
        result = ledger.view(store, assessment)
        for behavior in assessment['extraction']['behaviors']:
            tests = [t for t in result['tests'] if t['behavior_id'] == behavior['id']]
            # Separate outcome dimensions: detection success cannot imply prevention.
            dimensions = sorted({t['dimension'] for t in tests}) or ['validation']
            for dimension in dimensions:
                test = next((t for t in reversed(tests) if t['dimension'] == dimension), None)
                provenance = ('Synthetic' if test and test['method'] == 'synthetic log match' else
                              'Attestation' if test and test['method'] == 'analyst attestation' else
                              'Live' if test and any(e['kind'] == 'live system' for e in test['evidence']) else 'Lab')
                outcome = ('Stale evidence' if test['stale'] else test['result']) if test else 'No recorded validation'
                validation.append(dict(id=assessment['id']+':'+behavior['id']+':'+dimension,
                                       customer_id=ctx['customer_id'], environment_id=ctx['environment_id'],
                                       label=assessment['source']['title']+' · '+behavior['text'], origin='Case validation',
                                       owner='See case actions', outcome=provenance+' · '+dimension+' · '+outcome if test else outcome,
                                       recorded=bool(test), synthetic=provenance == 'Synthetic' or bool(assessment['source'].get('metadata', {}).get('fixture')),
                                       plans=[{'owner': a['owner'], 'retest': a.get('retest', ''), 'rationale': a.get('rationale', '')} for a in result['improvements'] if a.get('behavior_id') == behavior['id']],
                                       reference={'assessment': assessment['id']}, tested_at=test['executed_at'] if test else None))
    priorities = priority_rows(store.all('vulnerability_decision'), store.all('vulnerability_review'))
    outcomes = {(r['customer_id'], r['environment_id'], r['id']): r for r in validation}
    for row in priorities:
        outcome = outcomes.get((row['customer_id'], row['environment_id'], row['validation_subject_id']))
        if outcome:
            row.update(validation=outcome['outcome'], validation_current=True)
    validation.sort(key=lambda r: (0 if 'failed' in r['outcome'].lower() else 1 if 'stale' in r['outcome'].lower() or 'inconclusive' in r['outcome'].lower() else 2 if not r['recorded'] else 3, r['label']))
    return dict(priorities=priorities, validation=validation, as_of=now(), scopes=list(scopes.values()), cases=sorted(cases, key=lambda c: c['updated_at'] or '', reverse=True),
                revision_count=len(assessments), policy='One case per source and environment; latest assessment revision. Open action counts use recorded status. Exposure counts use the existing evidence review rules. Synthetic records are included and labeled.')


def priority_rows(decisions, reviews):
    """Project recorded decisions without running policy or creating new records."""
    latest = {}
    for decision in decisions:
        latest[decision['series_id']] = decision
    rows = []
    for d in latest.values():
        asset = d.get('asset') or {}
        review = next((r for r in reversed(reviews) if r['decision_id'] == d['id']), None)
        scores = ((d.get('enrichment', {}).get('cvss', {}).get('value') or {}).get('scores') or [])
        verification = d.get('verification', {})
        tests = verification.get('tests', [])
        validation = verification.get('status', 'not tested')
        if tests and tests[-1]['result'] != 'passed':
            validation = tests[-1]['result'] + ' · ' + validation
        rows.append(dict(validation_subject_id='infra:'+asset.get('logical_id', ''), id=d['id'], customer_id=d['context']['customer_id'], environment_id=d['context']['environment_id'],
                         cve=d['cve'], asset=asset.get('asset_id', 'Applicability not assessed'),
                         severity='; '.join(f"{s['score']} (CVSS {s['version']}, {s['source']})" for s in scores) or 'Severity not available',
                         exploitation='Reviewed exploitation / KEV evidence' if d.get('credible_exploitation') else 'No reviewed exploitation established',
                         applicability=asset.get('applicability', 'needs verification'), reachability=asset.get('reachability', 'unknown'),
                         owner=asset.get('owner') or 'Unassigned', response=review['response'] if review else d['response'],
                         proposed_response=d['response'], reviewed=bool(review), rationale=review['reason'] if review else '; '.join(r['explanation'] for r in d['reason_codes']),
                         synthetic=asset.get('evidence_kind') == 'synthetic fixture', assessed_at=d.get('created_at'),
                         validation=validation))
    return sorted(rows, key=lambda r: (not r['response'].startswith('Expedite'), r['reviewed'], r['cve'], r['asset']))
