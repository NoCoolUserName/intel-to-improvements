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
    for key, scope in scopes.items():
        scoped_actions = grouped[key]
        scope.update(cases=sum((c['customer_id'], c['environment_id']) == key for c in cases),
                     open_actions=sum(a['status'] != 'closed' for a in scoped_actions),
                     unassigned_actions=sum(a['status'] != 'closed' and (not a.get('owner', '').strip() or a['owner'].lower() == 'unassigned') for a in scoped_actions),
                     retest_actions=sum(a['status'] in ('deployed', 'retest requested') for a in scoped_actions))
        try:
            projection = overview(store, *key)
            metrics = {m['id']: m['value'] for m in projection['metrics']}
            scope.update(outstanding=metrics['outstanding'], overdue=metrics['overdue'],
                         needs_review=metrics['unreviewed'] + metrics['potential'],
                         appsec=metrics['appsec'], affected=metrics['affected'], error=None)
        except (KeyError, ValueError, OSError) as error:
            scope.update(outstanding=None, overdue=None, needs_review=None, appsec=None, affected=None, error=str(error))
    return dict(as_of=now(), scopes=list(scopes.values()), cases=sorted(cases, key=lambda c: c['updated_at'] or '', reverse=True),
                revision_count=len(assessments), policy='One case per source and environment; latest assessment revision. Open action counts use recorded status. Exposure counts use the existing evidence review rules. Synthetic records are included and labeled.')
