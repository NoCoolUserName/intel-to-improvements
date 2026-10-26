"""Read projection of the existing ledger; mutation stays in its origin workflows."""
import json
from . import appsec, ledger, profiles, vulnerabilities as vi

LIMIT = 1000


def in_scope(row, customer, environment):
    return bool(row and row.get('context', {}).get('customer_id') == customer
                and row.get('context', {}).get('environment_id') == environment)


def related(store, kind, id, customer, environment):
    row = store.maybe(kind, id) if id else None
    return row if in_scope(row, customer, environment) else None


def project(store, action, customer, environment, details=False):
    origin = action.get('origin') or {}
    reference = None
    title, kind = 'Origin record unavailable in this scope', 'Unavailable'
    outcome = 'Open the originating workflow to assess evidence'
    qualification = 'Work status and implementation claims do not establish verification.'
    tests, exceptions, source = [], [], None
    if origin.get('kind') == 'application_finding':
        original = related(store, 'application_finding', origin.get('finding_id'), customer, environment)
        if original:
            finding = appsec.latest(store, original)
            governance = appsec.view(store, finding)
            title = finding.get('rule_id') or 'Application finding'
            kind, outcome = 'AppSec', governance['verification']['status']
            tests, exceptions = governance['verification']['history'], governance['exceptions']
            source = {'id': original['source_id'], 'sha256': original['source_sha256'], 'origin_finding_id': original['id']}
            reference = {'kind': 'appsec', 'finding_id': finding['id'], 'action_id': action['id']}
            qualification = governance['limitations']
    elif origin.get('kind') == 'vulnerability_decision':
        decision = related(store, 'vulnerability_decision', action.get('assessment_id'), customer, environment)
        if decision:
            ctx = profiles.context(store, customer, environment).model_dump()
            asset = next((r for r in vi.current_exposures(store, ctx, decision['cve'])
                          if r['logical_id'] == origin.get('asset_logical_id')), None)
            verification = vi.verification(store, ctx, asset)
            title, kind = decision['cve'] + ' · ' + origin.get('asset_id', 'Unknown asset'), 'Vulnerability'
            outcome = verification['status']
            tests = [t for t in verification['tests'] if t.get('improvement_id') == action['id']]
            reference = {'kind': 'vulnerability', 'cve': decision['cve'], 'decision_id': decision['id'], 'action_id': action['id']}
            source = {'decision_id': decision['id'], 'assertion_ids': origin.get('source_assertions', [])}
            qualification = 'Asset-level verification uses existing scoped retests. This action’s linked retests are listed separately; synthetic/lab evidence stays qualified.'
    else:
        assessment = related(store, 'assessment', action.get('assessment_id'), customer, environment)
        if assessment:
            title, kind = assessment['source']['title'], 'Intelligence case'
            source = {'id': assessment['source']['id'], 'revision_id': assessment['source']['revision_id'],
                      'sha256': assessment['source']['content_hash'], 'assessment_id': assessment['id']}
            reference = {'kind': 'case', 'assessment_id': assessment['id'], 'action_id': action['id'],
                         'test_case': assessment['source']['origin'].startswith('authored-fixture:')}
            try:
                view = ledger.view(store, assessment)
                tests = [t for t in view['tests'] if t.get('improvement_id') == action['id']]
                outcome = ('Latest recorded retest: ' + tests[-1]['result'] + ' · ' + tests[-1]['method']
                           + (' · stale' if tests[-1]['stale'] else ' · current dependencies')) if tests else 'No action-linked retest recorded'
            except KeyError:
                outcome = 'Case evidence metadata unavailable; inspect the original record'
    row = {'id': action['id'], 'origin_kind': kind, 'related_title': title, 'owner': action['owner'],
           'proposed_change': action['proposed_change'], 'status': action['status'], 'priority': action['priority'],
           'retest': action['retest'], 'outcome': outcome, 'qualification': qualification,
           'reference': reference, 'opened_at': action.get('opened_at'), 'source': source,
           'customer_id': customer, 'environment_id': environment}
    if details:
        row.update(action=action, tests=tests, exceptions=exceptions)
    return row


def workspace(store, customer, environment, action_id=None):
    ctx = profiles.context(store, customer, environment).model_dump()
    if action_id:
        action = related(store, 'improvement', action_id, customer, environment)
        if action is None:
            raise KeyError('Improvement action not found in the selected customer/environment')
        return project(store, action, customer, environment, details=True)
    with store.connect() as connection:
        where = "kind='improvement' AND json_extract(data,'$.context.customer_id')=? AND json_extract(data,'$.context.environment_id')=?"
        args = (customer, environment)
        count, size = connection.execute('SELECT count(*),coalesce(sum(length(CAST(data AS BLOB))),0) FROM records WHERE ' + where, args).fetchone()
        if count > LIMIT or size > 16 * 1024 * 1024:
            raise ValueError('Improvement Actions limit: 1000 actions / 16 MiB; results unavailable, not truncated')
        actions = [json.loads(r[0]) for r in connection.execute('SELECT data FROM records WHERE ' + where + ' ORDER BY created_at,id', args)]
    return {'context': ctx, 'rows': [project(store, action, customer, environment) for action in actions],
            'qualification': 'Existing ledger records only. Reported ≠ Reviewed ≠ Assigned ≠ Implemented ≠ Verified. Edit and retest in the originating workflow.'}
