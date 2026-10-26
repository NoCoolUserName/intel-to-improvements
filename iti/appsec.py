"""Human-governed application remediation. No scanner execution or operational assurance."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from . import application_findings as af, profiles, ledger
from .appsec_models import Triage, Plan, ExceptionRequest, ExceptionDecision, Retest
from .models import ImprovementAction, TestRun, EvidenceAttachment
from .store import TransactionStore, uid, now, digest, canonical

APPLICABLE = 'Applicable / remediation warranted'
DUPLICATE = 'Duplicate of another finding'
EVIDENCE_KINDS = {'analyst attestation', 'supplied scanner report', 'supplied configuration/version evidence',
                  'targeted human-led test evidence', 'synthetic/lab evidence'}
LIMITS = 'Operator-recorded identities and judgments; no identity/authority authentication or independently established operational verification.'


def dt(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def versions(ctx):
    return {k: ctx[k] for k in ('customer_id', 'environment_id', 'customer_version', 'environment_version')}


@contextmanager
def transaction(store):
    with store.connect() as connection:
        connection.execute('BEGIN IMMEDIATE')
        yield TransactionStore(store, connection)


def finding(store, id, customer, environment):
    return af.scoped(store, 'application_finding', id, customer, environment)


def series(store, f):
    return [r for r in store.all('application_finding') if r['logical_id'] == f['logical_id'] and af.in_scope(r, f['context']['customer_id'], f['context']['environment_id'])]


def latest(store, f):
    return max(series(store, f), key=lambda r: (r['imported_at'], r['id']))


def context_hash(f):
    return digest(canonical({'operator': f['operator_context'], 'reported': f['reported_context']}))


def context_changes(store, f):
    """Flag explicit repository-context changes without guessing finding equivalence."""
    repositories = {f['operator_context'].get('repository')} | {r.get('repositoryUri') for r in f['reported_context']}
    repositories.discard(None)
    repositories.discard('')
    changed = []
    for batch in store.all('application_batch'):
        if not af.in_scope(batch, f['context']['customer_id'], f['context']['environment_id']) or batch['imported_at'] <= f['imported_at']:
            continue
        for run in batch['runs']:
            reported = run.get('versionControlProvenance', [])
            other = {batch['operator_context'].get('repository')} | {r.get('repositoryUri') for r in reported}
            if repositories & other and (batch['operator_context'] != f['operator_context'] or reported != f['reported_context']):
                changed.append(batch['id'])
                break
    return changed


def dependencies(store, f):
    current = latest(store, f)
    ctx = profiles.context(store, f['context']['customer_id'], f['context']['environment_id']).model_dump()
    return {'finding_id': current['id'], 'source_sha256': current['source_sha256'],
            'finding_context_hash': context_hash(current), 'profile': versions(ctx), 'changed_context_batches': context_changes(store, current)}


def scope(f):
    return ':'.join([f['context']['customer_id'], f['context']['environment_id'], 'appsec:' + f['logical_id']])


def subject(store, f, supplied_context):
    ctx = profiles.context(store, f['context']['customer_id'], f['context']['environment_id']).model_dump()
    if supplied_context != versions(ctx):
        raise ValueError('Stale or forged profile context; reload governance')
    if latest(store, f)['id'] != f['id']:
        raise ValueError('New finding evidence exists; review the latest occurrence')
    return {'id': f['id'], 'context': ctx, 'source': {'id': 'appsec:' + f['logical_id']}, 'application_finding': f}


def records(store, kind, f):
    return [r for r in store.all(kind) if r.get('logical_id') == f['logical_id'] and af.in_scope(r, f['context']['customer_id'], f['context']['environment_id'])]


def append(store, kind, f, ctx, values):
    prior = records(store, kind, f)
    if kind == 'appsec_exception_decision':
        prior = [r for r in prior if r['request_id'] == values['request_id']]
    row = values | {'logical_id': f['logical_id'], 'finding_id': f['id'], 'context': ctx,
                    'recorded_at': now(), 'previous_id': prior[-1]['id'] if prior else None, 'synthetic': f['synthetic'],
                    'application_context': {'operator': f['operator_context'], 'reported': f['reported_context']}}
    row['id'] = uid(kind, row)
    store.put(kind, row['id'], row, immutable=True)
    store.event(kind, scope(f), row)
    return row


def evidence_refs(store, f, ids):
    rows = []
    for id in ids:
        if id == f['source_id']:
            source = af.scoped(store, 'application_source', id, f['context']['customer_id'], f['context']['environment_id'])
            row = source | {'kind': 'original SARIF', 'finding_id': f['id']}
        else:
            row = af.scoped(store, 'appsec_evidence', id, f['context']['customer_id'], f['context']['environment_id'])
            if row['finding_id'] != f['id']:
                raise ValueError('Evidence belongs to a different finding occurrence')
        raw = (store.root / 'blobs' / row['sha256']).read_bytes()
        if digest(raw) != row['sha256']:
            raise ValueError('Evidence integrity check failed')
        rows.append(row)
    return rows


def review(store, f, ctx, value):
    value = Triage.model_validate(value).model_dump()
    evidence_refs(store, f, value['evidence_ids'])
    if value['disposition'] == DUPLICATE:
        if not value['duplicate_of']:
            raise ValueError('Duplicate requires a persisted target finding')
        target = finding(store, value['duplicate_of'], ctx['customer_id'], ctx['environment_id'])
        seen = {f['logical_id']}
        while target:
            if target['logical_id'] in seen:
                raise ValueError('Self or cyclic duplicate relationship rejected')
            seen.add(target['logical_id'])
            reviews = records(store, 'appsec_review', target)
            linked = reviews[-1].get('duplicate_of') if reviews and reviews[-1]['disposition'] == DUPLICATE else None
            target = finding(store, linked, ctx['customer_id'], ctx['environment_id']) if linked else None
    elif value['duplicate_of']:
        raise ValueError('Duplicate target requires duplicate disposition')
    previous = records(store, 'appsec_review', f)
    deps = dependencies(store, f)
    if previous and previous[-1]['dependencies'] == deps and all(previous[-1].get(k) == v for k, v in value.items()):
        return previous[-1]
    return append(store, 'appsec_review', f, ctx, value | {'dependencies': deps,
                  'previous_disposition': previous[-1]['disposition'] if previous else 'Needs review'})


def accepted_review(store, f, review_id):
    rows = records(store, 'appsec_review', f)
    if not rows or rows[-1]['id'] != review_id or rows[-1]['dependencies'] != dependencies(store, f):
        raise ValueError('Stale or forged triage review; record a current review')
    if rows[-1]['disposition'] != APPLICABLE:
        raise ValueError('Applicable triage required for remediation')
    return rows[-1]


def action_for(store, f):
    return store.maybe('improvement', uid('appsec_action', scope(f)))


def implementation_hash(action):
    return digest(canonical({k: action.get(k) for k in ('proposed_change', 'retest', 'remediation', 'reopened_at')}))


def improve(store, assessment, action, candidate_ref):
    """Called only through ledger.improve; reuse the existing action model and records."""
    f = assessment['application_finding']
    # Resolve again at the ledger boundary; never trust a client-origin dictionary.
    f = finding(store, f['id'], assessment['context']['customer_id'], assessment['context']['environment_id'])
    subject(store, f, versions(assessment['context']))
    command = assessment['appsec_command']
    reviewed = accepted_review(store, f, command['review_id'])
    if candidate_ref or action.origin is not None or action.behavior_id or action.vulnerability_assessment_id:
        raise ValueError('AppSec origin is server resolved; no client origin or CTI/CVE references')
    if any(not getattr(action, k).strip() or len(getattr(action, k)) > 4000 for k in ('owner', 'priority', 'rationale', 'proposed_change', 'retest')):
        raise ValueError('Owner, rationale, change, priority and retest are required and bounded')
    plan = Plan.model_validate(action.remediation).model_dump()
    if action.status == 'deployed':
        raise ValueError('Use fix reported / verification pending (retest requested)')
    if action.status in ('retest requested', 'closed') and not (plan['implementation_ref'] and plan['implementation_claim']):
        raise ValueError('Implementation reference and explicit fix claim required')
    old = action_for(store, f)
    if old and not action.id:
        return old  # safe repeated creation never overwrites edits
    if action.id and (not old or action.id != old['id']):
        raise ValueError('Action does not belong to this finding')
    if old and command['expected_updated_at'] != old['updated_at']:
        raise ValueError('Action changed; reload before editing')
    if not old and (action.status != 'open' or action.deployed_at or action.opened_at):
        raise ValueError('New AppSec action starts open with server timestamps')
    if old and old['status'] == 'closed' and action.status != 'closed':
        if action.status != 'open':
            raise ValueError('Reopen a closed action explicitly before further work')
    origin = old['origin'] if old else {'kind': 'application_finding', 'finding_id': f['id'], 'logical_id': f['logical_id'],
        'source_id': f['source_id'], 'source_sha256': f['source_sha256'], 'review_id': reviewed['id'],
        'operator_context': f['operator_context'], 'reported_context': f['reported_context']}
    timestamp = now()
    row = action.model_dump() | {'id': uid('appsec_action', scope(f)), 'origin': origin, 'remediation': plan,
        'context': old['context'] if old else assessment['context'], 'scope': scope(f), 'assessment_id': None,
        'opened_at': old['opened_at'] if old else timestamp, 'deployed_at': None, 'updated_at': timestamp,
        'change_reason': command['reason'], 'changed_by': command['actor'], 'review_id': reviewed['id'],
        'reopened_at': old.get('reopened_at') if old else None}
    if old and action.status == 'open' and old['status'] in ('closed', 'retest requested'):
        row['reopened_at'] = timestamp
    row['implementation_updated_at'] = old['implementation_updated_at'] if old and implementation_hash(old) == implementation_hash(row) else timestamp
    if action.status == 'closed':
        outcome = verification(store, f, row)
        if not outcome['can_close']:
            raise ValueError('Closure requires current evidence-reviewed supporting retest: ' + outcome['status'])
        row['closed_at'] = old.get('closed_at') if old and old['status'] == 'closed' else timestamp
    else:
        row['closed_at'] = None
    store.put('improvement', row['id'], row)
    store.event('improvement_' + action.status.replace(' ', '_'), scope(f), row)
    return row


def capture_evidence(store, f, ctx, name, raw, kind, description):
    if kind not in EVIDENCE_KINDS or not description.strip() or len(description) > 4000:
        raise ValueError('Evidence kind and bounded description required')
    if not name or name in ('.', '..') or ':' in name or len(name) > 200 or Path(name).name != name or '\\' in name or any(ord(c) < 32 for c in name):
        raise ValueError('Unsafe evidence filename')
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ValueError('Evidence must be nonempty and at most 2 MiB')
    sha = store.blob(raw)
    row = {'id': uid('appsec_evidence', f['id'], sha, kind, description, versions(ctx)), 'context': ctx,
        'finding_id': f['id'], 'logical_id': f['logical_id'], 'sha256': sha, 'filename': name,
        'description': description, 'kind': kind, 'recorded_at': now(), 'reference': 'blob:' + sha}
    prior = store.maybe('appsec_evidence', row['id'])
    if prior:
        return prior
    store.put('appsec_evidence', row['id'], row, immutable=True)
    store.event('appsec_evidence', scope(f), {'id': row['id'], 'sha256': sha})
    return row


def retest(store, assessment, value):
    value = Retest.model_validate(value)
    f = assessment['application_finding']
    attachments = evidence_refs(store, f, value.evidence_ids)
    test = TestRun(environment_version=assessment['context']['environment_version'], control_id='supplied AppSec evidence',
        control_version=value.implementation_ref, procedure=value.procedure, expected=value.expected, actual=value.actual,
        executed_at=value.executed_at, method=value.method, result=value.result, dimension='remediation', scope=scope(f),
        variant='operator-reviewed retest', improvement_id=value.action_id, measurement=value.model_dump(),
        evidence=[EvidenceAttachment(id=e['id'], reference='appsec-evidence:' + e['id'], sha256=e['sha256'],
            description=e.get('description', 'Original SARIF'), kind='analyst attestation' if e['kind']=='analyst attestation' else ('synthetic fixture replay' if f['synthetic'] or e['kind']=='synthetic/lab evidence' else 'supplied evidence')) for e in attachments])
    return ledger.record_test(store, assessment, test)


def record_test(store, assessment, test):
    f = finding(store, assessment['application_finding']['id'], assessment['context']['customer_id'], assessment['context']['environment_id'])
    subject(store, f, versions(assessment['context']))
    value = Retest.model_validate(test.measurement)
    if test.behavior_id or test.vulnerability_assessment_id or test.dimension != 'remediation' or test.scope != scope(f) or test.environment_version != assessment['context']['environment_version']:
        raise ValueError('Retest subject or dimension mismatch')
    if any(getattr(test, k) != getattr(value, k) for k in ('procedure', 'expected', 'actual', 'executed_at', 'result', 'method')):
        raise ValueError('Retest fields disagree with the reviewed measurement')
    reviewed = accepted_review(store, f, value.review_id)
    action = action_for(store, f)
    if not action or value.action_id != action['id'] or test.improvement_id != action['id']:
        raise ValueError('Retest must link the finding remediation action')
    plan = Plan.model_validate(action['remediation'])
    if not plan.implementation_ref or value.implementation_ref != plan.implementation_ref or value.finding_context_hash != context_hash(f):
        raise ValueError('Implementation or repository/ref/commit context mismatch')
    if action['status'] not in ('retest requested', 'closed'):
        raise ValueError('Record a fix claim before retesting')
    if dt(value.executed_at) > dt(now()) + timedelta(minutes=5):
        raise ValueError('Retest cannot be in the future')
    previous = [r for r in store.all('test') if r.get('appsec_logical_id') == f['logical_id']]
    if previous and dt(value.executed_at) < max(dt(r['executed_at']) for r in previous):
        raise ValueError('Execution time precedes latest retest; cannot replace it with an older outcome')
    attachments = evidence_refs(store, f, value.evidence_ids)
    if {e.id: e.sha256 for e in test.evidence} != {e['id']: e['sha256'] for e in attachments}:
        raise ValueError('Retest attachment references differ from preserved evidence')
    if value.method != 'analyst attestation' and any(e['kind'] in ('analyst attestation', 'original SARIF') for e in attachments):
        raise ValueError('Technical retest requires supplied technical evidence attachments')
    expected_kind = {'reliable rescan': 'supplied scanner report', 'version/configuration evidence': 'supplied configuration/version evidence', 'targeted human-led test': 'targeted human-led test evidence'}.get(value.method)
    if expected_kind and any(e['kind'] not in (expected_kind, 'synthetic/lab evidence') for e in attachments):
        raise ValueError('Evidence category does not support the selected retest method')
    if value.method == 'targeted human-led test' and not value.approval_reference:
        raise ValueError('Targeted test requires recorded approval reference')
    if value.method == 'reliable rescan' and not value.sarif_batch_id:
        raise ValueError('Supplied scanner retest must reference its imported SARIF batch')
    if value.basis == 'SARIF absence' and value.result == 'passed':
        raise ValueError('SARIF absence alone is inconclusive; record direct reviewed evidence instead')
    if value.sarif_batch_id:
        batch = af.scoped(store, 'application_batch', value.sarif_batch_id, assessment['context']['customer_id'], assessment['context']['environment_id'])
        if batch['operator_context'] != f['operator_context'] or any(r.get('versionControlProvenance', []) != f['reported_context'] for r in batch['runs']):
            raise ValueError('SARIF repository/ref/commit context differs; no implicit reconciliation')
        if value.result == 'passed':
            raise ValueError('Supplied SARIF cannot establish success by absence; use inconclusive or direct technical evidence')
    deps = dependencies(store, f) | {'implementation_hash': implementation_hash(action), 'review_id': reviewed['id']}
    row = test.model_dump() | {'id': uid('appsec_test', f['id'], value.model_dump(), deps), 'context': assessment['context'],
        'document_id': 'appsec:' + f['logical_id'], 'assessment_id': None, 'appsec_logical_id': f['logical_id'],
        'finding_id': f['id'], 'dependencies': deps, 'recorded_at': now(), 'confirmed_at': None,
        'assurance': 'synthetic/lab evidence reviewed' if f['synthetic'] or any(e['kind']=='synthetic/lab evidence' for e in attachments) else 'supplied evidence reviewed; not independently verified'}
    prior = store.maybe('test', row['id'])
    if prior:
        return prior
    store.put('test', row['id'], row, immutable=True)
    store.event('test_executed', scope(f), row)
    return row


def verification(store, f, action, as_of=None):
    tests = [r for r in store.all('test') if r.get('appsec_logical_id') == f['logical_id'] and af.in_scope(r, f['context']['customer_id'], f['context']['environment_id'])]
    reviews = records(store, 'appsec_review', f)
    expected = dependencies(store, f) | {'implementation_hash': implementation_hash(action) if action else None,
                                        'review_id': reviews[-1]['id'] if reviews else None}
    history = []
    for test in tests:
        reasons = []
        if test['dependencies'] != expected:
            reasons.append('Finding, profile, review or implementation changed; renewed review/retest required')
        if action and dt(test['executed_at']) < dt(action['implementation_updated_at']):
            reasons.append('Retest predates the recorded implementation/change; it cannot support current closure')
        if expected['changed_context_batches']:
            reasons.append('Later explicit repository context changed; inspect the new context without assuming finding equivalence')
        if dt(as_of or now()) - dt(test['executed_at']) > timedelta(days=30):
            reasons.append('Evidence older than 30 days')
        try:
            original = store.get('application_finding', test['finding_id'])
            evidence_refs(store, original, test['measurement']['evidence_ids'])
        except (KeyError, ValueError, OSError):
            reasons.append('Supporting evidence missing or integrity check failed')
        history.append(test | {'stale': bool(reasons), 'stale_reasons': reasons})
    current = history[-1] if history else None
    status = 'Fix reported / verification pending' if action and action['status'] == 'retest requested' else 'No retest evidence'
    can_close = False
    if current:
        if current['stale']:
            status = 'Stale evidence; renewed review/retest required'
        elif current['result'] != 'passed':
            status = 'Retest ' + current['result']
        elif current['method'] == 'analyst attestation':
            status = 'Fix attested; verification pending'
        else:
            status = 'Evidence-reviewed successful retest (' + current['assurance'] + ')'
            can_close = bool(reviews and reviews[-1]['disposition'] == APPLICABLE)
    return {'status': status, 'can_close': can_close, 'independent_operational_verification': False, 'history': history}


def request_exception(store, f, ctx, value):
    value = ExceptionRequest.model_validate(value).model_dump()
    evidence_refs(store, f, value['evidence_ids'])
    return append(store, 'appsec_exception_request', f, ctx, value | {'dependencies': dependencies(store, f)})


def decide_exception(store, f, ctx, request_id, value):
    request = af.scoped(store, 'appsec_exception_request', request_id, ctx['customer_id'], ctx['environment_id'])
    if request['finding_id'] != f['id'] or request['dependencies'] != dependencies(store, f):
        raise ValueError('Exception request has stale or different finding evidence')
    value = ExceptionDecision.model_validate(value).model_dump()
    if value['authority'].casefold() == request['requester'].casefold():
        raise ValueError('Record a separate accepting authority; identities remain operator-declared')
    return append(store, 'appsec_exception_decision', f, ctx, value | {'request_id': request_id, 'dependencies': dependencies(store, f), 'approval_basis': LIMITS})


def view(store, f):
    ctx = profiles.context(store, f['context']['customer_id'], f['context']['environment_id']).model_dump()
    deps = dependencies(store, f)
    reviews = [r | {'stale': r['dependencies'] != deps} for r in records(store, 'appsec_review', f)]
    current = reviews[-1] if reviews else None
    action = action_for(store, f)
    outcome = verification(store, f, action)
    requests = records(store, 'appsec_exception_request', f)
    decisions = records(store, 'appsec_exception_decision', f)
    exceptions = []
    for request in requests:
        history = [r for r in decisions if r['request_id'] == request['id']]
        decision = history[-1] if history else None
        status = decision['decision'] if decision else 'unapproved request'
        if dt(request['review_by']) <= dt(now()):
            status = 'expired'
        elif request['dependencies'] != deps or (decision and decision['dependencies'] != deps):
            status = 'stale; renewed decision required'
        elif status == 'approved':
            status = 'active operator-recorded acceptance; finding remains'
        exceptions.append(request | {'status': status, 'decisions': history})
    lifecycle = action['status'] if action else 'No remediation commitment'
    if action and action['status'] == 'closed':
        lifecycle = 'Closed with reviewed supporting evidence' if outcome['can_close'] else 'Reopen/review required; prior closure is historical'
    elif action and action['status'] == 'retest requested':
        lifecycle = 'Fix reported / verification pending'
    elif action and action.get('reopened_at') and action['status'] == 'open':
        lifecycle = 'Reopened'
    return {'context': versions(ctx), 'dependencies': deps, 'latest_finding_id': latest(store, f)['id'],
        'disposition': current['disposition'] if current and not current['stale'] else 'Needs review',
        'reviews': reviews, 'action': action, 'verification': outcome, 'lifecycle': lifecycle,
        'exceptions': exceptions, 'evidence': records(store, 'appsec_evidence', f), 'history': store.history(scope(f)), 'limitations': LIMITS}
