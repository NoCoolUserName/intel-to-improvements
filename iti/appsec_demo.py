"""Opt-in synthetic governance data, isolated from the existing Juniper/CVE examples."""
import json
from datetime import timedelta
from . import appsec, application_findings as af, profiles, ledger
from .models import CustomerProfile, EnvironmentProfile, ImprovementAction
from .store import ROOT, now

CUSTOMER = 'fictional-appsec-demo'
ENVIRONMENT = 'appsec-lab'


def load(service):
    store = service.store
    with store.lock('appsec-demo'):
        prior = store.maybe('appsec_demo', 'phase2')
        if prior:
            return prior
        if store.maybe('customer', CUSTOMER):
            raise ValueError('Synthetic demo scope already exists without a completed demo; use an isolated store')
        profiles.save(store, CustomerProfile(id=CUSTOMER, name='Juniper Software · AppSec synthetic demo', sector='technology',
            environments=[EnvironmentProfile(id=ENVIRONMENT, name='Synthetic remediation lab', platforms=['linux'],
                notes='Authored governance examples only; no real scanner, fix or operational outcome.')]))
        raw = (ROOT / 'fixtures/appsec/governance.sarif.json').read_bytes()
        operator = {'application': 'Juniper synthetic application', 'repository': 'synthetic/juniper-demo', 'synthetic': True}
        preview = af.preview(store, CUSTOMER, ENVIRONMENT, raw, operator)
        af.confirm(store, preview['id'], CUSTOMER, ENVIRONMENT)
        findings = {r['rule_id'].split('case-', 1)[1]: r for r in preview['findings']}
        for label, f in findings.items():
            with appsec.transaction(store) as tx:
                ctx = profiles.context(tx, CUSTOMER, ENVIRONMENT).model_dump()
                review = appsec.review(tx, f, ctx, {'reviewer': 'Synthetic security reviewer', 'disposition': appsec.APPLICABLE,
                    'reason': 'Authored demonstration applicability, not an operational judgment', 'evidence_ids': [f['source_id']]})
                if label.startswith('C-'):
                    expires = appsec.dt(now()) + timedelta(days=-1 if label == 'C-expired' else 30)
                    request = appsec.request_exception(tx, f, ctx, {'requester': 'Synthetic engineering requester',
                        'justification': 'Authored bounded business exception example', 'residual_risk': 'Synthetic finding remains unresolved',
                        'compensating_controls': 'Authored control claim, not tested', 'review_by': expires.isoformat(), 'evidence_ids': [f['source_id']]})
                    if label != 'C-unapproved':
                        appsec.decide_exception(tx, f, ctx, request['id'], {'authority': 'Synthetic risk authority', 'decision': 'approved',
                            'reason': 'Operator-recorded synthetic decision; expired example intentionally has a past review date'})
                    continue
                subject = appsec.subject(tx, f, appsec.versions(ctx))
                command = {'review_id': review['id'], 'actor': 'Synthetic engineering owner', 'reason': 'Authored demonstration step', 'expected_updated_at': None}
                subject['appsec_command'] = command
                action = ImprovementAction(owner='Synthetic application engineering', priority='medium', rationale='Correct the synthetic reviewed cause',
                    proposed_change='Authored change, no production code modified', retest='Inspect authored technical evidence and benign controls',
                    remediation={'security_reviewer': 'Synthetic security reviewer', 'expected_result': 'Authored cause removed',
                        'implementation_ref': 'synthetic-change-1', 'implementation_claim': 'Synthetic developer reports implementation'})
                saved = ledger.improve(tx, subject, action)
                action.id = saved['id']; action.status = 'in progress' if label == 'B' else 'retest requested'
                command['expected_updated_at'] = saved['updated_at']; saved = ledger.improve(tx, subject, action)
                if label == 'B':
                    continue
                attachment = appsec.capture_evidence(tx, f, ctx, 'synthetic-retest.txt',
                    b'Authored synthetic retest example; not executed against a real application.', 'synthetic/lab evidence', 'Synthetic positive and benign-control result')
                value = {'action_id': saved['id'], 'review_id': review['id'], 'implementation_ref': 'synthetic-change-1',
                    'finding_context_hash': appsec.context_hash(f), 'reviewer': 'Synthetic evidence reviewer',
                    'judgment': 'Accepted authored lab evidence solely for the synthetic workflow', 'procedure': 'Authored inspection example',
                    'expected': 'Authored corrected behavior', 'actual': 'Authored positive result', 'executed_at': now(),
                    'result': 'passed', 'method': 'version/configuration evidence', 'evidence_ids': [attachment['id']]}
                appsec.retest(tx, subject, value)
                action.status = 'closed'; command['expected_updated_at'] = saved['updated_at']; ledger.improve(tx, subject, action)
                if label == 'D':
                    appsec.retest(tx, subject, value | {'executed_at': now(), 'result': 'failed', 'actual': 'Authored later failure contradicts the earlier result'})
        document = json.loads(raw)
        for run in document['runs']:
            run['results'] = [r for r in run['results'] if r['ruleId'] in ('synthetic/case-B', 'synthetic/case-D')]
            for result in run['results']:
                result['message']['text'] = 'Synthetic later report still reports this finding; renewed review required.'
        later = af.preview(store, CUSTOMER, ENVIRONMENT, json.dumps(document).encode(), operator)
        af.confirm(store, later['id'], CUSTOMER, ENVIRONMENT)
        result = {'customer_id': CUSTOMER, 'environment_id': ENVIRONMENT, 'synthetic': True,
            'cases': {key: value['id'] for key, value in findings.items()}, 'later_findings': [f['id'] for f in later['findings']]}
        store.put('appsec_demo', 'phase2', result, immutable=True)
        return result
