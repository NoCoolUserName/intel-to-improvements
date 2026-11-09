"""Next-step ownership derived from existing action and qualified evidence state."""
def progress(action, verified=False, reviewed_outcome=False, failed=False):
    implementation = action.get('owner') or 'Unassigned'
    coordinator = action.get('remediation_coordinator') or 'Unassigned'
    reviewer = action.get('verification_reviewer') or (action.get('remediation') or {}).get('security_reviewer') or 'Unassigned'
    validation = action.get('validation_status', 'planned')
    if validation in ('blocked', 'not planned'):
        stage = 'Blocked' if validation == 'blocked' else 'Validation not planned'
        person = action.get('validation_responsible') or 'Unassigned'
    elif verified:
        stage, person = 'Verified outcome', coordinator
    elif reviewed_outcome:
        stage, person = 'Reviewed outcome (supplied/synthetic evidence)', coordinator
    elif failed or action['status'] in ('open', 'in progress'):
        stage, person = 'Awaiting implementation', implementation
    elif validation == 'awaiting review' or (action.get('evidence_reference') and validation != 'reviewed'):
        stage, person = 'Awaiting verification review', reviewer
    else:
        stage, person = 'Awaiting evidence', implementation
    return {'stage': stage, 'next_owner': person, 'implementation_owner': implementation,
            'remediation_coordinator': coordinator, 'verification_reviewer': reviewer,
            'validation_status': validation, 'validation_responsible': action.get('validation_responsible', ''),
            'validation_reason': action.get('validation_reason', ''),
            'evidence_supplier': action.get('evidence_supplier', ''), 'evidence_reference': action.get('evidence_reference', ''),
            'evidence_reviewed_by': action.get('evidence_reviewed_by', ''), 'evidence_proves': action.get('evidence_proves', ''),
            'evidence_uncertainty': action.get('evidence_uncertainty', '')}
