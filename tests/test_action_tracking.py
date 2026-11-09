import pytest
from pydantic import ValidationError
from iti.models import ImprovementAction
from iti.action_tracking import progress
from iti import ledger


def action(**values):
    return ImprovementAction(owner='Engineering',priority='high',rationale='Fix identified exposure',proposed_change='Deploy rebuilt artifact',retest='Review exact deployed version',**values)


def test_roles_and_next_steps_are_distinct():
    a=action(remediation_coordinator='Exposure manager',verification_reviewer='Evidence reviewer').model_dump()
    assert progress(a)['next_owner']=='Engineering'
    a['status']='retest requested'
    assert progress(a)['stage']=='Awaiting evidence'
    a['validation_status']='awaiting review'
    assert progress(a)['stage']=='Awaiting verification review'
    assert progress(a)['next_owner']=='Evidence reviewer'
    assert progress(a,verified=True)['stage']=='Verified outcome'
    assert progress(a,verified=True)['next_owner']=='Exposure manager'
    assert progress(a,reviewed_outcome=True)['stage']=='Reviewed outcome (supplied/synthetic evidence)'
    assert progress(a,failed=True)['next_owner']=='Engineering'


@pytest.mark.parametrize('status',['blocked','not planned'])
def test_blocked_or_declined_validation_needs_person_and_reason(status):
    with pytest.raises(ValidationError):
        action(validation_status=status)
    a=action(validation_status=status,validation_responsible='Risk owner',validation_reason='Production testing not authorized').model_dump()
    assert progress(a)['next_owner']=='Risk owner'
    assert progress(a)['validation_reason']=='Production testing not authorized'


def test_review_metadata_cannot_create_verified_outcome():
    with pytest.raises(ValidationError):
        action(validation_status='reviewed')
    a=action(validation_status='reviewed',evidence_supplier='Engineering',evidence_reference='artifact-review-1',evidence_reviewed_by='Reviewer',evidence_proves='Version observed in supplied artifact',evidence_uncertainty='Running deployment has not been confirmed').model_dump()
    a['status']='retest requested'
    assert progress(a)['stage']=='Awaiting evidence'


def test_roles_persist_through_existing_action_edit(service,assessed):
    a=action(behavior_id=assessed['extraction']['behaviors'][0]['id'],remediation_coordinator='Coordinator',verification_reviewer='Reviewer')
    saved=ledger.improve(service.store,assessed,a)
    assert saved['owner']=='Engineering' and saved['remediation_coordinator']=='Coordinator'
    edit=ImprovementAction.model_validate({k:v for k,v in saved.items() if k in ImprovementAction.model_fields})
    edit.validation_status='blocked'
    edit.validation_responsible='Coordinator'
    edit.validation_reason='Awaiting authorized test window'
    updated=ledger.improve(service.store,assessed,edit)
    assert updated['verification_reviewer']=='Reviewer'
    assert progress(updated)['next_owner']=='Coordinator'
