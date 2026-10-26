"""Bounded operator-recorded governance inputs; names do not authenticate authority."""
from datetime import datetime
from typing import Literal, Annotated
from pydantic import BaseModel, ConfigDict, Field, field_validator

Text = Annotated[str, Field(min_length=1, max_length=4000)]
Name = Annotated[str, Field(min_length=1, max_length=200)]
Reference = Annotated[str, Field(min_length=1, max_length=200)]
Disposition = Literal['Needs review', 'Applicable / remediation warranted', 'Needs further investigation',
                      'Not applicable', 'False positive (reviewed determination)', 'Duplicate of another finding']
EvidenceKind = Literal['analyst attestation', 'supplied scanner report', 'supplied configuration/version evidence',
                       'targeted human-led test evidence', 'synthetic/lab evidence']


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class Triage(Input):
    reviewer: Name
    disposition: Disposition
    reason: Text
    evidence_ids: list[Reference] = Field(default_factory=list, max_length=20)
    duplicate_of: Reference | None = None


class Plan(Input):
    security_reviewer: Name
    expected_result: Text
    target_date: str | None = None
    implementation_ref: str = Field(default='', max_length=300)
    implementation_claim: str = Field(default='', max_length=4000)

    @field_validator('target_date')
    @classmethod
    def date(cls, value):
        if value is not None:
            datetime.strptime(value, '%Y-%m-%d')
        return value


class ExceptionRequest(Input):
    requester: Name
    justification: Text
    residual_risk: Text
    compensating_controls: str = Field(default='', max_length=4000)
    review_by: str
    evidence_ids: list[Reference] = Field(default_factory=list, max_length=20)

    @field_validator('review_by')
    @classmethod
    def date(cls, value):
        if datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is None:
            raise ValueError('Timezone-aware review/expiration date required')
        return value


class ExceptionDecision(Input):
    authority: Name
    decision: Literal['approved', 'rejected', 'revoked']
    reason: Text


class Retest(Input):
    action_id: Reference
    review_id: Reference
    implementation_ref: Name
    finding_context_hash: Reference
    reviewer: Name
    judgment: Text
    procedure: Text
    expected: Text
    actual: Text
    executed_at: str
    result: Literal['passed', 'failed', 'inconclusive']
    method: Literal['analyst attestation', 'reliable rescan', 'version/configuration evidence', 'targeted human-led test']
    evidence_ids: list[Reference] = Field(min_length=1, max_length=20)
    approval_reference: str = Field(default='', max_length=1000)
    sarif_batch_id: Reference | None = None
    basis: Literal['direct evidence', 'SARIF absence'] = 'direct evidence'

    @field_validator('executed_at')
    @classmethod
    def date(cls, value):
        if datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is None:
            raise ValueError('Timezone-aware execution time required')
        return value
