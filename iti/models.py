"""Versioned public contracts. Facts and operational outcomes intentionally separate."""
from typing import Literal, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from datetime import datetime

SCHEMA_VERSION='1.0'
class Model(BaseModel):
    model_config=ConfigDict(extra='forbid')
    schema_version: str=SCHEMA_VERSION

class EvidenceSpan(Model):
    id: str
    revision_id: str
    text: str
    heading_path: list[str]=[]
    kind: str='paragraph'
    start: int
    end: int
    offset_space: Literal['normalized_unicode']='normalized_unicode'
    raw_start: int|None=None
    raw_end: int|None=None
    segment: str|None=None

class SourceDocument(Model):
    id: str
    revision_id: str
    content_revision_id: str|None=None
    title: str
    origin: str
    final_url: str|None=None
    redirects: list[str]=[]
    publisher: str|None=None
    authors: list[str]=[]
    retrieved_at: str
    published_at: str|None=None
    publication_precision: str='unknown'
    incident_time: str|None=None
    incident_precision: str='unknown'
    serials: list[dict]=[]
    content_hash: str
    representation: str
    hash_basis: str='selected input bytes'
    completeness: Literal['complete-for-supported-content','partial','failed']
    gaps: list[str]=[]
    scope: str
    normalized: str
    spans: list[EvidenceSpan]
    imported_objects: list[dict]=[]
    conversion_losses: list[str]=[]
    metadata: dict={}

class Claim(Model):
    id: str
    text: str
    evidence: list[str]
    kind: Literal['source_reported','analyst_inference','proposed','unsupported','conflicting']='source_reported'
    qualifier: str|None=None
    extraction_confidence: Literal['high','medium','low']='medium'
    confidence_rationale: str
    source_reliability: str='not independently assessed'
    review_required: bool=False

class Observable(Model):
    id: str
    type: Literal['ipv4','domain','url','sha256']
    value: str
    originals: list[str]
    evidence: list[str]
    role: Literal['malicious','benign','victim','legitimate_tool','unknown']
    maliciousness_asserted: bool=False
    context: str
    first_seen: str|None=None
    last_seen: str|None=None
    time_precision: str='unknown'
    to_ids: bool=False
    to_ids_reason: str='Review required; no automatic blocking recommendation'

class ReportedBehavior(Claim):
    platform: str='unknown'
    technique_id: str|None=None
    technique_name: str|None=None
    mapping_basis: Literal['source_asserted','analyst_proposed','none']='none'
    technology: list[str]=[]
    telemetry: list[str]=[]
    sequence: int|None=None
    key: str

class EntityRelationship(Claim):
    source_ref: str
    target_ref: str
    relationship: str

class Extraction(Model):
    id: str
    source_revision: str
    mode: Literal['replay','offline','live','analyst-curated']
    provider: str
    model: str|None=None
    claims: list[Claim]=[]
    observables: list[Observable]=[]
    behaviors: list[ReportedBehavior]=[]
    relationships: list[EntityRelationship]=[]
    sector_factors: list[dict]=[]
    cited_rules: list[str]=[]
    warnings: list[str]=[]
    usage: dict={}
    review_status: str='needs analyst review'

SECTORS={'unspecified':'Unspecified','financial-services':'Financial services','healthcare':'Healthcare','government':'Government','defense':'Defense','technology':'Technology','energy':'Energy','manufacturing':'Manufacturing','telecommunications':'Telecommunications','education':'Education','retail':'Retail','transportation':'Transportation','other':'Other / custom'}
class EnvironmentProfile(Model):
    id: str
    name: str
    version: int=1
    platforms: list[str]
    technologies: list[str]=[]
    exposed_services: list[str]=[]
    important_assets: list[str]=[]
    telemetry: dict[str,list[str]]={}
    retention_days: int=30
    controls: list[dict]=[]
    field_map: dict[str,str]={}
    backend: str='portable analyst procedure'
    notes: str='Declared availability; not checked by a live test'

class CustomerProfile(Model):
    id: str
    name: str
    version: int=1
    sector: str='unspecified'
    additional_sectors: list[str]=[]
    subsector: str|None=None
    priorities: list[str]=[]
    intelligence_requirements: list[str]=[]
    environments: list[EnvironmentProfile]
    misp_destination: str|None=None
    allow_live_processing: bool=True
    @field_validator('sector')
    @classmethod
    def sector_valid(cls,v):
        if v not in SECTORS: raise ValueError('Unknown sector identifier')
        return v

class Context(Model):
    customer_id: str
    customer_version: int
    environment_id: str
    environment_version: int
    policy_version: str='relevance-1'
    destination: str|None=None
    customer_snapshot: CustomerProfile
    environment_snapshot: EnvironmentProfile

class HuntStep(Model):
    id: str
    behavior_id: str
    evidence: list[str]
    assumptions: list[str]
    question: str
    hypothesis: str
    priority: str
    rationale: str
    scope: str
    prerequisites: list[str]
    required_fields: list[str]
    retention_days: int
    steps: list[dict]
    query: str|None=None
    query_origin: str
    backend: str
    field_mapping: dict[str,str]
    parameters: dict
    expected: str
    benign: list[str]
    negative_controls: list[str]
    branches: dict[str,str]
    preserve: list[str]
    escalation: str
    closure: str

class EmulationStep(Model):
    id: str
    behavior_id: str
    evidence: list[str]
    assumptions: list[str]
    objective: str
    applicability: str
    technique_id: str|None=None
    prerequisites: list[str]
    telemetry_checks: list[str]
    lab_scope: str
    test_data: str
    steps: list[str]
    expected_observables: list[str]
    expected_detection: str
    expected_prevention: str
    benign_controls: list[str]
    stop_conditions: list[str]
    cleanup: list[str]
    atomic_candidates: list[dict]
    limitations: list[str]
    exercise_designation: str='coordinated'
    evidence_template: dict

class DetectionCandidate(Model):
    id: str
    title: str
    behavior_id: str
    evidence: list[str]
    retrieval: str
    match: str
    explanation: str
    source: dict
    status: str
    author: str
    license: str
    logsource: dict
    fields: list[str]
    condition: Any
    attack_tags: list[str]
    limitations: list[str]
    environment_fit: str
    syntax_valid: bool
    conversion_supported: bool
    environment_ready: bool
    execution_tested: bool=False
    query: str|None=None
    conversion_error: str|None=None

class CoverageAssessment(Model):
    behavior_id: str
    applicability: Literal['applicable','not applicable','unknown']
    reason: str
    missing_prerequisites: list[str]=[]
    telemetry_readiness: str='unknown'
    detection_readiness: str='not assessed'
    deployment: str='unknown'
    detection_test: str='not tested'
    prevention_test: str='not tested'
    soc_response: str='not tested'
    synthetic_result: str='not tested'
    coverage_classification: str='unknown'
    hunts: list[str]=[]
    emulations: list[str]=[]
    candidates: list[str]=[]

class EvidenceAttachment(Model):
    id: str
    reference: str
    sha256: str|None=None
    description: str
    kind: Literal['live system','lab execution','synthetic fixture replay','analyst attestation']

class TestRun(Model):
    id: str=''
    behavior_id: str|None=None
    vulnerability_assessment_id: str|None=None
    measurement: dict[str,Any]|None=None
    residual_risk: str|None=None
    permanent_fix: str|None=None
    environment_version: int
    control_id: str
    control_version: str
    procedure: str
    expected: str
    actual: str
    executed_at: str
    recorded_at: str=''
    method: Literal['synthetic log match','lab emulation','observed SIEM alert','observed prevention','analyst attestation','reliable rescan','version/configuration evidence','targeted human-led test']
    result: Literal['passed','failed','inconclusive']
    dimension: Literal['telemetry','detection','prevention','soc_acknowledged','soc_response','deployment','remediation','mitigation']
    scope: str
    evidence: list[EvidenceAttachment]
    variant: str
    exercise: Literal['blind','coordinated']='coordinated'
    attempted_action: str|None=None
    control_outcome: str|None=None
    exercise_event_at: str|None=None
    baseline: bool=False
    control_deployed_at: str|None=None
    improvement_id: str|None=None
    @field_validator('executed_at','exercise_event_at','control_deployed_at')
    @classmethod
    def aware(cls,v):
        if v is not None and datetime.fromisoformat(v.replace('Z','+00:00')).tzinfo is None: raise ValueError('Timezone-aware timestamp required')
        return v
    @model_validator(mode='after')
    def proof(self):
        if not self.evidence: raise ValueError('Evidence reference required')
        if self.method=='synthetic log match' and self.dimension!='detection': raise ValueError('Synthetic match only evaluates detection fixture semantics')
        if self.dimension=='prevention' and self.result=='passed' and (self.method!='observed prevention' or not self.attempted_action or not self.control_outcome): raise ValueError('Prevention requires attempted action and observed enforcing control outcome')
        if self.dimension.startswith('soc_') and not self.exercise_event_at: raise ValueError('SOC timing requires exercise event/alert timestamp')
        return self

class ImprovementAction(Model):
    id: str=''
    behavior_id: str|None=None
    vulnerability_assessment_id: str|None=None
    remediation: dict[str,Any]|None=None
    owner: str
    priority: str
    status: Literal['open','in progress','deployed','retest requested','closed']='open'
    rationale: str
    proposed_change: str
    opened_at: str=''
    deployed_at: str|None=None
    retest: str
    origin: dict[str,Any]|None=None

class GmailScope(Model):
    query: str=Field(min_length=1,max_length=1000)
    label: str|None=None
    after: str|None=None
    before: str|None=None
    max_messages: int=Field(default=5,ge=1,le=25)

class HandoffMessage(Model):
    message_id: str|None=None
    thread_id: str|None=None
    account: str|None=None
    rfc_message_id: str|None=None
    sender: str|None=None
    subject: str
    message_date: str|None=None
    labels: list[str]=[]
    source_links: list[str]=[]
    report_serials: list[dict]=[]
    representation: Literal['connector-provided text','HTML','raw MIME','snippet']
    body: str=Field(max_length=500000)
    completeness: Literal['complete-for-supported-content','partial','failed']
    gaps: list[str]=[]
    attachments: list[dict]=[]
    part_id: str|None=None

class GmailHandoff(Model):
    schema_version: Literal['1.0']='1.0'
    request_id: str
    batch_id: str
    part: int=Field(default=1,ge=1,le=100)
    requested_scope: GmailScope
    context: dict
    retrieved_at: str
    account: str|None=None
    messages: list[HandoffMessage]=Field(max_length=25)
    returned_count: int|None=None
    retrieved_count: int|None=None
    failed_count: int|None=None
    omitted_count: int|None=None
    pagination_status: str
    limitations: list[str]=[]
