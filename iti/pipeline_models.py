"""Small contracts for operator-supplied pipeline snapshots."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

VERSION='pipeline-assurance-1'
LIMITATIONS=[
    'Configuration is not execution, enforcement, or proof of pipeline security.',
    'Repository, application, ref and commit are operator-provided; snapshot completeness/currentness is unknown.',
    'Merge enforcement and repository/organization runtime permissions are unknown.',
    'External actions, scripts and reusable workflows are never fetched or executed.',
    'Supplied execution metadata is not independently authenticated; control effectiveness remains unknown.',
]

class Input(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,str_strip_whitespace=True)

class PipelineContext(Input):
    repository: str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$',max_length=300)
    application: str|None=Field(default=None,max_length=300)
    ref: str=Field(min_length=1,max_length=300)
    commit: str|None=Field(default=None,pattern=r'^[0-9a-fA-F]{40}$')
    synthetic: bool=False

class Observation(Input):
    id: str
    check_id: str
    category: str
    description: str
    state: Literal['Observed configured','Potential concern','Not observed in supplied scope','Requires manual review','Unknown','Not applicable']
    workflow: str
    key: str
    line: int|None=None
    evidence: object
    reason: str
    limitations: list[str]
    rule_version: str=VERSION
    job_key: str|None=None
    job_name: str|None=None
    step_name: str|None=None
    step_number: int|None=None
    execution_matchable: bool=False

class Confirmation(Input):
    customer_id: str=Field(max_length=300)
    environment_id: str=Field(max_length=300)
    preview_id: str=Field(max_length=100)
