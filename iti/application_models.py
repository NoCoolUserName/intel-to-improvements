"""Scanner observations, deliberately separate from CVE exposure and ledger contracts."""
from typing import Literal
from pydantic import Field
from .models import Model, Context


class ApplicationContext(Model):
    application: str | None = Field(default=None, max_length=300)
    repository: str | None = Field(default=None, max_length=2000)
    branch: str | None = Field(default=None, max_length=300)
    commit: str | None = Field(default=None, max_length=300)
    synthetic: bool = False


class ApplicationFinding(Model):
    id: str
    logical_id: str
    identity_basis: str
    batch_id: str
    source_id: str
    source_sha256: str
    context: Context
    operator_context: ApplicationContext
    reported_context: list[dict]
    scanner: dict
    run_index: int
    result_index: int
    run_id: dict | None
    rule_id: str | None
    rule_metadata: dict
    message: dict
    resolved_message: str | None
    scanner_level: str | None
    level_source: str | None
    severity_metadata: dict
    cwes: list[str]
    cves: list[str]
    locations: list[dict]
    fingerprints: dict
    partial_fingerprints: dict
    imported_at: str
    scan_timestamps: list[dict]
    invocation_status: Literal['reported success', 'failed or incomplete', 'unknown']
    synthetic: bool
    synthetic_basis: list[str]
    warnings: list[str]
    verification: Literal['scanner reported; not independently validated'] = 'scanner reported; not independently validated'
