"""Local-only routes; the parent application supplies host/origin and body limits."""
from fastapi import UploadFile, File, Form, Response
from pydantic import BaseModel, ConfigDict, Field
from . import application_findings as findings
from .application_sarif import MAX_BYTES
from .store import digest


class Confirmation(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    customer_id: str = Field(max_length=300)
    environment_id: str = Field(max_length=300)
    preview_id: str = Field(max_length=100)


def register(app, svc):
    @app.post('/api/application-findings/preview')
    async def preview(customer_id: str = Form(), environment_id: str = Form(),
                      application: str | None = Form(None), repository: str | None = Form(None),
                      branch: str | None = Form(None), commit: str | None = Form(None),
                      synthetic: bool = Form(False), file: UploadFile = File()):
        raw = await file.read(MAX_BYTES + 1)
        return findings.preview(svc.store, customer_id, environment_id, raw,
            dict(application=application, repository=repository, branch=branch, commit=commit, synthetic=synthetic))

    @app.post('/api/application-findings/confirm')
    def confirm(body: Confirmation):
        return findings.confirm(svc.store, body.preview_id, body.customer_id, body.environment_id)

    @app.get('/api/application-findings')
    def workspace(customer_id: str, environment_id: str):
        return findings.workspace(svc.store, customer_id, environment_id)

    @app.get('/api/application-findings/imports/{id}')
    def batch(id: str, customer_id: str, environment_id: str):
        return findings.scoped(svc.store, 'application_batch', id, customer_id, environment_id)

    @app.get('/api/application-findings/sources/{id}')
    def source(id: str, customer_id: str, environment_id: str):
        row = findings.scoped(svc.store, 'application_source', id, customer_id, environment_id)
        raw = (svc.store.root / 'blobs' / row['sha256']).read_bytes()
        if digest(raw) != row['sha256']:
            raise ValueError('Stored SARIF evidence integrity check failed')
        return Response(raw, media_type='application/octet-stream', headers={'Content-Disposition': 'attachment; filename="evidence.sarif.json"'})

    @app.get('/api/application-findings/{id}')
    def detail(id: str, customer_id: str, environment_id: str):
        row = findings.scoped(svc.store, 'application_finding', id, customer_id, environment_id)
        return {'finding': row, 'import': findings.scoped(svc.store, 'application_batch', row['batch_id'], customer_id, environment_id),
            'source': findings.scoped(svc.store, 'application_source', row['source_id'], customer_id, environment_id)}
