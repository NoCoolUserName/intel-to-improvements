"""Scoped governance operations. All authoritative reads and writes share a transaction."""
import json
from fastapi import File, Form, UploadFile, Response
from pydantic import Field
from . import appsec, ledger
from .appsec_models import Input, Triage, ExceptionRequest, ExceptionDecision, Retest, Name, Text, Reference
from .models import ImprovementAction


class ScopeVersion(Input):
    customer_id: Reference
    environment_id: Reference
    customer_version: int = Field(ge=1, strict=True)
    environment_version: int = Field(ge=1, strict=True)


class Command(Input):
    context: ScopeVersion


class ReviewCommand(Command):
    review: Triage


class ActionCommand(Command):
    review_id: Reference
    actor: Name
    reason: Text
    expected_updated_at: str | None = None
    action: ImprovementAction


class RetestCommand(Command):
    retest: Retest


class RequestCommand(Command):
    request: ExceptionRequest


class DecisionCommand(Command):
    request_id: Reference
    decision: ExceptionDecision


def register(app, svc):
    @app.post('/api/appsec/demo')
    def demo():
        from . import appsec_demo
        return appsec_demo.load(svc)

    def execute(id, context, operation):
        with appsec.transaction(svc.store) as store:
            ctx = context.model_dump()
            f = appsec.finding(store, id, ctx['customer_id'], ctx['environment_id'])
            subject = appsec.subject(store, f, ctx)
            return operation(store, f, subject)

    @app.get('/api/application-findings/{id}/governance')
    def governance(id: str, customer_id: str, environment_id: str):
        with appsec.transaction(svc.store) as store:
            return appsec.view(store, appsec.finding(store, id, customer_id, environment_id))

    @app.post('/api/application-findings/{id}/review')
    def review(id: str, body: ReviewCommand):
        return execute(id, body.context, lambda s, f, a: appsec.review(s, f, a['context'], body.review.model_dump()))

    @app.post('/api/application-findings/{id}/action')
    def action(id: str, body: ActionCommand):
        def operation(store, f, subject):
            subject['appsec_command'] = body.model_dump(exclude={'context', 'action'})
            return ledger.improve(store, subject, body.action)
        return execute(id, body.context, operation)

    @app.post('/api/application-findings/{id}/retest')
    def retest(id: str, body: RetestCommand):
        return execute(id, body.context, lambda s, f, a: appsec.retest(s, a, body.retest.model_dump()))

    @app.post('/api/application-findings/{id}/exceptions')
    def exception_request(id: str, body: RequestCommand):
        return execute(id, body.context, lambda s, f, a: appsec.request_exception(s, f, a['context'], body.request.model_dump()))

    @app.post('/api/application-findings/{id}/exception-decisions')
    def exception_decision(id: str, body: DecisionCommand):
        return execute(id, body.context, lambda s, f, a: appsec.decide_exception(s, f, a['context'], body.request_id, body.decision.model_dump()))

    @app.post('/api/application-findings/{id}/attachments')
    async def attachment(id: str, context: str = Form(), kind: str = Form(), description: str = Form(), file: UploadFile = File()):
        if len(context) > 2000:
            raise ValueError('Context too large')
        ctx = ScopeVersion.model_validate(json.loads(context))
        raw = await file.read(2 * 1024 * 1024 + 1)
        return execute(id, ctx, lambda s, f, a: appsec.capture_evidence(s, f, a['context'], file.filename, raw, kind, description))

    @app.get('/api/application-findings/{id}/attachments/{evidence_id}')
    def download(id: str, evidence_id: str, customer_id: str, environment_id: str):
        f = appsec.finding(svc.store, id, customer_id, environment_id)
        row = appsec.evidence_refs(svc.store, f, [evidence_id])[0]
        return Response((svc.store.root / 'blobs' / row['sha256']).read_bytes(), media_type='application/octet-stream',
            headers={'Content-Disposition': 'attachment; filename="appsec-evidence.bin"'})
