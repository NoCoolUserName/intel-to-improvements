from fastapi import File, Form, UploadFile, Response
from . import pipeline, pipeline_config, pipeline_execution
from .pipeline_models import Confirmation
from .application_findings import scoped
from .store import digest


def register(app,service):
    @app.post('/api/pipeline-assurance/preview')
    async def preview(customer_id:str=Form(),environment_id:str=Form(),repository:str=Form(),ref:str=Form(),application:str|None=Form(None),commit:str|None=Form(None),synthetic:bool=Form(False),files:list[UploadFile]=File()):
        if len(files)>20:raise ValueError('Snapshot limit is 20 files')
        uploads=[];size=0
        for file in files:
            raw=await file.read(pipeline_config.MAX_FILE+1);size+=len(raw)
            if size>pipeline_config.MAX_TOTAL:raise ValueError('Snapshot aggregate limit is 4 MiB')
            uploads.append((file.filename,raw))
        return pipeline.preview(service.store,customer_id,environment_id,uploads,{'repository':repository,'ref':ref,'application':application,'commit':commit,'synthetic':synthetic})
    @app.post('/api/pipeline-assurance/execution-preview')
    async def execution(customer_id:str=Form(),environment_id:str=Form(),snapshot_id:str=Form(),file:UploadFile=File()):
        return pipeline.preview_execution(service.store,customer_id,environment_id,snapshot_id,await file.read(pipeline_execution.MAX_EXECUTION+1))
    @app.post('/api/pipeline-assurance/confirm')
    def confirm(body:Confirmation):return pipeline.confirm(service.store,body.preview_id,body.customer_id,body.environment_id)
    @app.get('/api/pipeline-assurance')
    def workspace(customer_id:str,environment_id:str):return pipeline.workspace(service.store,customer_id,environment_id)
    @app.get('/api/pipeline-assurance/sources/{id}')
    def source(id:str,customer_id:str,environment_id:str):
        row=scoped(service.store,'pipeline_source',id,customer_id,environment_id)
        raw=(service.store.root/'blobs'/row['sha256']).read_bytes()
        if digest(raw)!=row['sha256']:raise ValueError('Pipeline source integrity check failed')
        return Response(raw,media_type='application/octet-stream',headers={'Content-Disposition':'attachment; filename="pipeline-evidence.txt"'})
    @app.get('/api/pipeline-assurance/{id}')
    def detail(id:str,customer_id:str,environment_id:str):return pipeline.detail(service.store,id,customer_id,environment_id)
