from .models import CustomerProfile, EnvironmentProfile, Context
from .store import uid
WINDOWS=EnvironmentProfile(id='windows-ad',name='Windows / AD lab',platforms=['windows'],technologies=['ActiveMQ','Active Directory','PowerShell','RDP'],exposed_services=['ActiveMQ'],important_assets=['Domain controllers','Backup server'],telemetry={'process_creation':['Image','OriginalFileName','ParentImage','CommandLine','User','Computer','UtcTime'],'dns_query':['QueryName','Image'],'proxy':['url','src_ip']},field_map={x:x for x in ['Image','OriginalFileName','ParentImage','CommandLine','User','Computer','UtcTime']},backend='Splunk raw events',controls=[{'name':'Defender','deployed_at':None,'version':'unknown','status':'declared; not tested'}],notes='Fictional. Sysmon process telemetry declared. PowerShell script-block and LSASS process-access telemetry deliberately missing. Index selected by analyst, no CIM claim.')
MAC=EnvironmentProfile(id='mac-cloud',name='macOS / AWS / SaaS',platforms=['macos','linux','cloud'],technologies=['AWS','Okta','macOS'],important_assets=['Cloud identities','Customer data'],telemetry={'endpoint':['process.name','process.command_line'],'cloudtrail':['eventName','userIdentity','sourceIPAddress'],'identity':['actor','eventType','outcome']},backend='portable analyst procedure',notes='Fictional. CloudTrail and identity telemetry declared, never live tested. No Windows endpoints or ActiveMQ declared.')
def seed(store):
    if store.all('customer'): return
    for c in [CustomerProfile(id='fictional-bank',name='Northstar Bank · fictional',sector='financial-services',priorities=['Protect backups and privileged identities'],intelligence_requirements=['ransomware','credential access'],environments=[WINDOWS]),CustomerProfile(id='fictional-cloud',name='Cedar Cloud · fictional',sector='technology',priorities=['Cloud and SaaS continuity'],intelligence_requirements=['cloud identity','supply chain'],environments=[MAC])]: save(store,c)
def save(store,c):
    old=store.maybe('customer',c.id)
    if old:
        c.version=old['version']+1
        for e in c.environments:
            prev=next((p for p in old['environments'] if p['id']==e.id),None)
            if prev: e.version=prev['version']+1
    store.put('customer_version',f'{c.id}:{c.version}',c.model_dump(),immutable=True)
    store.put('customer',c.id,c.model_dump()); store.event('customer_profile_saved',c.id,{'version':c.version})
    return c

def context(store,customer_id,environment_id):
    c=CustomerProfile.model_validate(store.get('customer',customer_id)); e=next((e for e in c.environments if e.id==environment_id),None)
    if not e: raise ValueError('Environment does not belong to selected customer')
    return Context(customer_id=c.id,customer_version=c.version,environment_id=e.id,environment_version=e.version,destination=c.misp_destination,customer_snapshot=c,environment_snapshot=e)
