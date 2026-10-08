import argparse,json,sys,os
from pathlib import Path
from dotenv import load_dotenv
from .store import ROOT
load_dotenv(ROOT/'.env')
def main():
    from .services import Service
    p=argparse.ArgumentParser(description='Intel to Improvements local workbench');sub=p.add_subparsers(dest='command',required=True)
    for name in ['demo','test','eval','run','catalog-sync','health']:sub.add_parser(name)
    ing=sub.add_parser('ingest');ing.add_argument('value');ing.add_argument('--kind',choices=['url','path','text','case','source'],default='path');ing.add_argument('--csv-map',help='JSON canonical-to-source column map');ing.add_argument('--mode',choices=['offline','replay','live'],default='offline');ing.add_argument('--customer',default='fictional-bank');ing.add_argument('--environment',default='windows-ad')
    ex=sub.add_parser('export');ex.add_argument('assessment');ex.add_argument('--customer',default='fictional-bank')
    mc=sub.add_parser('misp-check');mc.add_argument('package');mc.add_argument('--customer',default='fictional-bank')
    gp=sub.add_parser('gmail-request');gp.add_argument('--query',required=True);gp.add_argument('--label');gp.add_argument('--after');gp.add_argument('--before');gp.add_argument('--max-messages',type=int,default=2);gp.add_argument('--customer',default='fictional-bank');gp.add_argument('--environment',default='windows-ad');gp.add_argument('--output')
    gi=sub.add_parser('gmail-import');gi.add_argument('path');gi.add_argument('--customer',default='fictional-bank');gi.add_argument('--mode',default='offline',choices=['offline','live']);gi.add_argument('--preview',action='store_true')
    gs=sub.add_parser('gmail-sample');gs.add_argument('request_id');gs.add_argument('--output',required=True)
    args=p.parse_args();svc=Service()
    if args.command=='run':
        import uvicorn
        uvicorn.run('iti.api:app',host=os.getenv('ITI_HOST','127.0.0.1'),port=int(os.getenv('ITI_PORT','8000')));return
    if args.command=='test':
        import subprocess;sys.exit(subprocess.call([sys.executable,'-m','pytest','-q']))
    if args.command=='catalog-sync':
        import subprocess;sys.exit(subprocess.call([sys.executable,str(ROOT/'scripts/fetch_catalogs.py'),'--full-sigma']))
    if args.command=='eval':
        from .evaluation import evaluate
        print(json.dumps(evaluate(),indent=2));return
    if args.command=='health':
        from .api import readiness
        print(json.dumps(readiness(),indent=2));return
    if args.command=='demo':
        output=[]
        for case in ['activemq-derived','no-ioc','insufficient','held-out']:
            j=svc.submit('fictional-bank','windows-ad','replay' if case=='activemq-derived' else 'offline','case',case,background=False)
            if j['state']!='complete':raise ValueError(str(j['data'].get('error')))
            package=svc.generate(j['data']['assessment_id'],'fictional-bank');output.append({'case':case,'assessment':j['data']['assessment_id'],'package':package['id'],'artifacts':str(svc.store.root/'artifacts'/package['id'])})
        # Shared research copy can be separately assessed; private source facts never leak via hash.
        j=svc.submit('fictional-cloud','mac-cloud','replay','case','activemq-derived',background=False);svc.generate(j['data']['assessment_id'],'fictional-cloud')
        print(json.dumps(output,indent=2));return
    if args.command=='ingest':result=svc.submit(args.customer,args.environment,args.mode,args.kind,args.value,background=False,metadata={'column_mapping':json.loads(args.csv_map)} if args.csv_map else None)
    elif args.command=='export':result=svc.generate(args.assessment,args.customer)
    elif args.command=='misp-check':
        from .misp import import_event
        result=import_event(svc.store,svc.scoped('package',args.package,args.customer))
    elif args.command=='gmail-request':
        from .gmail import prepare
        from .models import GmailScope
        result=prepare(svc.store,args.customer,args.environment,GmailScope(query=args.query,label=args.label,after=args.after,before=args.before,max_messages=args.max_messages))
        if args.output:Path(args.output).write_text(result['copyable_request'])
    elif args.command=='gmail-sample':
        from .gmail import sample
        result=sample(svc.store.get('gmail_request',args.request_id));Path(args.output).write_text(json.dumps(result,indent=2))
    else:
        from .gmail import preview,process
        from .ingestion import read_path
        raw,_=read_path(args.path);result=preview(svc.store,raw,args.customer) if args.preview else process(svc,raw,args.customer,args.mode,background=False)
    print(json.dumps(result,indent=2,default=str))
    if isinstance(result,dict) and result.get('state')=='failed':sys.exit(1)
if __name__=='__main__':main()
