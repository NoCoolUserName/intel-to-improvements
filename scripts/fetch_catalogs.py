"""Explicit, bounded catalog maintenance; downloads public catalog content, never IOCs."""
import json, urllib.request, hashlib, datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def get(url):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Intel-to-Improvements/0.1'}),timeout=45) as r: return r.read(60_000_000)
def save(path,data):
 p=ROOT/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data); return hashlib.sha256(data).hexdigest()
def main():
 import argparse
 p=argparse.ArgumentParser(); p.add_argument('--full-sigma',action='store_true'); args=p.parse_args()
 revisions={n:json.loads(get('https://api.github.com/repos/'+repo+'/commits/master'))['sha'] for n,repo in [('sigma','SigmaHQ/sigma'),('attack','mitre-attack/attack-stix-data'),('atomic','redcanaryco/atomic-red-team')]}
 manifest={'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'revisions':revisions,'files':[],'sigma_scope':'full public rules' if args.full_sigma else 'bounded subset'}
 sha=revisions['sigma']; tree=json.loads(get(f'https://api.github.com/repos/SigmaHQ/sigma/git/trees/{sha}?recursive=1'))
 wanted=['proc_creation_win_certutil_download','proc_creation_win_java_spawn_shell','proc_creation_win_powershell_base64_gzip','proc_creation_win_net_recon','proc_creation_win_remote_access_tools_anydesk','sysmon_accessing_lsass']
 paths=[x['path'] for x in tree['tree'] if x['path'].startswith('rules/') and x['path'].endswith('.yml') and (args.full_sigma or any(w in x['path'] for w in wanted))]
 for path in paths:
  data=get(f'https://raw.githubusercontent.com/SigmaHQ/sigma/{sha}/{path}'); local='catalogs/sigma/'+path.replace('/','__'); h=save(local,data); manifest['files'].append({'kind':'sigma','path':local,'upstream_path':path,'sha256':h,'url':f'https://github.com/SigmaHQ/sigma/blob/{sha}/{path}'})
 for repo,sha,path,dest in [('SigmaHQ/sigma',sha,'LICENSE','catalogs/SIGMA_LICENSE'),('redcanaryco/atomic-red-team',revisions['atomic'],'LICENSE.txt','catalogs/ATOMIC_LICENSE')]:
  save(dest,get(f'https://raw.githubusercontent.com/{repo}/{sha}/{path}'))
 data=json.loads(get(f'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{revisions["attack"]}/enterprise-attack/enterprise-attack.json'))
 # Whole technique metadata, no attack instructions; names/IDs/deprecation offline.
 rows=[]
 for o in data['objects']:
  if o['type']=='attack-pattern':
   refs=[r for r in o.get('external_references',[]) if r.get('source_name')=='mitre-attack']
   if refs: rows.append({k:o.get(k) for k in ['id','name','modified','revoked','x_mitre_deprecated','x_mitre_platforms']}|{'technique_id':refs[0]['external_id'],'url':refs[0]['url']})
 save('catalogs/attack.json',json.dumps(rows,indent=2).encode())
 save('catalogs/ATTACK_LICENSE',get(f'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{revisions["attack"]}/LICENSE.txt'))
 # Pin source files for inspection only; app never executes Atomic content.
 for tid in ['T1105','T1059.001','T1087.002']:
  path=f'atomics/{tid}/{tid}.yaml'; data=get(f'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{revisions["atomic"]}/{path}')
  save(f'catalogs/atomic/{tid}.yaml',data)
  manifest['files'].append({'kind':'atomic','path':f'catalogs/atomic/{tid}.yaml','upstream_path':path,'sha256':hashlib.sha256(data).hexdigest(),'url':f'https://github.com/redcanaryco/atomic-red-team/blob/{revisions["atomic"]}/{path}'})
 save('catalogs/manifest.json',json.dumps(manifest,indent=2).encode()); print('Pinned',len(paths),'Sigma rules and',len(rows),'ATT&CK techniques')
if __name__=='__main__': main()
