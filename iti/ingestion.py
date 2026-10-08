import copy
"""Explicit intake only. This module never follows links found inside intelligence."""
import base64, csv, io, ipaddress, json, re, socket, os, stat, time
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit, urljoin
import httpx
from bs4 import BeautifulSoup
from pypdf import PdfReader
from .models import SourceDocument, EvidenceSpan
from .store import digest, uid, now, canonical

PARSER_VERSION='parser-1.4'
MAX_BYTES=5*1024*1024
FORMATS={'.txt','.md','.html','.htm','.json','.csv','.eml','.pdf'}
DFIR_URL='https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/'
def public_url(url):
    p=urlsplit(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.port not in (None,80,443): raise ValueError('Only public HTTP(S) report URLs on standard ports are supported')
    addresses=sorted({a[4][0] for a in socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses): raise ValueError('Private, local, reserved or metadata destinations are forbidden')
    return p,addresses

def fetch(url):
    supplied=url; redirects=[]; started=time.monotonic()
    for _ in range(5):
        p,addresses=public_url(url)
        # Pin the validated address at connection time; do not resolve hostname again.
        ip=addresses[0]; host='['+ip+']' if ':' in ip else ip
        pinned=f'{p.scheme}://{host}'+(f':{p.port}' if p.port else '')+(p.path or '/')+('?' + p.query if p.query else '')
        with httpx.Client(timeout=httpx.Timeout(20,connect=8),trust_env=False,follow_redirects=False) as client:
            with client.stream('GET',pinned,headers={'Host':p.netloc,'User-Agent':'Intel-to-Improvements/0.1 (operator-selected research)'},extensions={'sni_hostname':p.hostname}) as response:
                if response.is_redirect:
                    url=urljoin(url,response.headers.get('location','')); redirects.append(url); continue
                response.raise_for_status()
                body=bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic()-started>40:raise ValueError('Overall source retrieval deadline exceeded')
                    body.extend(chunk)
                    if len(body)>MAX_BYTES: raise ValueError('Source exceeds 5 MiB limit')
                content_type=response.headers.get('content-type','')
        return bytes(body),{'origin':supplied,'final_url':url,'redirects':redirects,'content_type':content_type}
    raise ValueError('Redirect limit exceeded')

def list_reports(limit=15):
    if not 1<=limit<=25: raise ValueError('Listing limit must be 1..25')
    body,_=fetch('https://thedfirreport.com/reports/')
    soup=BeautifulSoup(body,'lxml'); links={}
    for a in soup.select('a[href]'):
        url=urljoin('https://thedfirreport.com/',a['href'])
        if re.match(r'^https://thedfirreport\.com/20\d\d/\d\d/\d\d/[^/]+/?$',url): links[url]={'url':url,'title':a.get_text(' ',strip=True) or url.rsplit('/',2)[-2]}
    return list(links.values())[:limit]

def read_path(value):
    p=Path(value).expanduser().resolve(strict=True)
    if not p.is_file(): raise ValueError('Select a readable regular file, not a directory/device')
    if p.suffix.lower() not in FORMATS: raise ValueError('Unsupported format; use txt/md/html/json/csv/eml/text PDF')
    if p.stat().st_size>MAX_BYTES: raise ValueError('File exceeds 5 MiB')
    fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise ValueError('Selected path is no longer a regular file')
        data=f.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise ValueError('File grew past size limit')
    return data,str(p)

def parse_bytes(data,name,representation=None,column_mapping=None):
    if len(data)>MAX_BYTES: raise ValueError('Input exceeds 5 MiB')
    ext=Path(name).suffix.lower()
    if ext not in FORMATS: raise ValueError(f'Unsupported file type {ext!r}')
    gaps=[]; metadata={}; blocks=[]; imported=[]; losses=[]
    def add(text,kind='paragraph',heading=None,segment=None):
        text=text.strip()
        if text: blocks.append({'text':text,'kind':kind,'heading_path':list(heading or []),'segment':segment})
    if ext=='.pdf':
        reader=PdfReader(io.BytesIO(data)); metadata['pages']=len(reader.pages)
        if reader.is_encrypted: raise ValueError('Encrypted PDFs are unsupported')
        for i,page in enumerate(reader.pages):
            txt=page.extract_text() or ''; add(txt,'page',[f'Page {i+1}'])
            if not txt.strip(): gaps.append(f'Page {i+1}: scanned/image-only or empty; OCR unavailable')
            if list(page.images): gaps.append(f'Page {i+1}: images not interpreted')
    elif ext=='.eml':
        msg=BytesParser(policy=policy.default).parsebytes(data)
        metadata.update({k:str(msg[k]) if msg[k] else None for k in ['Subject','From','Date','Message-ID']})
        metadata['title']=metadata.get('Subject'); metadata['attachments']=[]
        # Prefer complete text over alternate HTML; retain forwards/quotes in-place.
        body=msg.get_body(preferencelist=('plain','html'))
        if body:
            content=body.get_content()
            if body.get_content_type()=='text/html':
                sub=parse_bytes(content.encode(),'body.html'); blocks.extend(sub['blocks']); gaps.extend(sub['gaps'])
            else:
                for p in re.split(r'\n\s*\n',content): add(p,'paragraph',['Message body'],'body')
        else: gaps.append('No supported MIME body')
        for i,part in enumerate(msg.iter_attachments()):
            filename=part.get_filename() or f'part-{i}'; payload=part.get_payload(decode=True) or b''
            metadata['attachments'].append({'part':str(i),'filename':filename,'sha256':digest(payload),'bytes':len(payload)})
            if Path(filename).suffix.lower() in FORMATS- {'.eml'}:
                sub=parse_bytes(payload,filename)
                for b in sub['blocks']: b['segment']=f'attachment:{i}'; b['heading_path']=[filename]+b['heading_path']
                blocks.extend(sub['blocks']); gaps.extend(sub['gaps']); losses.extend(sub['losses'])
            else: gaps.append(f'Unsupported attachment {filename}; bytes retained in raw MIME')
    else:
        try: text=data.decode('utf-8-sig')
        except UnicodeDecodeError:
            text=data.decode('utf-8',errors='replace'); gaps.append('Invalid UTF-8 replaced; original bytes retained')
        if ext in ('.html','.htm'):
            soup=BeautifulSoup(text,'lxml')
            metadata['title']=soup.h1.get_text(' ',strip=True) if soup.h1 else (soup.title.get_text(' ',strip=True) if soup.title else None)
            for key,selector in [('published_at','meta[property="article:published_time"]'),('publisher','meta[property="og:site_name"]'),('author','meta[name="author"]')]:
                el=soup.select_one(selector)
                if el: metadata[key]=el.get('content')
            if not metadata.get('published_at'):
                el=soup.select_one('time[datetime]')
                if el: metadata['published_at']=el['datetime']
            article=soup.select_one('.single-content-section .content-column') or soup.select_one('.entry-content') or soup.find('article') or soup.find('main')
            if article is None: article=soup.body or soup; gaps.append('Generic fallback: no article/main region; inspect extraction')
            for el in article.select('script,style,nav,footer,aside,form,.sharedaddy,.related-posts,.wp-block-jetpack-subscriptions,.ad,.advertisement'):
                el.decompose()
            images=len(article.find_all('img'))
            if images: gaps.append(f'{images} image-only evidence regions not interpreted; no OCR')
            heading=[]; skip=False
            for el in article.find_all(['h1','h2','h3','h4','p','pre','table','li']):
                if el.find_parent(['pre','table','li']): continue
                t=el.get_text('\n' if el.name in ('pre','table') else ' ',strip=True)
                if el.name.startswith('h'):
                    skip=bool(re.search(r'offerings|related posts|subscribe|comments|leave a reply',t,re.I))
                    level=int(el.name[1]); heading=heading[:max(0,level-2)]+[t]
                elif not skip and not re.search(r'please subscribe|audio version of this report|check out our products|book a demo|access dfir labs',t,re.I): add(t,{'pre':'code','table':'table','li':'list_item'}.get(el.name,'paragraph'),heading)
        elif ext=='.json':
            obj=json.loads(text)
            if obj.get('type')=='bundle':
                import stix2
                from stix2validator import validate_string, ValidationOptions
                result=validate_string(text,ValidationOptions(version='2.1',strict=False))
                if not result.is_valid: raise ValueError('Invalid STIX bundle: '+str(result.errors))
                stix2.parse(text,allow_custom=False)
                supported={'identity','report','indicator','ipv4-addr','domain-name','url','file','attack-pattern','relationship','malware','note','observed-data'}
                for o in obj['objects']:
                    if o['type'] in supported:
                        imported.append(o); add(json.dumps(o,ensure_ascii=False),'structured',[o['type']],o['id'])
                    else: losses.append(f'Unsupported STIX type {o["type"]}: {o["id"]}')
                metadata['format']='stix21'; metadata['title']=next((o.get('name') for o in imported if o['type']=='report'),None)
            elif 'Event' in obj or ('info' in obj and 'Attribute' in obj):
                from pymisp import MISPEvent
                event=MISPEvent(); event.load(copy.deepcopy(obj)); event.to_json()
                ev=obj.get('Event',obj); metadata['format']='misp'; metadata['source_event_uuid']=ev.get('uuid'); metadata['title']=ev.get('info')
                for attr in ev.get('Attribute',[]):
                    imported.append({'type':'misp-attribute',**attr}); add(json.dumps(attr),'structured',['MISP attribute'],attr.get('uuid'))
                for report in ev.get('EventReport',[]): add(report.get('content',''),'paragraph',['MISP EventReport'],report.get('uuid'))
                add(ev.get('info',''),'paragraph',['MISP context'])
                if ev.get('Object'): losses.append('MISP objects retained raw; object-template normalization unsupported')
            else: raise ValueError('JSON must be a STIX 2.1 bundle, native MISP event, or imported through the Gmail handoff workflow')
        elif ext=='.csv':
            rows=list(csv.DictReader(io.StringIO(text)))
            if column_mapping:
                allowed={'type','value','role','context','first_seen','last_seen'}
                if set(column_mapping)-allowed:raise ValueError('CSV mapping uses unsupported canonical columns')
                rows=[{target:row.get(column_mapping.get(target,target),'') for target in allowed} for row in rows]
                metadata['column_mapping']=column_mapping
            if not rows or not {'type','value'}.issubset(rows[0]): raise ValueError('CSV requires type,value columns; optional role,context,first_seen,last_seen')
            for row in rows:
                if row['type'] not in ('ipv4','domain','url','sha256'): raise ValueError('Unsupported CSV indicator type')
                add(json.dumps(row),'indicator',['Indicator CSV']); imported.append({'type':'csv',**row})
            gaps.append('Indicator list contains no supported intrusion narrative')
        else:
            heading=[]
            for p in re.split(r'\n\s*\n',text):
                if re.match(r'^#{1,6}\s',p.strip()) and '\n' not in p.strip(): heading=[p.strip().lstrip('# ').strip()]
                else: add(p,'paragraph',heading)
    if not blocks: gaps.append('No supported text extracted')
    return {'blocks':blocks,'gaps':list(dict.fromkeys(gaps)),'metadata':metadata,'imported':imported,'losses':losses}

def ingest(store,data,name,origin,scope,metadata=None,representation=None,occurrence_key=None,extra_gaps=None):
    parsed=parse_bytes(data,name,representation,(metadata or {}).get('column_mapping')); meta=parsed['metadata']|(metadata or {})
    raw_hash=store.blob(data)
    # Exact copies share logical document only within the same declared scope.
    logical_key=uid('origin',scope,origin)
    existing=store.maybe('origin',logical_key)
    identical=next((s for s in store.all('source') if s['scope']==scope and s['content_hash']==raw_hash),None)
    doc_id=existing['document_id'] if existing else (identical['id'] if identical else uid('doc',scope,origin))
    content_revision_id=uid('content',doc_id,raw_hash)
    store.put('content_revision',content_revision_id,{'schema_version':'1.0','id':content_revision_id,'document_id':doc_id,'scope':scope,'raw_hash':raw_hash,'first_persisted_at':now()},immutable=True)
    rev_id=uid('rev',content_revision_id,PARSER_VERSION)
    store.put('origin',logical_key,{'document_id':doc_id},immutable=True)
    gaps=parsed['gaps']+(extra_gaps or [])
    offset=0; spans=[]; normalized=[]; current_segment=None
    for i,b in enumerate(parsed['blocks']):
        t=b['text']
        serial_match=re.search(r'\b(?:TB|PR)\d{4,10}\b',t)
        if serial_match and not re.search(r'quoted|forward|repeat',t,re.I):current_segment='report:'+serial_match.group()
        if not b.get('segment') or b.get('segment')=='body':b['segment']=current_segment or b.get('segment')
        spans.append(EvidenceSpan(id=uid('span',rev_id,i,t),revision_id=rev_id,start=offset,end=offset+len(t),**b)); normalized.append(t); offset+=len(t)+2
    text='\n\n'.join(normalized)
    tokens=set(re.findall(r'\w+',text.lower()));near=[]
    for other in store.all('source')[-200:]:
        if other['scope']!=scope or other['id']==doc_id or other['content_hash']==raw_hash:continue
        other_tokens=set(re.findall(r'\w+',other['normalized'].lower()));union=tokens|other_tokens
        overlap=len(tokens&other_tokens)/len(union) if union else 0
        if overlap>=0.65:near.append({'document_id':other['id'],'revision_id':other['revision_id'],'method':'token-set Jaccard candidate, not automatic merge/corroboration','overlap':round(overlap,3)})
    meta['near_duplicate_candidates']=near
    serials=[]
    for span in spans:
        for serial in re.findall(r'\b(?:TB|PR)\d{4,10}\b',span.text): serials.append({'value':serial,'publisher':meta.get('publisher'),'evidence':[span.id],'segment':span.segment})
    if not meta.get('incident_time'):
        incident=re.search(r'(?:intrusion|incident) began in (mid-)?(February) (20\d{2})',text,re.I)
        if incident:meta['incident_time']=incident.group(0).split('began in ',1)[-1];meta['incident_precision']='approximate month'
    segments={}
    for span in spans:
        if span.segment and span.segment.startswith('report:'):segments.setdefault(span.segment,[]).append(span.id)
    meta['report_segments']=[{'local_report_id':uid('report',scope,meta.get('publisher'),key),'serial':key.removeprefix('report:'),'evidence':refs,'source_revision':rev_id,'corroboration':'one containing source; repeated/forwarded text is not independent corroboration'} for key,refs in segments.items()]
    source=SourceDocument(id=doc_id,revision_id=rev_id,content_revision_id=content_revision_id,title=meta.get('title') or Path(name).stem,origin=origin,final_url=meta.get('final_url'),redirects=meta.get('redirects',[]),publisher=meta.get('publisher'),authors=meta.get('authors') or ([meta['author']] if meta.get('author') else []),retrieved_at=now(),published_at=meta.get('published_at'),publication_precision=meta.get('publication_precision',('second' if 'T' in meta['published_at'] else 'day') if meta.get('published_at') else 'unknown'),incident_time=meta.get('incident_time'),incident_precision=meta.get('incident_precision','unknown'),serials=serials,content_hash=raw_hash,representation=representation or Path(name).suffix.lstrip('.'),hash_basis=meta.get('hash_basis','selected input bytes'),completeness='partial' if gaps else 'complete-for-supported-content',gaps=gaps,scope=scope,normalized=text,spans=spans,imported_objects=parsed['imported'],conversion_losses=parsed['losses'],metadata=meta)
    if not spans: source.completeness='failed'
    store.put('source',rev_id,source.model_dump(),immutable=True)
    source=SourceDocument.model_validate(store.get('source',rev_id))
    store.blob(text.encode())
    # A reimport of the same origin/content is idempotent; each distinct transport retains an occurrence.
    oid=uid('occ',scope,occurrence_key or origin,raw_hash)
    store.put('occurrence',oid,{'schema_version':'1.0','id':oid,'content_revision_id':content_revision_id,'source_revision':rev_id,'document_id':doc_id,'origin':origin,'retrieved_at':now(),'content_hash':raw_hash,'metadata':meta},immutable=True)
    if spans: store.clock('source_ingestion',doc_id)
    if source.published_at and not store.maybe('publication_recorded',rev_id):
        store.event('source_published',doc_id,{'event_time':source.published_at,'precision':source.publication_precision,'source_revision':rev_id});store.put('publication_recorded',rev_id,{'at':now()},immutable=True)
    store.event('source_ingestion',doc_id,{'revision':rev_id,'occurrence':oid,'completeness':source.completeness})
    return source
