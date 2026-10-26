"""Source-linked CVE decisions. No scanning, version matching, or exploit execution."""
import csv
import io
import re
from datetime import datetime, timezone, timedelta
from . import profiles, vulnerability_enrichment as enrichment
from .store import uid, now, canonical, digest
from .vulnerability_models import CVE_PATTERN, RESPONSES, ExposureObservation, VulnerabilityAssertion, VulnerabilityReview, cve_id

POLICY = 'vulnerability-response-1'
CVE_RE = re.compile(r'(?<![A-Za-z0-9_-])'+CVE_PATTERN+r'(?![A-Za-z0-9_-])', re.I)
EXPEDITE, PRIORITIZE, INVESTIGATE, MONITOR, NOT_APPLICABLE = RESPONSES

def scoped(store, kind, id, customer, environment):
    row=store.get(kind,id)
    if row['context']['customer_id']!=customer or row['context']['environment_id']!=environment:raise KeyError('Not found in selected customer/environment')
    return row

def in_scope(row, ctx):
    return all(row['context'][k]==ctx[k] for k in ('customer_id','environment_id'))

def same_version(a,b):
    return all(a[k]==b[k] for k in ('customer_id','customer_version','environment_id','environment_version'))

def stamp(store, kind, row):
    prior=store.maybe(kind,row['id'])
    if prior:return prior
    store.put(kind,row['id'],row,immutable=True)
    store.event(kind,row['context']['customer_id']+':'+row['context']['environment_id'],{'id':row['id'],'cve':row.get('cve')})
    return row

def sync_sources(service, ctx):
    """Literal extraction runs even if optional model/behavior extraction failed."""
    store=service.store;references={}
    for a in service.assessments(ctx['customer_id']):
        if in_scope(a,ctx):references[a['source']['revision_id']]=a['context']
    for j in service.jobs(ctx['customer_id']):
        if in_scope(j['data'],ctx) and j['data'].get('source_revision'):references.setdefault(j['data']['source_revision'],j['data']['context'])
    for revision, frozen in references.items():
        source=store.get('source',revision)
        if source['scope'] not in ('shared',ctx['customer_id']):continue
        mentions={}
        for span in source['spans']:
            for match in CVE_RE.finditer(span['text']):
                mentions.setdefault(match[0].upper(),[]).append({'span_id':span['id'],'literal':match[0],
                  'start':span['start']+match.start(),'end':span['start']+match.end(),'offset_space':'normalized Unicode text'})
        for cve, occurrences in mentions.items():
            id=uid('vmention',ctx['customer_id'],ctx['environment_id'],revision,cve)
            stamp(store,'vulnerability_mention',{'id':id,'cve':cve,'context':frozen,'source':source,'occurrences':occurrences,'recorded_at':now()})
            clock_id=uid('vreceipt',ctx['customer_id'],ctx['environment_id'],cve)
            receipt=store.maybe('customer_receipt',uid('receipt',ctx['customer_id'],source['id']))
            store.put('vulnerability_receipt',clock_id,{'at':receipt['at'] if receipt else now()},immutable=True)

def mentions(store,ctx,cve=None):
    return [r for r in store.all('vulnerability_mention') if in_scope(r,ctx) and (not cve or r['cve']==cve)]

def assert_source(store,ctx,value):
    a=VulnerabilityAssertion.model_validate(value)
    found=next((m for m in mentions(store,ctx,a.cve) if m['source']['revision_id']==a.source_revision),None)
    if not found:raise ValueError('CVE/source revision is not associated with this customer/environment')
    spans={s['id']:s for s in found['source']['spans']}
    references=a.evidence+a.actor_evidence+a.event_evidence
    if any(ref not in spans for ref in references):raise ValueError('Dangling source evidence reference')
    if not any(a.cve in [m[0].upper() for m in CVE_RE.finditer(spans[ref]['text'])] for ref in a.evidence):raise ValueError('Cited evidence must contain this literal CVE')
    if a.actor and not any(a.actor.lower() in spans[ref]['text'].lower() for ref in a.actor_evidence):raise ValueError('Named actor must appear in its cited evidence; semantic relationship still requires analyst review')
    if any(not any(alias.casefold() in spans[ref]['text'].casefold() for ref in a.actor_evidence) for alias in a.aliases):raise ValueError('Each source-scoped alias requires literal supporting evidence')
    if a.event_time and not any(a.event_time.casefold() in spans[ref]['text'].casefold() for ref in a.event_evidence):raise ValueError('Use the reported event wording present in the selected evidence; publication time is separate')
    if a.supersedes:
        previous=scoped(store,'vulnerability_assertion',a.supersedes,ctx['customer_id'],ctx['environment_id'])
        if previous['cve']!=a.cve:raise ValueError('Cannot supersede another CVE assertion')
    row=a.model_dump()|{'context':ctx,'recorded_at':now()}
    row['id']=uid('vassertion',ctx,a.model_dump())
    return stamp(store,'vulnerability_assertion',row)

def observe(store,ctx,value):
    observation=ExposureObservation.model_validate(value)
    if datetime.fromisoformat(observation.observed_at.replace('Z','+00:00'))>datetime.now(timezone.utc)+timedelta(minutes=5):raise ValueError('Observation cannot be in the future')
    key=uid('exposure',ctx['customer_id'],ctx['environment_id'],observation.asset_id,observation.cve)
    with store.lock(key):
        old=[r for r in store.all('vulnerability_exposure') if in_scope(r,ctx) and r['asset_id']==observation.asset_id and r['cve']==observation.cve]
        # A changed scanner finding is another observation of the same asset/CVE.
        # Preserve identities created by earlier local development snapshots.
        if old:key=old[-1]['logical_id']
        data=observation.model_dump()
        if old:
            for field in ('commitment_response','commitment_deadline','commitment_reason'):
                if old[-1].get(field) and not data.get(field):data[field]=old[-1][field]
        id=uid('exposure_revision',key,ctx,data)
        prior=store.maybe('vulnerability_exposure',id)
        if prior:return prior
        row=data|{'id':id,'logical_id':key,'context':ctx,'recorded_at':now(),'previous_id':old[-1]['id'] if old else None}
        stamp(store,'vulnerability_exposure',row)
        store.clock('vulnerability_receipt',uid('vreceipt',ctx['customer_id'],ctx['environment_id'],observation.cve))
        if observation.applicability=='confirmed affected':
            store.clock('confirmed_exposure',key+':'+('synthetic' if observation.evidence_kind=='synthetic fixture' else 'operational'))
        return row

def current_exposures(store,ctx,cve):
    found={}
    for r in store.all('vulnerability_exposure'):
        if in_scope(r,ctx) and r['cve']==cve:found[r['asset_id']]=r
    return [r|{'assessment_stale':not same_version(r['context'],ctx) or datetime.now(timezone.utc)-datetime.fromisoformat(r['observed_at'].replace('Z','+00:00'))>timedelta(days=30)} for r in found.values()]

def preview_csv(store,ctx,text):
    if len(text.encode())>1024*1024:raise ValueError('Exposure CSV limit is 1 MiB')
    reader=csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
    allowed=set(ExposureObservation.model_fields)-{'schema_version'}
    if not reader.fieldnames or len(set(reader.fieldnames))!=len(reader.fieldnames):raise ValueError('Missing or duplicate CSV headers')
    extra=set(reader.fieldnames)-allowed
    if extra:raise ValueError('Unsupported CSV columns: '+', '.join(sorted(extra)))
    rows=[];errors=[];seen=set()
    for index,raw in enumerate(reader,start=2):
        if index>201:raise ValueError('Exposure CSV limit is 200 rows')
        try:
            if None in raw:raise ValueError('More values than CSV headers')
            parsed=ExposureObservation.model_validate({k:v.strip() for k,v in raw.items() if v is not None and v.strip()}).model_dump()
            key=(parsed['asset_id'],parsed['cve'])
            if key in seen:raise ValueError('Duplicate asset/CVE in this file; retain one explicit observation per import')
            seen.add(key)
            identical=any(same_version(r['context'],ctx) and all(r.get(k)==v for k,v in parsed.items()) for r in current_exposures(store,ctx,parsed['cve']))
            rows.append({'line':index,'observation':parsed,'duplicate':identical})
        except ValueError as exc:errors.append({'line':index,'error':str(exc)})
    row={'id':uid('vpreview',ctx,digest(text)),'context':ctx,'rows':rows,'errors':errors,'sha256':store.blob(text.encode()),'recorded_at':now()}
    return stamp(store,'vulnerability_csv_preview',row)

def import_csv(store,preview_id,customer,environment):
    p=scoped(store,'vulnerability_csv_preview',preview_id,customer,environment)
    if p['errors']:raise ValueError('Correct CSV errors and preview again; no partial import was applied')
    rows=[observe(store,p['context'],r['observation']) for r in p['rows']]
    return {'imported':len(rows),'duplicates':sum(r['duplicate'] for r in p['rows']),'records':rows,'context':p['context']}

def active_assertions(store,ctx,cve):
    rows=[r for r in store.all('vulnerability_assertion') if in_scope(r,ctx) and r['cve']==cve]
    superseded={r['supersedes'] for r in rows if r.get('supersedes') and r['review_status']=='reviewed'}
    return [r for r in rows if r['id'] not in superseded]

def verification(store,ctx,asset,as_of=None):
    if not asset:return {'status':'not tested','tests':[],'verified_at':None,'method':None}
    tests=[t for t in store.all('test') if t.get('vulnerability_asset_id')==asset['logical_id'] and in_scope(t,ctx)]
    eligible=[]
    for t in tests:
        dependencies=t.get('dependencies',{})
        action=store.maybe('improvement',t.get('improvement_id',''))
        action_current=action and dependencies.get('implementation_hash')==implementation_hash(action)
        fresh=action_current and same_version(t['context'],ctx) and dependencies.get('exposure_revision')==asset['id'] and datetime.fromisoformat((as_of or now()).replace('Z','+00:00'))-datetime.fromisoformat(t['executed_at'].replace('Z','+00:00'))<=timedelta(days=30)
        supported=t['method'] in ('reliable rescan','version/configuration evidence','targeted human-led test') and all(e['kind']=='live system' for e in t['evidence']) and asset['evidence_kind']!='synthetic fixture'
        eligible.append(t|{'fresh':fresh,'qualifies':supported})
    current=eligible[-1] if eligible else None
    verified=current and current['fresh'] and current['qualifies'] and current['result']=='passed'
    status=('verified '+current['dimension']) if verified else ('stale' if current and not current['fresh'] else ('attestation / synthetic or lab evidence only' if current and not current['qualifies'] else current['result'] if current else 'not tested'))
    return {'status':status,'tests':eligible,'verified_at':current['executed_at'] if verified else None,'method':current['method'] if current else None,'dimension':current['dimension'] if verified else None,'test_id':current['id'] if current else None}

def policy(assertions,asset,ctx,values,verified):
    reasons=[]
    supported=[a for a in assertions if a['review_status']=='reviewed' and a['classification'] in ('observed exploitation','attempted exploitation')]
    kev=values['kev'];kev_value=kev.get('value') or (kev.get('last_available') or {}).get('value') or {}
    credible=bool(supported or kev_value.get('listed') is True)
    reasons.append(('EXPLOITATION_REPORTED','Reviewed exploitation or KEV inclusion supports a response; it does not establish current activity or compromise here.') if credible else ('EXPLOITATION_UNKNOWN','No reviewed exploitation evidence established; a CVE mention/public exploit is insufficient.'))
    applicable=asset and same_version(asset['context'],ctx) and datetime.now(timezone.utc)-datetime.fromisoformat(asset['observed_at'].replace('Z','+00:00'))<=timedelta(days=30)
    if not applicable or asset['applicability']=='needs verification':
        response=INVESTIGATE;reasons.append(('URGENT_APPLICABILITY' if credible else 'APPLICABILITY_UNKNOWN','Confirm affected version/configuration and reachable attack path; missing context is neither affected nor safe.'))
    elif asset['applicability']=='assessed not affected':
        response=NOT_APPLICABLE;reasons.append(('DOCUMENTED_EXCLUSION',asset['applicability_reason']))
    elif credible and asset['reachability']=='confirmed' and asset['criticality'] in ('critical','high'):
        response=EXPEDITE;reasons.append(('EXPLOITED_REACHABLE_IMPORTANT','Confirmed affected, reachable, consequential asset with credible exploitation. Do not delay remediation for an offensive test.'))
    else:
        response=PRIORITIZE;reasons.append(('CONFIRMED_EXPOSURE','Confirmed affected asset; follow the existing program while resolving reachability and consequence.'))
    if verified['verified_at']:
        response=MONITOR;reasons.append(('SCOPED_VERIFICATION','Current scoped operational evidence supports reduced exposure; retain prior-compromise investigation and residual-risk review.'))
    reasons.append(('SCORES_NOT_OVERRIDES','EPSS, CVSS, actor attribution and unverified control claims do not cancel exploitation/exposure evidence.'))
    return response,[{'code':k,'explanation':v} for k,v in reasons],credible

def decide(store,ctx,cve,asset):
    assertions=active_assertions(store,ctx,cve);values=enrichment.latest(store,cve);v=verification(store,ctx,asset)
    response,reasons,credible=policy(assertions,asset,ctx,values,v)
    if any(m['source'].get('completeness')!='complete-for-supported-content' for m in mentions(store,ctx,cve)):
        reasons.append({'code':'SOURCE_LIMITATIONS','explanation':'Source parsing or derivative coverage is partial. Inspect source gaps; this decision cannot establish missing report content.'})
    key=uid('vdecision_series',ctx['customer_id'],ctx['environment_id'],cve,asset['logical_id'] if asset else 'unknown')
    history=[d for d in store.all('vulnerability_decision') if d['series_id']==key]
    reviews=[r for r in store.all('vulnerability_review') if r['series_id']==key]
    commitment=(reviews[-1]['response'] if reviews else None) or (asset or {}).get('commitment_response')
    proposal=response
    if commitment and RESPONSES.index(response)>RESPONSES.index(commitment):
        response=commitment;reasons.append({'code':'COMMITMENT_RETAINED','explanation':'A lower proposal cannot silently remove the accepted response or deadline. Explicit analyst override with a reason is required.'})
    inputs={'assertions':[a['id'] for a in assertions],'sources':[m['id'] for m in mentions(store,ctx,cve)],'exposure':asset['id'] if asset else None,'exposure_stale':asset.get('assessment_stale',False) if asset else True,
      'enrichment':{k:{'id':r.get('id'),'status':r['status']} for k,r in values.items()},'verification':{k:v[k] for k in ('status','test_id') if k in v},'context':ctx,'policy':POLICY}
    id=uid('vdecision',key,inputs);prior=store.maybe('vulnerability_decision',id)
    if prior:return prior
    previous=history[-1] if history else None
    changed=[k for k in inputs if not previous or previous['inputs'].get(k)!=inputs[k]]
    receipt=store.get('vulnerability_receipt',uid('vreceipt',ctx['customer_id'],ctx['environment_id'],cve))['at']
    row={'id':id,'series_id':key,'cve':cve,'context':ctx,'asset':asset,'inputs':inputs,'enrichment':values,'assertions':assertions,
      'response':response,'unconstrained_proposal':proposal,'reason_codes':reasons,'credible_exploitation':credible,'policy_version':POLICY,
      'verification':v,'receipt_at':receipt,'created_at':now(),'previous_id':previous['id'] if previous else None,'previous_response':previous['response'] if previous else None,'changed_inputs':changed,
      'deadline':(asset or {}).get('commitment_deadline'),'commitment':commitment,'sources':[m['id'] for m in mentions(store,ctx,cve)]}
    return stamp(store,'vulnerability_decision',row)

def review(store,id,customer,environment,value):
    decision=scoped(store,'vulnerability_decision',id,customer,environment);r=VulnerabilityReview.model_validate(value)
    if r.disposition=='accept' and r.response and r.response!=decision['response']:raise ValueError('Use override to choose a different response')
    # A stale browser must not accept a superseded proposal accidentally.
    ctx=profiles.context(store,customer,environment).model_dump()
    asset=next((a for a in current_exposures(store,ctx,decision['cve']) if decision['asset'] and a['logical_id']==decision['asset']['logical_id']),None)
    if decide(store,ctx,decision['cve'],asset)['id']!=id:raise ValueError('Decision inputs changed; reload and review the current recommendation')
    latest=[d for d in store.all('vulnerability_decision') if d['series_id']==decision['series_id']][-1]
    if latest['id']!=id:raise ValueError('Decision inputs changed; reload and review the current recommendation')
    row=r.model_dump()|{'id':uid('vreview',id,r.model_dump()),'decision_id':id,'series_id':decision['series_id'],'cve':decision['cve'],'context':decision['context'],
      'response':r.response if r.disposition=='override' else decision['response'],'recorded_at':now()}
    return stamp(store,'vulnerability_review',row)

def subject(store,decision_id,customer,environment):
    d=scoped(store,'vulnerability_decision',decision_id,customer,environment)
    return {'id':d['id'],'context':d['context'],'source':{'id':'vulnerability:'+d['cve']},'extraction':{'behaviors':[]},'vulnerability':d}

def action_origin(store,assessment):
    d=assessment['vulnerability'];reviews=[r for r in store.all('vulnerability_review') if r['decision_id']==d['id']]
    if not reviews:raise ValueError('Accept or override this decision before creating an improvement')
    if not d['asset']:raise ValueError('Record an asset or explicitly scoped investigation target before creating an action')
    return {'kind':'vulnerability_decision','assessment_id':d['id'],'review_id':reviews[-1]['id'],'cve':d['cve'],'asset_id':d['asset']['asset_id'],
      'asset_logical_id':d['asset']['logical_id'],'exposure_revision':d['asset']['id'],'policy_version':d['policy_version'],'source_assertions':d['inputs']['assertions']}

def validate_test(store,assessment,test):
    d=assessment['vulnerability'];asset=d['asset']
    if not asset or test.behavior_id is not None or test.vulnerability_assessment_id!=d['id']:raise ValueError('Verification must identify its vulnerability assessment and asset; no invented behavior')
    if test.dimension not in ('remediation','mitigation'):raise ValueError('Vulnerability verification must be remediation or mitigation')
    if test.method not in ('reliable rescan','version/configuration evidence','targeted human-led test','analyst attestation'):raise ValueError('Detection fixture semantics do not verify remediation')
    if not same_version(d['context'],profiles.context(store,d['context']['customer_id'],d['context']['environment_id']).model_dump()):raise ValueError('Profile changed; reassess before recording a new test')
    current=next(r for r in current_exposures(store,d['context'],d['cve']) if r['logical_id']==asset['logical_id'])
    if current['id']!=asset['id']:raise ValueError('Exposure changed; record verification against the current revision')
    if test.method!='analyst attestation':
        if any(e.kind=='analyst attestation' or not e.sha256 or not re.fullmatch(r'[0-9a-f]{64}',e.sha256) for e in test.evidence):raise ValueError('Measured verification requires hashed evidence; unsupported claims must use analyst attestation')
        for evidence in test.evidence:
            if not evidence.reference.startswith('vulnerability-evidence:'):raise ValueError('Attach the actual evidence file before recording measured verification')
            saved=scoped(store,'vulnerability_evidence',evidence.reference.split(':',1)[1],d['context']['customer_id'],d['context']['environment_id'])
            if saved['sha256']!=evidence.sha256 or saved['kind']!=evidence.kind:raise ValueError('Evidence hash or declared provenance differs from the preserved attachment')
        if not test.measurement or test.measurement.get('asset_id')!=asset['asset_id'] or not test.measurement.get('observed_value') or not test.measurement.get('acceptance_basis'):raise ValueError('Measured verification requires exact asset, observed result, and acceptance basis')
        if test.method=='targeted human-led test' and not test.measurement.get('approval_reference'):raise ValueError('Targeted test requires its approval reference; this app never executes it')
    if test.dimension=='mitigation' and test.result=='passed' and (not test.residual_risk or not test.permanent_fix):raise ValueError('Mitigation requires residual risk and remaining permanent fix')
    if not test.improvement_id:raise ValueError('Link verification to the existing improvement action')
    action=store.get('improvement',test.improvement_id)
    if not in_scope(action,d['context']) or (action.get('origin') or {}).get('asset_logical_id')!=asset['logical_id']:raise ValueError('Improvement does not belong to this asset/CVE/customer')
    return {'exposure_revision':asset['id'],'implementation_hash':implementation_hash(action),'customer_version':d['context']['customer_version'],'environment_version':d['context']['environment_version'],'control_id':test.control_id,'control_version':test.control_version}

def implementation_hash(action):
    return digest(canonical({k:action.get(k) for k in ('proposed_change','retest','remediation')}))

def capture_evidence(store,ctx,name,raw,kind):
    from pathlib import Path
    if not name or Path(name).name!=name or '\\' in name:raise ValueError('Unsafe evidence filename')
    if not raw or len(raw)>2*1024*1024:raise ValueError('Evidence must be nonempty and at most 2 MiB')
    if kind not in ('live system','lab execution','synthetic fixture replay','analyst attestation'):raise ValueError('Declare the evidence provenance')
    sha=store.blob(raw);id=uid('vevidence',ctx,name,sha,kind)
    return stamp(store,'vulnerability_evidence',{'id':id,'context':ctx,'filename':name,'sha256':sha,'kind':kind,'recorded_at':now(),'reference':'vulnerability-evidence:'+id})

def plans(store,ctx,cve,assertions):
    packages=[p for p in store.all('package') if in_scope(p,ctx) and CVE_RE.search(p['source']['normalized']) and cve in p['source']['normalized'].upper()]
    hunts=[{'package_id':p['id'],'assessment_id':p['assessment_id'],'hunt_id':h['id'],'hypothesis':h.get('hypothesis',h.get('question','Source-linked hunt')),'context':p['context']} for p in packages for h in p['hunts'] if set(h.get('evidence',[])) & {s['id'] for s in p['source']['spans'] if cve in s['text'].upper()}]
    reported=any(a['classification'] in ('observed exploitation','attempted exploitation') and a['review_status']=='reviewed' for a in assertions)
    return {'remediation':{'change':'Confirm the affected version/configuration against the authoritative vendor advisory, then apply the supported fix or a documented temporary mitigation. Exact fixed versions are not inferred by this app.',
      'verification':'Preserve before/after asset evidence. Use a reliable rescan, version/configuration result, or an approved targeted human-led test; record scope and acceptance criteria.',
      'limits':'D3FEND is a defensive approach catalog, not a vendor patch source. Patching does not establish absence of earlier compromise.'},
      'hunt':{'justified':reported,'reason':'Reviewed historical exploitation warrants a separate prior-compromise investigation; it does not assert compromise here.' if reported else 'No reviewed exploitation established. First review source evidence; no prior-compromise claim is generated.',
      'sequence':['Establish the asset’s actual exposure interval and available log retention; source event dates are historical context, not this asset’s incident dates.',
        'Review application/authentication, endpoint process and network records over that interval. For driver paths include driver-load and security-control events. Confirm those sources were actually collected.',
        'Pivot from anomalous access to child processes, privileged changes and persistence; compare authorized maintenance and deployment controls.',
        'Preserve raw events, timestamps, host identities and queries. Escalate corroborated suspicious activity; missing telemetry is inconclusive, not a clean result.'],
      'linked_hunts':hunts,'backend':'Human analyst procedure; no query executed'}}

def workspace(service,customer,environment):
    store=service.store;ctx=profiles.context(store,customer,environment).model_dump();sync_sources(service,ctx)
    cves=sorted({m['cve'] for m in mentions(store,ctx)}|{r['cve'] for r in store.all('vulnerability_exposure') if in_scope(r,ctx)})
    items=[]
    with store.lock('vulnerability-workspace:'+customer+':'+environment):
        for cve in cves:
            assets=current_exposures(store,ctx,cve);assertions=active_assertions(store,ctx,cve)
            decisions=[decide(store,ctx,cve,a) for a in (assets or [None])]
            actions=[a for a in store.all('improvement') if in_scope(a,ctx) and (a.get('origin') or {}).get('cve')==cve]
            histories=[r for r in store.all('vulnerability_decision') if in_scope(r,ctx) and r['cve']==cve]
            reviews=[r for r in store.all('vulnerability_review') if in_scope(r,ctx) and r['cve']==cve]
            from .ledger import seconds
            first_decision=min(r['created_at'] for r in histories)
            metrics=[]
            for d in decisions:
                a=d['asset'];v=d['verification'];kind='synthetic' if a and a['evidence_kind']=='synthetic fixture' else 'operational'
                clock=store.maybe('confirmed_exposure',a['logical_id']+':'+kind) if a else None
                metrics.append({'asset_id':a['asset_id'] if a else None,'scope':kind,'confirmed_exposure_at':clock['at'] if clock else None,
                  'verified_at':v['verified_at'],'confirmed_exposure_to_verified_seconds':seconds(clock['at'],v['verified_at']) if clock and v['verified_at'] and v['verified_at']>=clock['at'] else None})
            items.append({'cve':cve,'mentions':mentions(store,ctx,cve),'assertions':assertions,'assertion_history':[r for r in store.all('vulnerability_assertion') if in_scope(r,ctx) and r['cve']==cve],
              'assets':assets,'decisions':decisions,'decision_history':histories,'reviews':reviews,'actions':actions,'action_links':[r for r in store.all('vulnerability_action_link') if in_scope(r,ctx) and r['decision_id'] in {d['id'] for d in histories}],'enrichment':enrichment.latest(store,cve),'plans':plans(store,ctx,cve,assertions),
              'metrics':{'receipt_to_first_decision_seconds':seconds(decisions[0]['receipt_at'],first_decision),'receipt_at':decisions[0]['receipt_at'],'first_decision_at':first_decision,'outcomes':metrics}})
    return {'context':ctx,'policy_version':POLICY,'responses':RESPONSES,'items':items,'freshness_policy':'Verification: exact exposure/customer/environment versions, latest result, within 30 days. Synthetic/lab/attestation outcomes never enter operational remediation metrics.'}
