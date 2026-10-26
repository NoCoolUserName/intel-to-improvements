import React, {useEffect, useRef, useState} from 'react';
import ImprovementFields from './ImprovementFields';
type Obj = Record<string, any>;
const dispositions = ['Needs review','Applicable / remediation warranted','Needs further investigation','Not applicable','False positive (reviewed determination)','Duplicate of another finding'];
const kinds = ['analyst attestation','supplied scanner report','supplied configuration/version evidence','targeted human-led test evidence','synthetic/lab evidence'];
const json = (v: unknown) => <pre className="json">{JSON.stringify(v,null,2)}</pre>;
const text = (f: FormData, name: string) => String(f.get(name) || '');
function Field({label,name,value='',area=false,required=true,type='text'}:{label:string;name:string;value?:string;area?:boolean;required?:boolean;type?:string}) {
  return <label>{label}{area ? <textarea name={name} required={required} maxLength={4000} defaultValue={value}/> : <input name={name} type={type} required={required} maxLength={4000} defaultValue={value}/>}</label>;
}
export default function AppsecGovernance({finding,findings,imports,onInspect,initialTab,onActions}:{finding:Obj;findings:Obj[];imports:Obj[];onInspect:(id:string)=>void;initialTab?:string;onActions?:(id:string)=>void}) {
  const [data,setData]=useState<Obj>(),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),[tab,setTab]=useState(initialTab||'Triage');
  const alive=useRef(true), flight=useRef(false), file=useRef<File | undefined>(undefined);
  const scope=new URLSearchParams({customer_id:finding.context.customer_id,environment_id:finding.context.environment_id});
  const base='/api/application-findings/'+encodeURIComponent(finding.id);
  async function request(path:string,options?:RequestInit) {const r=await fetch(base+path,options);const v=await r.json();if(!r.ok)throw new Error(typeof v.detail==='string'?v.detail:'Invalid governance input; check required fields');return v;}
  async function load(){const v=await request('/governance?'+scope);if(!v.context || !Array.isArray(v.reviews))throw new Error('Governance data unavailable');if(alive.current)setData(v);}
  useEffect(()=>{alive.current=true;load().catch(e=>{if(alive.current)setError(String(e));});return()=>{alive.current=false;};},[]);
  async function act(fn:()=>Promise<unknown>){if(flight.current)return;flight.current=true;setBusy(true);setError('');setNotice('');try{await fn();if(alive.current){await load();setNotice('Recorded with immutable history.');}}catch(e){if(alive.current)setError(String(e));}finally{flight.current=false;if(alive.current)setBusy(false);}}
  async function post(path:string,body:Obj){return request(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({context:data!.context,...body})});}
  const action=data?.action, plan=action?.remediation || {}, review=data?.reviews.at(-1);
  const editable=data?.latest_finding_id===finding.id;
  const applicable=data?.disposition===dispositions[1] && editable;
  function submit(e:React.FormEvent<HTMLFormElement>,fn:(form:FormData)=>Promise<unknown>){e.preventDefault();const form=new FormData(e.currentTarget);act(()=>fn(form));}
  return <section className="appsec-governance" aria-label="AppSec governance">
    <h3>Human-governed remediation</h3><p>Reported ≠ Reviewed ≠ Assigned ≠ Implemented ≠ Verified. Security records review; engineering owns the change; a named reviewer evaluates supplied evidence.</p>
    <p className="fine">Local proof-of-concept governance workbench. Names and accepting authority are operator-declared, not authenticated. No independent operational verification is established.</p>
    {error&&<div role="alert" className="banner error">{error}<button disabled={busy} onClick={()=>act(load)}>Reload governance</button></div>}{notice&&<p role="status">{notice}</p>}
    {!data&&!error&&<p>Loading governance…</p>}
    {data&&<><p><strong>Triage:</strong> <span>{data.disposition}</span> · <strong>Work:</strong> <span>{data.lifecycle}</span></p><p><strong>Evidence outcome:</strong> <span>{data.verification.status}</span></p><p><strong>Risk acceptance:</strong> {data.exceptions.some((r:Obj)=>r.status.startsWith('active'))?'Active operator-recorded acceptance; finding remains':'No current approved exception'}</p>
      {!editable&&<p role="status">A later occurrence requires review. <button onClick={()=>onInspect(data.latest_finding_id)}>Inspect latest occurrence</button></p>}
      {action&&onActions&&<button onClick={()=>onActions(action.id)}>View in Improvement Actions</button>}
      <div className="toolbar" aria-label="Governance workflow">{['Triage','Remediation','Evidence & exceptions'].map(t=><button key={t} aria-pressed={tab===t} onClick={()=>setTab(t)}>{t}</button>)}<button disabled={busy} onClick={()=>act(load)}>Refresh governance</button></div>
      {tab==='Triage'&&<><form onSubmit={e=>submit(e,f=>post('/review',{review:{reviewer:text(f,'reviewer'),disposition:text(f,'disposition'),reason:text(f,'reason'),duplicate_of:text(f,'duplicate')||null,evidence_ids:[finding.source_id]}}))}>
        <fieldset disabled={busy||!editable}><legend>Record security triage</legend><Field label="Triage reviewer" name="reviewer"/><label>Disposition<select aria-label="Disposition" name="disposition" defaultValue="Needs review">{dispositions.map(v=><option key={v}>{v}</option>)}</select></label><Field label="Triage reason" name="reason" area/>
          <label>Duplicate target (only for duplicate disposition)<select aria-label="Duplicate target (only for duplicate disposition)" name="duplicate"><option value="">None</option>{findings.filter(r=>r.logical_id!==finding.logical_id).map(r=><option key={r.id} value={r.id}>{r.rule_id || 'Unknown rule'} · {r.id}</option>)}</select></label>
          <p className="fine">This decision cites the inspected immutable source {finding.source_id}. A false-positive determination is a human judgment.</p><button className="primary">Record reviewed decision</button>
        </fieldset></form><details><summary>Triage history and dependency freshness ({data.reviews.length})</summary>{data.reviews.map((r:Obj)=><article key={r.id}><h4>{r.disposition} · {r.stale?'Stale':'Current dependency match'}</h4><p>{r.reviewer}: {r.reason}</p>{json(r)}</article>)}</details></>}
      {tab==='Remediation'&&<><p>Priority is operator-selected. A fix claim or work status never proves remediation. Reopen by selecting Open and recording a reason.</p>
        {!applicable&&<p>Record current Applicable / remediation warranted triage before creating or updating the commitment.</p>}
        <form key={action?.updated_at || 'new'} onSubmit={e=>submit(e,f=>post('/action',{review_id:review?.id,actor:text(f,'actor'),reason:text(f,'change_reason'),expected_updated_at:action?.updated_at||null,action:{id:action?.id||'',owner:text(f,'owner'),priority:text(f,'priority'),status:action?text(f,'status'):'open',rationale:text(f,'rationale'),proposed_change:text(f,'change'),retest:text(f,'retest'),remediation:{security_reviewer:text(f,'security_reviewer'),expected_result:text(f,'expected_result'),target_date:text(f,'target_date')||null,implementation_ref:text(f,'implementation_ref'),implementation_claim:text(f,'implementation_claim')}}}))}>
          <fieldset disabled={busy||!applicable}><legend>{action?'Update existing improvement action':'Create improvement action'}</legend>
            <ImprovementFields defaults={action || {priority:'medium'}} lockedNew={!action} statuses={[['open','Open / reopen'],['in progress','In progress'],['retest requested','Fix reported / verification pending'],['closed','Close with reviewed supporting evidence']]}/>
            <Field label="Security reviewer" name="security_reviewer" value={plan.security_reviewer||review?.reviewer||''}/><Field label="Expected remediation result" name="expected_result" value={plan.expected_result||''} area/>
            <Field label="Target completion date (optional)" name="target_date" value={plan.target_date||''} required={false} type="date"/>
            <Field label="Implementation reference (commit/build/change)" name="implementation_ref" value={plan.implementation_ref||''} required={false}/><Field label="Implementation / fix claim" name="implementation_claim" value={plan.implementation_claim||''} required={false} area/>
            <Field label="Recorded by" name="actor"/><Field label="Change or reopening reason" name="change_reason" area/><button className="primary">{action?'Save ledger action':'Create ledger action'}</button>
          </fieldset></form>{action&&<details><summary>Immutable action origin and current ledger record</summary>{json(action)}</details>}
      </>}
      {tab==='Evidence & exceptions'&&<>
        <form onSubmit={e=>submit(e,async f=>{if(!file.current || file.current.size>2*1024*1024)throw new Error('Choose evidence, maximum 2 MiB');f.set('file',file.current);f.set('context',JSON.stringify(data.context));return request('/attachments',{method:'POST',body:f});})}>
          <fieldset disabled={busy||!editable}><legend>Preserve supporting evidence</legend><label>Evidence file<input type="file" required onChange={e=>{file.current=e.target.files?.[0];}}/></label><label>Evidence kind<select aria-label="Evidence kind" name="kind">{kinds.map(k=><option key={k}>{k}</option>)}</select></label><Field label="Evidence description" name="description" area/><button>Upload immutable evidence</button></fieldset>
        </form>
        <details><summary>Evidence attachments ({data.evidence.length})</summary>{data.evidence.map((e:Obj)=><article key={e.id}><p>{e.kind} · {e.description}</p><p>{e.sha256}</p>{e.finding_id===finding.id&&<a href={base+'/attachments/'+encodeURIComponent(e.id)+'?'+scope} download>Download evidence {e.filename}</a>}</article>)}</details>
        <form onSubmit={e=>submit(e,f=>post('/retest',{retest:{action_id:action?.id,review_id:review?.id,implementation_ref:text(f,'tested_implementation'),finding_context_hash:data.dependencies.finding_context_hash,reviewer:text(f,'retest_reviewer'),judgment:text(f,'judgment'),procedure:text(f,'procedure'),expected:text(f,'expected'),actual:text(f,'actual'),executed_at:text(f,'executed_at'),result:text(f,'result'),method:text(f,'method'),evidence_ids:f.getAll('evidence_ids'),approval_reference:text(f,'approval_reference'),sarif_batch_id:text(f,'batch')||null,basis:text(f,'basis')}}))}>
          <fieldset disabled={busy||!applicable||!action}><legend>Record reviewed retest</legend><p>Evidence must refer to this finding and the declared implementation. SARIF absence stays inconclusive. Synthetic/lab and supplied evidence cannot establish independent operational assurance.</p>
            <Field label="Tested implementation reference" name="tested_implementation" value={plan.implementation_ref||''}/><label>Retest method<select aria-label="Retest method" name="method">{['analyst attestation','version/configuration evidence','targeted human-led test','reliable rescan'].map(m=><option key={m}>{m}</option>)}</select></label>
            <label>Conclusion basis<select aria-label="Conclusion basis" name="basis"><option>direct evidence</option><option>SARIF absence</option></select></label><label>Supplied SARIF batch (required for scanner retest)<select aria-label="Supplied SARIF batch (required for scanner retest)" name="batch"><option value="">None</option>{imports.map(b=><option key={b.id} value={b.id}>{b.id}</option>)}</select></label>
            <Field label="Retest procedure" name="procedure" area/><Field label="Expected retest result" name="expected" area/><Field label="Actual observed result" name="actual" area/><Field label="Execution time (with timezone)" name="executed_at"/>
            <label>Retest outcome<select aria-label="Retest outcome" name="result"><option>inconclusive</option><option>failed</option><option>passed</option></select></label><label>Supporting attachments (select one or more)<select aria-label="Supporting attachments (select one or more)" name="evidence_ids" multiple required>{data.evidence.filter((e:Obj)=>e.finding_id===finding.id).map((e:Obj)=><option key={e.id} value={e.id}>{e.kind} · {e.description}</option>)}</select></label>
            <Field label="Retest reviewer" name="retest_reviewer"/><Field label="Reviewer judgment and evidence rationale" name="judgment" area/><Field label="Targeted-test approval reference" name="approval_reference" required={false}/><button>Record evidence-reviewed retest</button>
          </fieldset></form>
        <details><summary>Retest history ({data.verification.history.length})</summary>{data.verification.history.map((t:Obj)=><article key={t.id}><h4>{t.result} · {t.stale?'Stale':'Current dependencies'} · {t.assurance}</h4><p>{t.stale_reasons.join('; ')}</p>{json(t)}</article>)}</details>
        <form onSubmit={e=>submit(e,f=>post('/exceptions',{request:{requester:text(f,'requester'),justification:text(f,'justification'),residual_risk:text(f,'residual_risk'),compensating_controls:text(f,'controls'),review_by:text(f,'review_by'),evidence_ids:[finding.source_id]}}))}>
          <fieldset disabled={busy||!editable}><legend>Request bounded risk exception</legend><Field label="Exception requester" name="requester"/><Field label="Business justification" name="justification" area/><Field label="Residual risk" name="residual_risk" area/><Field label="Claimed compensating controls" name="controls" area required={false}/><Field label="Expiration / mandatory review time (with timezone)" name="review_by"/><p>A request is unapproved. Acceptance does not fix the finding or change scanner severity.</p><button>Record exception request</button></fieldset>
        </form>
        {data.exceptions.map((r:Obj)=><article key={r.id} className="vi-decision"><h4>Exception: {r.status}</h4><p>{r.requester} · {r.justification}</p><p>Residual risk: {r.residual_risk}</p><p>Review by: {r.review_by}</p>
          <form onSubmit={e=>submit(e,f=>post('/exception-decisions',{request_id:r.id,decision:{authority:text(f,'authority'),decision:text(f,'decision'),reason:text(f,'decision_reason')}}))}>
            <fieldset disabled={busy||!editable}><legend>Operator-recorded acceptance decision</legend><Field label={'Accepting authority for '+r.id} name="authority"/><label>Exception decision<select aria-label="Exception decision" name="decision"><option>rejected</option><option>approved</option><option>revoked</option></select></label><Field label={'Decision reason for '+r.id} name="decision_reason" area/><button>Record exception decision</button></fieldset>
          </form><details><summary>Request and decision history</summary>{json(r)}</details></article>)}
      </>}
      <details><summary>Append-only governance and improvement history ({data.history.length})</summary>{json(data.history)}</details>
    </>}
  </section>;
}
