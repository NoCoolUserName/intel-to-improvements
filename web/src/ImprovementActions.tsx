import React,{useEffect,useState} from 'react';
import ImprovementDetails from './ImprovementDetails';
type Obj=Record<string,any>;
type Props={customer:string;environment:string;actionId?:string;assessmentId?:string;onInspect:(id?:string)=>void;onManage:(row:Obj)=>void;onClearFilter:()=>void};
export default function ImprovementActions(props:Props){return <Workspace key={props.customer+':'+props.environment} {...props}/>}
function Workspace({customer,environment,actionId,assessmentId,onInspect,onManage,onClearFilter}:Props){
  const [data,setData]=useState<Obj>(),[detail,setDetail]=useState<Obj>(),[error,setError]=useState(''),[detailError,setDetailError]=useState(''),[revision,setRevision]=useState(0);
  const [owner,setOwner]=useState(''),[status,setStatus]=useState('');
  const query='?'+new URLSearchParams({customer_id:customer,environment_id:environment});
  async function request(path:string){const r=await fetch('/api/improvements'+path+query);const d=await r.json();if(!r.ok)throw Error(typeof d.detail==='string'?d.detail:'Improvement records unavailable');return d}
  useEffect(()=>{let alive=true;setError('');request('').then(d=>{if(alive)setData(d)}).catch(e=>{if(alive)setError(String(e))});return()=>{alive=false}},[revision]);
  useEffect(()=>{let alive=true;setDetail(undefined);setDetailError('');if(actionId)request('/'+encodeURIComponent(actionId)).then(d=>{if(alive)setDetail(d)}).catch(e=>{if(alive)setDetailError(String(e))});return()=>{alive=false}},[actionId,revision]);
  const rows=(data?.rows||[]).filter((row:Obj)=>(!assessmentId||row.reference?.assessment_id===assessmentId)&&(!owner||row.owner===owner)&&(!status||row.status===status));
  return <section aria-label="Existing improvement ledger">
    <div className="panel padded"><h2>Accountable corrective work</h2><p>{data?.qualification||'Existing actions within the selected customer and environment. Edit and retest through their originating workflows.'}</p>
      <p className="fine">Customer: {customer} · Environment: {environment}</p><button onClick={()=>setRevision(r=>r+1)}>Refresh actions</button>
      {assessmentId&&<p>Showing actions linked to the selected case assessment. <button onClick={onClearFilter}>Show all scoped actions</button></p>}
      {data&&<div className="row"><label>Action owner<select aria-label="Action owner" value={owner} onChange={e=>setOwner(e.target.value)}><option value="">All owners</option>{[...new Set<string>(data.rows.map((r:Obj)=>r.owner))].map(v=><option key={v}>{v}</option>)}</select></label><label>Work status<select aria-label="Work status" value={status} onChange={e=>setStatus(e.target.value)}><option value="">All statuses</option>{[...new Set<string>(data.rows.map((r:Obj)=>r.status))].map(v=><option key={v}>{v}</option>)}</select></label></div>}
    </div>
    {error&&<p role="alert">{error}</p>}{!data&&!error&&<p role="status">Loading existing improvement actions…</p>}
    {data&&!rows.length&&<div className="empty">No existing improvement actions match this scope and filter. Create an action through a case, finding or reviewed vulnerability decision.</div>}
    {rows.length>0&&<div className="panel table-wrap"><table><caption>Existing ledger actions · implementation and verification remain separate</caption><thead><tr><th>Origin / evidence</th><th>Corrective action</th><th>Owner / work status</th><th>Evidence-qualified outcome</th><th>Inspect</th></tr></thead><tbody>{rows.map((row:Obj)=><tr key={row.id}>
      <td>{row.related_title}<small>{row.origin_kind}</small></td><td>{row.proposed_change}<small>Retest: {row.retest}</small></td><td>{row.owner}<small>{row.status}</small></td><td>{row.outcome}<small>{row.qualification}</small></td><td><button onClick={()=>onInspect(row.id)} aria-label={'Inspect action '+row.id}>Inspect action</button></td>
    </tr>)}</tbody></table></div>}
    {actionId&&<aside className="panel padded" aria-label="Selected improvement action"><button onClick={()=>onInspect(undefined)}>Close action details</button>{detailError&&<p role="alert">{detailError}</p>}{!detail&&!detailError&&<p role="status">Loading action details…</p>}{detail&&<>
      <ImprovementDetails action={detail.action}/><h3>Evidence outcome</h3><p>{detail.outcome}</p><p>{detail.qualification}</p>
      {detail.reference?<button className="primary" onClick={()=>onManage(detail)}>Open originating workflow</button>:<p>The originating record is unavailable in this scope. Its saved action remains inspectable.</p>}
      <details><summary>Original action and source provenance</summary><pre>{JSON.stringify({action:detail.action,source:detail.source},null,2)}</pre></details>
      <details><summary>Existing retest evidence and exceptions</summary><pre>{JSON.stringify({tests:detail.tests,exceptions:detail.exceptions},null,2)}</pre></details>
    </>}</aside>}
  </section>;
}
