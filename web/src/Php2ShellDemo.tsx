import React, {useEffect, useState} from 'react';
import './php2shell.css';
type Demo = {customer_id:string; environment_id:string; assessment_id:string; label:string;
  stops:{workspace:string;task:string}[]; sources:{title:string;url:string}[]; checks:Record<string,unknown>};
export const PHP2SHELL_CUSTOMER = 'fictional-harborlight';
const files = ['dossier.md','waf-results.json','findings.sarif.json','initial-pipeline.yml','initial-run.json','revised-pipeline.yml','revised-run.json'];
export default function Php2ShellDemo({customer,onLoaded,onNavigate}: {customer:string;onLoaded:(demo:Demo)=>Promise<void>;onNavigate:(workspace:string)=>void}) {
  const [demo,setDemo]=useState<Demo|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  useEffect(()=>{let alive=true;if(customer===PHP2SHELL_CUSTOMER)fetch('/api/demos/php2shell').then(async r=>{
    const data=await r.json();if(!r.ok)throw Error(data.detail);if(alive)setDemo(data);
  }).catch(e=>{if(alive)setError(String(e))});return()=>{alive=false}},[customer]);
  async function load(){setBusy(true);setError('');try{const r=await fetch('/api/demos/php2shell',{method:'POST'});const data=await r.json();if(!r.ok)throw Error(data.detail);await onLoaded(data);setDemo(data)}catch(e){setError(String(e))}finally{setBusy(false)}}
  return <section className="panel padded php2shell-demo" aria-label="PHP2Shell working case">
    <div className="php2shell-intro"><div><div className="eyebrow">CONNECTED WORKING CASE · FICTIONAL INVESTMENT FIRM</div>
      <h2>PHP2Shell at Harborlight Capital</h2><p>Follow the evidence from an urgent PHP advisory to investor-portal exposure, temporary controls, engineering commitments and qualified validation.</p>
    </div>{customer!==PHP2SHELL_CUSTOMER&&<button className="primary" disabled={busy} onClick={load}>{busy?'Preparing working case…':'Open PHP2Shell working case'}</button>}</div>
    <p className="fine">All firm assets, findings, approvals and results are synthetic. The dated source summaries link to their publishers. Reopening preserves edits. No probe or pipeline is executed.</p>
    {error&&<p role="alert">{error} <button disabled={busy} onClick={load}>Retry working case</button></p>}
    {customer===PHP2SHELL_CUSTOMER&&!demo&&!error&&<p role="status">Loading case guide…</p>}
    {demo&&customer===PHP2SHELL_CUSTOMER&&<details className="php2shell-guide"><summary>PHP2Shell case guide · all 12 workspaces</summary>
      <div className="php2shell-stops">{demo.stops.map((stop,i)=><article key={stop.workspace}>
        <span className="php2shell-number">{String(i+1).padStart(2,'0')}</span><div><button className="text-link" onClick={()=>onNavigate(stop.workspace)}>Open {stop.workspace}</button><p>{stop.task}</p></div>
      </article>)}</div>
      <div className="two-col"><div><h3>Primary sources and correction</h3><ul>{demo.sources.map(s=><li key={s.url}><a href={s.url} target="_blank" rel="noreferrer">{s.title}</a></li>)}</ul>
        <p>AttackIQ’s probe covers a particular request pattern. A blocked sample does not establish comprehensive protection; a missing signature is inconclusive. The October 23 Unit 42 exploitation update was retracted October 25.</p></div>
        <div><h3>Download the authored inputs</h3><ul>{files.map(name=><li key={name}><a href={'/api/demos/php2shell/files/'+name} download>{name}</a></li>)}</ul></div></div>
      <details><summary>Case checks and evidence boundaries</summary><p>These are fixture integrity and generation checks, not independent operational verification.</p><pre>{JSON.stringify(demo.checks,null,2)}</pre></details>
    </details>}
  </section>;
}
