import React,{useEffect,useState} from 'react';
import {workspaceLabel,workspaceHash} from './navigation';
import './brotli.css';

export const BROTLI_CUSTOMER='fictional-harborlight-brotli';
type Target={kind:'assessment'|'cve'|'finding'|'action';id:string};
type Demo={id:string;customer_id:string;environment_id:string;assessment_id:string;cve:string;label:string;
  sources:{id:string;url:string;published_at?:string;excerpt_sha256?:string;retrieval_status?:string}[];
  relations:{asset_to_exposure:Record<string,string>;asset_to_decision:Record<string,string>;
    asset_to_vulnerability_action:Record<string,string>;rule_to_finding:Record<string,string>;
    pipeline_snapshot_ids:string[];relationship_limits:string[]};
  stops:{workspace:string;task:string}[];checks:Record<string,unknown>};
const files=['dossier.md','sources.json','inventory.json','artifact-evidence.json','events.json','findings.sarif.json','initial-pipeline.yml','initial-run.json','revised-pipeline.yml','revised-run.json'];
const questions=['What do we know?','Where does it matter?','Who owns the change?','Why is the claimed fix insufficient?','What evidence would change our decision?','What can leadership accurately report?'];

export default function BrotliDemo({customer,onLoaded,onNavigate}: {customer:string;onLoaded:(demo:Demo)=>Promise<void>;
  onNavigate:(workspace:string,target?:Target)=>void}){
  const [demo,setDemo]=useState<Demo|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  useEffect(()=>{let active=true;if(customer===BROTLI_CUSTOMER)fetch('/api/demos/brotli').then(async r=>{
    const data=await r.json();if(!r.ok)throw Error(data.detail);if(active)setDemo(data);
  }).catch(e=>{if(active)setError(String(e))});return()=>{active=false}},[customer]);
  async function load(){setBusy(true);setError('');try{const r=await fetch('/api/demos/brotli',{method:'POST'});
    const data=await r.json();if(!r.ok)throw Error(data.detail);await onLoaded(data);setDemo(data)}catch(e){setError(String(e))}finally{setBusy(false)}}
  const scope=demo?{customer:demo.customer_id,environment:demo.environment_id}:{};
  return <section className="panel padded brotli-demo" aria-label="Brotli exposure working case">
    <div className="brotli-intro"><div><div className="eyebrow">EVIDENCE-LED CASE · ENTIRELY FICTIONAL CUSTOMER</div>
      <h2>Brotli exposure response</h2><p>Follow one CVE through source review, six contrasting assets, engineering commitments, a failed bundled-runtime claim and qualified evidence.</p></div>
      {customer!==BROTLI_CUSTOMER&&<button className="primary" disabled={busy} onClick={load}>{busy?'Loading case…':'Load Brotli working case'}</button>}</div>
    <p className="fine">Load preview: creates <b>Harborlight Capital — fictional Brotli demo</b> in <b>Financial-services application estate — synthetic</b>. No existing customer is selected or changed until you load it. All assets, tests and run reports are authored replay.</p>
    {error&&<p role="alert">{error} <button disabled={busy} onClick={load}>Retry</button></p>}
    {customer===BROTLI_CUSTOMER&&!demo&&!error&&<p role="status">Loading case guide…</p>}
    {demo&&customer===BROTLI_CUSTOMER&&<details className="brotli-guide" open><summary>Case guide · {demo.stops.length} existing workspaces</summary>
      <div className="brotli-questions">{questions.map((q,i)=><span key={q}><b>{i+1}.</b> {q}</span>)}</div>
      <div className="brotli-stops">{demo.stops.map((stop,i)=><article key={stop.workspace}><span className="brotli-number">{String(i+1).padStart(2,'0')}</span><div>
        <button className="text-link" onClick={()=>onNavigate(stop.workspace,stop.workspace==='Case overview'?{kind:'assessment',id:demo.assessment_id}:stop.workspace==='Vulnerability Intelligence'?{kind:'cve',id:demo.cve}:undefined)}>Open {workspaceLabel(stop.workspace)}</button><p>{stop.task}</p></div></article>)}</div>
      <h3>Inspect the linked records</h3><p className="fine">These IDs are the stored records. Shared asset names alone do not establish a native relationship between CVE, SARIF and pipeline records.</p>
      <div className="brotli-records">{Object.entries(demo.relations.asset_to_exposure).map(([asset,id])=><article key={asset}><strong>{asset}</strong>
        <small>Exposure {id}</small><button className="text-link" onClick={()=>onNavigate('Vulnerability Intelligence',{kind:'cve',id:demo.cve})}>CVE decision {demo.relations.asset_to_decision[asset]?.slice(0,25)}…</button>
        {demo.relations.asset_to_vulnerability_action[asset]&&<a href={workspaceHash('Improvement Actions',{...scope,record:demo.relations.asset_to_vulnerability_action[asset]})}>Open owner action</a>}</article>)}</div>
      <p className="fine">Advisor package: the host update attestation cannot replace the self-contained 8.0.32 bundle. Its latest authored retest fails. The separate client API pass is a synthetic candidate comparison, never an operational fix.</p>
      <div className="brotli-links"><div><h3>Application and pipeline evidence</h3><ul>{Object.entries(demo.relations.rule_to_finding).map(([rule,id])=><li key={id}><button className="text-link" onClick={()=>onNavigate('Application Findings',{kind:'finding',id})}>{rule}</button> · stored finding {id}</li>)}</ul><p>Pipeline snapshots: {demo.relations.pipeline_snapshot_ids.join(' · ')}</p><button className="text-link" onClick={()=>onNavigate('Pipeline Assurance')}>Compare skipped and revised check evidence</button></div>
      <div><h3>Downloads</h3><ul><li><a href="/api/demos/brotli/summary.md" download>Human-readable scenario summary</a></li><li><a href="/api/demos/brotli/manifest.json" download>Versioned ID and relationship manifest</a></li>{files.map(name=><li key={name}><a href={'/api/demos/brotli/files/'+name} download>{name}</a></li>)}</ul></div></div>
      <details><summary>Source retrieval and checks</summary><p>Source excerpts are web-renderer text only, each hashed as UTF-8. The CISA feed returned 403 and the NVD page returned no readable text.</p><ul>{demo.sources.map(source=><li key={source.id}><a href={source.url} target="_blank" rel="noreferrer">{source.id} · publisher page</a> {source.published_at||'date unavailable'} · {source.excerpt_sha256||source.retrieval_status}</li>)}</ul><pre>{JSON.stringify(demo.checks,null,2)}</pre></details>
      <details><summary>Relationship limits and evidence qualification</summary><ul>{demo.relations.relationship_limits.map(x=><li key={x}>{x}</li>)}</ul><p>Policy proposals use the existing vulnerability-response rule. Source severity, reported exploitation and asset consequence stay separate. No direct KEV/EPSS enrichment, scanner, SIEM, patch deployment or production verification is asserted.</p></details>
    </details>}
  </section>;
}
