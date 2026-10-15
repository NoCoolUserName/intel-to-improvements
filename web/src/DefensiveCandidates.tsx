import React, {useEffect, useState} from 'react';
import './defenses.css';
type Obj = Record<string,any>;

export function useDefenses(assessment:Obj|undefined, customer:string, environment:string, revision:number) {
  const key=assessment?.id+':'+customer+':'+environment;
  const [result,setResult]=useState<{key:string,data:Obj}>();
  useEffect(()=>{
    if(!assessment || assessment.context.customer_id!==customer || assessment.context.environment_id!==environment)return;
    const controller=new AbortController();let active=true;
    setResult(undefined);
    fetch(`/api/assessments/${encodeURIComponent(assessment.id)}/defenses?customer_id=${encodeURIComponent(customer)}&environment_id=${encodeURIComponent(environment)}`,{signal:controller.signal})
      .then(async response=>{const data=await response.json();if(!response.ok)throw Error(data.detail||'Could not load catalog');return data;})
      .then(data=>{if(active)setResult({key,data});})
      .catch(e=>{if(active)setResult({key,data:{state:'catalog_unavailable',message:String(e)}});});
    return()=>{active=false;controller.abort();};
  },[key,revision]);
  return result?.key===key?result.data:undefined;
}

export default function DefensiveCandidates({data,behavior,assessment,customer,environment,onCreate,onView,retry}:Obj) {
  const [expanded,setExpanded]=useState(false);
  if(!assessment || assessment.context.customer_id!==customer || assessment.context.environment_id!==environment)return null;
  const row=data?.behaviors?.[behavior.id];
  const candidates=row?.candidates||[];
  return <section className="defenses" aria-label="Possible defensive countermeasures">
    <h3>Possible defensive countermeasures</h3>
    <p className="fine">Catalog suggestions need analyst review. They do not establish deployment, detection or prevention.</p>
    {!data?<p role="status">Loading local D3FEND catalog…</p>:data.state==='catalog_unavailable'?<div role="status"><p>{data.message}</p><button onClick={retry}>Retry catalog</button><p>Human-led plans and manual improvements remain available.</p></div>:row&&<>
      <p className="fine"><b>Behavior applicability:</b> {row.applicability.applicability||'unknown'} · {row.applicability.reason||row.applicability.telemetry_readiness||'Review environment prerequisites'}<br/>Known gaps: {row.applicability.missing_prerequisites?.join(', ')||'None recorded; availability is not verified'}.<br/><b>Defense suitability:</b> {row.suitability}</p>
      <p className="fine">ATT&amp;CK {row.attack_id||'unmapped'} · mapping basis: {row.mapping_basis||'none'} · {row.confidence_rationale}{row.qualifier&&` · ${row.qualifier}`}</p>
      {!candidates.length?<p>{row.message}</p>:<>
        <ul className="defense-list">{(expanded?candidates:candidates.slice(0,3)).map((c:Obj)=><li key={c.id}>
          <div className="row"><strong>{c.d3fend_id} · {c.name}</strong><span className="badge amber">Candidate — review required</span></div>
          <p>{c.explanation}</p>
          <a href={c.reference} target="_blank" rel="noreferrer">Official D3FEND reference{c.reference_scope!=='technique'?' (general resources)':''}</a>
          <details><summary>Catalog provenance</summary><p className="fine">{c.catalog.relationship_semantics}</p><pre className="json">{JSON.stringify(c.catalog,null,2)}</pre></details>
          {c.improvement?<button onClick={()=>onView(c.improvement.id)}>View improvement · {c.improvement.status}</button>:<button onClick={()=>onCreate(c)}>Create improvement for {c.d3fend_id}</button>}
        </li>)}</ul>
        {candidates.length>3&&<button className="small" onClick={()=>setExpanded(!expanded)}>{expanded?'Show first 3':`Show all ${candidates.length}`}</button>}
        <p className="fine">Sorted by D3FEND ID; this is not a ranking.</p>
      </>}
    </>}
  </section>;
}

export function DefenseOrigin({origin}:Obj) {
  return origin?<details className="defense-origin"><summary>D3FEND origin · {origin.d3fend_id} {origin.name}</summary><p>{origin.explanation}</p><p className="fine">Frozen when selected. Source evidence: {origin.evidence.join(', ')}. Catalog: {origin.catalog.catalog_sha256}.</p><pre className="json">{JSON.stringify(origin,null,2)}</pre></details>:null;
}
