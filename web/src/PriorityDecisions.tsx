import React,{useState} from 'react';
import './vulnerability.css';
type Row=Record<string,any>;
export default function PriorityDecisions({rows,onOpen,portfolio=false}:{rows:Row[];onOpen:(row:Row)=>void;portfolio?:boolean}){
 const [selected,setSelected]=useState<string|null>(null);
 const cards=[
  {label:'Asset / CVE decisions',matches:(_r:Row)=>true},
  {label:'Expedite response',matches:(r:Row)=>r.response.startsWith('Expedite')},
  {label:'Priority response awaiting decision',matches:(r:Row)=>!r.reviewed},
  {label:'Needs exposure investigation',matches:(r:Row)=>r.response.startsWith('Investigate')}
 ];
 const active=cards.find(c=>c.label===selected);
 const visible=active?rows.filter(active.matches):rows;
 return <section className="panel padded priority-decisions" aria-label="Priority decisions"><h2>{portfolio?'Company priority decisions':'Vulnerability priorities'}</h2>
 <div className="summary-grid">{cards.map(({label,matches})=><button type="button" className="stat priority-summary-card" key={label} aria-label={label} aria-pressed={selected===label} onClick={()=>setSelected(current=>current===label?null:label)}><span>{label}</span><strong>{rows.filter(matches).length}</strong></button>)}</div>
 <p className="fine">Latest saved decisions. Needs exposure investigation counts asset/CVE decisions whose affected status or exposure still requires confirmation; it does not mean confirmed affected assets. Severity, reported exploitation and local exposure are separate inputs. Open a decision to inspect its evidence and accept or override the proposed response.</p>
 {!rows.length?<p>No recorded vulnerability decisions in this scope.</p>:!visible.length?<p>No decisions match this filter.</p>:<div className="table-wrap priority-table"><table><thead><tr><th>#</th><th>Asset / CVE</th><th>Technical severity / exploitation</th><th>Organizational exposure</th><th>Response / decision rationale</th><th>Validation</th></tr></thead><tbody>{visible.map((r,index)=><tr key={r.id}><td><b>{index+1}</b></td><td><button className="text-link" onClick={()=>onOpen(r)}>{r.cve} · {r.asset}</button><small>{r.owner}{r.synthetic?' · Synthetic example':''}</small>{portfolio&&<small>{r.environment_name||r.environment_id}</small>}</td><td>{r.severity}<small>{r.exploitation}</small></td><td>{r.applicability}<small>Reachability: {r.reachability}</small></td><td><b>{r.response}</b><small>{r.reviewed?'Decision recorded':'Proposed · accept or override'}</small><details><summary>Why this response?</summary><p>{r.rationale}</p>{r.response!==r.proposed_response&&<p>Policy proposal: {r.proposed_response}</p>}<small>Assessed {r.assessed_at?new Date(r.assessed_at).toLocaleString():'date unavailable'}</small></details></td><td>{r.validation==='not tested'?'No recorded validation':r.validation}<small>{r.validation_current?'Current evidence review':'Assessment outcome; open to refresh'}</small></td></tr>)}</tbody></table></div>}
 </section>
}
