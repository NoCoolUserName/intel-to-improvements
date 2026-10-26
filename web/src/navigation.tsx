import React,{useEffect,useState} from 'react';
import {Layers,Plus,BookOpen,Search,FlaskConical,ShieldCheck,FileJson,ChartNoAxesCombined,Users,ListChecks,ChevronRight} from 'lucide-react';

// IDs preserve existing workspace state and callbacks. Labels are presentation only.
export const NAV_GROUPS = [
  {title:'Overview',items:[{id:'Exposure Overview',label:'Exposure Overview',slug:'exposure-overview',icon:ChartNoAxesCombined},{id:'Coverage',label:'Coverage',slug:'coverage',icon:Layers}]},
  {title:'Intelligence',items:[{id:'Add Intelligence',label:'Add Intelligence',slug:'add-intelligence',icon:Plus},{id:'Case overview',label:'Cases & Analysis',slug:'cases-and-analysis',icon:BookOpen},{id:'Vulnerability Intelligence',label:'Vulnerability Intelligence',slug:'vulnerability-intelligence',icon:ShieldCheck},{id:'Intelligence exports',label:'Intelligence Exports',slug:'intelligence-exports',icon:FileJson}]},
  {title:'Exposures & Improvements',items:[{id:'Application Findings',label:'Application Findings',slug:'application-findings',icon:FileJson},{id:'Improvement Actions',label:'Improvement Actions',slug:'improvement-actions',icon:ListChecks}]},
  {title:'Validation',items:[{id:'Hunts',label:'Hunts',slug:'hunts',icon:Search},{id:'Purple team',label:'Purple Team',slug:'purple-team',icon:FlaskConical}]},
  {title:'Assurance & Quality',items:[{id:'Pipeline Assurance',label:'Pipeline Assurance',slug:'pipeline-assurance',icon:ShieldCheck},{id:'Evaluation',label:'Evaluation',slug:'evaluation',icon:ChartNoAxesCombined}]},
  {title:'Workspace',items:[{id:'Customer profiles',label:'Customer Profiles',slug:'customer-profiles',icon:Users}]},
] as const;
type WorkspaceItem={id:string;label:string;slug:string;icon:typeof Layers};
export const WORKSPACES = NAV_GROUPS.flatMap<WorkspaceItem>(group=>[...group.items]);
export function workspaceLabel(id:string){return WORKSPACES.find(item=>item.id===id)?.label||id}
export const DESCRIPTIONS:Record<string,string>={
  'Exposure Overview':'Review scoped findings, accountability and evidence-qualified outcomes.',
  'Coverage':'Inspect intelligence assessment coverage, telemetry gaps and independent timing.',
  'Add Intelligence':'Bring in selected sources to understand adversary behavior and customer relevance.',
  'Case overview':'Trace source evidence, relevance and proposed behaviors into investigation and action.',
  'Vulnerability Intelligence':'Review CVE evidence, asset applicability and owner decisions.',
  'Intelligence exports':'Share scoped intelligence and validation plans with their evidence and provenance.',
  'Application Findings':'Review supplied findings and coordinate evidence-qualified remediation.',
  'Improvement Actions':'Follow existing corrective work, ownership and retests across the selected workspace.',
  'Hunts':'Investigate defensive assumptions using bounded questions and retained evidence.',
  'Purple team':'Plan human-led validation and preserve what each test actually establishes.',
  'Pipeline Assurance':'Inspect supplied configuration and execution; effectiveness remains a separate question.',
  'Evaluation':'Inspect the workbench’s analytical reliability and capability evidence.',
  'Customer profiles':'Define customer priorities, environment scope, technologies and declared controls.',
};
export type NavigationTarget={customer?:string;environment?:string;record?:string;assessment?:string};
export function parseWorkspaceHash(hash:string){
  const [path,query='']=hash.replace(/^#\/?/,'').split('?');
  const segments=path.split('/');let slug='';let record:string|undefined;
  try{slug=decodeURIComponent(segments[0]);record=segments[1]?decodeURIComponent(segments[1]):undefined}catch{/* Malformed links fall back to Coverage. */}
  const item=WORKSPACES.find(item=>item.slug===slug||item.id===slug||(item.id==='Case overview'&&slug==='case-overview'));
  const params=new URLSearchParams(query);
  return {workspace:item?.id||'Coverage',record:item?.id==='Improvement Actions'?record:undefined,
    customer:params.get('customer')||undefined,environment:params.get('environment')||undefined,assessment:params.get('assessment')||undefined};
}
export function workspaceHash(id:string,target:NavigationTarget={}){
  const item=WORKSPACES.find(item=>item.id===id);if(!item)return '#/coverage';
  const params=new URLSearchParams();for(const key of ['customer','environment','assessment'] as const)if(target[key])params.set(key,target[key]!);
  return '#/'+item.slug+(target.record&&id==='Improvement Actions'?'/'+encodeURIComponent(target.record):'')+(params.size?'?'+params:'');
}
export function useWorkspaceNavigation(){
  const [route,setRoute]=useState(()=>parseWorkspaceHash(location.hash));
  useEffect(()=>{const update=()=>setRoute(parseWorkspaceHash(location.hash));window.addEventListener('hashchange',update);return()=>window.removeEventListener('hashchange',update)},[]);
  function navigate(id:string,target:NavigationTarget={}){const hash=workspaceHash(id,target);setRoute(parseWorkspaceHash(hash));if(location.hash!==hash)location.hash=hash}
  return {route,navigate};
}
export default function WorkspaceNavigation({active,onNavigate}:{active:string;onNavigate:(id:string)=>void}){
  return <nav aria-label="Workbench navigation">{NAV_GROUPS.map((group,i)=><section className="nav-group" key={group.title} aria-labelledby={'nav-group-'+i}>
    <h2 id={'nav-group-'+i} className="nav-group-heading">{group.title}</h2><div className="nav-group-items">{group.items.map(({id,label,icon:Icon})=><button key={id} onClick={()=>onNavigate(id)} className={active===id?'active':''} aria-current={active===id?'page':undefined}><Icon size={18}/><span className="nav-label">{label}</span>{active===id&&<ChevronRight size={14}/>}</button>)}</div>
  </section>)}</nav>;
}
