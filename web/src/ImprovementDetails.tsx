import React from 'react';
import {DefenseOrigin} from './DefensiveCandidates';
type Obj=Record<string,any>;
/** Shared immutable-origin presentation; edits remain in existing domain forms. */
export default function ImprovementDetails({action,children}:{action:Obj;children?:React.ReactNode}){
  const origin=action.origin;
  const defenseOrigin=origin?.d3fend_id&&Array.isArray(origin.evidence)&&origin.catalog&&(!origin.kind||origin.kind==='d3fend_candidate');
  return <><h2>Improvement action</h2><span className="badge">{action.status}</span><h3>{action.proposed_change}</h3>
    <p>Owner: {action.owner} · Priority: {action.priority}</p><p>{action.rationale}</p><p>Retest: {action.retest}</p>
    <p className="fine">Customer {action.context.customer_id} v{action.context.customer_version} · Environment {action.context.environment_id} v{action.context.environment_version}. Opened {action.opened_at||'Unknown'}.</p>
    <p className="fine">Work status and implementation claims remain separate from evidence-qualified outcomes.</p>{defenseOrigin&&<DefenseOrigin origin={origin}/>}{children}</>;
}
