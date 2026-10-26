type Obj=Record<string,any>;
/** Shared fields for behavior, D3FEND and vulnerability actions in the same ledger. */
export default function ImprovementFields({defaults,lockedNew=false,statuses}:{defaults?:Obj,lockedNew?:boolean,statuses?:string[][]}){return <>
<label>Owner<input required name="owner" defaultValue={defaults?.owner||''} placeholder="Control or asset owner"/></label>
<label>Priority<select aria-label="Priority" name="priority" defaultValue={defaults?.priority||'high'}><option>high</option><option>medium</option><option>low</option></select></label>
<label>Status<select aria-label="Status" name="status" disabled={lockedNew} defaultValue={defaults?.status||'open'}>{(statuses||['open','in progress','deployed','retest requested','closed'].map(v=>[v,v])).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
<label>Rationale<textarea required name="rationale" defaultValue={defaults?.rationale||''}/></label>
<label>Proposed change<textarea required name="change" defaultValue={defaults?.proposed_change||''}/></label>
<label>Retest plan<textarea required name="retest" defaultValue={defaults?.retest||''}/></label>
</>}
