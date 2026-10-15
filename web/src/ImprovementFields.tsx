type Obj=Record<string,any>;
/** Shared fields for behavior, D3FEND and vulnerability actions in the same ledger. */
export default function ImprovementFields({defaults,lockedNew=false}:{defaults?:Obj,lockedNew?:boolean}){return <>
<label>Owner<input required name="owner" defaultValue={defaults?.owner||''} placeholder="Control or asset owner"/></label>
<label>Priority<select name="priority" defaultValue={defaults?.priority||'high'}><option>high</option><option>medium</option><option>low</option></select></label>
<label>Status<select name="status" disabled={lockedNew} defaultValue={defaults?.status||'open'}><option>open</option><option>in progress</option><option>deployed</option><option>retest requested</option><option>closed</option></select></label>
<label>Rationale<textarea required name="rationale" defaultValue={defaults?.rationale||''}/></label>
<label>Proposed change<textarea required name="change" defaultValue={defaults?.proposed_change||''}/></label>
<label>Retest plan<textarea required name="retest" defaultValue={defaults?.retest||''}/></label>
</>}
