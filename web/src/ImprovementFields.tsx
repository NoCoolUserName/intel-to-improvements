type Obj=Record<string,any>;
/** Shared fields for behavior, D3FEND and vulnerability actions in the same ledger. */
export default function ImprovementFields({defaults,lockedNew=false,statuses}:{defaults?:Obj,lockedNew?:boolean,statuses?:string[][]}){return <>
<label>Implementation owner<input required name="owner" defaultValue={defaults?.owner||''} placeholder="Control or asset owner"/></label>
<label>Remediation coordinator<input name="remediation_coordinator" defaultValue={defaults?.remediation_coordinator||''}/></label>
<label>Verification reviewer<input name="verification_reviewer" defaultValue={defaults?.verification_reviewer||defaults?.remediation?.security_reviewer||''}/></label>
<label>Validation plan status<select name="validation_status" defaultValue={defaults?.validation_status||'planned'}>{['planned','awaiting evidence','awaiting review','reviewed','blocked','not planned'].map(s=><option key={s}>{s}</option>)}</select></label>
<details><summary>Validation responsibility and evidence review</summary>
<p>For blocked or deliberately unplanned validation, record the responsible person and reason. Marking evidence reviewed records a review, not a successful technical result.</p>
{[['validation_responsible','Person responsible for validation decision'],['validation_reason','Blocker or decision reason'],['evidence_supplier','Evidence supplied by'],['evidence_reference','Supplied evidence reference'],['evidence_reviewed_by','Evidence reviewed by'],['evidence_proves','What the evidence supports'],['evidence_uncertainty','What remains uncertain']].map(([name,label])=><label key={name}>{label}<textarea name={name} maxLength={4000} defaultValue={defaults?.[name]||''}/></label>)}
</details>
<label>Priority<select aria-label="Priority" name="priority" defaultValue={defaults?.priority||'high'}><option>high</option><option>medium</option><option>low</option></select></label>
<label>Status<select aria-label="Status" name="status" disabled={lockedNew} defaultValue={defaults?.status||'open'}>{(statuses||['open','in progress','deployed','retest requested','closed'].map(v=>[v,v])).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
<label>Rationale<textarea required name="rationale" defaultValue={defaults?.rationale||''}/></label>
<label>Proposed change<textarea required name="change" defaultValue={defaults?.proposed_change||''}/></label>
<label>Retest plan<textarea required name="retest" defaultValue={defaults?.retest||''}/></label>
</>}

export function actionTracking(values:FormData|Obj){const data=values instanceof FormData?Object.fromEntries(values):values;return Object.fromEntries(['remediation_coordinator','verification_reviewer','validation_status','validation_responsible','validation_reason','evidence_supplier','evidence_reference','evidence_reviewed_by','evidence_proves','evidence_uncertainty'].map(k=>[k,data[k]||(k==='validation_status'?'planned':'')]))}
