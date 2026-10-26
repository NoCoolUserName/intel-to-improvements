import React, {useEffect, useRef, useState} from 'react';
import './vulnerability.css';
import AppsecGovernance from './AppsecGovernance';
type Obj = Record<string, any>;
async function request(path: string, options?: RequestInit) {
  const response = await fetch('/api/application-findings' + path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Invalid import request');
  return data;
}
const json = (value: unknown) => <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
export default function ApplicationFindings(props: {customer: string; environment: string; onDemo?: (value:Obj)=>void; initialFindingId?: string; initialTab?:string; onActions?:(id:string)=>void}) {
  return <Workspace key={props.customer + ':' + props.environment} {...props}/>;
}
function Workspace({customer, environment, onDemo, initialFindingId, initialTab, onActions}: {customer: string; environment: string; onDemo?: (value:Obj)=>void; initialFindingId?: string; initialTab?:string; onActions?:(id:string)=>void}) {
  const [data, setData] = useState<Obj>(), [preview, setPreview] = useState<Obj>(), [detail, setDetail] = useState<Obj>();
  const [error, setError] = useState(''), [notice, setNotice] = useState(''), [busy, setBusy] = useState(false);
  const selectedFile = useRef<File | undefined>(undefined);
  const alive = useRef(true), selection = useRef(0);
  const query = '?' + new URLSearchParams({customer_id: customer, environment_id: environment});
  async function load() {const result = await request(query); if (alive.current) setData(result);}
  useEffect(() => {alive.current = true; load().catch(e => {if (alive.current) setError(String(e));}); return () => {alive.current = false;};}, []);
  async function action(fn: () => Promise<void>) {
    setError(''); setBusy(true);
    try {await fn();} catch (e) {if (alive.current) setError(String(e));}
    finally {if (alive.current) setBusy(false);}
  }
  async function inspect(id: string) {
    const token = ++selection.current; setDetail(undefined);
    await action(async () => {const value = await request('/' + encodeURIComponent(id) + query); if (alive.current && token === selection.current) setDetail(value);});
  }
  useEffect(() => {if (initialFindingId) inspect(initialFindingId);}, [initialFindingId]);
  function table(rows: Obj[], persisted: boolean) {
    return <div className="table-wrap"><table><caption>{persisted ? 'Persisted scanner findings' : 'Previewed scanner findings'}</caption><thead><tr>{['Application / repository','Scanner','Rule','CWE','Scanner level','Source location','Import identity'].map(h => <th key={h}>{h}</th>)}</tr></thead><tbody>{rows.map(r => <tr key={r.id}>
      <td>{r.operator_context.application || 'Unknown application'}<small>{r.operator_context.repository || r.reported_context[0]?.repositoryUri || 'Unknown repository'}</small>{r.synthetic && <small>Synthetic fixture</small>}</td>
      <td>{r.scanner.name} {r.scanner.version || '(version unknown)'}</td>
      <td>{persisted ? <button className="text-link" onClick={() => inspect(r.id)} aria-label={'Inspect ' + (r.rule_id || 'unknown rule') + ' ' + r.id}>{r.rule_id || 'Unknown rule'}</button> : r.rule_id || 'Unknown rule'}</td>
      <td>{r.cwes.join(', ') || 'Unknown'}</td><td>{r.scanner_level || 'Unknown'}<small>{r.level_source || 'Not reported'}</small></td>
      <td>{r.locations.map((l: Obj, i: number) => <div key={i}>{l.artifact.uri || 'Unknown URI'}{l.region.startLine ? ':' + l.region.startLine : ''}{l.region.startColumn ? ':' + l.region.startColumn : ''}</div>)}</td><td>{r.batch_id}</td>
    </tr>)}</tbody></table></div>;
  }
  const finding = detail?.finding;
  return <section className="vulnerability-workspace application-findings">
    <h2>SARIF imports and findings</h2><p>Manually import SARIF 2.1.0 for the customer and environment selected above. Scanner reports are not independently validated vulnerabilities.</p>
    <p className="fine">No scanner execution, automated remediation or enterprise risk scoring is performed. Supplied evidence review is separate; scan completeness is unknown. Missing findings never mean fixed.</p>
    {onDemo&&<button disabled={busy} onClick={()=>action(async()=>{const response=await fetch('/api/appsec/demo',{method:'POST'});const value=await response.json();if(!response.ok)throw new Error(value.detail);if(alive.current)onDemo(value);})}>Load synthetic remediation demo</button>}
    {error && <div role="alert" className="banner error">{error}<button disabled={busy} onClick={() => action(load)}>Retry findings</button></div>}
    {notice && <p role="status">{notice}</p>}
    <div className="panel padded"><h2>Import SARIF</h2><form onChange={() => {setPreview(undefined); setNotice('');}} onSubmit={e => {
      e.preventDefault(); const form = new FormData(e.currentTarget); const file = selectedFile.current;
      setPreview(undefined); if (!file?.size || file.size > 4 * 1024 * 1024) {setError('Choose a nonempty SARIF file, maximum 4 MiB'); return;}
      form.set('file', file); form.set('customer_id', customer); form.set('environment_id', environment); form.set('synthetic', form.get('synthetic') ? 'true' : 'false');
      action(async () => {const value = await request('/preview', {method: 'POST', body: form}); if (alive.current) setPreview(value);});
    }}><fieldset disabled={busy}><legend>Manually supplied context (kept separate from SARIF)</legend>
      <label>SARIF file<input type="file" name="file" onChange={e => {selectedFile.current = e.target.files?.[0];}} accept=".sarif,.json,application/json" required/></label>
      <div className="form-grid">{[['application','Application label'],['repository','Repository identifier'],['branch','Branch / ref'],['commit','Commit']].map(([name, label]) => <label key={name}>{label}<input name={name} maxLength={name === 'repository' ? 2000 : 300}/></label>)}</div>
      <label className="check"><input type="checkbox" name="synthetic"/>Synthetic / demo report</label><button className="primary" type="submit">Preview SARIF</button>
    </fieldset></form>
    {preview && <div><h3>Import preview: {preview.findings.length} findings</h3><p>Frozen profile v{preview.context.customer_version}, environment v{preview.context.environment_version}. Expires {preview.expires_at}.</p>
      <p>Normalizer: {preview.normalizer || 'sarif-normalizer-1'}. A different normalizer creates a separate batch; existing imports stay unchanged.</p>
      {preview.already_imported && <p>Identical batch already imported; confirmation will return the existing batch.</p>}
      <ul>{preview.warnings.map((w: string, i: number) => <li key={i}>{w}</li>)}</ul>
      <details><summary>Per-finding limitations and run provenance</summary>{json({findings: preview.findings.map((r: Obj) => ({rule: r.rule_id, warnings: r.warnings, invocation: r.invocation_status})), runs: preview.runs})}</details>
      {table(preview.findings, false)}<button disabled={busy} className="primary" onClick={() => action(async () => {
        const result = await request('/confirm', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({customer_id: customer, environment_id: environment, preview_id: preview.id})});
        if (!alive.current) return; setPreview(undefined); setNotice((result.duplicate ? 'Existing import: ' : 'Imported: ') + result.id); await load();
      })}>Confirm SARIF import</button></div>}
    </div>
    {data && <><div className="panel padded"><h2>Findings in selected scope</h2>{data.findings.length ? table(data.findings, true) : <p>No application findings in this scope.</p>}</div>
      <div className="panel padded"><h2>Import history and limitations</h2>{data.imports.map((batch: Obj) => <details key={batch.id}><summary>{batch.id} · {batch.finding_ids.length} findings · {batch.imported_at}</summary>{json(batch)}<a href={'/api/application-findings/sources/' + encodeURIComponent(batch.source_id) + query} download>Download original SARIF evidence</a></details>)}</div></>}
    {finding && <div className="panel padded" aria-label="Finding details"><h2>Finding details: {finding.rule_id || 'Unknown rule'}</h2><p>{finding.verification}</p><blockquote>{finding.resolved_message ?? 'Message unresolved; inspect original message below.'}</blockquote>
      <AppsecGovernance initialTab={initialTab} onActions={onActions} key={finding.id} finding={finding} findings={data?.findings||[]} imports={data?.imports||[]} onInspect={inspect}/>
      <h3>Original reported message</h3>{json(finding.message)}<h3>Rule metadata</h3>{json(finding.rule_metadata)}
      <h3>Scanner and run</h3>{json({scanner: finding.scanner, run_id: finding.run_id, run_index: finding.run_index, result_index: finding.result_index, invocation_status: finding.invocation_status, scan_timestamps: finding.scan_timestamps, scanner_level: finding.scanner_level, level_source: finding.level_source, severity_metadata: finding.severity_metadata})}
      <h3>Location, identifiers and fingerprints</h3>{json({locations: finding.locations, cwes: finding.cwes, cves: finding.cves, fingerprints: finding.fingerprints, partial_fingerprints: finding.partial_fingerprints, logical_id: finding.logical_id, identity_basis: finding.identity_basis})}
      <h3>Evidence and import context</h3>{json({source: detail?.source, operator_context: finding.operator_context, sarif_reported_context: finding.reported_context, frozen_context: finding.context, batch_id: finding.batch_id, imported_at: finding.imported_at, synthetic: finding.synthetic, synthetic_basis: finding.synthetic_basis})}
      <a href={'/api/application-findings/sources/' + encodeURIComponent(finding.source_id) + query} download>Download original SARIF evidence</a>
      <h3>Missing / unsupported metadata and verification limitations</h3><ul>{[...finding.warnings, ...detail!.import.warnings].map((w: string, i: number) => <li key={i}>{w}</li>)}</ul>
    </div>}
  </section>;
}
