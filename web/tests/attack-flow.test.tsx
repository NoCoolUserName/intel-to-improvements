import React, {act} from 'react';
import {createRoot, type Root} from 'react-dom/client';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import AttackFlowPanel, {attackFlowUrls} from '../src/AttackFlowPanel';
let host: HTMLDivElement, root: Root;
const makePackage = (id='package-1', customer='bank') => ({id,context:{customer_id:customer,environment_id:'windows'},source:{title:'A source <img src=x onerror=alert(1)>'},artifacts:{names:['attack-flow.json'],validation:{attack_flow:{status:'generated',actions:2,edges:0,ordering:'unordered',explanation:'Temporal order unknown.',source_gaps:['image-only evidence']}}}});
const render = (pack=makePackage(), customer='bank', regenerate=vi.fn()) => act(()=>root.render(<><AttackFlowPanel pack={pack} customer={customer} environment="windows" regenerate={regenerate} busy={false}/><h2>Human-led validation scenarios</h2><p>Existing human plan</p></>));
function frame() {return host.querySelector('iframe')!;}
function message(target: HTMLIFrameElement, overrides={}, source: Window|null=target.contentWindow, origin=location.origin) {
  const url=new URL(target.src);
  return new MessageEvent('message',{origin,source,data:{type:'iti-attack-flow',frame:url.searchParams.get('iti_frame'),packageId:url.searchParams.get('iti_package'),status:'ready',nodes:2,...overrides}});
}
beforeEach(()=>{
  (globalThis as any).IS_REACT_ACT_ENVIRONMENT=true;
  vi.stubGlobal('ResizeObserver',class{observe(){}disconnect(){}});
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue({json:async()=>({available:true})}));
  host=document.createElement('div');document.body.appendChild(host);root=createRoot(host);
});
afterEach(async()=>{await act(()=>root.unmount());host.remove();vi.unstubAllGlobals();vi.useRealTimers();});
it('encodes an absolute scoped artifact URL and uses the same local flow for editing',()=>{
  const urls=attackFlowUrls('http://localhost:8000','p 1','customer & private','env/one','frame1');
  const viewer=new URL(urls.viewer), editor=new URL(urls.editor), artifact=new URL(viewer.searchParams.get('src')!);
  expect(artifact.origin).toBe('http://localhost:8000');expect(artifact.searchParams.get('customer_id')).toBe('customer & private');
  expect(viewer.searchParams.has('readonly')).toBe(true);expect(editor.searchParams.has('readonly')).toBe(false);
  expect(editor.searchParams.get('src')).toBe(urls.artifact);
});
it('does not trust iframe load; validates message origin, source, frame and package',async()=>{
  await render();const iframe=frame();await act(()=>iframe.dispatchEvent(new Event('load')));
  expect(host.textContent).toContain('Loading and rendering');
  for(const event of [message(iframe,{},iframe.contentWindow,'https://evil.invalid'),message(iframe,{},window),message(iframe,{packageId:'other'}),message(iframe,{frame:'stale'}),message(iframe,{nodes:0})])await act(()=>window.dispatchEvent(event));
  expect(host.textContent).toContain('Loading and rendering');
  await act(()=>window.dispatchEvent(message(iframe)));expect(host.textContent).not.toContain('Loading and rendering');
  expect(host.querySelector('img')).toBeNull(); // Source text stays text.
});
it('rapid scope/package switch removes old frame immediately and ignores stale results',async()=>{
  await render();const old=frame(), oldMessage=message(old);await render(makePackage(),'cloud');
  expect(host.querySelector('iframe')).toBeNull();expect(host.textContent).toContain('Existing human plan');
  await render(makePackage('package-2','cloud'),'cloud');const current=frame();
  expect(current).not.toBe(old);expect(current.src).toContain('package-2');
  await act(()=>window.dispatchEvent(oldMessage));expect(host.textContent).toContain('Loading and rendering');
  await act(()=>window.dispatchEvent(message(current)));expect(host.textContent).not.toContain('Loading and rendering');
});
it('shows failure/retry without losing downloads or human scenarios',async()=>{
  await render();const old=frame();await act(()=>window.dispatchEvent(message(old,{status:'error',message:'Invalid bundle'})));
  expect(host.textContent).toContain('Invalid bundle');expect(host.textContent).toContain('Existing human plan');
  expect(host.querySelector('a[download]')).not.toBeNull();expect(host.querySelector('iframe')).toBeNull();
  const retry=[...host.querySelectorAll('button')].find(b=>b.textContent?.includes('Retry'))!;
  await act(()=>retry.click());expect(frame().src).not.toBe(old.src);
});
it('keeps old packages usable with regeneration and no-action packages honest',async()=>{
  const old=makePackage();old.artifacts={names:['hunt.md'],validation:{}} as any;const regenerate=vi.fn();
  await render(old,'bank',regenerate);expect(host.querySelector('iframe')).toBeNull();
  await act(()=>host.querySelector('button')!.click());expect(regenerate).toHaveBeenCalledOnce();
  expect(host.textContent).toContain('Existing human plan');
  const empty=makePackage();empty.artifacts.names=[];empty.artifacts.validation.attack_flow={status:'empty',reason:'No evidenced actions'} as any;
  await render(empty);expect(host.textContent).toContain('No evidenced actions');expect(host.querySelector('iframe')).toBeNull();
});
it('makes a missing build and a render timeout explicit',async()=>{
  vi.mocked(fetch).mockResolvedValueOnce({json:async()=>({available:false,reason:'Build the local viewer'})} as Response);
  await render();expect(host.textContent).toContain('Build the local viewer');
  await render(makePackage('fresh'));vi.useFakeTimers();
  // Retry starts a fresh bounded render wait.
  await act(()=>window.dispatchEvent(message(frame(),{status:'error',message:'Retry'})));
  await act(()=>[...host.querySelectorAll('button')].find(b=>b.textContent?.includes('Retry'))!.click());
  await act(()=>vi.advanceTimersByTime(20001));expect(host.textContent).toContain('did not confirm a rendered graph');
  expect(host.textContent).toContain('Existing human plan');
});
it('gates a changed environment even when customer and package ID are unchanged',async()=>{
  const pack=makePackage();await render(pack);expect(frame()).not.toBeNull();
  await act(()=>root.render(<AttackFlowPanel pack={pack} customer="bank" environment="mac-cloud" regenerate={vi.fn()} busy={false}/>));
  expect(host.querySelector('iframe')).toBeNull();
});
