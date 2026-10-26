import React from 'react';
import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, render, screen, waitFor, fireEvent} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ApplicationFindings from '../src/ApplicationFindings';
const context = {customer_id:'a',environment_id:'e',customer_version:1,environment_version:1};
const finding = {id:'finding',batch_id:'batch',rule_id:'test-rule',operator_context:{application:'Example app'},reported_context:[],scanner:{name:'Synthetic scanner'},cwes:['CWE-79'],scanner_level:null,level_source:null,locations:[{artifact:{uri:'javascript:alert(1)'},region:{startLine:10}}],warnings:['Missing scanner version'],message:{text:'<script>alert(1)</script>'},resolved_message:'<script>alert(1)</script>',verification:'scanner reported; not independently validated',context,source_id:'source'};
const preview = {id:'preview',context,findings:[finding],warnings:['Scan completeness unknown'],runs:[],expires_at:'2026-10-26T12:00:00Z'};
const response = (data:unknown, status=200) => new Response(JSON.stringify(data), {status});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
function mount(){return render(<ApplicationFindings customer="a" environment="e"/>);}
it('previews then explicitly confirms, lists persisted data and renders evidence as safe text',async()=>{
  let imported=false;
  const fetcher=vi.fn(async(url:any,options:any)=>{
    if(String(url).endsWith('/preview'))return response(preview);
    if(String(url).endsWith('/confirm')){imported=true;return response({id:'batch'});}
    if(String(url).includes('/finding?'))return response({finding,source:{sha256:'hash'},import:{warnings:['No remediation performed']}});
    return response({findings:imported?[finding]:[],imports:[]});
  });vi.stubGlobal('fetch',fetcher);
  const user=userEvent.setup();const {container}=mount();await screen.findByText('No application findings in this scope.');
  await user.upload(screen.getByLabelText('SARIF file'),new File(['{}'],'synthetic.sarif',{type:'application/json'}));
  // jsdom 30 native required-file validity does not see user-event's FileList.
  fireEvent.submit(screen.getByRole('button',{name:'Preview SARIF'}).closest('form')!);
  await screen.findByText('Import preview: 1 findings');expect(imported).toBe(false);
  await user.click(screen.getByRole('button',{name:'Confirm SARIF import'}));
  await user.click(await screen.findByRole('button',{name:'Inspect test-rule finding'}));
  await screen.findByRole('heading',{name:'Finding details: test-rule'});
  expect(container.querySelector('script')).toBeNull();expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
  expect(screen.getByText('No remediation performed')).toBeTruthy();
  const confirm=fetcher.mock.calls.find(([u])=>String(u).endsWith('/confirm')) as any;
  expect(JSON.parse(confirm[1].body)).toEqual({customer_id:'a',environment_id:'e',preview_id:'preview'});
  const upload=fetcher.mock.calls.find(([u])=>String(u).endsWith('/preview')) as any;
  expect(upload[1].body.get('environment_id')).toBe('e');
});
it('invalidates preview on context edits and rejects large files before uploading',async()=>{
  const fetcher=vi.fn(async(url:any)=>response(String(url).endsWith('/preview')?preview:{findings:[],imports:[]}));vi.stubGlobal('fetch',fetcher);
  mount();const user=userEvent.setup();await user.upload(screen.getByLabelText('SARIF file'),new File(['{}'],'example.json'));
  // jsdom 30 native required-file validity does not see user-event's FileList.
  fireEvent.submit(screen.getByRole('button',{name:'Preview SARIF'}).closest('form')!);await screen.findByRole('button',{name:'Confirm SARIF import'});
  await user.type(screen.getByLabelText('Repository identifier'),'new-repo');expect(screen.queryByRole('button',{name:'Confirm SARIF import'})).toBeNull();
  await user.upload(screen.getByLabelText('SARIF file'),new File(['x'.repeat(4*1024*1024+1)],'huge.json'));
  // jsdom 30 native required-file validity does not see user-event's FileList.
  fireEvent.submit(screen.getByRole('button',{name:'Preview SARIF'}).closest('form')!);expect(await screen.findByRole('alert')).toBeTruthy();
  expect(fetcher.mock.calls.filter(([u])=>String(u).endsWith('/preview'))).toHaveLength(1);
});
it('discards late responses from a prior customer',async()=>{
  let resolveOld:(v:any)=>void=()=>{};
  vi.stubGlobal('fetch',vi.fn((url:any)=>String(url).includes('customer_id=a')?new Promise(r=>{resolveOld=r}):Promise.resolve(response({findings:[],imports:[]}))));
  const {rerender}=mount();rerender(<ApplicationFindings customer="b" environment="e"/>);
  await screen.findByText('No application findings in this scope.');resolveOld(response({findings:[finding],imports:[]}));
  await waitFor(()=>expect(screen.queryByText('Example app')).toBeNull());
});
it('shows validation errors without offering confirmation',async()=>{
  vi.stubGlobal('fetch',vi.fn(async(url:any)=>String(url).endsWith('/preview')?response({detail:'Invalid SARIF structure'},422):response({findings:[],imports:[]})));
  mount();const user=userEvent.setup();await user.upload(screen.getByLabelText('SARIF file'),new File(['{}'],'invalid.json'));
  // jsdom 30 native required-file validity does not see user-event's FileList.
  fireEvent.submit(screen.getByRole('button',{name:'Preview SARIF'}).closest('form')!);expect((await screen.findByRole('alert')).textContent).toContain('Invalid SARIF structure');
  expect(screen.queryByRole('button',{name:'Confirm SARIF import'})).toBeNull();
});
