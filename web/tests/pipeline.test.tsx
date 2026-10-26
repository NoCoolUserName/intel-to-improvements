import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {render,screen,cleanup,fireEvent,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PipelineAssurance from '../src/PipelineAssurance';
const operator={repository:'synthetic/repo',ref:'main',commit:'a'.repeat(40),synthetic:true};
const observation={id:'c',description:'SAST configuration',category:'Security testing',state:'Observed configured',workflow:'.github/workflows/test.yml',key:'jobs.scan.steps.0',line:5,evidence:'<img src=x onerror="alert(1)">',reason:'Configuration does not establish execution',limitations:['Merge enforcement unknown']};
const snapshot={id:'snapshot',operator_context:operator,imported_at:'2026-01-01',assessment_at:'2026-01-01',rule_version:'pipeline-assurance-1',observations:[observation],limitations:['No execution or independent verification'],files:[{path:'.github/workflows/test.yml',filename:'test.yml',sha256:'immutable-hash',source_id:'source',document:{on:'push'},locations:{on:2}}]};
const summary={...snapshot,workflows:['.github/workflows/test.yml'],observation_count:1};
const preview={id:'preview',kind:'pipeline_snapshot',payload:snapshot,expires_at:'2026-01-01',rule_version:'pipeline-assurance-1'};
const execution={id:'execution',snapshot_id:'snapshot',provenance:'SUPPLIED EXECUTION METADATA; not independently authenticated',source_sha256:'execution-hash',source_id:'execution-source',workflow_run:{id:1,run_attempt:1,head_sha:'a'.repeat(40)},jobs:{jobs:[]},controls:{c:{state:'Reported skipped',reason:'Job skipped'}},warnings:['Partial jobs response'],independently_verified:false};
const response=(d:unknown,status=200)=>new Response(JSON.stringify(d),{status});
afterEach(()=>{cleanup();vi.unstubAllGlobals()});
function mount(){return render(<PipelineAssurance customer="c" environment="e"/>)}
it('uploads multiple YAML files, previews, explicitly confirms and inspects immutable source',async()=>{
 let saved=false;
 vi.stubGlobal('fetch',vi.fn(async(url:any,options:any)=>String(url).endsWith('/preview')?response(preview):String(url).endsWith('/confirm')?(saved=true,response(snapshot)):String(url).includes('/snapshot?')?response({snapshot,executions:[]}):response({snapshots:saved?[summary]:[]})));
 const user=userEvent.setup();const {container}=mount();await screen.findByText('No workflows imported in this scope.');
 await user.type(screen.getByLabelText('Repository (owner/name)'),'synthetic/repo');await user.type(screen.getByLabelText('Branch / ref'),'main');
 await user.upload(screen.getByLabelText('Workflow YAML files'),[new File(['on: push'],'a.yml'),new File(['on: push'],'b.yaml')]);
 fireEvent.submit(screen.getByRole('button',{name:'Preview pipeline snapshot'}).closest('form')!);
 await screen.findByRole('heading',{name:'Configuration preview'});expect(saved).toBe(false);
 expect(screen.getByText('Unknown / no evidence')).toBeTruthy();expect(container.querySelector('img,script')).toBeNull();
 await user.click(screen.getByRole('button',{name:'Confirm pipeline import'}));await screen.findByRole('heading',{name:'Snapshot snapshot'});
 expect(screen.getByText(/No execution metadata available/)).toBeTruthy();expect(screen.getByText(/immutable-hash/)).toBeTruthy();
 expect(screen.getByRole('link',{name:'Download original test.yml'}).getAttribute('href')).toContain('customer_id=c&environment_id=e');
});
it('selects supplied execution without changing configured state; new previews never inherit old execution',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(url:any)=>String(url).endsWith('/preview')?response(preview):String(url).includes('/snapshot?')?response({snapshot,executions:[execution]}):response({snapshots:[summary]})));
 const user=userEvent.setup();mount();await user.click(await screen.findByRole('button',{name:/Inspect synthetic\/repo/}));
 await user.selectOptions(screen.getByLabelText('Supplied run to inspect'),'execution');
 expect(await screen.findByText('Reported skipped')).toBeTruthy();expect(screen.getByText('Observed configured')).toBeTruthy();expect(screen.getByText(/not independently authenticated$/)).toBeTruthy();
 await user.upload(screen.getByLabelText('Workflow YAML files'),new File(['on: push'],'a.yml'));fireEvent.submit(screen.getByRole('button',{name:'Preview pipeline snapshot'}).closest('form')!);
 await screen.findByRole('heading',{name:'Configuration preview'});expect(screen.getAllByText('Reported skipped')).toHaveLength(1);
 expect(screen.getByText('Unknown / no evidence')).toBeTruthy();
});
it('previews execution metadata then confirms it with frozen snapshot scope',async()=>{
 const fetcher=vi.fn(async(url:any)=>String(url).endsWith('/execution-preview')?response({...preview,kind:'pipeline_execution',payload:execution}):String(url).endsWith('/confirm')?response(execution):String(url).includes('/snapshot?')?response({snapshot,executions:[]}):response({snapshots:[summary]}));vi.stubGlobal('fetch',fetcher);
 const user=userEvent.setup();mount();await user.click(await screen.findByRole('button',{name:/Inspect synthetic\/repo/}));
 await user.upload(screen.getByLabelText('Execution JSON'),new File(['{}'],'run.json',{type:'application/json'}));fireEvent.submit(screen.getByRole('button',{name:'Preview execution metadata'}).closest('form')!);
 await screen.findByRole('heading',{name:'Execution metadata preview'});await user.click(screen.getByRole('button',{name:'Confirm pipeline import'}));
 await waitFor(()=>expect(fetcher.mock.calls.some(([u,o])=>String(u).endsWith('/confirm')&&JSON.parse(o.body).preview_id==='preview')).toBe(true));
});
it('renders validation errors and supports retry without offering confirmation',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>response({detail:'Invalid YAML structure'},422)));mount();expect((await screen.findByRole('alert')).textContent).toContain('Invalid YAML');expect(screen.queryByRole('button',{name:'Confirm pipeline import'})).toBeNull();
});
it('drops late snapshot responses when customer changes',async()=>{
 let resolve!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn().mockImplementationOnce(()=>new Promise(r=>{resolve=r})).mockResolvedValue(response({snapshots:[]})));
 const view=mount();view.rerender(<PipelineAssurance customer="other" environment="e"/>);await screen.findByText('No workflows imported in this scope.');resolve(response({snapshots:[summary]}));await waitFor(()=>expect(screen.queryByRole('button',{name:/Inspect synthetic\/repo/})).toBeNull());
});
