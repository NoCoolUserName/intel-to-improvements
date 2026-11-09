import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,render,screen,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImprovementActions from '../src/ImprovementActions';
afterEach(()=>{cleanup();vi.unstubAllGlobals()});
const row={id:'action-a',origin_kind:'AppSec',related_title:'Synthetic finding',owner:'Synthetic engineering',status:'retest requested',priority:'high',proposed_change:'Upgrade serving runtime',retest:'Inspect exact worker version',outcome:'Attestation only',qualification:'Supplied/synthetic evidence does not prove operational remediation',reference:{kind:'appsec',finding_id:'finding-a'},customer_id:'customer-a',environment_id:'env-a'};
const detail={...row,action:{...row,origin:{kind:'application_finding',finding_id:'finding-a',source_id:'source-a',source_sha256:'a'.repeat(64)},context:{customer_id:'customer-a',environment_id:'env-a',customer_version:1,environment_version:1}},tests:[],exceptions:[]};
const props={customer:'customer-a',environment:'env-a',onInspect:vi.fn(),onManage:vi.fn(),onClearFilter:vi.fn()};
it('shows actual ledger records and opens their existing workflow without a new mutation path',async()=>{
  const fetcher=vi.fn(async(input:string)=>new Response(JSON.stringify(input.startsWith('/api/improvements/action-a')?detail:{rows:[row],qualification:'Existing ledger records'})));vi.stubGlobal('fetch',fetcher);
  render(<ImprovementActions {...props} actionId="action-a"/>);
  await screen.findByRole('button',{name:'Open originating workflow'});expect(screen.getAllByText('Attestation only').length).toBeGreaterThan(0);
  await userEvent.click(screen.getByRole('button',{name:'Open originating workflow'}));expect(props.onManage).toHaveBeenCalledWith(detail);
  expect(fetcher.mock.calls.every(c=>c.length===1&&c[0].includes('customer_id=customer-a&environment_id=env-a'))).toBe(true);
});
it('keeps missing action links recoverable while the scoped list remains available',async()=>{
  vi.stubGlobal('fetch',vi.fn(async(input:string)=>new Response(JSON.stringify(input.includes('/missing?')?{detail:'Action not found in selected scope'}:{rows:[row]}),{status:input.includes('/missing?')?404:200})));
  render(<ImprovementActions {...props} actionId="missing"/>);await screen.findByText('Error: Action not found in selected scope');
  expect(screen.getByRole('button',{name:'Inspect action action-a'})).toBeTruthy();expect(screen.queryByRole('button',{name:'Open originating workflow'})).toBeNull();
});
it('discards a late response immediately when the selected scope changes',async()=>{
  let resolve:(value:Response)=>void=()=>{};vi.stubGlobal('fetch',vi.fn(async(input:string)=>input.includes('customer_id=customer-a')?new Promise<Response>(r=>{resolve=r}):new Response(JSON.stringify({rows:[]}))));
  const view=render(<ImprovementActions {...props}/>);view.rerender(<ImprovementActions {...props} customer="customer-b" environment="env-b"/>);
  resolve(new Response(JSON.stringify({rows:[row]})));await waitFor(()=>expect(screen.getByText(/No existing improvement actions match/)).toBeTruthy());expect(screen.queryByText('Upgrade serving runtime')).toBeNull();
});
it('shows separate implementation, coordination and review responsibilities with next-step ownership',async()=>{
 const tracked={...row,remediation_coordinator:'Exposure manager',verification_reviewer:'Evidence reviewer',stage:'Awaiting verification review',next_owner:'Evidence reviewer',validation_responsible:'Exposure manager',validation_reason:'Evidence needs reviewer approval'};
 vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify({rows:[tracked]}))));
 render(<ImprovementActions {...props}/>);await screen.findByText('Awaiting verification review');
 expect(screen.getByText('Coordinator: Exposure manager')).toBeTruthy();expect(screen.getByText('Reviewer: Evidence reviewer')).toBeTruthy();expect(screen.getByText('Next: Evidence reviewer')).toBeTruthy();
});
it('shows only the open actions requested by a dashboard count',async()=>{
 const closed={...row,id:'closed',status:'closed',proposed_change:'Closed change'};
 vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify({rows:[row,closed]}))));
 const onClearFilter=vi.fn();render(<ImprovementActions {...props} openOnly onClearFilter={onClearFilter}/>);
 await screen.findByText('Showing 1 open action.');
 expect(screen.getByText('Upgrade serving runtime')).toBeTruthy();expect(screen.queryByText('Closed change')).toBeNull();
 await userEvent.click(screen.getByRole('button',{name:'Show all scoped actions'}));expect(onClearFilter).toHaveBeenCalled();
});
