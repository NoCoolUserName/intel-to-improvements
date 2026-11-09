import React from 'react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {act,render,screen,cleanup,waitFor,within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ExposureOverview from '../src/ExposureOverview';
const scope={customer_id:'a',environment_id:'env',customer_name:'Customer A',environment_name:'Production',cases:1,open_actions:2,unassigned_actions:1,retest_actions:1,outstanding:3,overdue:1,needs_review:2,appsec:2,affected:1,error:null};
const data={as_of:'2026-11-08T20:00:00Z',scopes:[scope,{...scope,customer_id:'b',customer_name:'Customer B',cases:0,open_actions:0}],cases:[{id:'case-a',customer_id:'a',environment_id:'env',title:'Brotli case',relevance:'High',updated_at:'2026-11-07T20:00:00Z',synthetic:true,open_actions:2}],revision_count:4,policy:'Latest revision per source and environment.'};
const response=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status});
beforeEach(()=>{vi.stubGlobal('matchMedia',vi.fn(()=>({matches:true,addEventListener:vi.fn(),removeEventListener:vi.fn()})));vi.stubGlobal('scrollTo',vi.fn())});
afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.useRealTimers()});
it('shows system totals and cases, with no manual refresh or demo-loading box',async()=>{
 const fetcher=vi.fn(async()=>response(data));vi.stubGlobal('fetch',fetcher);render(<ExposureOverview onOpen={vi.fn()}/>);
 await screen.findByRole('button',{name:'Brotli case',exact:true});
 expect(fetcher.mock.calls[0][0]).toBe('/api/exposure-overview/portfolio');
 expect(screen.getByText('Fictional Company · 2 network zones / segments')).toBeTruthy();
 expect(screen.getByRole('option',{name:'All network zones and segments'})).toBeTruthy();
 expect(screen.getByText('Synthetic example')).toBeTruthy();
 expect(screen.queryByRole('button',{name:/refresh|load synthetic/i})).toBeNull();
 expect(screen.queryByText('Exposure and accountable work')).toBeNull();
});
it('filters customers, searches cases and opens the correct scoped destination',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>response(data)));const onOpen=vi.fn();render(<ExposureOverview onOpen={onOpen}/>);const user=userEvent.setup();
 await user.click(await screen.findByRole('button',{name:'Brotli case'}));
 expect(onOpen).toHaveBeenLastCalledWith('Case overview',{customer:'a',environment:'env',assessment:'case-a'});
 await user.type(screen.getByRole('searchbox',{name:'Find a case'}),'missing');expect(screen.queryByRole('button',{name:'Brotli case',exact:true})).toBeNull();
 await user.selectOptions(screen.getByRole('combobox',{name:'Dashboard network zone / segment'}),'b:env');
 const row=screen.getAllByRole('row').find(r=>r.textContent?.includes('Production'))!;
 await user.click(within(row).getByRole('button',{name:'Actions'}));expect(onOpen).toHaveBeenLastCalledWith('Improvement Actions',{customer:'b',environment:'env'});
});
it('updates automatically and retains the last snapshot if an update fails',async()=>{
 vi.useFakeTimers();const fetcher=vi.fn().mockResolvedValueOnce(response(data)).mockResolvedValueOnce(response({detail:'Temporarily unavailable'},503)).mockResolvedValue(response({...data,cases:[{...data.cases[0],title:'Updated case'}]}));vi.stubGlobal('fetch',fetcher);
 render(<ExposureOverview onOpen={vi.fn()}/>);await act(async()=>{});
 expect(screen.getByRole('button',{name:'Brotli case',exact:true})).toBeTruthy();
 await act(async()=>{await vi.advanceTimersByTimeAsync(10000)});
 expect(screen.getByRole('alert').textContent).toContain('Showing the last successful snapshot');expect(screen.getByRole('button',{name:'Brotli case',exact:true})).toBeTruthy();
 await act(async()=>{await vi.advanceTimersByTimeAsync(10000)});
 expect(screen.getByRole('button',{name:'Updated case',exact:true})).toBeTruthy();expect(screen.queryByRole('alert')).toBeNull();
});
it('shows missing exposure totals as unavailable rather than zero',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>response({...data,scopes:[{...scope,error:'Evidence unavailable',outstanding:null,appsec:null,affected:null}]})));
 render(<ExposureOverview onOpen={vi.fn()}/>);await waitFor(()=>expect(screen.getByText('Unavailable')).toBeTruthy());expect(screen.getByRole('alert').textContent).toContain('Evidence unavailable');
});
it('links priority and validation subjects to their original scopes',async()=>{
 const row={id:'decision',customer_id:'a',environment_id:'env',cve:'CVE-2026-0001',asset:'advisor',response:'Expedite remediation/mitigation',proposed_response:'Expedite remediation/mitigation',reviewed:false,validation:'not tested',rationale:'Affected asset',severity:'Unknown',exploitation:'Reported',applicability:'confirmed affected',reachability:'confirmed',owner:'Engineering'};
 vi.stubGlobal('fetch',vi.fn(async()=>response({...data,priorities:[row],validation:[{id:'infra:1',customer_id:'a',environment_id:'env',label:'Advisor validation',outcome:'No recorded validation',recorded:false,synthetic:true,owner:'Engineering',origin:'Infrastructure',reference:{cve:row.cve},plans:[]}]})));
 const onOpen=vi.fn();render(<ExposureOverview onOpen={onOpen}/>);const user=userEvent.setup();
 await user.click(await screen.findByRole('button',{name:'CVE-2026-0001 · advisor'}));expect(onOpen).toHaveBeenLastCalledWith('Vulnerability Intelligence',{customer:'a',environment:'env',record:row.cve});
 await user.click(screen.getByRole('button',{name:'Inspect evidence and plan'}));expect(onOpen).toHaveBeenLastCalledWith('Vulnerability Intelligence',{customer:'a',environment:'env',assessment:undefined,record:row.cve});
 await user.selectOptions(screen.getByRole('combobox',{name:'Validation view'}),'recorded');expect(screen.queryByText('Advisor validation')).toBeNull();
});
it('opens the actions behind a working-case count without changing the environment filter',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>response(data)));const onOpen=vi.fn(),onEnvironmentChange=vi.fn();render(<ExposureOverview onOpen={onOpen} onEnvironmentChange={onEnvironmentChange}/>);
 const toggle=await screen.findByRole('button',{name:'Open Working Cases'});
 expect(toggle.getAttribute('aria-expanded')).toBe('false');expect(screen.queryByRole('region',{name:'Open working case list'})).toBeNull();
 await userEvent.click(toggle);
 expect(toggle.getAttribute('aria-expanded')).toBe('true');
 await screen.findByRole('heading',{name:'Open Working Cases'});
 await userEvent.click(screen.getByRole('button',{name:/Brotli case.*2 open actions/}));
 expect(onOpen).toHaveBeenCalledWith('Improvement Actions',{customer:'a',environment:'env',work:'open'});
 expect(onEnvironmentChange).not.toHaveBeenCalled();expect((screen.getByRole('combobox',{name:'Dashboard network zone / segment'}) as HTMLSelectElement).value).toBe('');
});
it('expands outstanding records and opens each record in its scoped source workspace',async()=>{
 const exposures=[
  {id:'app:one',customer_id:'a',environment_id:'env',label:'APP-1',origin:'AppSec',status:'Reviewed applicable',synthetic:true,reference:{finding_id:'finding-1'}},
  {id:'infra:one',customer_id:'a',environment_id:'env',label:'CVE-2026-11149 · gateway',origin:'Infrastructure',status:'confirmed affected',synthetic:true,reference:{cve:'CVE-2026-11149'}}
 ];
 vi.stubGlobal('fetch',vi.fn(async()=>response({...data,exposures})));const onOpen=vi.fn();render(<ExposureOverview onOpen={onOpen}/>);
 const toggle=await screen.findByRole('button',{name:'Outstanding exposures'});
 expect(toggle.getAttribute('aria-expanded')).toBe('false');expect(screen.queryByRole('region',{name:'Outstanding exposure records'})).toBeNull();
 await userEvent.click(toggle);
 const list=screen.getByRole('region',{name:'Outstanding exposure records'});
 expect(toggle.getAttribute('aria-expanded')).toBe('true');
 await userEvent.click(within(list).getByRole('button',{name:/APP-1/}));
 expect(onOpen).toHaveBeenLastCalledWith('Application Findings',{customer:'a',environment:'env',record:'finding-1'});
 await userEvent.click(within(list).getByRole('button',{name:/CVE-2026-11149/}));
 expect(onOpen).toHaveBeenLastCalledWith('Vulnerability Intelligence',{customer:'a',environment:'env',record:'CVE-2026-11149'});

});
it('opens a numbered, filtered remediation list from the Open remediation actions card',async()=>{
 const action={id:'open-1',customer_id:'a',environment_id:'env',status:'open',proposed_change:'Update gateway',related_title:'Brotli',stage:'Awaiting implementation',next_owner:'Engineering',implementation_owner:'Engineering',remediation_coordinator:'Coordinator',verification_reviewer:'Reviewer'};
 vi.stubGlobal('fetch',vi.fn(async()=>response({...data,action_tracking:[action,{...action,id:'closed-1',status:'closed',proposed_change:'Closed work'}]})));
 render(<ExposureOverview onOpen={vi.fn()}/>);
 const toggle=await screen.findByRole('button',{name:'Open remediation actions'});
 expect(toggle.getAttribute('aria-pressed')).toBe('false');
 await userEvent.click(toggle);
 const steps=screen.getByRole('region',{name:'Remediation Action Next Steps'});
 expect(toggle.getAttribute('aria-pressed')).toBe('true');
 expect(within(steps).getByText('Showing 1 open actions')).toBeTruthy();
 expect(within(steps).getByRole('row',{name:/1 Update gateway/})).toBeTruthy();
 expect(within(steps).queryByText('Closed work')).toBeNull();
 await userEvent.click(within(steps).getByRole('button',{name:'Show all actions'}));
 expect(within(steps).getByRole('row',{name:/2 Closed work/})).toBeTruthy();
 await userEvent.click(toggle);
 expect(toggle.getAttribute('aria-expanded')).toBe('false');
 expect(screen.queryByRole('region',{name:'Remediation Action Next Steps'})).toBeNull();
});
it('puts pending validation and blockers in Needs attention without flagging deliberately unplanned validation',async()=>{
 const stages=['Awaiting evidence','Awaiting verification review','Blocked','Validation not planned','Verified outcome','Awaiting implementation'];
 vi.stubGlobal('fetch',vi.fn(async()=>response({...data,action_tracking:stages.map((stage,i)=>({id:String(i),customer_id:'a',environment_id:'env',stage}))})));
 render(<ExposureOverview onOpen={vi.fn()}/>);await screen.findByRole('heading',{name:'Needs attention'});
 const box=screen.getByRole('heading',{name:'Needs attention'}).parentElement!;
 expect(within(box).getByText(/remediation actions awaiting validation/).textContent).toBe('2 remediation actions awaiting validation');
 expect(within(box).getByText(/validation blocked/).textContent).toBe('1 validation blocked');
 expect(within(box).queryByText(/validation deliberately not planned/)).toBeNull();
 expect(screen.queryByText('Awaiting retest')).toBeNull();
});

it('drills into each attention category with its selected scope and source record',async()=>{
 const base={customer_id:'a',environment_id:'env',status:'open',owner:'Engineering',next_owner:'Engineering'};
 const action_tracking=[
  {...base,id:'evidence',proposed_change:'Collect evidence',stage:'Awaiting evidence'},
  {...base,id:'blocked',proposed_change:'Unblock validation',stage:'Blocked'},
  {...base,id:'unassigned',proposed_change:'Assign engineer',owner:'',stage:'Awaiting implementation'},
  {...base,id:'late',proposed_change:'Overdue change',stage:'Awaiting implementation',past_due:true},
  {...base,id:'other-scope',customer_id:'b',proposed_change:'Other scope',stage:'Blocked'}
 ];
 const review_records=[{id:'review',customer_id:'a',environment_id:'env',label:'Needs applicability review',origin:'Infrastructure',status:'needs verification',synthetic:true,reference:{cve:'CVE-2026-11149'}}];
 vi.stubGlobal('fetch',vi.fn(async()=>response({...data,action_tracking,review_records})));
 const onOpen=vi.fn();render(<ExposureOverview environmentValue="a:env" onOpen={onOpen}/>);
 const attention=(await screen.findByRole('heading',{name:'Needs attention'})).parentElement!;
 for(const [label,change] of [['Remediation actions awaiting validation','Collect evidence'],['Validation blocked','Unblock validation'],['Open actions without an owner','Assign engineer'],['Actions past their due date','Overdue change']]){
  await userEvent.click(within(attention).getByRole('button',{name:label}));
  const steps=screen.getByRole('region',{name:'Remediation Action Next Steps'});
  expect(within(steps).getAllByRole('row')).toHaveLength(2);
  expect(within(steps).getByRole('button',{name:change})).toBeTruthy();
  const selected=within(attention).getByRole('button',{name:label});
  expect(selected.getAttribute('aria-pressed')).toBe('true');
  await userEvent.click(selected);
  expect(selected.getAttribute('aria-pressed')).toBe('false');
  expect(within(steps).getAllByRole('row')).toHaveLength(5);
  await userEvent.click(selected);
 }
 const steps=screen.getByRole('region',{name:'Remediation Action Next Steps'});
 await userEvent.click(within(steps).getByRole('button',{name:'Overdue change'}));
 expect(onOpen).toHaveBeenLastCalledWith('Improvement Actions',{customer:'a',environment:'env',record:'late'});
 await userEvent.click(within(attention).getByRole('button',{name:'Findings or assets awaiting review'}));
 const reviews=screen.getByRole('region',{name:'Findings and assets awaiting review'});
 await userEvent.click(within(reviews).getByRole('button',{name:/Needs applicability review/}));
 expect(onOpen).toHaveBeenLastCalledWith('Vulnerability Intelligence',{customer:'a',environment:'env',record:'CVE-2026-11149'});
 const selected=within(attention).getByRole('button',{name:'Findings or assets awaiting review'});
 expect(selected.getAttribute('aria-pressed')).toBe('true');
 await userEvent.click(selected);
 expect(selected.getAttribute('aria-pressed')).toBe('false');
 expect(screen.queryByRole('region',{name:'Findings and assets awaiting review'})).toBeNull();
 expect(screen.getByRole('region',{name:'Outstanding exposure records'})).toBeTruthy();
});
