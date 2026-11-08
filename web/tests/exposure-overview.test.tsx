import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {act,render,screen,cleanup,waitFor,within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ExposureOverview from '../src/ExposureOverview';
const scope={customer_id:'a',environment_id:'env',customer_name:'Customer A',environment_name:'Production',cases:1,open_actions:2,unassigned_actions:1,retest_actions:1,outstanding:3,overdue:1,needs_review:2,appsec:2,affected:1,error:null};
const data={as_of:'2026-11-08T20:00:00Z',scopes:[scope,{...scope,customer_id:'b',customer_name:'Customer B',cases:0,open_actions:0}],cases:[{id:'case-a',customer_id:'a',environment_id:'env',title:'Brotli case',relevance:'High',updated_at:'2026-11-07T20:00:00Z',synthetic:true,open_actions:2}],revision_count:4,policy:'Latest revision per source and environment.'};
const response=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status});
afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.useRealTimers()});
it('shows system totals and cases, with no manual refresh or demo-loading box',async()=>{
 const fetcher=vi.fn(async()=>response(data));vi.stubGlobal('fetch',fetcher);render(<ExposureOverview onOpen={vi.fn()}/>);
 await screen.findByText('Brotli case');
 expect(fetcher.mock.calls[0][0]).toBe('/api/exposure-overview/portfolio');
 expect(screen.getByText('All customers · 2 environments')).toBeTruthy();
 expect(screen.getByText('Synthetic example')).toBeTruthy();
 expect(screen.queryByRole('button',{name:/refresh|load synthetic/i})).toBeNull();
 expect(screen.queryByText('Exposure and accountable work')).toBeNull();
});
it('filters customers, searches cases and opens the correct scoped destination',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>response(data)));const onOpen=vi.fn();render(<ExposureOverview onOpen={onOpen}/>);const user=userEvent.setup();
 await user.click(await screen.findByRole('button',{name:'Brotli case'}));
 expect(onOpen).toHaveBeenLastCalledWith('Case overview',{customer:'a',environment:'env',assessment:'case-a'});
 await user.type(screen.getByRole('searchbox',{name:'Find a case'}),'missing');expect(screen.queryByText('Brotli case')).toBeNull();
 await user.selectOptions(screen.getByRole('combobox',{name:'Dashboard customer'}),'b');
 const row=screen.getAllByRole('row').find(r=>r.textContent?.includes('Customer B'))!;
 await user.click(within(row).getByRole('button',{name:'Actions'}));expect(onOpen).toHaveBeenLastCalledWith('Improvement Actions',{customer:'b',environment:'env'});
});
it('updates automatically and retains the last snapshot if an update fails',async()=>{
 vi.useFakeTimers();const fetcher=vi.fn().mockResolvedValueOnce(response(data)).mockResolvedValueOnce(response({detail:'Temporarily unavailable'},503)).mockResolvedValue(response({...data,cases:[{...data.cases[0],title:'Updated case'}]}));vi.stubGlobal('fetch',fetcher);
 render(<ExposureOverview onOpen={vi.fn()}/>);await act(async()=>{});
 expect(screen.getByText('Brotli case')).toBeTruthy();
 await act(async()=>{await vi.advanceTimersByTimeAsync(10000)});
 expect(screen.getByRole('alert').textContent).toContain('Showing the last successful snapshot');expect(screen.getByText('Brotli case')).toBeTruthy();
 await act(async()=>{await vi.advanceTimersByTimeAsync(10000)});
 expect(screen.getByText('Updated case')).toBeTruthy();expect(screen.queryByRole('alert')).toBeNull();
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
