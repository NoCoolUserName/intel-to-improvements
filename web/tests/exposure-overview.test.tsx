import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {render,screen,cleanup,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ExposureOverview from '../src/ExposureOverview';
const row={id:'app:1',entity:'exposure',origin:'AppSec',label:'<script>alert(1)</script>',owner:'Unassigned',status:'Needs review',verification:'Pending / no qualifying evidence',environment_id:'e',synthetic:true,source_ids:['immutable-source'],reference:{finding_id:'f'},age_days:null,overdue_days:null};
const action={...row,id:'action:1',entity:'action',label:'Owned action',owner:'Engineering',status:'open',overdue_days:2,age_days:8};
const data={context:{customer_id:'c',environment_id:'e'},as_of:'2026-10-26T00:00:00Z',synthetic_present:true,caveat:'Local records only',evidence_policy:'Qualified supplied evidence only',raw_appsec_occurrences:3,rows:[row,action],metrics:[{id:'appsec',label:'Current logical AppSec findings',value:1,record_ids:[row.id],population_count:1,population:'exposure',definition:'Latest logical occurrence; historical imports excluded',exclusions:'Historical rows excluded'}],timing:[{cohort:'Operational infrastructure',sample_count:0,median_seconds:null,record_ids:[],definition:'Only qualifying outcomes',unavailable_reason:'No eligible current resolved records'}]};
const response=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status});
afterEach(()=>{cleanup();vi.unstubAllGlobals()});
function mount(extra:any={}){const onInspect=vi.fn(),onDemo=vi.fn();return {...render(<ExposureOverview customer="c" environment="e" onInspect={onInspect} onDemo={onDemo} {...extra}/>),onInspect,onDemo}}
it('loads scoped backend data, reconciles metric drilldown and exposes definitions safely',async()=>{
 const fetcher=vi.fn(async()=>response(data));vi.stubGlobal('fetch',fetcher);const user=userEvent.setup();const {container,onInspect}=mount();
 expect(screen.getByRole('status').textContent).toContain('Loading');
 await user.click(await screen.findByRole('button',{name:'Current logical AppSec findings: 1'}));
 expect(fetcher.mock.calls[0][0]).toContain('customer_id=c&environment_id=e');
 expect(screen.getByRole('status').textContent).toContain('1 matching records');
 await user.click(screen.getByText('Definition: Current logical AppSec findings'));
 expect(screen.getByText(/Latest logical occurrence/)).toBeTruthy();
 expect(screen.getByText(/Not available/)).toBeTruthy();expect(container.querySelector('script,img')).toBeNull();
 await user.click(screen.getByRole('button',{name:'Inspect '+row.label}));expect(onInspect).toHaveBeenCalledWith(row);
});
it('filters ownership, overdue and classification; keyboard controls remain usable',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>response(data)));const user=userEvent.setup();mount();await screen.findByText(/2 matching records/);
 await user.selectOptions(screen.getByLabelText('Owner / team'),'Engineering');expect(screen.getByRole('status').textContent).toContain('1 matching records');
 await user.click(screen.getByLabelText('Overdue actions only'));expect(screen.getByRole('status').textContent).toContain('1 matching records');
 await user.selectOptions(screen.getByLabelText('Data classification'),'other');expect(screen.getByRole('status').textContent).toContain('0 matching records');
 screen.getByLabelText('Data classification').focus();await user.tab();expect(document.activeElement).toBe(screen.getByLabelText('Sort records'));
});
it('handles errors, retry and an empty population without invented timing',async()=>{
 const fetcher=vi.fn().mockResolvedValueOnce(response({detail:'Overview unavailable'},422)).mockResolvedValue(response({...data,rows:[],raw_appsec_occurrences:0,metrics:[{...data.metrics[0],value:0,record_ids:[],population_count:0}]}));vi.stubGlobal('fetch',fetcher);const user=userEvent.setup();mount();
 expect((await screen.findByRole('alert')).textContent).toContain('Overview unavailable');await user.click(screen.getByRole('button',{name:'Retry overview'}));
 await screen.findByText('No registered exposure, source mention or remediation records in this scope.');expect(screen.getByText(/Not available/)).toBeTruthy();
});
it('discards late responses after switching scope',async()=>{
 let resolve!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn().mockImplementationOnce(()=>new Promise(r=>{resolve=r})).mockResolvedValue(response({...data,rows:[],metrics:[{...data.metrics[0],value:0,record_ids:[]}]})));
 const props={onInspect:vi.fn(),onDemo:vi.fn()};const view=render(<ExposureOverview customer="c" environment="e" {...props}/>);
 view.rerender(<ExposureOverview customer="other" environment="e" {...props}/>);await screen.findByText(/No registered exposure/);resolve(response(data));
 await waitFor(()=>expect(screen.queryByText(row.label)).toBeNull());expect(screen.getByText(/Selected customer: other/)).toBeTruthy();
});
it('ignores a demo response after the customer changes',async()=>{
 let resolve!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.endsWith('/demo')?new Promise<Response>(r=>{resolve=r}):response(data)));
 const props={onInspect:vi.fn(),onDemo:vi.fn()};const view=render(<ExposureOverview customer="c" environment="e" {...props}/>);const user=userEvent.setup();await user.click(screen.getByRole('button',{name:'Load synthetic leadership demo'}));
 view.rerender(<ExposureOverview customer="other" environment="e" {...props}/>);resolve(response({customer_id:'demo',environment_id:'demo'}));await waitFor(()=>expect(screen.getByText(/Selected customer: other/)).toBeTruthy());expect(props.onDemo).not.toHaveBeenCalled();
});
