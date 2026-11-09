import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,render,screen,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import BrotliDemo,{BROTLI_CUSTOMER} from '../src/BrotliDemo';

afterEach(()=>{cleanup();vi.unstubAllGlobals()});
const demo={id:'brotli-cve-2026-111497-v1',customer_id:BROTLI_CUSTOMER,environment_id:'brotli-estate',assessment_id:'assessment-1',cve:'CVE-2026-111497',label:'Synthetic',
  sources:[],stops:[{workspace:'Case overview',task:'Inspect evidence'}],checks:{operational_tests_executed:false},relations:{
    asset_to_exposure:{'advisor-package':'exposure-1'},asset_to_decision:{'advisor-package':'decision-1'},
    asset_to_vulnerability_action:{'advisor-package':'action-1'},rule_to_finding:{'demo/self-contained-package':'finding-1'},
    pipeline_snapshot_ids:['pipeline-1'],relationship_limits:['No native cross-domain foreign key']}};

it('loads only after explicit action with the previewed fictional scope',async()=>{
  const fetcher=vi.fn(async()=>new Response(JSON.stringify(demo)));vi.stubGlobal('fetch',fetcher);
  const loaded=vi.fn(async()=>{});render(<BrotliDemo customer="fictional-bank" onLoaded={loaded} onNavigate={()=>{}}/>);
  expect(fetcher).not.toHaveBeenCalled();
  expect(screen.getByText(/Load preview: creates/).textContent).toContain('Financial-services application estate — synthetic');
  await userEvent.click(screen.getByRole('button',{name:'Load Brotli working case'}));
  await waitFor(()=>expect(loaded).toHaveBeenCalledWith(demo));
  expect(fetcher.mock.calls[0][1]).toEqual({method:'POST'});
});

it('links the actual scoped action without an unrelated case filter and selects the finding',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify(demo))));
  const navigate=vi.fn();render(<BrotliDemo customer={BROTLI_CUSTOMER} onLoaded={async()=>{}} onNavigate={navigate}/>);
  const link=await screen.findByRole('link',{name:'Open owner action'});
  expect(link.getAttribute('href')).toBe('#/improvement-actions/action-1?customer=fictional-harborlight-brotli&environment=brotli-estate');
  await userEvent.click(screen.getByRole('button',{name:'demo/self-contained-package'}));
  expect(navigate).toHaveBeenCalledWith('Application Findings',{kind:'finding',id:'finding-1'});
});
