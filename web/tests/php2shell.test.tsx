import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,render,screen,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Php2ShellDemo,{PHP2SHELL_CUSTOMER} from '../src/Php2ShellDemo';
afterEach(()=>{cleanup();vi.unstubAllGlobals()});
const demo={customer_id:PHP2SHELL_CUSTOMER,environment_id:'php-estate',assessment_id:'assessment-demo',label:'Synthetic',
  stops:[{workspace:'Purple team',task:'Interpret the bounded request probe.'}],sources:[],checks:{operational_tests_executed:false}};
it('loads only on explicit action and selects the returned dedicated scope',async()=>{
  const fetcher=vi.fn(async()=>new Response(JSON.stringify(demo)));vi.stubGlobal('fetch',fetcher);
  const loaded=vi.fn(async()=>{});render(<Php2ShellDemo customer="fictional-bank" onLoaded={loaded} onNavigate={()=>{}}/>);
  expect(fetcher).not.toHaveBeenCalled();await userEvent.click(screen.getByRole('button',{name:'Open PHP2Shell working case'}));
  await waitFor(()=>expect(loaded).toHaveBeenCalledWith(demo));expect(fetcher.mock.calls[0][1]).toEqual({method:'POST'});
});
it('restores the guide without reseeding and navigates with synthetic boundaries visible',async()=>{
  const fetcher=vi.fn(async()=>new Response(JSON.stringify(demo)));vi.stubGlobal('fetch',fetcher);const navigate=vi.fn();
  render(<Php2ShellDemo customer={PHP2SHELL_CUSTOMER} onLoaded={async()=>{}} onNavigate={navigate}/>);
  await screen.findByText('PHP2Shell case guide · all 12 workspaces');await userEvent.click(screen.getByText('PHP2Shell case guide · all 12 workspaces'));
  await userEvent.click(screen.getByRole('button',{name:'Open Purple team'}));expect(navigate).toHaveBeenCalledWith('Purple team');
  expect(screen.getByText(/All firm assets, findings/)).toBeTruthy();expect(fetcher.mock.calls[0]).toEqual(['/api/demos/php2shell']);
});
