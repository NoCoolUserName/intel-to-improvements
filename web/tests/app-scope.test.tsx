import React from 'react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {act,cleanup,render,screen,waitFor,within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from '../src/App';

vi.mock('../src/PipelineAssurance',()=>({default:({customer,environment}:any)=><span>Overview scope: {customer}/{environment}</span>}));
vi.mock('../src/ExposureOverview',()=>({default:({onOpen,onEnvironmentChange,environmentValue}:any)=><div><select aria-label="Dashboard environment" value={environmentValue||''} onChange={e=>onEnvironmentChange(e.target.value)}><option value="">All environments</option><option value="brotli:estate">Brotli estate</option><option value="leadership:lab">Leadership lab</option></select><button onClick={()=>onOpen('Pipeline Assurance',{customer:'leadership',environment:'lab'})}>Open dashboard environment</button></div>}));

const assessment={id:'brotli-assessment',context:{customer_id:'brotli',environment_id:'estate'},source:{id:'brotli-source',title:'Brotli case'},extraction:{mode:'offline'},relevance:{rank:'High'}};
const boot={company:{name:'Harborlight Capital',sector:'test'},company_customer_ids:['brotli','leadership'],customers:[
  {id:'brotli',name:'Brotli customer',sector:'test',version:1,environments:[{id:'estate',name:'Brotli estate',version:1}]},
  {id:'leadership',name:'Leadership demo',sector:'test',version:1,environments:[{id:'lab',name:'Leadership lab',version:1}]},
],sectors:{test:'Test'},cases:[]};
const response=(value:unknown)=>new Response(JSON.stringify(value),{status:200});
let requests:string[];
beforeEach(()=>{
  location.hash='#/pipeline-assurance?customer=brotli&environment=estate';
  requests=[];
  vi.stubGlobal('fetch',vi.fn(async(input:string)=>{
    const url=String(input);requests.push(url);
    if(url==='/api/bootstrap')return response(boot);
    if(url.startsWith('/api/assessments?'))return response(url.includes('customer_id=brotli')?[assessment]:[]);
    if(url.startsWith('/api/ledger/'))return url.includes('customer_id=brotli')?response({rows:[],counts:{}}):new Response(JSON.stringify({detail:'Not found in selected customer/environment'}),{status:404});
    return response([]);
  }));
});
afterEach(()=>{cleanup();vi.unstubAllGlobals();location.hash=''});

async function changeEnvironment(user:any,value:string){
 const nav=screen.getByRole('navigation',{name:'Workbench navigation'});
 const previous=nav.querySelector('[aria-current="page"]')!.textContent!;
 await user.click(within(nav).getByRole('button',{name:'Exposure Overview',exact:true}));
 await user.selectOptions(screen.getByRole('combobox',{name:'Dashboard environment'}),value);
 await user.click(within(nav).getByRole('button',{name:previous,exact:true}));
 expect(screen.queryByRole('combobox',{name:'Dashboard environment'})).toBeNull();
 expect(screen.queryByText('FICTIONAL COMPANY AND DEMO')).toBeNull();
}

it('does not fetch an old case after changing the customer selector',async()=>{
  const user=userEvent.setup();render(<App/>);
  await waitFor(()=>expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=brotli'))).toBe(true));
  await changeEnvironment(user,'leadership:lab');
  await screen.findByText('Overview scope: leadership/lab');
  expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=leadership'))).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
});

it('does not fetch an old case when the dashboard opens another environment',async()=>{
  const user=userEvent.setup();render(<App/>);
  await waitFor(()=>expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=brotli'))).toBe(true));
  await user.click(screen.getByRole('button',{name:'Exposure Overview',exact:true}));
  expect(screen.queryByRole('combobox',{name:'Active customer'})).toBeNull();
  await user.click(screen.getByRole('button',{name:'Open dashboard environment'}));
  await screen.findByText('Overview scope: leadership/lab');
  expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=leadership'))).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
});

it('ignores a late ledger error from the previous customer',async()=>{
  let rejectLedger!:(reason:Error)=>void;
  const originalFetch=fetch;
  vi.stubGlobal('fetch',vi.fn((input:string)=>String(input).includes('/api/ledger/brotli-assessment?')
    ?new Promise<Response>((_resolve,reject)=>{rejectLedger=reject})
    :originalFetch(input)));
  const user=userEvent.setup();render(<App/>);
  await waitFor(()=>expect(rejectLedger).toBeDefined());
  await changeEnvironment(user,'leadership:lab');
  await screen.findByText('Overview scope: leadership/lab');
  await act(async()=>{rejectLedger(new Error('Not found in selected customer/environment'))});
  expect(screen.queryByRole('alert')).toBeNull();
});


it('keeps one of each demo card through repeated intake navigation and customer changes',async()=>{
  const user=userEvent.setup();render(<App/>);
  await screen.findByText('Overview scope: brotli/estate');
  for(const customer of ['leadership','brotli','leadership','brotli']){
    await user.click(within(screen.getByRole('navigation',{name:'Workbench navigation'})).getByRole('button',{name:'Add Intelligence',exact:true}));
    await changeEnvironment(user,customer+':'+(customer==='brotli'?'estate':'lab'));
    expect(screen.getAllByRole('region',{name:'PHP2Shell working case'})).toHaveLength(1);
    expect(screen.getAllByRole('region',{name:'Brotli exposure working case'})).toHaveLength(1);
    await user.click(screen.getByRole('button',{name:'Pipeline Assurance',exact:true}));
    expect(screen.queryByRole('region',{name:'PHP2Shell working case'})).toBeNull();
    expect(screen.queryByRole('region',{name:'Brotli exposure working case'})).toBeNull();
  }
});
