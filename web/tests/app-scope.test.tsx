import React from 'react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {act,cleanup,render,screen,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from '../src/App';

vi.mock('../src/ExposureOverview',()=>({default:({customer,environment,onDemo}:any)=><div>
  <span>Overview scope: {customer}/{environment}</span>
  <button onClick={()=>onDemo({customer_id:'leadership',environment_id:'lab'})}>Switch demo scope</button>
</div>}));

const assessment={id:'brotli-assessment',context:{customer_id:'brotli',environment_id:'estate'},source:{id:'brotli-source',title:'Brotli case'},extraction:{mode:'offline'},relevance:{rank:'High'}};
const boot={customers:[
  {id:'brotli',name:'Brotli customer',sector:'test',version:1,environments:[{id:'estate',name:'Brotli estate',version:1}]},
  {id:'leadership',name:'Leadership demo',sector:'test',version:1,environments:[{id:'lab',name:'Leadership lab',version:1}]},
],sectors:{test:'Test'}};
const response=(value:unknown)=>new Response(JSON.stringify(value),{status:200});
let requests:string[];
beforeEach(()=>{
  location.hash='#/exposure-overview?customer=brotli&environment=estate';
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

it('does not fetch an old case after changing the customer selector',async()=>{
  const user=userEvent.setup();render(<App/>);
  await waitFor(()=>expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=brotli'))).toBe(true));
  await user.selectOptions(screen.getByRole('combobox',{name:'Active customer'}),'leadership');
  await screen.findByText('Overview scope: leadership/lab');
  expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=leadership'))).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
});

it('does not fetch an old case when the overview switches to another demo',async()=>{
  const user=userEvent.setup();render(<App/>);
  await waitFor(()=>expect(requests.some(url=>url.includes('/api/ledger/brotli-assessment?customer_id=brotli'))).toBe(true));
  await user.click(screen.getByRole('button',{name:'Switch demo scope'}));
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
  await user.selectOptions(screen.getByRole('combobox',{name:'Active customer'}),'leadership');
  await screen.findByText('Overview scope: leadership/lab');
  await act(async()=>{rejectLedger(new Error('Not found in selected customer/environment'))});
  expect(screen.queryByRole('alert')).toBeNull();
});
