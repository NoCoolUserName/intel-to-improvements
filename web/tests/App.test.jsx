import React from 'react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import {act, cleanup, render, screen, waitFor, within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from '../src/App';
import catalog from '../../catalogs/d3fend/catalog.json';

// Authored, minimal API fixtures. No live services or user intelligence are used.
const evidenceText = '<img src=x onerror="alert(1)"> is untrusted report text.';
function assessment(id, title) {
  return {
    id, context: {customer_id: id.startsWith('bank') ? 'fictional-bank' : 'fictional-cloud', customer_version: 1, environment_id: id.startsWith('bank') ? 'windows-ad' : 'mac-cloud'},
    source: {id: `source-${id}`, title, revision_id: `revision-${id}`, serials: [], gaps: [],
      origin: 'Authored test fixture', spans: [{id: 'span-1', text: evidenceText,
        heading_path: ['Evidence'], kind: 'text', start: 0, end: evidenceText.length}]},
    extraction: {mode: 'replay', behaviors: [{id: 'behavior-1', text: `${title} behavior`,
      evidence: ['span-1'], technique_id: 'T1059', confidence_rationale: 'Fixture only'}],
      claims: [], warnings: [], observables: []},
    relevance: {rank: 'High', explanation: 'Authored relevance fixture', sector: {},
      technology_matches: [], intelligence_requirement_matches: [], recency: {}},
    coverage: [{behavior_id: 'behavior-1', missing_prerequisites: [], applicability: 'applicable'}],
    candidates: [],
  };
}
const bankCase = assessment('bank-case', 'Bank investigation');
const cloudCase = assessment('cloud-case', 'Cloud investigation');
const bankPackage = {id: 'bank-package', assessment_id: bankCase.id, context: {...bankCase.context, destination: ''},
  hunts:[], emulations:[], source:bankCase.source, extraction:bankCase.extraction,
  artifacts: {names: ['cti.stix21.json', 'cti.misp.json', 'package.zip'], validation: {status: 'fixture'}}};
function actionRow(bank=true) {
  const a=bank?bankCase:cloudCase, id=bank?'bank-action':'cloud-action';
  const action={id,owner:bank?'Bank control owner':'Cloud control owner',priority:'high',status:'open',rationale:'Authored improvement',proposed_change:bank?'Improve Bank defense':'Improve Cloud defense',retest:'Inspect original evidence',context:a.context};
  return {...action,action,origin_kind:'Intelligence case',related_title:a.source.title,outcome:'No action-linked retest recorded',qualification:'Implementation claims do not prove verification',customer_id:a.context.customer_id,environment_id:a.context.environment_id,reference:{kind:'case',assessment_id:a.id,action_id:id},tests:[],exceptions:[]};
}
const bootstrap = {
  customers: [
    {id: 'fictional-bank', name: 'Fictional Bank', version: 1, sector: 'finance',
      environments: [{id: 'windows-ad', name: 'Windows AD', version: 1}]},
    {id: 'fictional-cloud', name: 'Fictional Cloud', version: 1, sector: 'technology',
      environments: [{id: 'mac-cloud', name: 'Mac Cloud', version: 1}]},
  ], sectors: {finance: 'Finance', technology: 'Technology'}, cases: [], templates: [],
};
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: {'Content-Type': 'application/json'},
});
function respond(input) {
  const url = new URL(String(input), 'http://localhost');
  const bank = url.searchParams.get('customer_id') === 'fictional-bank';
  switch (url.pathname) {
    case '/api/bootstrap': return json(bootstrap);
    case '/api/exposure-overview/portfolio': return json({as_of:'2026-11-08T00:00:00Z',cases:[],scopes:bootstrap.customers.flatMap(c=>c.environments.map(e=>({customer_id:c.id,environment_id:e.id,customer_name:c.name,environment_name:e.name,cases:0,open_actions:0}))),revision_count:0,policy:'Fixture'});
    case '/api/assessments/bank-case/defenses': case '/api/assessments/cloud-case/defenses':
      return json({state:'ready',behaviors:{}});
    case '/api/evaluation': return json({status: 'NOT RUN'});
    case '/api/improvements': return json({rows:[actionRow(bank)],qualification:'Existing ledger records only'});
    case '/api/improvements/bank-action': return bank?json(actionRow()):json({detail:'Not found in this scope'},404);
    case '/api/improvements/cloud-action': return !bank?json(actionRow(false)):json({detail:'Not found in this scope'},404);
    case '/api/assessments': return json(bank ? [bankCase] : [cloudCase]);
    case '/api/packages': return json(bank ? [bankPackage] : []);
    case '/api/jobs': case '/api/overrides': return json([]);
    case '/api/ledger/bank-case': case '/api/ledger/cloud-case':
      return json({counts: {}, metrics: {}, improvements: [], tests: [], history: []});
    default: throw new Error(`Unexpected API request: ${url.pathname}`);
  }
}
beforeEach(() => {
  localStorage.clear();
  history.replaceState(null,'','/');
  document.head.innerHTML = '<meta name="theme-color" content="#152d31">';
  vi.stubGlobal('fetch', vi.fn(async input => respond(input)));
});
afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks();});
async function mount() {
  const user = userEvent.setup();
  const view = render(<App/>);
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('bank-case'));
  return {user, ...view};
}

async function selectEnvironment(user,value){
  const nav=screen.getByRole('navigation',{name:'Workbench navigation'});
  const previous=nav.querySelector('[aria-current="page"]').textContent;
  await user.click(within(nav).getByRole('button',{name:'Exposure Overview',exact:true}));
  const environment=await screen.findByRole('combobox',{name:'Dashboard environment'});
  const strip=within(screen.getByRole('banner')).getByRole('group',{name:'Company and environment context'});
  expect(strip.contains(environment)).toBe(true);
  expect(screen.getByRole('banner').compareDocumentPosition(screen.getByRole('heading',{name:'Exposure Overview'})) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  await user.selectOptions(environment,value);
  await user.click(within(nav).getByRole('button',{name:previous,exact:true}));
  expect(screen.queryByRole('group',{name:'Company and environment context'})).toBeNull();
}

it('keeps the chosen theme across customer changes and a remount', async () => {
  const {user, unmount} = await mount();
  const theme = screen.getByRole('combobox', {name: 'Color theme'});
  const navigation = screen.getByRole('navigation', {name: 'Workbench navigation'});
  expect(navigation.nextElementSibling).toBe(theme.closest('label'));
  expect(theme.closest('.sidebar')).not.toBeNull();
  expect(screen.queryByRole('banner')).toBeNull();
  expect(within(theme).getAllByRole('option').map(option => option.textContent)).toEqual([
    'Original · Forest', 'Ocean', 'Midnight', 'Golden Ledger',
  ]);
  screen.getByRole('button', {name: 'Customer Profiles'}).focus();
  await user.tab();
  expect(document.activeElement).toBe(theme);
  for (const value of ['sailpoint', 'golden-ledger', 'original', 'dropzone']) {
    await user.selectOptions(theme, value);
    expect(document.documentElement.dataset.theme).toBe(value);
    expect(localStorage.getItem('iti.appearance.theme')).toBe(value);
  }
  await selectEnvironment(user,'fictional-cloud:mac-cloud');
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('cloud-case'));
  expect(location.hash).toContain('environment=mac-cloud');
  expect(document.documentElement.dataset.theme).toBe('dropzone');
  expect(screen.getByRole('combobox', {name: 'Color theme'}).value).toBe('dropzone');
  unmount(); render(<App/>);
  expect(screen.getByRole('combobox', {name: 'Color theme'}).value).toBe('dropzone');
});

it('opens cited evidence as text and closes it with an accessible control', async () => {
  const {user} = await mount();
  await user.click(screen.getByRole('button', {name: 'Bank investigation behavior'}));
  const drawer = screen.getByRole('complementary', {name: 'Evidence and detail drawer'});
  expect(within(drawer).getByText(evidenceText).tagName).toBe('BLOCKQUOTE');
  expect(drawer.querySelector('img')).toBeNull();
  await user.click(within(drawer).getByRole('button', {name: 'Close drawer'}));
  expect(screen.queryByRole('complementary', {name: 'Evidence and detail drawer'})).toBeNull();
});

it('scopes STIX, MISP and ZIP links and clears them when switching customers', async () => {
  const {user} = await mount();
  await user.click(screen.getByRole('button', {name: 'Intelligence Exports'}));
  for (const [label, name] of [['cti.stix21.json', 'cti.stix21.json'], ['cti.misp.json', 'cti.misp.json'], ['Download ZIP', 'package.zip']]) {
    const link = screen.getByRole('link', {name: label});
    expect(link.getAttribute('href')).toBe(`/api/artifacts/bank-package/${name}?customer_id=fictional-bank&environment_id=windows-ad`);
  }
  await selectEnvironment(user,'fictional-cloud:mac-cloud');
  await screen.findByText('Generate a package to validate and download exports.');
  expect(screen.queryByRole('link', {name: 'Download ZIP'})).toBeNull();
});

it('shows a failed package request and allows dismissing the error', async () => {
  fetch.mockImplementation(async (input, options) => {
    if (String(input).endsWith('/generate')) {
      expect(options.method).toBe('POST');
      expect(JSON.parse(options.body)).toEqual({customer_id: 'fictional-bank'});
      return json({detail: 'Package validation failed'}, 422);
    }
    return respond(input);
  });
  const {user} = await mount();
  await user.click(screen.getByRole('button', {name: 'Generate updated package'}));
  expect((await screen.findByRole('alert')).textContent).toContain('Package validation failed');
  expect(screen.getByRole('button', {name: 'Generate updated package'}).disabled).toBe(false);
  await user.click(screen.getByRole('button', {name: 'Dismiss error'}));
  expect(screen.queryByRole('alert')).toBeNull();
});

it('ignores a late investigation response for the previous customer', async () => {
  let releaseBank;
  fetch.mockImplementation(async input => {
    if (String(input).startsWith('/api/assessments?customer_id=fictional-bank')) {
      return new Promise(resolve => {releaseBank = () => resolve(json([bankCase]));});
    }
    return respond(input);
  });
  const user = userEvent.setup(); render(<App/>);
  await selectEnvironment(user,'fictional-cloud:mac-cloud');
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('cloud-case'));
  await act(async () => {releaseBank();});
  expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('cloud-case');
  expect(screen.queryByRole('option', {name: /Bank investigation/})).toBeNull();
  expect(screen.queryByRole('button', {name: 'Bank investigation behavior'})).toBeNull();
});


// Real catalog IDs/names, with authored assessment linkage and simplified provenance.
const defenseIds=['D3-APCA','D3-CSPP','D3-NTCD','D3-NTF'];
const defenseNames=defenseIds.map(id=>catalog.techniques[id].name);
function defenseFixture(saved) {
  return {state:'ready',assessment_id:bankCase.id,behaviors:{'behavior-1':{
    attack_id:'T1105',mapping_basis:'analyst_proposed',confidence_rationale:'Authored mapping fixture',
    applicability:{applicability:'applicable',reason:'Windows lab',missing_prerequisites:['DNS logging']},
    suitability:'Analyst review required',candidates:defenseIds.map((id,i)=>({
      id:'candidate-'+id,snapshot_id:'snapshot-1',behavior_id:'behavior-1',d3fend_id:id,name:defenseNames[i],
      reference:'https://d3fend.mitre.org/resources/',reference_scope:'general',
      explanation:'Pinned association; no verified protection',catalog:{revision:'pinned-fixture',catalog_sha256:'fixture',relationship_semantics:'Derived association'},
      evidence:['span-1'],improvement:saved&&i===0?{id:saved.id,status:saved.status}:null,
      prefill:{priority:'high',status:'open',rationale:'Reported behavior; evidence span-1. Separate catalog-derived recommendation.',proposed_change:'Assess and implement '+id,retest:'Name the control, scope, result and evidence'},
    }))}}};
}
function withDefenses() {
  let saved;let writes=0;
  fetch.mockImplementation(async (input,options)=>{
    const url=new URL(String(input),'http://localhost');
    if(url.pathname==='/api/assessments/bank-case/defenses')return json(defenseFixture(saved));
    if(url.pathname==='/api/ledger/bank-case/improve'){
      const body=JSON.parse(options.body);writes++;
      expect(body.customer_id).toBe('fictional-bank');expect(body.environment_id).toBe('windows-ad');
      if(!body.action.id){
        expect(body.candidate_ref).toEqual({snapshot_id:'snapshot-1',candidate_id:'candidate-D3-APCA'});
        expect(body.action.origin).toBeUndefined();
      }
      saved={...body.action,id:'improvement-1',assessment_id:bankCase.id,context:bankCase.context,origin:{...defenseFixture().behaviors['behavior-1'].candidates[0],explanation:'Frozen association'}};
      return json(saved);
    }
    if(url.pathname==='/api/ledger/bank-case')return json({counts:{},metrics:{},tests:[],history:[],improvements:saved?[saved]:[]});
    return respond(input);
  });
  return {saved:()=>saved,writes:()=>writes};
}
it('opens a bounded candidate list, edits the existing form and retains the saved action after remount',async()=>{
  const state=withDefenses();const {user,unmount}=await mount();
  await user.click(screen.getByRole('button',{name:'Bank investigation behavior'}));
  await screen.findByRole('button',{name:'Create improvement for D3-APCA'});
  expect(screen.queryByRole('button',{name:'Create improvement for D3-NTF'})).toBeNull();
  await user.click(screen.getByRole('button',{name:'Show all 4'}));
  expect(screen.getByRole('button',{name:'Create improvement for D3-NTF'})).toBeTruthy();
  await user.click(screen.getByRole('button',{name:'Create improvement for D3-APCA'}));
  expect(screen.getByRole('textbox',{name:'Implementation owner'}).value).toBe('');
  expect(screen.getByRole('combobox',{name:'Behavior'}).disabled).toBe(true);
  expect(screen.getByRole('combobox',{name:'Status'}).value).toBe('open');
  expect(screen.getByRole('textbox',{name:'Rationale'}).value).toContain('span-1');
  await user.type(screen.getByRole('textbox',{name:'Implementation owner'}),'Lab owner');
  await user.clear(screen.getByRole('textbox',{name:'Proposed change'}));
  await user.type(screen.getByRole('textbox',{name:'Proposed change'}),'Assess lab protocol control');
  await user.clear(screen.getByRole('textbox',{name:'Retest plan'}));
  await user.type(screen.getByRole('textbox',{name:'Retest plan'}),'Named control; benign lab variant; collect event');
  await user.dblClick(screen.getByRole('button',{name:'Record improvement'}));
  await waitFor(()=>expect(screen.queryByRole('heading',{name:'Review defensive improvement'})).toBeNull());
  expect(state.writes()).toBe(1);expect(state.saved().proposed_change).toBe('Assess lab protocol control');
  expect(state.saved().retest).toBe('Named control; benign lab variant; collect event');
  unmount();render(<App/>);
  await user.click(await screen.findByRole('button',{name:'Bank investigation behavior'}));
  await user.click(await screen.findByRole('button',{name:'View improvement · open'}));
  expect(screen.getByRole('heading',{name:'Assess lab protocol control'})).toBeTruthy();
  expect(within(screen.getByRole('complementary',{name:'Evidence and detail drawer'})).getByText(/D3FEND origin/)).toBeTruthy();
  expect(state.writes()).toBe(1);
  await user.click(screen.getByRole('button',{name:'Close drawer'}));
  await user.click(screen.getByText(/History and independent clocks/));
  await user.click(screen.getByRole('button',{name:'Mark deployed'}));
  await user.click(screen.getByRole('button',{name:'Bank investigation behavior'}));
  expect(await screen.findByRole('button',{name:'View improvement · deployed'})).toBeTruthy();
  expect(state.saved().origin.d3fend_id).toBe('D3-APCA');
});
it('closes a candidate form on customer change and ignores the previous catalog response',async()=>{
  withDefenses();const {user}=await mount();
  await user.click(screen.getByRole('button',{name:'Bank investigation behavior'}));
  await user.click(await screen.findByRole('button',{name:'Create improvement for D3-APCA'}));
  await selectEnvironment(user,'fictional-cloud:mac-cloud');
  await screen.findByRole('button',{name:'Cloud investigation behavior'});
  expect(screen.queryByRole('button',{name:'Record improvement'})).toBeNull();
  expect(screen.queryByText('D3-APCA')).toBeNull();
});
it('does not render a delayed catalog result after customer switching',async()=>{
  let release;
  fetch.mockImplementation(async input=>String(input).includes('/bank-case/defenses')?new Promise(resolve=>{release=()=>resolve(json(defenseFixture()));}):respond(input));
  const {user}=await mount();await waitFor(()=>expect(release).toBeTypeOf('function'));
  await selectEnvironment(user,'fictional-cloud:mac-cloud');
  await user.click(await screen.findByRole('button',{name:'Cloud investigation behavior'}));
  await act(async()=>release());
  expect(screen.queryByRole('button',{name:'Create improvement for D3-APCA'})).toBeNull();
});

it('keeps manual improvements available when the catalog is invalid',async()=>{
  fetch.mockImplementation(async input=>String(input).includes('/defenses?')?json({state:'catalog_unavailable',message:'Catalog checksum mismatch'}):respond(input));
  const {user}=await mount();await user.click(screen.getByRole('button',{name:'Bank investigation behavior'}));
  expect(await screen.findByText('Catalog checksum mismatch')).toBeTruthy();
  expect(screen.getByRole('button',{name:'Retry catalog'})).toBeTruthy();
  await user.click(screen.getByRole('button',{name:'Close drawer'}));
  await user.click(screen.getByRole('button',{name:'Record improvement / result'}));
  expect(screen.getByRole('textbox',{name:'Implementation owner'})).toBeTruthy();
  expect(screen.getByRole('combobox',{name:'Behavior'}).disabled).toBe(false);
});

it('integrates Application Findings with selected scope without requiring a CTI case', async () => {
  vi.stubGlobal('fetch', vi.fn(async input => String(input).startsWith('/api/application-findings?') ? json({findings:[],imports:[]}) : respond(input)));
  const {user} = await mount();
  await user.click(screen.getByRole('button', {name:'Application Findings',exact:true}));
  await screen.findByText('No application findings in this scope.');
  expect(screen.queryByRole('combobox',{name:'Working case'})).toBeNull();
  await selectEnvironment(user,'fictional-cloud:mac-cloud');
  await waitFor(()=>expect(vi.mocked(fetch).mock.calls.some(([url])=>String(url)==='/api/application-findings?customer_id=fictional-cloud&environment_id=mac-cloud')).toBe(true));
});

it('opens an existing scoped action in its original case workflow and continues into Hunts',async()=>{
  const {user}=await mount();
  await user.click(screen.getByRole('button',{name:'Improvement Actions',exact:true}));
  await screen.findByText('Improve Bank defense');
  await user.click(screen.getByRole('button',{name:'Inspect action bank-action'}));
  await screen.findByRole('button',{name:'Open originating workflow'});
  await user.click(screen.getByRole('button',{name:'Open originating workflow'}));
  expect(screen.getByRole('heading',{name:'Coverage',exact:true})).toBeTruthy();
  const drawer=screen.getByRole('complementary',{name:'Evidence and detail drawer'});
  expect(within(drawer).getByText('Improve Bank defense')).toBeTruthy();
  expect(within(drawer).getByRole('button',{name:'Edit improvement'})).toBeTruthy();
  expect(location.hash).toContain('environment=windows-ad');
  await user.click(within(drawer).getByRole('button',{name:'Close drawer'}));
  await user.click(screen.getByRole('button',{name:'Open case hunts'}));
  expect(screen.getByRole('heading',{name:'Hunts',exact:true})).toBeTruthy();
  expect(screen.getByRole('combobox',{name:'Working case'}).value).toBe('bank-case');
});

it('restores direct nested action links in their explicit scope without fetching the previous customer ledger',async()=>{
  history.replaceState(null,'','/#/improvement-actions/cloud-action?customer=fictional-cloud&environment=mac-cloud');
  render(<App/>);await screen.findByRole('heading',{name:'Improvement action',exact:true});
  expect(location.hash).toContain('environment=mac-cloud');
  expect(location.hash).toContain('environment=mac-cloud');
  expect(screen.getByRole('button',{name:'Improvement Actions',exact:true}).getAttribute('aria-current')).toBe('page');
  const calls=fetch.mock.calls.filter(([input])=>String(input).startsWith('/api/improvements'));
  expect(calls.every(([input])=>String(input).includes('customer_id=fictional-cloud&environment_id=mac-cloud'))).toBe(true);
  expect(screen.queryByText('Improve Bank defense')).toBeNull();
});

it('keeps the renamed parent workspace active for direct and nested legacy case links',async()=>{
  history.replaceState(null,'','/#/case-overview/revision-a?customer=fictional-bank&environment=windows-ad');
  render(<App/>);await screen.findByRole('heading',{name:'Cases & Analysis',exact:true});
  expect(within(screen.getByRole('navigation',{name:'Workbench navigation'})).getByRole('button',{name:'Cases & Analysis',exact:true}).getAttribute('aria-current')).toBe('page');
});

it('saves a fictional company independently of the sector choice',async()=>{
  let company={name:'Northstar Bank',sector:'finance'};
  const calls=[];
  vi.stubGlobal('fetch',vi.fn(async(input,options)=>{
    if(String(input)==='/api/company-profile'){
      company=JSON.parse(options.body);calls.push(company);return json(company);
    }
    if(String(input)==='/api/bootstrap')return json({...bootstrap,company,company_customer_ids:[company.name==='Cedar Cloud'?'fictional-cloud':'fictional-bank']});
    return respond(input);
  }));
  const user=userEvent.setup();render(<App/>);
  await waitFor(()=>expect(screen.getByRole('combobox',{name:'Working case'}).value).toBe('bank-case'));
  await user.click(screen.getByRole('button',{name:'Customer Profiles',exact:true}));
  await user.selectOptions(screen.getByRole('combobox',{name:'Fictional Company'}),'Cedar Cloud');
  await user.selectOptions(screen.getByRole('combobox',{name:'Primary sector'}),'finance');
  await user.click(screen.getByRole('button',{name:'Save company profile'}));
  await waitFor(()=>expect(calls).toEqual([{name:'Cedar Cloud',sector:'finance'}]));
  await waitFor(()=>expect(location.hash).toContain('environment=mac-cloud'));
  expect(screen.queryByRole('combobox',{name:'Active customer'})).toBeNull();
});

it('shows the company’s Brotli working case from another environment and switches scope with it',async()=>{
  history.replaceState(null,'','/#/cases-and-analysis?customer=fictional-bank&environment=windows-ad');
  const brotli={...cloudCase,source:{...cloudCase.source,title:'Brotli exposure response'}};
  const choices=[{id:bankCase.id,title:bankCase.source.title,customer_id:'fictional-bank',environment_id:'windows-ad'},{id:brotli.id,title:brotli.source.title,customer_id:'fictional-cloud',environment_id:'mac-cloud'}];
  vi.stubGlobal('fetch',vi.fn(async input=>{
    const url=new URL(String(input),'http://localhost');
    if(url.pathname==='/api/bootstrap')return json({...bootstrap,company:{name:'Harborlight Capital',sector:'finance'},company_customer_ids:['fictional-bank','fictional-cloud']});
    if(url.pathname==='/api/exposure-overview/portfolio')return json({cases:choices});
    if(url.pathname==='/api/assessments'&&url.searchParams.get('customer_id')==='fictional-cloud')return json([brotli]);
    return respond(input);
  }));
  const user=userEvent.setup();render(<App/>);
  await screen.findByRole('option',{name:'Brotli exposure response · Mac Cloud'});
  await user.selectOptions(screen.getByRole('combobox',{name:'Working case'}),'cloud-case');
  await waitFor(()=>expect(screen.getByRole('combobox',{name:'Working case'}).value).toBe('cloud-case'));
  expect(location.hash).toContain('environment=mac-cloud');expect(location.hash).toContain('assessment=cloud-case');
  expect(vi.mocked(fetch).mock.calls.some(([url])=>String(url).includes('/api/ledger/bank-case?customer_id=fictional-cloud'))).toBe(false);
});

it('opens a working-case count as an open-only action list and preserves it while inspecting',async()=>{
  const open=actionRow(true),closed={...actionRow(true),id:'closed-action',status:'closed',proposed_change:'Closed fixture change'};
  vi.stubGlobal('fetch',vi.fn(async input=>{
    const url=new URL(String(input),'http://localhost');
    if(url.pathname==='/api/exposure-overview/portfolio')return json({as_of:'2026-11-08T00:00:00Z',cases:[{id:bankCase.id,title:bankCase.source.title,customer_id:'fictional-bank',environment_id:'windows-ad'}],scopes:[{customer_id:'fictional-bank',environment_id:'windows-ad',environment_name:'Windows AD',cases:1,open_actions:1}],revision_count:1,policy:'Fixture'});
    if(url.pathname==='/api/improvements')return json({rows:[open,closed]});
    return respond(input);
  }));
  const {user}=await mount();
  await user.click(screen.getByRole('button',{name:'Exposure Overview',exact:true}));
  await user.click(await screen.findByRole('button',{name:'Open Working Cases'}));
  await user.click(screen.getByRole('button',{name:/Bank investigation.*1 open actions/}));
  await screen.findByText('Showing 1 open action.');expect(location.hash).toContain('work=open');
  expect(screen.queryByText('Closed fixture change')).toBeNull();
  await user.click(screen.getByRole('button',{name:'Inspect action bank-action'}));
  await screen.findByRole('button',{name:'Open originating workflow'});expect(location.hash).toContain('work=open');
  await user.click(screen.getByRole('button',{name:'Close action details'}));expect(location.hash).toContain('work=open');
  await user.click(screen.getByRole('button',{name:'Show all scoped actions'}));
  await screen.findByText('Closed fixture change');expect(location.hash).not.toContain('work=open');
});
