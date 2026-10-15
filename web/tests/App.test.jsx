import React from 'react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import {act, cleanup, render, screen, waitFor, within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from '../src/App';

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
  artifacts: {names: ['cti.stix21.json', 'cti.misp.json', 'package.zip'], validation: {status: 'fixture'}}};
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
    case '/api/evaluation': return json({status: 'NOT RUN'});
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
  document.head.innerHTML = '<meta name="theme-color" content="#152d31">';
  vi.stubGlobal('fetch', vi.fn(async input => respond(input)));
});
afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks();});
async function mount() {
  const user = userEvent.setup();
  const view = render(<App/>);
  await screen.findByRole('option', {name: 'Fictional Cloud'});
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('bank-case'));
  return {user, ...view};
}

it('keeps the chosen theme across customer changes and a remount', async () => {
  const {user, unmount} = await mount();
  await user.selectOptions(screen.getByRole('combobox', {name: 'Color theme'}), 'dropzone');
  await user.selectOptions(screen.getByRole('combobox', {name: 'Active customer'}), 'fictional-cloud');
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('cloud-case'));
  expect(screen.getByRole('combobox', {name: 'Active environment'}).value).toBe('mac-cloud');
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
  await user.click(screen.getByRole('button', {name: 'Intelligence exports'}));
  for (const [label, name] of [['cti.stix21.json', 'cti.stix21.json'], ['cti.misp.json', 'cti.misp.json'], ['Download ZIP', 'package.zip']]) {
    const link = screen.getByRole('link', {name: label});
    expect(link.getAttribute('href')).toBe(`/api/artifacts/bank-package/${name}?customer_id=fictional-bank&environment_id=windows-ad`);
  }
  await user.selectOptions(screen.getByRole('combobox', {name: 'Active customer'}), 'fictional-cloud');
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
  await screen.findByRole('option', {name: 'Fictional Cloud'});
  await user.selectOptions(screen.getByRole('combobox', {name: 'Active customer'}), 'fictional-cloud');
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('cloud-case'));
  await act(async () => {releaseBank();});
  expect(screen.getByRole('combobox', {name: 'Working case'}).value).toBe('cloud-case');
  expect(screen.queryByRole('option', {name: /Bank investigation/})).toBeNull();
  expect(screen.queryByRole('button', {name: 'Bank investigation behavior'})).toBeNull();
});

