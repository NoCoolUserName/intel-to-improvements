import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,render,screen,within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WorkspaceNavigation,{parseWorkspaceHash,workspaceHash} from '../src/navigation';
afterEach(cleanup);
const groups=['Overview','Intelligence','Exposures & Improvements','Validation','Assurance & Quality','Workspace'];
const labels=['Exposure Overview','Coverage','Add Intelligence','Cases & Analysis','Vulnerability Intelligence','Intelligence Exports','Application Findings','Improvement Actions','Hunts','Purple Team','Pipeline Assurance','Evaluation','Customer Profiles'];
it('keeps every destination in the specified grouped order with one accessible active item',async()=>{
  const navigate=vi.fn();render(<WorkspaceNavigation active="Case overview" onNavigate={navigate}/>);
  const nav=screen.getByRole('navigation',{name:'Workbench navigation'});
  expect(within(nav).getAllByRole('heading').map(h=>h.textContent)).toEqual(groups);
  expect(within(nav).getAllByRole('button').map(b=>b.textContent)).toEqual(labels);
  expect(within(nav).getByRole('button',{name:'Cases & Analysis'}).getAttribute('aria-current')).toBe('page');
  expect(nav.querySelectorAll('[aria-current=page]').length).toBe(1);
  const user=userEvent.setup();for(const label of labels)await user.click(within(nav).getByRole('button',{name:label,exact:true}));
  expect(navigate.mock.calls.map(c=>c[0])).toEqual(['Exposure Overview','Coverage','Add Intelligence','Case overview','Vulnerability Intelligence','Intelligence exports','Application Findings','Improvement Actions','Hunts','Purple team','Pipeline Assurance','Evaluation','Customer profiles']);
  within(nav).getByRole('button',{name:'Coverage',exact:true}).focus();await user.keyboard('{Enter}');expect(navigate).toHaveBeenLastCalledWith('Coverage');
});
it('resolves direct, nested and legacy labels while retaining explicit scope',()=>{
  const hash=workspaceHash('Improvement Actions',{record:'action / 1',customer:'customer-a',environment:'env-a',assessment:'case-a'});
  expect(parseWorkspaceHash(hash)).toEqual({workspace:'Improvement Actions',record:'action / 1',customer:'customer-a',environment:'env-a',assessment:'case-a'});
  expect(parseWorkspaceHash('#/case-overview').workspace).toBe('Case overview');
  expect(parseWorkspaceHash('#/Case%20overview').workspace).toBe('Case overview');
  expect(parseWorkspaceHash('#/purple-team/scenario-a').workspace).toBe('Purple team');
  expect(parseWorkspaceHash('#/%E0%A4%A').workspace).toBe('Coverage');
  expect(parseWorkspaceHash('#/unknown').workspace).toBe('Coverage');
});
