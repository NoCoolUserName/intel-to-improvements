import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,render,screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PriorityDecisions from '../src/PriorityDecisions';
afterEach(cleanup);
it('keeps severity, exploitation, reviewed response and absent validation separate',async()=>{
 const row={id:'decision',cve:'CVE-2026-0001',asset:'advisor',owner:'Engineering',severity:'Severity not available',exploitation:'Reviewed exploitation / KEV evidence',applicability:'confirmed affected',reachability:'confirmed',response:'Investigate applicability/exposure',proposed_response:'Expedite remediation/mitigation',reviewed:true,rationale:'Confirm deployed artifact',validation:'not tested',synthetic:true};
 const onOpen=vi.fn();render(<PriorityDecisions rows={[row]} onOpen={onOpen}/>);
 expect(screen.getByText('Severity not available')).toBeTruthy();expect(screen.getByText('No recorded validation')).toBeTruthy();expect(screen.getByText('Analyst reviewed')).toBeTruthy();
 await userEvent.click(screen.getByRole('button',{name:'CVE-2026-0001 · advisor'}));expect(onOpen).toHaveBeenCalledWith(row);
 expect(screen.getByText('Confirm deployed artifact')).toBeTruthy();
});

it('filters by each card, keeps counts stable and clears selection on a second click',async()=>{
 const rows=[
  {id:'urgent',cve:'CVE-2026-0001',asset:'urgent',response:'Expedite remediation/mitigation',reviewed:true},
  {id:'investigate',cve:'CVE-2026-0002',asset:'investigate',response:'Investigate applicability/exposure',reviewed:false},
  {id:'routine',cve:'CVE-2026-0003',asset:'routine',response:'Routine remediation',reviewed:false}
 ];
 render(<PriorityDecisions portfolio rows={rows} onOpen={vi.fn()}/>);
 for(const [label,ids] of [['Expedite response',['urgent']],['Awaiting analyst review',['investigate','routine']],['Needs exposure investigation',['investigate']],['Asset / CVE decisions',['urgent','investigate','routine']]] as [string,string[]][]){
  const card=screen.getByRole('button',{name:label});
  await userEvent.click(card);
  expect(card.getAttribute('aria-pressed')).toBe('true');
  for(const row of rows)expect(!!screen.queryByRole('button',{name:row.cve+' · '+row.asset})).toBe(ids.includes(row.id));
  expect(screen.getByRole('button',{name:'Asset / CVE decisions'}).textContent).toContain('3');
  await userEvent.click(card);
  expect(card.getAttribute('aria-pressed')).toBe('false');
  expect(screen.getAllByRole('row')).toHaveLength(4);
 }
 await userEvent.click(screen.getByRole('button',{name:'Expedite response'}));
 await userEvent.click(screen.getByRole('button',{name:'Needs exposure investigation'}));
 expect(screen.getByRole('button',{name:'Expedite response'}).getAttribute('aria-pressed')).toBe('false');
});
