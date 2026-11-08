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
