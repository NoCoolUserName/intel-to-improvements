export function analysisMode(mode: string): {label: string; description: string} {
  if (mode === 'live') return {label: 'Model API analysis', description: 'This result was produced through the configured model API. This is an analysis method, not a connection-status indicator.'};
  if (mode === 'replay') return {label: 'Saved demo analysis', description: 'Previously curated findings for exact known source content; no new model request.'};
  if (mode === 'offline') return {label: 'Local analysis · no AI', description: 'Fixed recognition rules run on this computer. URLs can still be fetched over the internet. Select Model API analysis for a new API-backed assessment; existing results keep their original method.'};
  return {label: 'Unknown analysis method', description: 'No recognized processing method was recorded.'};
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return 'Pending';
  if (seconds < 60) return `${Math.max(0, seconds).toFixed(1)}s`;
  const whole = Math.floor(seconds);
  const days = Math.floor(whole / 86400);
  const hours = Math.floor(whole % 86400 / 3600);
  const minutes = Math.floor(whole % 3600 / 60);
  if (days) return `${days}d ${hours}h ${minutes}m`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${whole % 60}s`;
}

// Only bundled edge-case examples are hidden; real sources with insufficient
// evidence remain visible and retain their honest Unknown relevance assessment.
export function isTestCase(source: {origin?: string}): boolean {
  return ['authored-fixture:insufficient', 'authored-fixture:held-out', 'authored-fixture:held-out-cloud'].includes(source.origin ?? '');
}
export function isTestDemo(id: string): boolean {
  return ['insufficient', 'held-out', 'held-out-cloud'].includes(id);
}
