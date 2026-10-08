export const THEMES = [
  { id: 'original', label: 'Original · Forest' },
  { id: 'sailpoint', label: 'SailPoint · Ocean' },
  { id: 'dropzone', label: 'Dropzone AI · Midnight' },
] as const;
export type ThemeId = typeof THEMES[number]['id'];
const STORAGE_KEY = 'iti.appearance.theme';

export function readTheme(): ThemeId {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    return THEMES.find(theme => theme.id === saved)?.id ?? 'original';
  } catch {
    return 'original';
  }
}

export function applyTheme(theme: ThemeId) {
  document.documentElement.dataset.theme = theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  meta?.setAttribute('content', { original: '#152d31', sailpoint: '#011c48', dropzone: '#14141c' }[theme]);
  try { window.localStorage.setItem(STORAGE_KEY, theme); } catch { /* Storage may be disabled. */ }
}
