import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {applyTheme, readTheme} from '../src/theme';

beforeEach(() => {
  localStorage.clear();
  document.head.innerHTML = '<meta name="theme-color" content="#152d31">';
  delete document.documentElement.dataset.theme;
});
afterEach(() => vi.restoreAllMocks());

describe('appearance preferences', () => {
  it.each([null, 'unknown-theme', ''])('uses the default for missing or invalid preference %s', saved => {
    if (saved !== null) localStorage.setItem('iti.appearance.theme', saved);
    expect(readTheme()).toBe('original');
  });
  it.each([
    ['original', '#152d31'], ['sailpoint', '#011c48'], ['dropzone', '#14141c'], ['golden-ledger', '#f5c518'],
  ])('applies and remembers %s', (theme, color) => {
    applyTheme(theme);
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(document.querySelector('meta[name="theme-color"]').content).toBe(color);
    expect(localStorage.getItem('iti.appearance.theme')).toBe(theme);
    expect(readTheme()).toBe(theme);
  });
  it('works when browser storage is blocked', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {throw new Error('blocked');});
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {throw new Error('blocked');});
    expect(readTheme()).toBe('original');
    expect(() => applyTheme('dropzone')).not.toThrow();
    expect(document.documentElement.dataset.theme).toBe('dropzone');
  });
  it('applies the theme without a theme-color meta element', () => {
    document.head.innerHTML = '';
    expect(() => applyTheme('sailpoint')).not.toThrow();
    expect(document.documentElement.dataset.theme).toBe('sailpoint');
  });
});
