# Workbench themes

The **Appearance** dropdown in the main top bar offers:

- **Original · Forest**: the original layout and palette, selected by default.
- **Ocean**: light surfaces, navy navigation, blue actions and cyan highlights.
- **Midnight**: dark charcoal surfaces, violet actions and teal highlights.
- **Golden Ledger**: yellow navigation and actions, warm white surfaces, charcoal text, green details and serif display headings.

This is one workbench with four color palettes. Switching themes preserves customer/environment selection, source evidence and operational state. The preference uses browser localStorage (`iti.appearance.theme`), not customer records. Invalid stored values fall back to Original. With storage disabled, switching still works for the current session. Native form color scheme and browser theme-color follow the palette. Responsive styling keeps the control visible on narrower screens.

## Sources

Inspected the companies' official public sites and their linked stylesheets on 2026-10-08:

- [SailPoint](https://www.sailpoint.com/): navy `#011c48`, blue `#0033a1`, link blue `#004fb5`, cyan `#54c0e8`, light background `#f2f5f7`.
- [Dropzone AI](https://www.dropzone.ai/): stylesheet swatches `--swatch--dark: #14141c`, `--swatch--dark-secondary: #1c1f29`, `--swatch--brand: #606eea`, `--swatch--brand-2: #1cb797`. The workbench darkens primary-button violet to `#5664db` for readable white labels and uses lighter violet links on dark surfaces.

These are independently implemented brand-inspired palettes; the app retains its own identity and icons. No external company CSS, fonts, scripts or logos are bundled or loaded by the theme.

## Verification

- TypeScript/Vite production build.
- Executed all three state changes and preference persistence against the actual TypeScript theme module with DOM/storage stubs; also checked invalid-value fallback, blocked storage, and browser meta color updates. These are scoped functional checks, not a rendered-browser test.
- Calculated WCAG contrast for body/muted text, links, buttons, sidebar text and semantic status labels in both added palettes; recorded results in `validation/themes.json`. All checked normal-text pairs meet 4.5:1. This is not a full accessibility certification.
- Browser visual review remains unavailable under this session's computer-use permissions. No screenshot or rendered-browser success is claimed.

Theme behavior lives in `web/src/theme.ts`, and palette/scoped overrides live in `web/src/themes.css`. Original styles are preserved in `web/src/style.css`; alternate overrides only apply when their theme is selected.
