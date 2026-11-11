# StuntKey brand notes (round 11)

## Matched from calasautomations.com (read from C:\Users\danie\calas-site-deploy)
- Tokens from `devtools/stuntkey/index.html`, `calas-ui.css`, `calas-brandbar.js`: paper #fff / #0F2231 dark, sunk #F1F6F9 / #0A1722, ink #12212C / #EEF4F8, ink-2 #4E5B66 / #B2C3CF, rule #D9E3EA / #1E3A4D, accent #155F87 (dark: #5CAAD6), navy #0B2E45, gold #F0C171.
- Gold only as the 2px header hairline, 2px footer top rule, card top borders (3px), step badges and the hero italic word (the site's hero pattern).
- Header (`.cbar` pattern): crest + Libre Baskerville name in blue + mono tagline with blue rule; tagline here is "BY CALAS AUTOMATIONS".
- Crest: the real favicon.png (5039 bytes) base64-embedded as a CSS mask, coloured by the accent; coin-flip `rotateY(0 to 360deg)` 6s linear infinite, no perspective, no preserve-3d; disabled under prefers-reduced-motion. No SVG anywhere.
- Buttons: 6px radius, IBM Plex Sans 600, blue fill, ghost variant, gold CTA variant (as `.btn.gold`).
- Navy hero band with white serif title and gold italic emphasis; footer with small crest and Calas Automations Inc. line.
- An existing page for this product already lives at calas-site-deploy/devtools/stuntkey/index.html; docs/site is aligned to its wording (same facts, same "formerly OathKey and SafeEasyAPI").

## Gaps / differences
- The real site loads shared files (calas-ui.css, calas-nav.css/js, brandbar.js, hero-bg.jpg). StuntKey pages are self-contained, so the site mega-menu and hero photo are NOT copied; the hero uses the navy band only. When hosted under /devtools/stuntkey/, Dan may swap in the site's own header/footer.
- Local page loads no web fonts (privacy: no external requests). It uses Libre Baskerville / IBM Plex if installed, else Georgia / system sans, so headings look slightly different offline. docs/site loads Google Fonts like the real site.
- docs/site has no "Sign in" / site menu links by design. Canonical URLs point at https://calasautomations.com/devtools/stuntkey/.
- Not published anywhere. Rebuild with `python docs/_work/build_brand.py` (sources in docs/_work/brand_src/).
- The site's `og:url` on the live StuntKey page points at /privacy/ (copy-paste bug, in calas-site-deploy, not touched).

## Screenshot check
Playwright is NOT installed on the PC. Used headless Chrome instead (docs/_work/shoot.ps1; 390px is rendered in an exact 390px iframe because headless Chrome will not go below ~500px). Shots in docs/_work/shots/ at 1280 and 390, light and dark, for the local page and the three docs pages. Bug found and fixed: command text invisible in light mode (inline-code style leaking into `.cmd`). No horizontal overflow at 390.
