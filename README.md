# CSP Inspector (Chrome extension)

View and parse the current page's Content-Security-Policy, capture CSP violations, and test URLs against the policy.

## Install

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select this folder.
3. Pin the extension, then **reload any tab you want to inspect** (content scripts only attach to pages loaded after install).

After editing the code, click the reload icon on the extension card, then reload the page.

## Features

- **Policy**: every policy on the page (enforced header, report-only header, `<meta>` tag), one row per directive with
  colour-coded sources. Includes lint warnings (`'unsafe-inline'`, `'unsafe-eval'`, broad sources, duplicates, unknown
  directives, missing `object-src` / `base-uri` / reporting) and which unset fetch directives fall back to which.
  The filter box highlights matching sources. Click a source to copy it, or copy the whole policy raw or one directive per line.
- **Violations**: `securitypolicyviolation` events from the tab, de-duplicated with counts, showing directive, blocked URL,
  source file:line, and the source to add (`connect-src https://host`). The badge shows the count. Violations raised
  inside iframes (for example the Midtrans payment frame) are hidden by default, because they come from that frame's own
  CSP, not ours. **Copy suggested additions** gives one line per directive.
- **Test URL**: checks whether a URL is allowed for a directive (with `default-src` / `child-src` fallback, wildcards,
  ports, paths and scheme upgrades) and shows which source matched.

## How the policy is read

The background worker records the CSP response headers of each top-level navigation. If none were recorded for the tab
(for example the extension was installed after the page loaded, or a service worker served the page from cache), the
popup re-fetches the current URL from the page and reads the headers. **Refetch** forces this.

Violations are kept per tab and cleared on the next full page load. SPA route changes keep collecting into the same list.

## Files

- `icons/`: `icon.svg` source plus 16/32/48/128 PNGs
- `manifest.json`: MV3 manifest (`webRequest`, `storage`, `scripting`, all hosts)
- `background.js`: header capture, violation store, badge
- `content.js`: forwards `securitypolicyviolation` events
- `csp.js`: parser, fallback resolution, source matching, warnings, fix suggestions
- `popup.html` / `popup.css` / `popup.js`: UI
