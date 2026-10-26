/* global CSP */
'use strict';

const $ = (sel) => document.querySelector(sel);

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

const state = {
  tab: null,
  pageUrl: '',
  policies: [], // [{ kind: 'enforce' | 'report-only' | 'meta', policy }]
  source: '',
  error: '',
  violations: [],
};

function toast(text) {
  const el = $('#toast');
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 1400);
}

async function copy(text, label = 'Copied') {
  await navigator.clipboard.writeText(text);
  toast(label);
}

// ---------- Loading ----------

// Runs in the page: reads <meta> CSP tags and, when asked, re-fetches the page to read its headers.
async function readPageCsp(doFetch) {
  const meta = [...document.querySelectorAll('meta[http-equiv]')]
    .filter((m) => m.httpEquiv.toLowerCase() === 'content-security-policy')
    .map((m) => m.content);
  const out = { url: location.href, meta, enforce: [], reportOnly: [] };
  if (!doFetch) return out;
  try {
    const res = await fetch(location.href, { cache: 'no-store', credentials: 'include' });
    out.status = res.status;
    out.enforce = [res.headers.get('content-security-policy')].filter(Boolean);
    out.reportOnly = [res.headers.get('content-security-policy-report-only')].filter(Boolean);
  } catch (e) {
    out.error = String(e);
  }
  return out;
}

async function runInPage(doFetch) {
  const [injection] = await chrome.scripting.executeScript({
    target: { tabId: state.tab.id },
    func: readPageCsp,
    args: [doFetch],
  });
  return injection.result;
}

function setPolicies(record, meta) {
  state.policies = [
    ...CSP.parseHeaderValues(record.enforce).map((policy) => ({ kind: 'enforce', policy })),
    ...CSP.parseHeaderValues(record.reportOnly).map((policy) => ({ kind: 'report-only', policy })),
    ...CSP.parseHeaderValues(meta).map((policy) => ({ kind: 'meta', policy })),
  ];
}

async function load(forceFetch) {
  state.error = '';
  const tabId = state.tab.id;
  const stored = await chrome.storage.session.get([`hdr:${tabId}`, `vio:${tabId}`]);
  state.violations = stored[`vio:${tabId}`] || [];

  const captured = stored[`hdr:${tabId}`];
  // SPA route changes keep the same document, so a capture for the same origin still applies.
  const capturedUsable = !forceFetch && captured && sameOrigin(captured.url, state.pageUrl);

  try {
    const page = await runInPage(!capturedUsable);
    if (capturedUsable) {
      setPolicies(captured, page.meta);
      state.source = `Response headers of the page load (HTTP ${captured.status}, ${timeAgo(captured.time)})`;
    } else {
      setPolicies(page, page.meta);
      state.source = page.error ? '' : `Re-fetched ${shortUrl(page.url)} (HTTP ${page.status})`;
      if (page.error) state.error = `Could not re-fetch the page: ${page.error}`;
    }
  } catch (e) {
    if (captured) {
      setPolicies(captured, []);
      state.source = `Response headers of the page load (HTTP ${captured.status})`;
    } else {
      state.policies = [];
      state.error = `Cannot read this page (${e.message}). Reload the tab and try again.`;
    }
  }
  renderAll();
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch (_) {
    return false;
  }
}

function shortUrl(u) {
  try {
    const url = new URL(u);
    return url.host + url.pathname;
  } catch (_) {
    return u;
  }
}

function timeAgo(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

// ---------- Policy view ----------

function renderPolicies() {
  const root = $('#policies');
  root.replaceChildren();
  $('#origin-note').textContent = state.source;

  if (state.error) root.append(h('div', { class: 'error' }, state.error));
  if (!state.policies.length) {
    if (!state.error) root.append(h('div', { class: 'empty' }, 'This page has no Content-Security-Policy (header, report-only header or <meta>).'));
    return;
  }

  const q = $('#filter').value.trim().toLowerCase();
  state.policies.forEach(({ kind, policy }, i) => root.append(renderPolicyCard(kind, policy, i, q)));
}

function renderPolicyCard(kind, policy, index, q) {
  const label = { enforce: 'Enforced', 'report-only': 'Report-only', meta: '<meta> tag' }[kind];
  const formatted = [...policy.directives].map(([n, s]) => [n, ...s].join(' ')).join(';\n');

  const rows = [];
  for (const [name, sources] of policy.directives) {
    const nameHit = q && name.includes(q);
    const chips = sources.map((src) => {
      const hit = q && src.toLowerCase().includes(q);
      const cls = ['chip', CSP.sourceKind(src), hit && 'hit', q && !hit && !nameHit && 'dim'].filter(Boolean).join(' ');
      return h('span', { class: cls, title: 'Click to copy', onclick: () => copy(src) }, src);
    });
    if (q && !nameHit && !sources.some((s) => s.toLowerCase().includes(q))) continue;
    const known = CSP.FETCH_DIRECTIVES.includes(name) || CSP.TESTABLE_DIRECTIVES.includes(name)
      || ['sandbox', 'report-uri', 'report-to', 'upgrade-insecure-requests', 'block-all-mixed-content',
        'require-trusted-types-for', 'trusted-types', 'webrtc', 'fenced-frame-src'].includes(name);
    rows.push(h('tr', null,
      h('td', { class: `dir${known ? '' : ' unknown'}` }, name, h('div', { class: 'muted' }, sources.length ? `${sources.length}` : '')),
      h('td', null, sources.length ? h('div', { class: 'chips' }, chips) : h('span', { class: 'empty-list' }, '(no value)'))));
  }

  const missing = CSP.FETCH_DIRECTIVES.filter((d) => d !== 'default-src' && !policy.directives.has(d));
  const fallbackLines = missing.map((d) => {
    const eff = CSP.effectiveDirective(policy, d);
    return eff ? `${d} → ${eff}` : `${d} → unrestricted`;
  });

  const warnings = CSP.warnings(policy, kind);

  return h('div', { class: 'card' },
    h('div', { class: 'card-head' },
      h('span', { class: `badge ${kind}` }, label),
      h('span', { class: 'muted' }, `Policy ${index + 1} · ${policy.directives.size} directives`),
      h('span', { class: 'spacer' }),
      h('button', { onclick: () => copy(policy.raw, 'Raw policy copied') }, 'Copy raw'),
      h('button', { onclick: () => copy(formatted, 'Formatted policy copied') }, 'Copy formatted')),
    warnings.length && !q ? h('ul', { class: 'warnings' }, warnings.map((w) => h('li', { class: w.level }, w.text))) : null,
    rows.length ? h('table', null, rows) : h('div', { class: 'empty' }, 'No directive matches the filter.'),
    fallbackLines.length && !q ? h('div', { class: 'fallbacks' }, 'Not set (uses fallback): ',
      fallbackLines.map((l, i) => [i ? ', ' : '', h('code', null, l)])) : null);
}

// ---------- Violations view ----------

function visibleViolations() {
  const topOnly = $('#top-only').checked;
  return state.violations.filter((v) => !topOnly || v.isTop);
}

function renderViolations() {
  const list = visibleViolations();
  $('#vio-count').textContent = state.violations.length ? String(state.violations.length) : '';
  const root = $('#violations');
  root.replaceChildren();
  if (!list.length) {
    root.append(h('div', { class: 'empty' }, state.violations.length
      ? 'No violations in the top frame. Untick "Top frame only" to see iframe violations.'
      : 'No violations captured since this page loaded. Use the page (or reload it) to collect them.'));
    return;
  }

  const sorted = [...list].sort((a, b) => b.lastSeen - a.lastSeen);
  for (const v of sorted) {
    const suggestion = CSP.suggestionFor(v.blocked);
    const where = v.source ? `${v.source}${v.line ? `:${v.line}` : ''}${v.column ? `:${v.column}` : ''}` : '';
    root.append(h('div', { class: 'vio' },
      h('div', { class: 'vio-head' },
        h('span', { class: `badge ${v.disposition}` }, v.disposition === 'enforce' ? 'Blocked' : 'Report-only'),
        h('code', null, v.directive),
        h('span', { class: 'spacer' }),
        h('span', { class: 'times' }, `${v.count}× · ${timeAgo(v.lastSeen)}`)),
      h('div', { class: 'vio-body' },
        h('span', { class: 'k' }, 'Blocked'), h('span', { class: 'v' }, v.blocked || '(empty)'),
        suggestion ? [h('span', { class: 'k' }, 'Add'), h('span', { class: 'v' }, `${fixDirective(v)} ${suggestion}`)] : null,
        where ? [h('span', { class: 'k' }, 'Source'), h('span', { class: 'v' }, where)] : null,
        v.sample ? [h('span', { class: 'k' }, 'Sample'), h('span', { class: 'v' }, v.sample)] : null,
        [h('span', { class: 'k' }, 'Document'), h('span', { class: 'v' }, v.documentUrl)]),
      v.isTop ? null : h('div', { class: 'vio-note' },
        `From an iframe (${v.frameOrigin}). This is that frame's own CSP, not this page's policy.`),
      h('div', { class: 'vio-actions' },
        suggestion ? h('button', { onclick: () => copy(suggestion) }, 'Copy source') : null,
        /^https?:|^wss?:/.test(v.blocked || '') ? h('button', { onclick: () => openTest(v.directive, v.blocked) }, 'Test against policy') : null)));
  }
}

// The directive to edit: the reported one, or the fallback it resolves to in the matching policy
// (a "script-src-elem" violation is fixed in script-src when script-src-elem isn't set).
function fixDirective(v) {
  if (!v.isTop) return v.directive;
  const kind = v.disposition === 'report' ? 'report-only' : 'enforce';
  for (const { kind: k, policy } of state.policies) {
    if (k !== kind && !(kind === 'enforce' && k === 'meta')) continue;
    const eff = CSP.effectiveDirective(policy, v.directive);
    if (eff) return eff;
  }
  return v.directive;
}

function suggestionsText() {
  const byDirective = new Map();
  for (const v of visibleViolations()) {
    const s = CSP.suggestionFor(v.blocked);
    if (!s) continue;
    const d = fixDirective(v);
    if (!byDirective.has(d)) byDirective.set(d, new Set());
    byDirective.get(d).add(s);
  }
  return [...byDirective].map(([d, set]) => `${d} ${[...set].join(' ')}`).join('\n');
}

// ---------- Test view ----------

function openTest(directive, url) {
  $('#test-directive').value = directive in CSP.FALLBACK || CSP.TESTABLE_DIRECTIVES.includes(directive) ? directive : 'connect-src';
  $('#test-url').value = url;
  showView('test');
  runTest();
}

function runTest() {
  const directive = $('#test-directive').value;
  const target = $('#test-url').value.trim();
  const root = $('#test-results');
  root.replaceChildren();
  if (!target) return;
  if (!state.policies.length) {
    root.append(h('div', { class: 'empty' }, 'No policy on this page, so everything is allowed.'));
    return;
  }
  state.policies.forEach(({ kind, policy }, i) => {
    const r = CSP.check(policy, directive, target, state.pageUrl);
    const label = { enforce: 'Enforced', 'report-only': 'Report-only', meta: '<meta> tag' }[kind];
    const verdict = r.allowed ? 'Allowed' : (kind === 'report-only' ? 'Would be reported' : 'Blocked');
    root.append(h('div', { class: `result ${r.allowed ? 'allowed' : 'blocked'}` },
      h('div', { class: 'vio-head' },
        h('span', { class: `badge ${kind}` }, label),
        h('span', { class: 'muted' }, `Policy ${i + 1}`),
        h('span', { class: 'verdict' }, verdict)),
      h('div', { class: 'vio-body' },
        h('span', { class: 'k' }, 'Directive'),
        h('span', { class: 'v' }, r.effective ? (r.effective === directive ? directive : `${directive} → falls back to ${r.effective}`) : directive),
        r.matchedBy ? [h('span', { class: 'k' }, 'Matched'), h('span', { class: 'v' }, r.matchedBy)] : null,
        r.reason ? [h('span', { class: 'k' }, 'Why'), h('span', { class: 'v' }, r.reason)] : null,
        !r.allowed && CSP.suggestionFor(target)
          ? [h('span', { class: 'k' }, 'Fix'), h('span', { class: 'v' }, `add ${CSP.suggestionFor(target)} to ${r.effective || directive}`)]
          : null)));
  });
}

// ---------- Wiring ----------

function showView(name) {
  for (const btn of document.querySelectorAll('.tab')) btn.classList.toggle('active', btn.dataset.view === name);
  for (const view of document.querySelectorAll('.view')) view.hidden = view.id !== `view-${name}`;
}

function renderAll() {
  renderPolicies();
  renderViolations();
}

async function init() {
  [state.tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.pageUrl = state.tab.url || '';
  $('#page').textContent = state.pageUrl;
  $('#page').title = state.pageUrl;

  const select = $('#test-directive');
  for (const d of CSP.TESTABLE_DIRECTIVES) select.append(h('option', { value: d }, d));
  select.value = 'connect-src';

  for (const btn of document.querySelectorAll('.tab')) btn.addEventListener('click', () => showView(btn.dataset.view));
  $('#filter').addEventListener('input', renderPolicies);
  $('#top-only').addEventListener('change', renderViolations);
  $('#refetch').addEventListener('click', () => load(true));
  $('#copy-suggestions').addEventListener('click', () => {
    const text = suggestionsText();
    if (text) copy(text, 'Suggestions copied');
    else toast('Nothing to suggest');
  });
  $('#clear-violations').addEventListener('click', async () => {
    await chrome.storage.session.set({ [`vio:${state.tab.id}`]: [] });
    await chrome.action.setBadgeText({ tabId: state.tab.id, text: '' });
  });
  $('#test-form').addEventListener('submit', (e) => {
    e.preventDefault();
    runTest();
  });

  chrome.storage.session.onChanged.addListener((changes) => {
    const change = changes[`vio:${state.tab.id}`];
    if (change) {
      state.violations = change.newValue || [];
      renderViolations();
    }
  });

  await load(false);
  if (state.violations.length) showView('violations');
}

init();
