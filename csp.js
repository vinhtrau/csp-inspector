// CSP parsing, fallback resolution, URL matching (CSP Level 3, simplified) and lint warnings.
(function (root) {
  'use strict';

  // Fetch directive -> fallback chain (first present wins).
  const FALLBACK = {
    'script-src': ['default-src'],
    'script-src-elem': ['script-src', 'default-src'],
    'script-src-attr': ['script-src', 'default-src'],
    'style-src': ['default-src'],
    'style-src-elem': ['style-src', 'default-src'],
    'style-src-attr': ['style-src', 'default-src'],
    'img-src': ['default-src'],
    'connect-src': ['default-src'],
    'font-src': ['default-src'],
    'media-src': ['default-src'],
    'object-src': ['default-src'],
    'manifest-src': ['default-src'],
    'child-src': ['default-src'],
    'frame-src': ['child-src', 'default-src'],
    'worker-src': ['child-src', 'script-src', 'default-src'],
  };

  const FETCH_DIRECTIVES = ['default-src', ...Object.keys(FALLBACK)];
  const TESTABLE_DIRECTIVES = [...Object.keys(FALLBACK), 'form-action', 'frame-ancestors', 'base-uri'];

  const KNOWN = new Set([
    ...FETCH_DIRECTIVES, 'base-uri', 'form-action', 'frame-ancestors', 'sandbox', 'report-uri', 'report-to',
    'upgrade-insecure-requests', 'block-all-mixed-content', 'require-trusted-types-for', 'trusted-types',
    'webrtc', 'fenced-frame-src', 'prefetch-src', 'navigate-to', 'plugin-types',
  ]);
  const META_IGNORED = ['frame-ancestors', 'report-uri', 'sandbox'];

  const DEFAULT_PORTS = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21' };

  function parsePolicy(text) {
    const directives = new Map();
    const duplicates = [];
    for (const part of text.split(';')) {
      const tokens = part.trim().split(/\s+/).filter(Boolean);
      if (!tokens.length) continue;
      const name = tokens[0].toLowerCase();
      if (directives.has(name)) {
        duplicates.push(name);
        continue;
      }
      directives.set(name, tokens.slice(1));
    }
    return { raw: text.trim(), directives, duplicates };
  }

  // A header can hold several policies separated by commas; repeated headers are separate policies too.
  function parseHeaderValues(values) {
    const policies = [];
    for (const value of values || []) {
      for (const part of value.split(',')) {
        if (part.trim()) policies.push(parsePolicy(part));
      }
    }
    return policies;
  }

  function sourceKind(src) {
    const s = src.toLowerCase();
    if (s === "'none'") return 'none';
    if (s.startsWith("'nonce-")) return 'nonce';
    if (/^'sha(256|384|512)-/.test(s)) return 'hash';
    if (s.startsWith("'unsafe-") || s === "'wasm-unsafe-eval'") return 'unsafe';
    if (s.startsWith("'")) return 'keyword';
    if (s === '*') return 'wildcard';
    if (/^[a-z][a-z0-9+.-]*:$/.test(s)) return 'scheme';
    return 'host';
  }

  function effectiveDirective(policy, name) {
    if (policy.directives.has(name)) return name;
    for (const fallback of FALLBACK[name] || []) {
      if (policy.directives.has(fallback)) return fallback;
    }
    return null;
  }

  // CSP3 "scheme-part match": http: also allows https:, ws: allows wss:/http:/https:, wss: allows https:.
  function schemeMatches(expected, actual) {
    if (expected === actual) return true;
    if (expected === 'http:') return actual === 'https:';
    if (expected === 'ws:') return ['wss:', 'http:', 'https:'].includes(actual);
    if (expected === 'wss:') return actual === 'https:';
    return false;
  }

  const portOf = (u) => u.port || DEFAULT_PORTS[u.protocol] || '';

  function safeDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (_) {
      return s;
    }
  }

  const HOST_SOURCE = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|\*\.[^:/]+|[^:/*]+)(?::(\*|\d+))?(\/.*)?$/i;

  function matchSource(src, url, self) {
    const kind = sourceKind(src);
    const s = src.toLowerCase();

    if (kind === 'wildcard') {
      return ['http:', 'https:', 'ws:', 'wss:', 'ftp:'].includes(url.protocol) || url.protocol === self.protocol;
    }
    if (kind === 'scheme') return schemeMatches(s, url.protocol);
    if (s === "'self'") {
      if (url.hostname !== self.hostname) return false;
      const schemeOk = schemeMatches(self.protocol, url.protocol) || (self.protocol === 'https:' && url.protocol === 'wss:');
      const portOk = portOf(url) === portOf(self) || (!url.port && !self.port);
      return schemeOk && portOk;
    }
    if (kind !== 'host') return false;

    const m = HOST_SOURCE.exec(src);
    if (!m) return false;
    const [, scheme, host, port, path] = m;

    if (scheme) {
      if (!schemeMatches(scheme.toLowerCase() + ':', url.protocol)) return false;
    } else if (self.protocol === 'http:') {
      if (!['http:', 'https:'].includes(url.protocol)) return false;
    } else if (url.protocol !== self.protocol && !(self.protocol === 'https:' && url.protocol === 'wss:')) {
      return false;
    }

    const h = host.toLowerCase();
    const uh = url.hostname.toLowerCase();
    if (h.startsWith('*.')) {
      if (!uh.endsWith(h.slice(1))) return false;
    } else if (h !== '*' && h !== uh) {
      return false;
    }

    if (port && port !== '*') {
      if (port !== portOf(url) && !(port === '80' && portOf(url) === '443')) return false;
    } else if (!port && url.port) {
      return false;
    }

    if (path && path !== '/') {
      const p = safeDecode(path);
      const up = safeDecode(url.pathname);
      if (p.endsWith('/') ? !up.startsWith(p) : up !== p) return false;
    }
    return true;
  }

  // Would `target` be allowed by `policy` for `directive`, on a page at `pageUrl`?
  function check(policy, directive, target, pageUrl) {
    const effective = effectiveDirective(policy, directive);
    if (!effective) {
      return { effective: null, allowed: true, reason: `No ${directive} or fallback directive, so it is not restricted` };
    }
    let url;
    let self;
    try {
      self = new URL(pageUrl);
      url = new URL(target, pageUrl);
    } catch (_) {
      return { effective, allowed: false, reason: 'Invalid URL' };
    }
    const sources = policy.directives.get(effective);
    for (const src of sources) {
      if (matchSource(src, url, self)) return { effective, allowed: true, matchedBy: src };
    }
    let reason = 'No source in the list matches';
    if (!sources.length) reason = 'Empty source list (same as \'none\')';
    else if (sources.length === 1 && sources[0].toLowerCase() === "'none'") reason = `${effective} is 'none', so everything is blocked`;
    return { effective, allowed: false, reason };
  }

  // What to add to a directive so a violation would be allowed.
  function suggestionFor(blocked) {
    const b = (blocked || '').trim();
    if (b === 'inline') return "'unsafe-inline'";
    if (b === 'eval') return "'unsafe-eval'";
    if (b === 'wasm-eval') return "'wasm-unsafe-eval'";
    if (b === 'trusted-types-policy' || b === 'trusted-types-sink') return null;
    if (/^[a-z][a-z0-9+.-]*$/i.test(b)) return b.toLowerCase() + ':'; // "data", "blob"
    try {
      const u = new URL(b);
      if (['data:', 'blob:', 'filesystem:'].includes(u.protocol)) return u.protocol;
      return u.origin;
    } catch (_) {
      return b || null;
    }
  }

  function warnings(policy, kind) {
    const out = [];
    const d = policy.directives;
    const add = (level, text) => out.push({ level, text });

    for (const name of policy.duplicates) add('warn', `Duplicate "${name}" is ignored; only the first one counts.`);
    for (const name of d.keys()) {
      if (!KNOWN.has(name)) add('warn', `Unknown directive "${name}" (typo or unsupported).`);
    }
    if (kind === 'meta') {
      for (const name of META_IGNORED) {
        if (d.has(name)) add('warn', `"${name}" is ignored when the policy is set with a <meta> tag.`);
      }
    }

    const scriptDir = effectiveDirective(policy, 'script-src');
    if (!scriptDir) {
      add('bad', 'Scripts are not restricted (no script-src or default-src).');
    } else {
      const srcs = d.get(scriptDir).map((s) => s.toLowerCase());
      const hasNonceOrHash = srcs.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
      if (srcs.includes("'unsafe-inline'")) {
        add(hasNonceOrHash ? 'info' : 'warn', hasNonceOrHash
          ? `${scriptDir}: 'unsafe-inline' is ignored by modern browsers because a nonce or hash is present.`
          : `${scriptDir} allows inline scripts ('unsafe-inline').`);
      }
      if (srcs.includes("'unsafe-eval'")) add('warn', `${scriptDir} allows eval() ('unsafe-eval').`);
      for (const broad of ['*', 'https:', 'http:', 'data:']) {
        if (srcs.includes(broad)) add('bad', `${scriptDir} allows scripts from any "${broad}" source.`);
      }
      if (srcs.includes("'strict-dynamic'")) add('info', `${scriptDir} uses 'strict-dynamic'; host allow-lists are ignored by CSP3 browsers.`);
    }

    const objectDir = effectiveDirective(policy, 'object-src');
    if (!objectDir || d.get(objectDir).join(' ').toLowerCase() !== "'none'") {
      add('info', "object-src is not 'none' (plugins/<object> allowed).");
    }
    if (!d.has('base-uri')) add('info', 'base-uri is not set, so injected <base> tags are not restricted.');
    if (kind !== 'meta' && !d.has('frame-ancestors')) add('info', 'frame-ancestors is not set (clickjacking protection relies on X-Frame-Options).');
    if (!d.has('report-uri') && !d.has('report-to')) add('info', 'No report-uri/report-to: violations only show in the browser console.');
    return out;
  }

  const api = {
    FALLBACK, FETCH_DIRECTIVES, TESTABLE_DIRECTIVES,
    parsePolicy, parseHeaderValues, sourceKind, effectiveDirective, matchSource, check, suggestionFor, warnings,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.CSP = api;
})(typeof self !== 'undefined' ? self : this);
