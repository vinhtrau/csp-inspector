// Forwards CSP violation events from every frame to the background worker.
document.addEventListener('securitypolicyviolation', (e) => {
  try {
    chrome.runtime.sendMessage({
      type: 'csp-violation',
      violation: {
        directive: e.effectiveDirective || e.violatedDirective,
        violatedDirective: e.violatedDirective,
        blocked: e.blockedURI,
        disposition: e.disposition, // "enforce" or "report"
        source: e.sourceFile,
        line: e.lineNumber,
        column: e.columnNumber,
        sample: e.sample,
        documentUrl: e.documentURI,
        frameOrigin: location.origin,
        isTop: window === window.top,
      },
    }).catch(() => {});
  } catch (_) {
    // Extension was reloaded; this content script is orphaned.
  }
}, true);
