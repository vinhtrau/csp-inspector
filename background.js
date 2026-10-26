// Captures CSP response headers of top-level navigations and collects violations per tab.
const MAX_VIOLATIONS = 500;
const headerKey = (tabId) => `hdr:${tabId}`;
const violationKey = (tabId) => `vio:${tabId}`;

// Serialise read-modify-write updates so concurrent violations don't overwrite each other.
let queue = Promise.resolve();
function update(key, fn) {
  queue = queue.then(async () => {
    const stored = await chrome.storage.session.get(key);
    const next = fn(stored[key]);
    await chrome.storage.session.set({ [key]: next });
    return next;
  }).catch((err) => console.error('CSP Inspector storage update failed', err));
  return queue;
}

function setBadge(tabId, count) {
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#c62828' }).catch(() => {});
  chrome.action.setBadgeText({ tabId, text: count ? String(count) : '' }).catch(() => {});
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const headers = details.responseHeaders || [];
    const pick = (name) => headers.filter((h) => h.name.toLowerCase() === name).map((h) => h.value || '');
    chrome.storage.session.set({
      [headerKey(details.tabId)]: {
        url: details.url,
        status: details.statusCode,
        time: Date.now(),
        enforce: pick('content-security-policy'),
        reportOnly: pick('content-security-policy-report-only'),
      },
    });
    update(violationKey(details.tabId), () => []);
    setBadge(details.tabId, 0);
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders', 'extraHeaders']
);

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.type !== 'csp-violation' || !sender.tab) return;
  const tabId = sender.tab.id;
  const v = msg.violation;
  const id = [v.frameOrigin, v.disposition, v.directive, v.blocked, v.source, v.line].join('|');
  update(violationKey(tabId), (list = []) => {
    const existing = list.find((x) => x.id === id);
    if (existing) {
      existing.count += 1;
      existing.lastSeen = Date.now();
    } else if (list.length < MAX_VIOLATIONS) {
      list.push({ ...v, id, count: 1, firstSeen: Date.now(), lastSeen: Date.now() });
    }
    return list;
  }).then((list) => list && setBadge(tabId, list.length));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([headerKey(tabId), violationKey(tabId)]);
});
