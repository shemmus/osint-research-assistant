// ── Context Menus ──────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(details => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'osint-lookup',
      title: 'OSINT Lookup: "%s"',
      contexts: ['selection']
    });
    chrome.contextMenus.create({
      id: 'osint-scan',
      title: 'OSINT: Scan page for threats',
      contexts: ['page', 'selection']
    });
  });

  // First-ever install: open the settings page, which doubles as a quick-start
  // guide ("How it works" is the first section). The toolbar popup is easy to
  // miss right after install, so this is the one guaranteed moment to show a
  // brand-new user what the shortcuts do.
  if (details.reason === 'install') {
    chrome.runtime.openOptionsPage();
  }
});

// ── Per-service timeouts ───────────────────────────────────────────────────
// crt.sh regularly takes 20s+; a blanket 8s limit made it fail every time.
const TIMEOUT = {
  feed:    45000,
  otx:     12000,
  ripe:    12000,
  vt:      12000,
  shodan:  12000,
  graph:   20000,
  crtsh:   30000,
  urlscan: 15000,
  rdap:    12000,
  tor:     12000,
  cve:      8000,
  mhr:      8000,
  _default: 8000
};

async function fetchT(url, opts = {}, svc = '_default') {
  const ms   = TIMEOUT[svc] ?? TIMEOUT._default;
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`Timed out after ${ms / 1000}s.`);
    throw e;
  } finally {
    clearTimeout(tid);
  }
}

// ── Cache (chrome.storage.session survives service-worker restarts) ────────
const DEFAULT_TTL = 15 * 60 * 1000;

async function cacheGet(key) {
  try {
    const o = await chrome.storage.session.get(key);
    const e = o[key];
    if (!e) return null;
    if (Date.now() > e.exp) { chrome.storage.session.remove(key); return null; }
    return e.val;
  } catch (_) { return null; }
}

async function cacheSet(key, val, ttl = DEFAULT_TTL) {
  try { await chrome.storage.session.set({ [key]: { val, exp: Date.now() + ttl } }); }
  catch (_) {}
}

// ── Local threat index ─────────────────────────────────────────────────────
// abuse.ch gates its API behind a key but leaves the bulk feeds open. Pulling
// them once and matching locally means page-wide triage costs no requests at
// all, which is the only way to check 40 indicators without hitting a limit.
const FEED_KEY = 'osint_feedindex';
const FEED_TTL = 6 * 60 * 60 * 1000;

const FEEDS = {
  threatfox: 'https://threatfox.abuse.ch/export/json/recent/',
  urlhaus:   'https://urlhaus.abuse.ch/downloads/hostfile/',
  feodo:     'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  openphish: 'https://openphish.com/feed.txt'
};

function hostOf(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch (_) { return null; }
}

async function buildIndex() {
  const idx = { v: 1, at: Date.now(), tf: {}, uh: {}, fd: {}, op: {}, counts: {} };

  // ThreatFox — the only free source that names the malware family.
  try {
    const r = await fetchT(FEEDS.threatfox, {}, 'feed');
    if (r.ok) {
      const d = await r.json();
      let n = 0;
      for (const key of Object.keys(d)) {
        const e = Array.isArray(d[key]) ? d[key][0] : d[key];
        if (!e?.ioc_value) continue;
        let val = String(e.ioc_value).toLowerCase();
        if (e.ioc_type === 'ip:port') val = val.split(':')[0];
        else if (e.ioc_type === 'url') { const h = hostOf(val); if (!h) continue; val = h; }
        idx.tf[val] = [
          e.malware_printable || '',
          e.threat_type || '',
          e.confidence_level ?? '',
          (e.first_seen_utc || '').split(' ')[0]
        ].join('|');
        n++;
      }
      idx.counts.threatfox = n;
    }
  } catch (_) {}

  // URLhaus hosts currently serving malware.
  try {
    const r = await fetchT(FEEDS.urlhaus, {}, 'feed');
    if (r.ok) {
      const txt = await r.text();
      let n = 0;
      for (const line of txt.split('\n')) {
        const s = line.trim();
        if (!s || s.startsWith('#')) continue;
        const host = s.split(/\s+/).pop().toLowerCase();
        if (host && host !== 'localhost') { idx.uh[host] = 1; n++; }
      }
      idx.counts.urlhaus = n;
    }
  } catch (_) {}

  // Feodo Tracker — botnet command-and-control servers.
  try {
    const r = await fetchT(FEEDS.feodo, {}, 'feed');
    if (r.ok) {
      const d = await r.json();
      let n = 0;
      for (const e of (Array.isArray(d) ? d : [])) {
        if (!e.ip_address) continue;
        idx.fd[e.ip_address] = [e.malware || '', e.status || '', e.first_seen || ''].join('|');
        n++;
      }
      idx.counts.feodo = n;
    }
  } catch (_) {}

  // OpenPhish community feed.
  try {
    const r = await fetchT(FEEDS.openphish, {}, 'feed');
    if (r.ok) {
      const txt = await r.text();
      let n = 0;
      for (const line of txt.split('\n')) {
        const h = hostOf(line.trim());
        if (h) { idx.op[h] = 1; n++; }
      }
      idx.counts.openphish = n;
    }
  } catch (_) {}

  idx.total = Object.keys(idx.tf).length + Object.keys(idx.uh).length +
              Object.keys(idx.fd).length + Object.keys(idx.op).length;
  await chrome.storage.local.set({ [FEED_KEY]: idx });
  memoIndex = idx;
  return idx;
}

let indexPromise = null;

// Hold the parsed index for as long as this worker lives. storage.local.get
// deserialises the whole 200 KB structure on every call — measured at 0.9ms,
// against 0.03ms for the lookup it exists to serve. The worker is killed after
// ~30s idle, so this is a cache, not a leak.
let memoIndex = null;

async function getIndex({ force = false } = {}) {
  if (!force) {
    if (memoIndex && memoIndex.v === 1 && Date.now() - memoIndex.at < FEED_TTL) return memoIndex;
    try {
      const o = await chrome.storage.local.get(FEED_KEY);
      const idx = o[FEED_KEY];
      if (idx && idx.v === 1) {
        memoIndex = idx;
        if (Date.now() - idx.at >= FEED_TTL) refreshInBackground();   // stale but usable
        return idx;
      }
    } catch (_) {}
  }
  if (!indexPromise) indexPromise = buildIndex().finally(() => { indexPromise = null; });
  return indexPromise;
}

function refreshInBackground() {
  if (!indexPromise) indexPromise = buildIndex().finally(() => { indexPromise = null; });
}

// Instant, request-free reputation check.
function matchIndex(idx, value, type) {
  if (!idx) return null;
  const v = String(value).toLowerCase();
  const host = (type === 'url') ? hostOf(v) : v;
  const hits = [];

  const tf = idx.tf[host] ?? idx.tf[v];
  if (tf !== undefined) {
    const [malware, threat, conf, seen] = String(tf).split('|');
    hits.push({ src: 'ThreatFox', malware, threat, confidence: conf, firstSeen: seen });
  }
  const fd = idx.fd[v];
  if (fd !== undefined) {
    const [malware, status, seen] = String(fd).split('|');
    hits.push({ src: 'Feodo Tracker', malware, threat: 'botnet_cc', status, firstSeen: seen });
  }
  if (host && idx.uh[host] !== undefined) hits.push({ src: 'URLhaus', threat: 'malware_distribution' });
  if (host && idx.op[host] !== undefined) hits.push({ src: 'OpenPhish', threat: 'phishing' });

  return hits.length ? hits : null;
}

// ── Refang ─────────────────────────────────────────────────────────────────
// Threat-intel IOCs are almost never shared in clickable form.
// 185.220.101[.]45  ·  hxxps://evil[.]com  ·  user[at]mail[.]com
function refang(s) {
  return String(s).trim()
    .replace(/^[<(\[]+|[>)\]]+$/g, '')
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/\[\/\]/g, '/')
    .replace(/\[at\]|\(at\)|\[@\]|\(@\)/gi, '@')
    .replace(/\s+dot\s+/gi, '.')
    .replace(/\s+at\s+/gi, '@')
    .replace(/^hxxp/i, 'http')
    .replace(/^meow/i, 'http')
    .trim();
}

// ── IOC Detection ──────────────────────────────────────────────────────────
const OCT = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_RE = new RegExp(`^${OCT}(?:\\.${OCT}){3}$`);

function detectIOCType(t) {
  if (IPV4_RE.test(t)) return 'ip';
  if (/^[0-9a-fA-F:]{3,39}$/.test(t) && t.split(':').length >= 3) return 'ipv6';
  if (/^[a-fA-F0-9]{64}$/.test(t)) return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(t)) return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(t)) return 'md5';
  if (/^https?:\/\//i.test(t)) return 'url';
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(t)) return 'email';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(t)) return 'domain';
  return 'unknown';
}

function analyze(raw) {
  const original = String(raw).trim();
  const value    = refang(original);
  return { value, original, type: detectIOCType(value), defanged: value !== original };
}

// ── Entry points ───────────────────────────────────────────────────────────
// executeScript resolves only after the injected script has run, so the
// message listener is already registered — no timing guesswork needed.
async function send(tabId, message) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
  await chrome.tabs.sendMessage(tabId, message);
}

async function openPanel(tabId, raw) {
  const { value, original, type, defanged } = analyze(raw);
  await send(tabId, { action: 'showPanel', query: value, original, type, defanged });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  try {
    if (info.menuItemId === 'osint-lookup') {
      await openPanel(tab.id, info.selectionText || '');
    } else if (info.menuItemId === 'osint-scan') {
      await send(tab.id, { action: 'toggleScan' });
    }
  } catch (_) {
    // Restricted page (chrome://, Web Store, PDF viewer) — nothing to inject into.
  }
});

// Keyboard shortcut — analysts live on the keyboard, not the context menu.
chrome.commands.onCommand.addListener(async (cmd, tab) => {
  if (!tab?.id) return;
  try {
    if (cmd === 'lookup-selection') {
      const [r] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => (window.getSelection() ? window.getSelection().toString() : '')
      });
      const sel = (r?.result || '').trim();
      if (sel) await openPanel(tab.id, sel);
    } else if (cmd === 'scan-page') {
      await send(tab.id, { action: 'toggleScan' });
    }
  } catch (_) {}
});

// ── Message Router ─────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  if (msg.action === 'fetchAPI') {
    cachedDispatch(msg).then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'analyze') {
    respond(analyze(msg.raw));
    return false;
  }
  if (msg.action === 'lookupActiveTab') {
    lookupOnActiveTab(msg.raw).then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'scanActiveTab') {
    scanOnActiveTab().then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'caseActiveTab') {
    caseOnActiveTab().then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'triage') {
    triage(msg.iocs || []).then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'feedStatus') {
    feedStatus(msg.refresh).then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'health') {
    healthReport().then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
  if (msg.action === 'resetHealth') {
    chrome.storage.local.remove(HEALTH_KEY).then(() => respond({ ok: true })).catch(() => respond({ ok: true }));
    return true;
  }
  if (msg.action === 'expand') {
    expandNode(msg.value, msg.type).then(respond).catch(e => respond({ error: e.message }));
    return true;
  }
});

// ── Pivot expansion ────────────────────────────────────────────────────────
// Returns the neighbours of one node. The graph itself is walked on the
// content side, one node at a time, so a wide fan-out never blocks the UI and
// the user decides how deep to go.
async function expandNode(value, type) {
  const idx  = await getIndex();
  const out  = [];
  const seen = new Set();
  const add = (v, t, rel, label) => {
    if (!v) return;
    // ASNs and prefixes are identifiers, not hostnames — don't case-fold them.
    const raw = String(v).replace(/\.$/, '');
    const val = (t === 'asn' || t === 'prefix') ? raw.toUpperCase() : raw.toLowerCase();
    if (!val || val.toLowerCase() === String(value).toLowerCase()) return;
    const k = `${t}:${val}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ value: val, type: t, rel, label: label || null, flagged: !!matchIndex(idx, val, t) });
  };

  if (type === 'ip' || type === 'ipv6') {
    const [rp, ia, db] = await Promise.all([
      ripe(value, type).catch(() => null),
      ipapi(value, type).catch(() => null),
      internetdb(value, type).catch(() => null)
    ]);
    if (rp?.asns?.length) {
      const a = rp.asns[0];
      add(`AS${a.asn}`, 'asn', 'announced by', a.holder || null);
    }
    if (rp?.prefix) add(rp.prefix, 'prefix', 'in prefix');
    if (ia?.hostname) add(ia.hostname, 'domain', 'reverse DNS');
    (db?.hostnames || []).slice(0, 8).forEach(h => add(h, 'domain', 'hostname'));
  } else if (type === 'domain' || type === 'url') {
    let host = value;
    if (type === 'url') { try { host = new URL(value).hostname; } catch (_) {} }
    const [dn, ct, wh] = await Promise.all([
      dns(host, 'domain').catch(() => null),
      crtsh(host, 'domain').catch(() => null),
      rdap(host, 'domain').catch(() => null)
    ]);
    (dn?.records?.A    || []).slice(0, 6).forEach(v => add(v, 'ip', 'resolves to'));
    (dn?.records?.AAAA || []).slice(0, 4).forEach(v => add(v, 'ipv6', 'resolves to'));
    (dn?.records?.CNAME|| []).slice(0, 3).forEach(v => add(v, 'domain', 'CNAME'));
    (dn?.records?.MX   || []).slice(0, 3).forEach(v => add(String(v).split(/\s+/).pop(), 'domain', 'MX'));
    (wh?.nameservers   || []).slice(0, 4).forEach(v => add(v, 'domain', 'name server'));
    (ct?.uniqueSubdomains || []).slice(0, 12).forEach(v => add(v, 'domain', 'certificate'));
  } else if (type === 'asn') {
    const as = String(value).toUpperCase().replace(/^AS?/, 'AS');
    const [pfx, nb] = await Promise.all([
      fetchT(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${as}`, {}, 'graph')
        .then(x => x.ok ? x.json() : null).catch(() => null),
      fetchT(`https://stat.ripe.net/data/asn-neighbours/data.json?resource=${as}`, {}, 'graph')
        .then(x => x.ok ? x.json() : null).catch(() => null)
    ]);
    (pfx?.data?.prefixes || []).slice(0, 14).forEach(p => add(p.prefix, 'prefix', 'announces'));
    (nb?.data?.neighbours || []).slice(0, 10).forEach(n => add(`AS${n.asn}`, 'asn', 'peer', n.type || null));
  } else {
    return { neighbours: [], _na: true };
  }

  return { neighbours: out };
}

// ── Bulk triage ────────────────────────────────────────────────────────────
// Only sources that cost nothing per item: the local index for everything, and
// DNS for hashes. A whole threat report can be graded without touching a
// rate-limited API.
async function triage(iocs) {
  const idx = await getIndex();
  const out = await Promise.all(iocs.map(async ({ value, type }) => {
    const hits = matchIndex(idx, value, type);
    let verdict = hits ? 'malicious' : 'unknown';
    let note = '';
    let malware = '';

    if (hits) {
      malware = hits.map(h => h.malware).filter(Boolean)[0] || '';
      note = hits.map(h => h.src).join(', ');
    } else if (type === 'md5' || type === 'sha1') {
      try {
        const m = await mhr(value, type);
        if (m.known) {
          verdict = 'malicious';
          note = 'Team Cymru MHR';
          malware = m.detectionRate != null ? `${m.detectionRate}% AV` : '';
        }
      } catch (_) {}
    } else if (type === 'ip') {
      try {
        const list = await cacheGet('__torexit__');
        if (list && list.includes(value)) { verdict = 'suspicious'; note = 'Tor exit node'; }
      } catch (_) {}
    }
    return { value, type, verdict, note, malware };
  }));

  return { results: out, indexedAt: idx?.at || null, indexSize: idx?.total || 0 };
}

async function feedStatus(refresh) {
  const idx = await getIndex({ force: !!refresh });
  return { at: idx?.at || null, total: idx?.total || 0, counts: idx?.counts || {} };
}

// Warm the index up so the first triage is instant.
chrome.runtime.onInstalled.addListener(() => { getIndex().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => { getIndex().catch(() => {}); });

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { error: 'no-tab' };
  if (/^(chrome|edge|about|devtools|chrome-extension):/i.test(tab.url || '')) {
    return { error: 'restricted-page' };
  }
  return { tab };
}

async function scanOnActiveTab() {
  const a = await activeTab();
  if (a.error) return a;
  try {
    await send(a.tab.id, { action: 'toggleScan' });
  } catch (_) {
    return { error: 'restricted-page' };
  }
  return { ok: true };
}

async function caseOnActiveTab() {
  const a = await activeTab();
  if (a.error) return a;
  try {
    await send(a.tab.id, { action: 'showCase' });
  } catch (_) {
    return { error: 'restricted-page' };
  }
  return { ok: true };
}

// Lookup typed straight into the popup — no selection needed.
async function lookupOnActiveTab(raw) {
  const info = analyze(raw);
  if (info.type === 'unknown') return { error: 'unrecognised' };

  const a = await activeTab();
  if (a.error) return a;
  try {
    await openPanel(a.tab.id, raw);
  } catch (_) {
    return { error: 'restricted-page' };
  }
  return { ok: true, type: info.type };
}

async function cachedDispatch({ service, query, type }) {
  const key = `${service}:${type}:${query}`;
  const hit = await cacheGet(key);
  if (hit) return { ...hit, _cached: true };

  const t0 = Date.now();
  const res = await dispatch({ service, query, type });
  if (!res._na) await recordHealth(service, !res.error, Date.now() - t0, res.error);
  if (!res.error) await cacheSet(key, res);
  return res;
}

// ── Source health ──────────────────────────────────────────────────────────
// Three sources went behind auth while this was being built. Treat upstream
// decay as normal and make it visible instead of silently degrading.
const HEALTH_KEY = 'osint_health';

async function recordHealth(service, ok, ms, err) {
  try {
    const o = await chrome.storage.local.get(HEALTH_KEY);
    const h = o[HEALTH_KEY] || {};
    const s = h[service] || { ok: 0, fail: 0, streak: 0, ms: 0, lastError: null, lastAt: 0 };
    if (ok) {
      s.ok++; s.streak = 0; s.lastError = null;
      s.ms = s.ms ? Math.round(s.ms * 0.7 + ms * 0.3) : ms;   // rolling latency
    } else {
      s.fail++; s.streak++;
      s.lastError = String(err || 'error').slice(0, 120);
    }
    s.lastAt = Date.now();
    h[service] = s;
    await chrome.storage.local.set({ [HEALTH_KEY]: h });
  } catch (_) {}
}

async function healthReport() {
  try {
    const o = await chrome.storage.local.get(HEALTH_KEY);
    return { health: o[HEALTH_KEY] || {} };
  } catch (_) { return { health: {} }; }
}

async function dispatch({ service, query, type }) {
  try {
    switch (service) {
      case 'ipapi':      return await ipapi(query, type);
      case 'internetdb': return await internetdb(query, type);
      case 'greynoise':  return await greynoise(query, type);
      case 'tor':        return await tor(query, type);
      case 'rdap':       return await rdap(query, type);
      case 'crtsh':      return await crtsh(query, type);
      case 'dns':        return await dns(query, type);
      case 'circl':      return await circl(query, type);
      case 'mhr':        return await mhr(query, type);
      case 'feeds':      return await feeds(query, type);
      case 'otx':        return await otx(query, type);
      case 'ripe':       return await ripe(query, type);
      case 'vt':         return await virustotal(query, type);
      case 'shodan':     return await shodan(query, type);
      case 'emailrep':   return await emailrep(query, type);
      case 'urlscan':    return await urlscan(query, type);
      default:           return { error: 'Unknown service.' };
    }
  } catch (e) {
    return { error: e.message };
  }
}

// ── ip-api.com  (HTTP – free, no key) ─────────────────────────────────────
async function ipapi(query, type) {
  if (type !== 'ip' && type !== 'ipv6') return { _na: true };
  const fields = 'status,message,country,countryCode,regionName,city,isp,org,as,reverse,mobile,proxy,hosting,lat,lon,timezone';
  const r = await fetchT(`http://ip-api.com/json/${query}?fields=${fields}`, {}, 'ipapi');
  if (r.status === 429) return { error: 'ip-api rate limit reached (45 req / 45s). Try again shortly.' };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();
  if (d.status === 'fail') return { error: d.message || 'Query failed.' };
  const flags = [...(d.proxy ? ['Proxy / VPN'] : []), ...(d.hosting ? ['Hosting / DC'] : []), ...(d.mobile ? ['Mobile'] : [])];
  return {
    verdict: (d.proxy || d.hosting) ? 'suspicious' : 'clean',
    country: d.country, countryCode: d.countryCode,
    region: d.regionName, city: d.city,
    isp: d.isp, org: d.org, as: d.as,
    hostname: d.reverse,
    isProxy: d.proxy, isHosting: d.hosting, isMobile: d.mobile,
    lat: d.lat, lon: d.lon, timezone: d.timezone, flags
  };
}

// ── Shodan InternetDB  (free, no key) + CVE enrichment ────────────────────
async function internetdb(query, type) {
  if (type !== 'ip' && type !== 'ipv6') return { _na: true };
  const r = await fetchT(`https://internetdb.shodan.io/${query}`, {}, 'internetdb');
  if (r.status === 404) return { verdict: 'clean', ports: [], vulns: [], tags: [], hostnames: [], cpes: [] };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();
  const vulns = d.vulns || [];

  // InternetDB only returns bare CVE IDs — enrich the top few with CVSS + summary.
  let cveDetails = [];
  if (vulns.length) {
    cveDetails = await mapLimit(vulns.slice(0, 6), 2, cveDetail);
    // KEV entries first (actively exploited), then by CVSS.
    cveDetails.sort((a, b) => (b.kev - a.kev) || ((b.score ?? -1) - (a.score ?? -1)));
  }
  const top     = cveDetails.find(c => c.score != null);
  const anyKev  = cveDetails.some(c => c.kev);
  const maxScore = top ? top.score : null;

  return {
    verdict: !vulns.length ? 'clean'
           : (anyKev || (maxScore != null && maxScore >= 7)) ? 'malicious'
           : 'suspicious',
    ports: d.ports || [], hostnames: d.hostnames || [],
    cpes: d.cpes || [], tags: d.tags || [], vulns,
    cveDetails, maxScore, kevCount: cveDetails.filter(c => c.kev).length
  };
}

// Bounded concurrency. Firing every CVE lookup at once rate-limits us against
// our own enrichment source — the CI source probe caught exactly that.
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const n = i++;
      out[n] = await fn(items[n]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

// `metrics` is an array on some records and a bare object on others.
function collectMetrics(container) {
  const m = container && container.metrics;
  if (!m) return [];
  return Array.isArray(m) ? m : [m];
}

async function cveDetail(id) {
  // A published CVE record barely changes, so cache it for a day rather than
  // re-fetching the same handful on every lookup of the same host.
  const ck = `cve:${id}`;
  const hit = await cacheGet(ck);
  if (hit) return hit;

  try {
    const r = await fetchT(`https://cve.circl.lu/api/cve/${id}`, {}, 'cve');
    if (r.status === 429) return { id, rateLimited: true };
    if (!r.ok) return { id };
    const d = await r.json();
    const cna = d.containers?.cna || {};
    const adp = d.containers?.adp || [];

    // CVSS lives in the ADP (CISA) container, not the CNA one — the CNA
    // container usually carries only a textual severity.
    const metrics = [...collectMetrics(cna), ...adp.flatMap(collectMetrics)];

    let score = null, severity = null, kev = false, textual = null;
    for (const m of metrics) {
      const c = m.cvssV4_0 || m.cvssV3_1 || m.cvssV3_0 || m.cvssV2_0;
      if (c && c.baseScore != null && score == null) {
        score = c.baseScore;
        severity = c.baseSeverity || null;
      }
      if (m.other?.type === 'kev') kev = true;
      const oc = m.other?.content;
      if (!textual && oc && typeof oc === 'object') textual = oc.other || oc.text || null;
    }
    if (!severity && textual) severity = String(textual).toUpperCase();

    const desc = (cna.descriptions || []).find(x => String(x.lang || '').toLowerCase().startsWith('en'));
    const out = {
      id, score, severity, kev,
      summary: desc ? String(desc.value).replace(/\s+/g, ' ').slice(0, 240) : null
    };
    await cacheSet(ck, out, 24 * 60 * 60 * 1000);
    return out;
  } catch (_) {
    return { id };
  }
}

// ── GreyNoise Community  (free, no key) ───────────────────────────────────
async function greynoise(query, type) {
  if (type !== 'ip' && type !== 'ipv6') return { _na: true };
  const r = await fetchT(`https://api.greynoise.io/v3/community/${query}`, {}, 'greynoise');
  if (r.status === 404) return { verdict: 'clean', unseen: true };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();
  const cls = d.classification || '';
  return {
    verdict: cls === 'malicious' ? 'malicious' : cls === 'benign' ? 'clean' : 'suspicious',
    classification: cls, noise: d.noise, riot: d.riot,
    name: d.name, lastSeen: d.last_seen, link: d.link
  };
}

// ── Tor exit nodes  (free list, cached 6h, matched locally) ───────────────
async function tor(query, type) {
  if (type !== 'ip') return { _na: true };
  let list = await cacheGet('__torexit__');
  if (!list) {
    const r = await fetchT('https://check.torproject.org/torbulkexitlist', {}, 'tor');
    if (!r.ok) return { error: `HTTP ${r.status}` };
    const txt = await r.text();
    list = txt.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'));
    await cacheSet('__torexit__', list, 6 * 60 * 60 * 1000);
  }
  const isExit = list.includes(query);
  return {
    verdict: isExit ? 'suspicious' : 'clean',
    isExit,
    listSize: list.length,
    link: 'https://metrics.torproject.org/exonerator.html'
  };
}

// Registries only hold a record for the *registered* domain, not arbitrary
// subdomains — rdap.org 400s on "en.wikipedia.org" because Public Interest
// Registry has no record for anything but "wikipedia.org". This is not a
// full public-suffix-list implementation, just the two-label suffixes common
// enough to matter (co.uk, com.tr, com.au, ...); anything else falls back to
// "last two labels", which is right for the overwhelming majority of TLDs.
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk', 'sch.uk', 'nhs.uk', 'police.uk',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.za', 'net.za', 'org.za', 'gov.za', 'web.za',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx',
  'co.il', 'net.il', 'org.il', 'gov.il',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.kr', 'ne.kr', 'or.kr', 'go.kr',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar',
  'co.id', 'net.id', 'org.id', 'go.id',
  'com.my', 'net.my', 'org.my', 'gov.my'
]);

function registrableDomain(host) {
  const labels = host.toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  const take = TWO_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  return labels.slice(-take).join('.');
}

// ── RDAP / Whois  (free, no key) ──────────────────────────────────────────
async function rdap(query, type) {
  let url, lookupDomain = query;
  if (type === 'ip' || type === 'ipv6') {
    url = `https://rdap.org/ip/${query}`;
  } else if (type === 'domain') {
    lookupDomain = registrableDomain(query);
    url = `https://rdap.org/domain/${lookupDomain}`;
  } else if (type === 'url') {
    try { lookupDomain = registrableDomain(new URL(query).hostname); } catch (_) {}
    url = `https://rdap.org/domain/${lookupDomain}`;
  } else {
    return { _na: true };
  }
  const r = await fetchT(url, { redirect: 'follow' }, 'rdap');
  if (r.status === 404) return { error: 'No RDAP record found.' };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();

  if (type === 'ip' || type === 'ipv6') {
    return {
      handle: d.handle, name: d.name, country: d.country,
      startAddress: d.startAddress, endAddress: d.endAddress, type: d.type,
      events: (d.events || []).map(e => ({ action: e.eventAction, date: e.eventDate?.split('T')[0] }))
    };
  }
  const getDate = a => (d.events || []).find(e => e.eventAction === a)?.eventDate?.split('T')[0];
  const nameservers = (d.nameservers || []).map(ns => ns.ldhName?.toLowerCase()).filter(Boolean);
  const reg = (d.entities || []).find(e => e.roles?.includes('registrar'));
  const registrar = reg?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || reg?.handle || null;
  const regDate = getDate('registration');
  return {
    domainName: d.ldhName || lookupDomain,
    registered: regDate, expires: getDate('expiration'),
    lastChanged: getDate('last changed'),
    status: d.status || [], nameservers, registrar,
    ageWarning: regDate ? (Date.now() - new Date(regDate)) / 86400000 < 30 : false,
    link: `https://rdap.org/domain/${lookupDomain}`
  };
}

// ── crt.sh  (free, no key — slow, 30s budget) ─────────────────────────────
async function crtsh(query, type) {
  let domain = query;
  if (type === 'url') { try { domain = new URL(query).hostname; } catch (_) {} }
  if (type !== 'domain' && type !== 'url') return { _na: true };
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
  // crt.sh intermittently answers 404/5xx under load; a genuinely empty result
  // comes back as 200 with []. So a 404/5xx here is a server hiccup — retry with
  // backoff before giving up.
  let r = await fetchT(url, {}, 'crtsh');
  const backoffsMs = [900, 2500];
  for (const wait of backoffsMs) {
    if (r.ok || (r.status !== 404 && r.status < 500)) break;
    await new Promise(res => setTimeout(res, wait));
    r = await fetchT(url, {}, 'crtsh');
  }
  if (!r.ok) return { error: `crt.sh is unavailable right now (HTTP ${r.status}). It throttles under load — try again in a moment.` };
  let data;
  try { data = await r.json(); } catch (_) { return { error: 'Failed to parse crt.sh response.' }; }
  if (!data?.length) return { certCount: 0, uniqueSubdomains: [] };
  const names = new Set();
  data.forEach(c => (c.name_value || '').split('\n').forEach(n => {
    const t = n.trim().toLowerCase();
    if (t && !t.includes('@')) names.add(t);
  }));
  const dl = domain.toLowerCase();
  const subdomains = [...names].filter(n => n.endsWith(`.${dl}`) || n === dl).sort().slice(0, 50);
  const recent = data.slice(0, 5).map(c => ({
    issuer: c.issuer_name?.match(/O=([^,]+)/)?.[1]?.trim() || '—',
    notBefore: c.not_before?.split('T')[0],
    notAfter:  c.not_after?.split('T')[0],
    cn: c.common_name
  }));
  return { certCount: data.length, uniqueSubdomains: subdomains, recentCerts: recent, link: `https://crt.sh/?q=${domain}` };
}

// ── Google DNS  (free, no key) ────────────────────────────────────────────
async function dns(query, type) {
  let domain = query;
  if (type === 'url') { try { domain = new URL(query).hostname; } catch (_) {} }
  if (type !== 'domain' && type !== 'url') return { _na: true };
  const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
  const records = {};
  await Promise.all(types.map(async t => {
    try {
      const r = await fetchT(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${t}`, {}, 'dns');
      if (r.ok) {
        const data = await r.json();
        const ans = (data.Answer || []).map(a => a.data);
        if (ans.length) records[t] = ans;
      }
    } catch (_) {}
  }));
  return { records };
}

// ── CIRCL HASHLOOKUP  (free, no key) ──────────────────────────────────────
async function circl(query, type) {
  if (!['md5', 'sha1', 'sha256'].includes(type)) return { _na: true };
  const r = await fetchT(`https://hashlookup.circl.lu/lookup/${type}/${query}`, {}, 'circl');
  if (r.status === 404) return { verdict: 'unknown', found: false };
  if (!r.ok) return { error: `CIRCL HTTP ${r.status}` };
  const d = await r.json();
  return {
    verdict: d.KnownMalicious ? 'malicious' : 'clean',
    found: true,
    fileName: d.FileName,
    fileSize: d.FileSize,
    md5: d.MD5, sha1: d['SHA-1'], sha256: d['SHA-256'],
    knownMalicious: d.KnownMalicious,
    mimeType: d.mimetype,
    trustScore: d['hashlookup:trust'],
    productName: d.ProductCode?.ProductName,
    source: d.source,
    link: `https://hashlookup.circl.lu/lookup/${type}/${query}`
  };
}

// ── abuse.ch / OpenPhish feeds  (matched locally, no request per lookup) ──
async function feeds(query, type) {
  if (!['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'].includes(type)) return { _na: true };
  const idx = await getIndex();
  const hits = matchIndex(idx, query, type);
  return {
    // Only a hit carries information. The feeds hold a few thousand current
    // indicators, so "not listed" is not evidence of safety and must never
    // pull the overall verdict towards clean.
    verdict: hits ? 'malicious' : 'unknown',
    hits: hits || [],
    indexedAt: idx?.at || null,
    indexSize: idx?.total || 0,
    counts: idx?.counts || {}
  };
}

// ── Optional key layer ─────────────────────────────────────────────────────
// Everything above works with no account at all. A key only ever adds depth —
// nothing degrades without one. Keys live in storage.local so they stay on
// this machine rather than riding the profile sync.
async function getKeys() {
  try {
    const o = await chrome.storage.local.get('osint_keys');
    return o.osint_keys || {};
  } catch (_) { return {}; }
}

const VT_PATH = {
  ip: 'ip_addresses', ipv6: 'ip_addresses', domain: 'domains',
  md5: 'files', sha1: 'files', sha256: 'files'
};

async function virustotal(query, type) {
  const keys = await getKeys();
  if (!keys.vt) return { _na: true, _needsKey: 'VirusTotal' };
  const seg = VT_PATH[type];
  if (!seg) return { _na: true };

  const r = await fetchT(`https://www.virustotal.com/api/v3/${seg}/${encodeURIComponent(query)}`,
    { headers: { 'x-apikey': keys.vt } }, 'vt');
  if (r.status === 401) return { error: 'VirusTotal rejected the key.' };
  if (r.status === 429) return { error: 'VirusTotal quota exhausted (4 req/min on the free tier).' };
  if (r.status === 404) return { verdict: 'unknown', notFound: true };
  if (!r.ok) return { error: `HTTP ${r.status}` };

  const a = (await r.json()).data?.attributes || {};
  const st = a.last_analysis_stats || {};
  const mal = st.malicious || 0, sus = st.suspicious || 0;
  const total = mal + sus + (st.harmless || 0) + (st.undetected || 0);
  const engines = Object.entries(a.last_analysis_results || {})
    .filter(([, v]) => v.category === 'malicious')
    .map(([k, v]) => `${k}: ${v.result}`)
    .slice(0, 8);

  return {
    verdict: mal >= 3 ? 'malicious' : (mal + sus) >= 1 ? 'suspicious' : total ? 'clean' : 'unknown',
    malicious: mal, suspicious: sus, total,
    reputation: a.reputation,
    names: (a.names || []).slice(0, 4),
    typeDesc: a.type_description || null,
    engines,
    link: `https://www.virustotal.com/gui/search/${encodeURIComponent(query)}`
  };
}

async function shodan(query, type) {
  const keys = await getKeys();
  if (!keys.shodan) return { _na: true, _needsKey: 'Shodan' };
  if (type !== 'ip' && type !== 'ipv6') return { _na: true };

  const r = await fetchT(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(query)}?key=${encodeURIComponent(keys.shodan)}`,
    {}, 'shodan');
  if (r.status === 401) return { error: 'Shodan rejected the key.' };
  if (r.status === 404) return { verdict: 'unknown', notFound: true };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();

  return {
    verdict: (d.vulns || []).length ? 'suspicious' : 'clean',
    ports: d.ports || [],
    vulns: Object.keys(d.vulns || {}),
    os: d.os || null,
    org: d.org || null,
    isp: d.isp || null,
    hostnames: d.hostnames || [],
    tags: d.tags || [],
    services: (d.data || []).slice(0, 6).map(s => ({
      port: s.port, product: s.product || null, version: s.version || null,
      transport: s.transport || null
    })),
    lastUpdate: (d.last_update || '').split('T')[0],
    link: `https://www.shodan.io/host/${encodeURIComponent(query)}`
  };
}

// ── AlienVault OTX  (free, no key) ────────────────────────────────────────
// The only source here that names the *campaign* an indicator belongs to,
// and the only one carrying MITRE ATT&CK technique IDs.
const OTX_PATH = {
  ip: 'IPv4', ipv6: 'IPv6', domain: 'domain', url: 'url',
  md5: 'file', sha1: 'file', sha256: 'file'
};

async function otx(query, type) {
  const seg = OTX_PATH[type];
  if (!seg) return { _na: true };
  const r = await fetchT(
    `https://otx.alienvault.com/api/v1/indicators/${seg}/${encodeURIComponent(query)}/general`,
    {}, 'otx'
  );
  if (r.status === 404) return { verdict: 'unknown', pulseCount: 0, pulses: [] };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();

  const pulses = (d.pulse_info?.pulses || []).slice(0, 6).map(p => ({
    name: p.name,
    created: (p.created || '').split('T')[0],
    adversary: p.adversary || null,
    families: (p.malware_families || []).map(m => m.display_name || m).filter(Boolean),
    attack: (p.attack_ids || []).map(a => a.id || a).filter(Boolean).slice(0, 6),
    tags: (p.tags || []).slice(0, 6)
  }));

  // OTX marks well-known infrastructure explicitly; trust that over a bare
  // pulse count, since popular addresses turn up in reports as references.
  const val = (d.validation || []).map(v => String(v.source || '').toLowerCase());
  const whitelisted = val.some(v => v.includes('whitelist') || v.includes('false_positive'));
  const n = d.pulse_info?.count || 0;

  return {
    verdict: whitelisted ? 'clean' : n >= 3 ? 'malicious' : n >= 1 ? 'suspicious' : 'unknown',
    pulseCount: n,
    pulses,
    whitelisted,
    validation: (d.validation || []).map(v => v.source).filter(Boolean),
    asn: d.asn || null,
    country: d.country_name || null,
    families: [...new Set(pulses.flatMap(p => p.families))].slice(0, 6),
    attack: [...new Set(pulses.flatMap(p => p.attack))].slice(0, 8),
    link: `https://otx.alienvault.com/indicator/${seg === 'file' ? 'file' : seg.toLowerCase()}/${encodeURIComponent(query)}`
  };
}

// ── RIPEstat  (free, no key) — the routing view behind an address ─────────
async function ripe(query, type) {
  if (type !== 'ip' && type !== 'ipv6') return { _na: true };
  const r = await fetchT(
    `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(query)}`,
    {}, 'ripe'
  );
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = (await r.json()).data || {};
  const asns = (d.asns || []).map(a => ({ asn: a.asn, holder: a.holder }));

  let prefixCount = null, neighbours = null;
  if (asns.length) {
    const as = `AS${asns[0].asn}`;
    const [pfx, nb] = await Promise.all([
      fetchT(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${as}`, {}, 'ripe')
        .then(x => x.ok ? x.json() : null).catch(() => null),
      fetchT(`https://stat.ripe.net/data/asn-neighbours/data.json?resource=${as}`, {}, 'ripe')
        .then(x => x.ok ? x.json() : null).catch(() => null)
    ]);
    prefixCount = pfx?.data?.prefixes?.length ?? null;
    neighbours  = nb?.data?.neighbours?.length ?? null;
  }

  return {
    prefix: d.resource || null,
    announced: d.announced,
    asns,
    prefixCount,
    neighbours,
    link: `https://stat.ripe.net/app/launchpad/S1_${encodeURIComponent(query)}`
  };
}

// ── Team Cymru Malware Hash Registry  (free, no key, over DNS) ────────────
// CIRCL answers "is this a known *good* file"; this answers "is it known
// malware", which is what people actually paste a hash in to find out.
// MD5 and SHA-1 only — the registry rejects SHA-256.
async function mhr(query, type) {
  if (type !== 'md5' && type !== 'sha1') return { _na: true };
  const host = `${query.toLowerCase()}.malware.hash.cymru.com`;
  const r = await fetchT(`https://dns.google/resolve?name=${host}&type=TXT`, {}, 'mhr');
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();

  // NXDOMAIN (3) simply means the registry has never seen the sample.
  if (!d.Answer?.length) return { verdict: 'unknown', known: false };

  const txt = String(d.Answer[0].data || '').replace(/"/g, '').trim();
  const [tsRaw, pctRaw] = txt.split(/\s+/);
  const ts  = Number(tsRaw);
  const pct = Number(pctRaw);
  return {
    verdict: 'malicious',
    known: true,
    detectionRate: Number.isFinite(pct) ? pct : null,
    lastSeen: Number.isFinite(ts) ? new Date(ts * 1000).toISOString().split('T')[0] : null,
    link: 'https://www.team-cymru.com/mhr'
  };
}

// ── mailcheck.ai  (free, no key) ──────────────────────────────────────────
async function emailrep(query, type) {
  if (type !== 'email') return { _na: true };
  const r = await fetchT(`https://api.mailcheck.ai/email/${encodeURIComponent(query)}`, {}, 'emailrep');
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();
  const suspicious = d.disposable || d.spam || !d.mx;
  return {
    verdict: suspicious ? 'suspicious' : 'clean',
    domain: d.domain,
    domainAge: d.domain_age_in_days != null ? `${d.domain_age_in_days} days` : null,
    mx: d.mx,
    mxProviders: (d.mx_providers || []).map(p => p.slug).join(', ') || null,
    disposable: d.disposable,
    publicDomain: d.public_domain,
    spam: d.spam,
    alias: d.alias,
    roleAccount: d.role_account,
    didYouMean: d.did_you_mean || null,
    link: `https://mailcheck.ai/#${encodeURIComponent(query)}`
  };
}

// ── URLScan.io  (free, no key) ────────────────────────────────────────────
async function urlscan(query, type) {
  let domain = query;
  if (type === 'url') { try { domain = new URL(query).hostname; } catch (_) {} }
  if (type !== 'domain' && type !== 'url') return { _na: true };
  const r = await fetchT(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`, {}, 'urlscan');
  if (r.status === 429) return { error: 'URLScan rate limit reached. Try again shortly.' };
  if (!r.ok) return { error: `HTTP ${r.status}` };
  const d = await r.json();
  const results = d.results || [];
  if (!results.length) return { total: 0, results: [] };
  const malicious  = results.filter(r2 => r2.verdicts?.overall?.malicious).length;
  const suspicious = results.filter(r2 => r2.verdicts?.overall?.suspicious).length;
  return {
    verdict: malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean',
    total: d.total || results.length,
    maliciousCount: malicious,
    suspiciousCount: suspicious,
    recentScans: results.slice(0, 5).map(r2 => ({
      time: r2.task?.time?.split('T')[0],
      url: r2.page?.url,
      country: r2.page?.country,
      malicious: !!r2.verdicts?.overall?.malicious,
      suspicious: !!r2.verdicts?.overall?.suspicious,
      link: `https://urlscan.io/result/${r2.task?.uuid}/`
    })),
    link: `https://urlscan.io/search/#domain:${domain}`
  };
}
