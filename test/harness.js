const fs = require('fs');
const { JSDOM } = require('jsdom');

const EXT = require('path').join(__dirname, '..') + require('path').sep;

let pass = 0, fail = 0;
const ok  = (l) => { pass++; console.log(`  ok    ${l}`); };
const bad = (l, d) => { fail++; console.log(`  FAIL  ${l}${d ? `\n          ${d}` : ''}`); };
function eq(l, got, want) { got === want ? ok(l) : bad(l, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
function truthy(l, v) { v ? ok(l) : bad(l, `got ${JSON.stringify(v)}`); }

// ── Fake chrome + page ─────────────────────────────────────────────────────
function makeEnv(pageHtml, opts = {}) {
  const dom = new JSDOM(pageHtml, {
    url: 'https://report.example/threat',
    pretendToBeVisual: true,
    runScripts: 'outside-only'
  });
  const { window } = dom;

  const syncStore  = { ...(opts.sync  || {}) };
  const localStore = { ...(opts.local || {}) };
  const changeListeners = [];
  const msgListeners = [];
  const sent = [];

  const area = (store) => ({
    get: async (k) => (k == null ? { ...store } : (store[k] !== undefined ? { [k]: store[k] } : {})),
    set: async (o) => {
      const changes = {};
      for (const [k, v] of Object.entries(o)) { changes[k] = { oldValue: store[k], newValue: v }; store[k] = v; }
      changeListeners.forEach(fn => fn(changes, store === syncStore ? 'sync' : 'local'));
    },
    remove: async (k) => { delete store[k]; },
    clear: async () => { for (const k of Object.keys(store)) delete store[k]; }
  });

  const chrome = {
    runtime: {
      lastError: null,
      onMessage: { addListener: (fn) => msgListeners.push(fn) },
      sendMessage: (msg, cb) => {
        sent.push(msg);
        let reply;
        if (msg.action === 'expand') {
          const key = `${msg.type}:${msg.value}`;
          reply = { neighbours: (opts.expand && opts.expand[key]) || [] };
        } else if (msg.action === 'triage') {
          reply = {
            results: (msg.iocs || []).map(i => (opts.triage && opts.triage[i.value]) ||
              { value: i.value, type: i.type, verdict: 'unknown', note: '', malware: '' }),
            indexedAt: Date.now(), indexSize: 4000
          };
        } else {
          // Default to 'unknown', never 'clean' — a stub that invents clean
          // verdicts hides exactly the bug class we are testing for.
          reply = (opts.replies && opts.replies[msg.service]) || { verdict: 'unknown' };
        }
        setTimeout(() => cb && cb(reply), 0);
      },
      openOptionsPage: () => {}
    },
    storage: {
      sync:  area(syncStore),
      local: area(localStore),
      onChanged: { addListener: (fn) => changeListeners.push(fn) }
    }
  };

  window.chrome = chrome;
  const src = fs.readFileSync(require('path').join(__dirname,'..','content.js'), 'utf8');
  window.eval(src);

  return {
    window, doc: window.document, chrome, sent, syncStore, localStore,
    fire: (msg) => msgListeners.forEach(fn => fn(msg)),
    panel: () => {
      for (const el of window.document.body.children) if (el.shadowRoot) return el.shadowRoot;
      return null;
    },
    host: () => {
      for (const el of window.document.body.children) if (el.shadowRoot) return el;
      return null;
    }
  };
}

const wait = (ms = 30) => new Promise(r => setTimeout(r, ms));

(async () => {
  // ── 1. Scan mode must not follow links ───────────────────────────────────
  console.log('\n[scan mode]');
  {
    const env = makeEnv(`<body><p>Contact <a href="https://elsewhere.test/go" id="lnk">
      abuse at 185.220.101.45 or mail admin@evil.com</a></p></body>`);
    env.fire({ action: 'toggleScan' });
    await wait();

    const marks = env.doc.querySelectorAll('.__osint_ioc__');
    eq('IOCs highlighted inside anchor', marks.length, 2);

    let navigated = false;
    env.window.addEventListener('click', (e) => { if (!e.defaultPrevented) navigated = true; }, false);

    const ip = [...marks].find(m => m.dataset.type === 'ip');
    const ev = new env.window.MouseEvent('click', { bubbles: true, cancelable: true });
    ip.dispatchEvent(ev);
    await wait();

    eq('click is preventDefault()ed (no navigation)', ev.defaultPrevented, true);
    truthy('panel opened from scan click', !!env.panel());
  }

  // ── 2. Settings must apply without reloading the page ────────────────────
  console.log('\n[settings propagation]');
  {
    const env = makeEnv('<body><p>8.8.8.8</p></body>', {
      sync: { osint_settings: { lang: 'en', theme: 'dark', disabled: {}, rememberPanel: true, historyOn: true } }
    });
    env.fire({ action: 'showPanel', query: '8.8.8.8', type: 'ip' });
    await wait();
    const before = env.panel().querySelectorAll('.tab').length;
    truthy('panel has tabs initially', before > 0);

    // user turns off two services + switches to TR in the options page
    await env.chrome.storage.sync.set({
      osint_settings: { lang: 'tr', theme: 'light', disabled: { ipapi: true, greynoise: true }, rememberPanel: true, historyOn: true }
    });
    await wait();

    env.fire({ action: 'showPanel', query: '8.8.8.8', type: 'ip' });
    await wait();

    const after = env.panel().querySelectorAll('.tab').length;
    eq('disabled services removed from tabs', after, before - 2);
    truthy('theme change applied to host', env.host().classList.contains('light'));
    const lang = env.panel().querySelector('#lang-btn').textContent.trim();
    eq('language switched to TR (button offers EN)', lang, 'EN');
  }

  // ── 3. Language toggle must not refetch every service ────────────────────
  console.log('\n[language toggle]');
  {
    const env = makeEnv('<body><p>x</p></body>');
    env.fire({ action: 'showPanel', query: '8.8.8.8', type: 'ip' });
    await wait();
    const firstRound = env.sent.length;
    env.panel().querySelector('#lang-btn').click();
    await wait();
    const added = env.sent.length - firstRound;
    eq('no refetch on language switch', added, 0);
  }

  // ── 4. History ───────────────────────────────────────────────────────────
  console.log('\n[history]');
  {
    const env = makeEnv('<body><p>x</p></body>');
    env.fire({ action: 'showPanel', query: '1.2.3.4', type: 'ip' });
    await wait();
    const h = env.localStore.osint_history || [];
    eq('history recorded', h.length, 1);
    eq('history entry value', h[0] && h[0].q, '1.2.3.4');
  }

  // ── 5. History disabled must be honoured ─────────────────────────────────
  console.log('\n[history off]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      sync: { osint_settings: { lang: 'en', theme: 'dark', disabled: {}, rememberPanel: true, historyOn: false } }
    });
    env.fire({ action: 'showPanel', query: '9.9.9.9', type: 'ip' });
    await wait();
    eq('nothing written when history is off', (env.localStore.osint_history || []).length, 0);
  }

  // ── 6. Aggregate verdict ─────────────────────────────────────────────────
  console.log('\n[aggregate verdict]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        ipapi:      { verdict: 'clean' },
        internetdb: { verdict: 'malicious', ports: [22], vulns: ['CVE-1'] },
        greynoise:  { verdict: 'suspicious' },
        tor:        { verdict: 'clean', isExit: false },
        rdap:       { handle: 'X' }
      }
    });
    env.fire({ action: 'showPanel', query: '5.5.5.5', type: 'ip' });
    await wait(60);
    const ov = env.panel().querySelector('#overall');
    truthy('overall marked malicious', ov.className.includes('malicious'));
    truthy('overall shows a count', /\d+/.test(ov.textContent));
  }

  // ── 7. Summary tab ───────────────────────────────────────────────────────
  console.log('\n[summary tab]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        ipapi: { verdict: 'suspicious', country: 'Germany', city: 'Munich', isp: 'Hetzner',
                 as: 'AS24940', hostname: 'exit.tor-network.net', flags: ['Proxy / VPN'] },
        internetdb: { verdict: 'malicious', ports: [22, 443], vulns: ['CVE-2021-44228'],
                      cveDetails: [{ id: 'CVE-2021-44228', score: 10, kev: true }], maxScore: 10, kevCount: 1 },
        greynoise: { verdict: 'malicious', classification: 'malicious', lastSeen: '2026-08-01' },
        tor: { verdict: 'suspicious', isExit: true, listSize: 1380 },
        rdap: { handle: 'H1', name: 'Hetzner' }
      }
    });
    env.fire({ action: 'showPanel', query: '185.220.101.45', type: 'ip' });
    await wait(60);
    const p = env.panel();

    const first = p.querySelector('.tab');
    eq('summary is the first tab', first.dataset.svc, 'summary');
    truthy('summary tab is active by default', first.classList.contains('active'));

    const sum = p.querySelector('#pane-summary');
    truthy('summary shows location', /Munich/.test(sum.textContent));
    truthy('summary shows worst CVE with KEV', /CVE-2021-44228/.test(sum.textContent) && /KEV/.test(sum.textContent));
    truthy('summary shows Tor exit', /Tor/i.test(sum.textContent));
    eq('one finding line per service', sum.querySelectorAll('.finding').length, 8);
  }

  // ── 8. Pivots ────────────────────────────────────────────────────────────
  console.log('\n[pivots]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        ipapi: { verdict: 'clean', country: 'DE', hostname: 'mail.evil.com' },
        internetdb: { verdict: 'clean', ports: [], vulns: [], hostnames: [] },
        greynoise: { verdict: 'clean', unseen: true },
        tor: { verdict: 'clean', isExit: false },
        rdap: { handle: 'H' }
      }
    });
    env.fire({ action: 'showPanel', query: '9.9.9.9', type: 'ip' });
    await wait(60);
    const p = env.panel();

    const target = p.querySelector('.pv[data-pv="mail.evil.com"]');
    truthy('hostname rendered as a pivot', !!target);

    const before = env.sent.length;
    target.dispatchEvent(new env.window.MouseEvent('click', { bubbles: true, cancelable: true }));
    await wait(60);

    eq('pivot switched the query', env.panel().querySelector('#qtext').textContent.trim(), 'mail.evil.com');
    truthy('pivot triggered new lookups', env.sent.length > before);
    const domainSvcs = env.sent.slice(before).map(m => m.service);
    truthy('pivot queried domain services', domainSvcs.includes('crtsh') || domainSvcs.includes('dns'));
  }

  // ── 9. DNS records pivot with correct types ──────────────────────────────
  console.log('\n[dns pivots]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        dns: { records: { A: ['93.184.216.34'], MX: ['10 mail.example.com.'], NS: ['a.iana-servers.net.'] } },
        rdap: { domainName: 'example.com' }, crtsh: { certCount: 0, uniqueSubdomains: [] },
        urlscan: { total: 0, results: [] }
      }
    });
    env.fire({ action: 'showPanel', query: 'example.com', type: 'domain' });
    await wait(60);
    const p = env.panel();
    const a  = p.querySelector('#pane-dns .pv[data-pvt="ip"]');
    const mx = p.querySelector('#pane-dns .pv[data-pv="mail.example.com"]');
    const ns = p.querySelector('#pane-dns .pv[data-pv="a.iana-servers.net"]');
    eq('A record pivots as ip', a && a.dataset.pv, '93.184.216.34');
    truthy('MX priority stripped for pivot', !!mx);
    truthy('NS trailing dot stripped', !!ns);
  }

  // ── 10. A malicious hash must actually read as malicious ─────────────────
  console.log('\n[malicious hash]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        mhr:   { verdict: 'malicious', known: true, detectionRate: 93, lastSeen: '2026-08-01' },
        circl: { verdict: 'clean', found: true, fileName: 'eicar.com', knownMalicious: 'malshare.com' }
      }
    });
    env.fire({ action: 'showPanel', query: '44d88612fea8a8f36de82e1278abb02f', type: 'md5' });
    await wait(60);
    const p = env.panel();

    const ov = p.querySelector('#overall');
    truthy('overall verdict is malicious', ov.className.includes('malicious'));

    const sum = p.querySelector('#pane-summary');
    truthy('summary states it is known malware', /93/.test(sum.textContent));
    truthy('malware DB tab present for md5', !!p.querySelector('.tab[data-svc="mhr"]'));
  }

  // ── 11. Unknown hash must not be dressed up as clean ─────────────────────
  console.log('\n[unknown hash]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        mhr:   { verdict: 'unknown', known: false },
        circl: { verdict: 'unknown', found: false }
      }
    });
    env.fire({ action: 'showPanel', query: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', type: 'md5' });
    await wait(60);
    const p = env.panel();
    const ov = p.querySelector('#overall');
    truthy('overall is not claimed clean', !ov.className.includes('clean'));
    truthy('pane warns absence is not proof of safety',
      /not proof|kanıtı değil/i.test(p.querySelector('#pane-mhr').textContent));
  }

  // ── 12. SHA-256 has no malware registry — say so ─────────────────────────
  console.log('\n[sha256 coverage]');
  {
    const env = makeEnv('<body><p>x</p></body>', { replies: { circl: { verdict: 'unknown', found: false } } });
    env.fire({ action: 'showPanel', query: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type: 'sha256' });
    await wait(60);
    const p = env.panel();
    eq('no malware-DB tab for sha256', p.querySelectorAll('.tab[data-svc="mhr"]').length, 0);
    truthy('summary explains the gap',
      /MD5 and SHA-1|MD5 ve SHA-1/i.test(p.querySelector('#pane-summary').textContent));
  }

  // ── 13. Page triage ──────────────────────────────────────────────────────
  console.log('\n[page triage]');
  {
    const page = `<body><article>
      <p>C2 at 47.95.207.79 and 121.37.255.60 served the loader.</p>
      <p>Staging domain evil-cdn.xyz, contact billing@paypa1.com.</p>
      <p>Benign infrastructure: 8.8.8.8 and google.com.</p>
      <p>Sample 44d88612fea8a8f36de82e1278abb02f was dropped.</p>
      <p>Repeated mention of 47.95.207.79 later in the report.</p>
    </article></body>`;
    const env = makeEnv(page, {
      triage: {
        '47.95.207.79':   { value: '47.95.207.79', type: 'ip', verdict: 'malicious', note: 'ThreatFox', malware: 'Cobalt Strike' },
        '121.37.255.60':  { value: '121.37.255.60', type: 'ip', verdict: 'malicious', note: 'ThreatFox', malware: 'Cobalt Strike' },
        'evil-cdn.xyz':   { value: 'evil-cdn.xyz', type: 'domain', verdict: 'malicious', note: 'URLhaus', malware: '' },
        '44d88612fea8a8f36de82e1278abb02f': { value: '44d88612fea8a8f36de82e1278abb02f', type: 'md5', verdict: 'malicious', note: 'Team Cymru MHR', malware: '93% AV' }
      }
    });

    env.fire({ action: 'toggleScan' });
    await wait(80);

    const triageMsg = env.sent.find(m => m.action === 'triage');
    truthy('triage request sent', !!triageMsg);

    const values = triageMsg.iocs.map(i => i.value);
    eq('repeated indicator deduplicated', values.filter(v => v === '47.95.207.79').length, 1);
    truthy('hash picked up', values.includes('44d88612fea8a8f36de82e1278abb02f'));
    truthy('email picked up', values.includes('billing@paypa1.com'));

    const marks = [...env.doc.querySelectorAll('.__osint_ioc__')];
    const bad = marks.filter(m => m.dataset.v === 'malicious');
    eq('both mentions of the C2 coloured', bad.filter(m => m.dataset.val === '47.95.207.79').length, 2);
    truthy('clean IP not coloured malicious',
      marks.filter(m => m.dataset.val === '8.8.8.8').every(m => m.dataset.v !== 'malicious'));

    const bar = env.doc.getElementById('__osint_bar__');
    truthy('bar reports the malicious count', /4/.test(bar.textContent));

    // open the sorted list
    const showBtn = [...bar.querySelectorAll('button')].find(b => /list|liste/i.test(b.textContent));
    truthy('list button present', !!showBtn);
    showBtn.dispatchEvent(new env.window.MouseEvent('click', { bubbles: true, cancelable: true }));
    await wait(40);

    let listShadow = null;
    for (const el of env.doc.body.children) {
      if (el.shadowRoot && el.shadowRoot.querySelector('.tri-row')) listShadow = el.shadowRoot;
    }
    truthy('triage list rendered', !!listShadow);
    const rows = [...listShadow.querySelectorAll('.tri-row')];
    eq('one row per unique indicator', rows.length, values.length);
    truthy('worst verdict sorted first',
      rows[0].querySelector('.chip-dot').className.includes('malicious'));
    truthy('malware family shown in list', /Cobalt Strike/.test(listShadow.textContent));
  }

  // ── 14. Pivot graph ──────────────────────────────────────────────────────
  console.log('\n[pivot graph]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      expand: {
        'ip:185.220.101.45': [
          { value: 'AS60729', type: 'asn', rel: 'announced by', label: 'TORSERVERS-NET', flagged: false },
          { value: '185.220.101.0/24', type: 'prefix', rel: 'in prefix', flagged: false },
          { value: 'tor-exit-45.for-privacy.net', type: 'domain', rel: 'reverse DNS', flagged: true }
        ],
        'asn:AS60729': [
          { value: '185.220.101.0/24', type: 'prefix', rel: 'announces', flagged: false },
          { value: 'AS1299', type: 'asn', rel: 'peer', flagged: false }
        ]
      }
    });

    env.fire({ action: 'showPanel', query: '185.220.101.45', type: 'ip' });
    await wait(60);

    const gBtn = env.panel().querySelector('#graph-btn');
    truthy('graph button offered for an IP', !!gBtn);
    gBtn.click();
    await wait(80);

    let gsh = null;
    for (const el of env.doc.body.children) {
      if (el.shadowRoot && el.shadowRoot.querySelector('#gcanvas')) gsh = el.shadowRoot;
    }
    truthy('graph panel opened', !!gsh);

    const expandCalls = env.sent.filter(m => m.action === 'expand');
    eq('root expanded automatically', expandCalls.length, 1);
    eq('root is the queried indicator', expandCalls[0].value, '185.220.101.45');

    // The simulation lives on canvas, so assert against the model the UI drives.
    const st = env.window.eval('null');   // model is closure-private; probe via UI instead
    const sel = gsh.querySelector('#gsel');
    truthy('selection strip starts hidden', sel.classList.contains('hidden'));

    const legend = gsh.querySelector('#glegend');
    truthy('legend explains the node colours', /ASN/.test(legend.textContent));
    truthy('legend explains the flagged colour', /threat feed|feed/i.test(legend.textContent));

    const canvas = gsh.querySelector('#gcanvas');
    truthy('canvas present and sized', canvas.width > 0 && canvas.height > 0);

    // Far-from-any-node double-click must not expand anything.
    canvas.dispatchEvent(new env.window.MouseEvent('dblclick', { bubbles: true, clientX: 9000, clientY: 9000 }));
    await wait(30);
    eq('empty-space double-click expands nothing', env.sent.filter(m => m.action === 'expand').length, 1);

    // The render loop must survive a canvas with no 2d context (jsdom has none)
    // rather than throwing on every frame.
    await wait(60);
    truthy('render loop survives a null 2d context', !!gsh.querySelector('#gcanvas'));

    gsh.querySelector('#g-close').click();
    await wait(20);
    let stillOpen = false;
    for (const el of env.doc.body.children) if (el.shadowRoot && el.shadowRoot.querySelector('#gcanvas')) stillOpen = true;
    truthy('graph closes cleanly', !stillOpen);
  }

  // ── 15. Case file and standards-compliant export ─────────────────────────
  console.log('\n[case file / exports]');
  {
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        feeds: { verdict: 'malicious', hits: [{ src: 'ThreatFox', malware: 'Cobalt Strike', threat: 'botnet_cc' }] },
        otx:   { verdict: 'malicious', pulseCount: 4, pulses: [{ name: 'Cobalt Strike infra', created: '2026-07-01' }],
                 families: ['Cobalt Strike'], attack: ['T1071', 'T1105'] },
        ipapi: { verdict: 'suspicious', country: 'CN' }
      }
    });
    env.fire({ action: 'showPanel', query: '47.95.207.79', type: 'ip' });
    await wait(80);

    const caseBtn = env.panel().querySelector('#case-btn');
    truthy('case button present', !!caseBtn);
    caseBtn.click();
    await wait(60);

    const stored = env.localStore.osint_case;
    truthy('indicator written to the case', !!stored && stored.items.length === 1);
    const it = stored.items[0];
    eq('verdict captured',  it.verdict, 'malicious');
    eq('malware captured',  it.malware, 'Cobalt Strike');
    truthy('sources captured', it.sources.includes('ThreatFox') && it.sources.includes('AlienVault OTX'));
    truthy('ATT&CK captured', it.attack.includes('T1071'));

    // open the case panel and pull the exports out of it
    env.fire({ action: 'showCase' });
    await wait(80);
    let csh = null;
    for (const el of env.doc.body.children) {
      if (el.shadowRoot && el.shadowRoot.querySelector('.cbtn[data-x="stix"]')) csh = el.shadowRoot;
    }
    truthy('case panel rendered', !!csh);

    // capture what a download would contain
    const downloads = [];
    const realCreate = env.window.URL.createObjectURL;
    env.window.URL.createObjectURL = () => 'blob:stub';
    env.window.URL.revokeObjectURL = () => {};
    const origClick = env.window.HTMLAnchorElement.prototype.click;
    env.window.HTMLAnchorElement.prototype.click = function () { downloads.push(this.download); };
    // read the payloads directly through the same builders the buttons use
    const blobs = [];
    const RealBlob = env.window.Blob;
    env.window.Blob = function (parts, opts) { blobs.push(String(parts[0])); return new RealBlob(parts, opts); };

    csh.querySelector('.cbtn[data-x="stix"]').click();
    csh.querySelector('.cbtn[data-x="misp"]').click();
    csh.querySelector('.cbtn[data-x="csv"]').click();
    await wait(60);
    env.window.HTMLAnchorElement.prototype.click = origClick;
    env.window.URL.createObjectURL = realCreate;

    eq('three files offered', downloads.length, 3);
    truthy('stix filename', /\.stix\.json$/.test(downloads[0]));

    // ── STIX 2.1 shape ──
    const bundle = JSON.parse(blobs[0]);
    eq('bundle type', bundle.type, 'bundle');
    truthy('bundle id is a uuid', /^bundle--[0-9a-f-]{36}$/.test(bundle.id));
    const ind = bundle.objects.find(o => o.type === 'indicator');
    truthy('indicator present', !!ind);
    eq('spec version', ind.spec_version, '2.1');
    eq('pattern type', ind.pattern_type, 'stix');
    eq('ipv4 pattern', ind.pattern, "[ipv4-addr:value = '47.95.207.79']");
    truthy('malicious label', ind.labels.includes('malicious-activity'));
    truthy('timestamps are STIX format', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/.test(ind.created));
    const mal = bundle.objects.find(o => o.type === 'malware');
    truthy('malware SDO emitted', mal && mal.name === 'Cobalt Strike' && mal.is_family === true);
    const rel = bundle.objects.find(o => o.type === 'relationship');
    truthy('indicator indicates malware',
      rel && rel.relationship_type === 'indicates' && rel.source_ref === ind.id && rel.target_ref === mal.id);

    // ── MISP shape ──
    const misp = JSON.parse(blobs[1]);
    truthy('MISP event wrapper', !!misp.Event);
    const attr = misp.Event.Attribute[0];
    eq('MISP attribute type', attr.type, 'ip-dst');
    eq('MISP category', attr.category, 'Network activity');
    eq('to_ids set for malicious', attr.to_ids, true);

    // ── CSV shape ──
    const csv = blobs[2].split('\n');
    truthy('CSV header', /^"value","type","verdict"/.test(csv[0]));
    truthy('CSV row quoted', csv[1].startsWith('"47.95.207.79"'));
  }

  // ── 16. Large pages must not freeze the tab ──────────────────────────────
  console.log('\n[large page limits]');
  {
    const paras = [];
    for (let i = 0; i < 3000; i++) {
      paras.push(`<p>Host ${i} at 10.${i % 250}.${(i * 7) % 250}.${(i * 13) % 250} and cdn${i}.ex${i % 40}.com</p>`);
    }
    const env = makeEnv(`<body><article>${paras.join('')}</article></body>`);
    env.fire({ action: 'toggleScan' });

    // the scan yields between slices, so wait for it to settle
    let prev = -1, marks = 0;
    for (let i = 0; i < 60; i++) {
      await wait(30);
      marks = env.doc.querySelectorAll('.__osint_ioc__').length;
      if (marks === prev && marks > 0) break;
      prev = marks;
    }

    truthy('marks are capped', marks > 0 && marks <= 1500);
    const tri = env.sent.find(m => m.action === 'triage');
    truthy('triage request sent', !!tri);
    truthy('batch is capped', tri.iocs.length <= 400);

    const payload = JSON.stringify(tri).length / 1024;
    truthy(`message stays small (${payload.toFixed(0)}KB)`, payload < 60);

    const bar = env.doc.getElementById('__osint_bar__');
    truthy('bar admits the page was truncated',
      /more not graded|değerlendirilmedi|truncated|kırpıldı/i.test(bar.textContent));
  }

  // ── 17. Every action tells the user what happened ────────────────────────
  console.log('\n[action feedback]');
  {
    const toastText = (env) => {
      for (const el of env.doc.body.children) {
        const w = el.shadowRoot && el.shadowRoot.querySelector('.wrap');
        if (w) return w.textContent;
      }
      return '';
    };

    // clipboard success
    {
      const env = makeEnv('<body><p>x</p></body>');
      let written = null;
      env.window.navigator.clipboard = { writeText: (s) => { written = s; return Promise.resolve(); } };
      env.fire({ action: 'showPanel', query: '1.2.3.4', type: 'ip' });
      await wait(60);
      env.panel().querySelector('#copy-btn').click();
      await wait(40);
      eq('copy writes the indicator', written, '1.2.3.4');
      truthy('copy is confirmed', /copied|kopyaland/i.test(toastText(env)));
    }

    // clipboard failure must not be swallowed
    {
      const env = makeEnv('<body><p>x</p></body>');
      env.window.navigator.clipboard = { writeText: () => Promise.reject(new Error('denied')) };
      env.fire({ action: 'showPanel', query: '1.2.3.4', type: 'ip' });
      await wait(60);
      env.panel().querySelector('#report-btn').click();
      await wait(40);
      truthy('clipboard failure is reported', /clipboard|panoya/i.test(toastText(env)));
    }

    // adding to the case
    {
      const env = makeEnv('<body><p>x</p></body>');
      env.window.navigator.clipboard = { writeText: () => Promise.resolve() };
      env.fire({ action: 'showPanel', query: '9.9.9.9', type: 'ip' });
      await wait(60);
      env.panel().querySelector('#case-btn').click();
      await wait(60);
      truthy('case add is confirmed with a count', /9\.9\.9\.9.*1|1.*9\.9\.9\.9/.test(toastText(env)));
    }

    // exporting from an empty case
    {
      const env = makeEnv('<body><p>x</p></body>');
      env.fire({ action: 'showCase' });
      await wait(60);
      let csh = null;
      for (const el of env.doc.body.children) {
        if (el.shadowRoot && el.shadowRoot.querySelector('.cbtn[data-x="stix"]')) csh = el.shadowRoot;
      }
      csh.querySelector('.cbtn[data-x="stix"]').click();
      await wait(60);
      truthy('empty export says so', /empty|boş/i.test(toastText(env)));
    }

    // a page with nothing to grade must not sit on "checking…"
    {
      const env = makeEnv('<body><article><p>Just prose, no indicators at all.</p></article></body>');
      env.fire({ action: 'toggleScan' });
      await wait(150);
      const bar = env.doc.getElementById('__osint_bar__');
      truthy('bar exists', !!bar);
      truthy('bar does not hang on "checking"', !/checking|kontrol edil/i.test(bar.textContent));
      truthy('bar states nothing was found', /no indicators|bulunamadı/i.test(bar.textContent));
    }
  }

  // ── 18. XSS: third-party API fields must never become live markup ────────
  // WHOIS/registrar fields, certificate CN/O fields and feed metadata are
  // attacker-influenceable — a domain owner controls their own WHOIS text,
  // and free CAs will issue certs with near-arbitrary CN/O content. Any of
  // these rendered as raw HTML is a stored XSS against the analyst.
  console.log('\n[xss: api fields are rendered as text, not markup]');
  {
    const PAYLOAD = '<img src=x onerror=window.__xss=1>';
    const PAYLOAD2 = '"><svg onload=window.__xss2=1>';

    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        ipapi: { verdict: 'suspicious', isp: PAYLOAD, org: PAYLOAD2, country: 'DE', hostname: 'ok.example.com' },
        feeds: { verdict: 'malicious', hits: [{ src: 'ThreatFox', malware: PAYLOAD, threat: 'botnet_cc' }] },
        rdap:  { handle: PAYLOAD, name: PAYLOAD2, country: 'DE' }
      }
    });
    env.fire({ action: 'showPanel', query: '1.2.3.4', type: 'ip' });
    await wait(80);

    const panelHTML = env.panel().querySelector('#content').innerHTML;
    truthy('no <img> tag materialised from an ISP field', !env.panel().querySelector('img'));
    truthy('no <svg> tag materialised from an org field', !env.panel().querySelector('svg'));
    truthy('payload text is present, but inert (as text)', panelHTML.includes('onerror=window.__xss'));
    truthy('the injected handler never actually ran', env.window.__xss !== 1 && env.window.__xss2 !== 1);
    truthy('malware family from a feed hit is escaped', !env.panel().querySelector('.cve-card img'));
  }

  // Certificate fields (crt.sh) and scanned URLs (URLScan) are the clearest
  // attacker-controlled surface — a domain owner requests their own cert.
  {
    const PAYLOAD = '<img src=x onerror=window.__xss3=1>';
    const env = makeEnv('<body><p>x</p></body>', {
      replies: {
        crtsh: {
          certCount: 1, uniqueSubdomains: [],
          recentCerts: [{ cn: PAYLOAD, issuer: PAYLOAD, notBefore: '2026-01-01', notAfter: '2026-06-01' }]
        },
        urlscan: {
          verdict: 'malicious', total: 1,
          recentScans: [{ url: PAYLOAD, time: '2026-01-01', country: 'RU', malicious: true, link: PAYLOAD }]
        }
      }
    });
    env.fire({ action: 'showPanel', query: 'evil.example', type: 'domain' });
    await wait(80);

    truthy('cert CN/issuer fields produce no live element', !env.panel().querySelector('img'));
    truthy('scanned URL field produces no live element',
      !env.panel().querySelector('.cert-cn img'));
    truthy('window was never touched by the cert or scan payload',
      env.window.__xss3 !== 1);
  }

  // ── 19. CSV export neutralises formula injection ─────────────────────────
  // Excel/Sheets treats a cell starting with =, +, -, @ as a formula on open.
  // A malware family name pulled from a feed is attacker-influenceable text.
  console.log('\n[csv export: formula injection is neutralised]');
  {
    const env = makeEnv('<body><p>x</p></body>');
    env.window.localStorage.setItem('__probe__', '1');
    // Reach the exporter through the case panel, with a case item whose
    // fields start with formula trigger characters.
    env.fire({ action: 'showPanel', query: '5.5.5.5', type: 'ip' });
    await wait(60);
    await env.chrome.storage.local.set({
      osint_case: {
        name: 'test', created: Date.now(),
        items: [{
          value: '=cmd|"/c calc"!A1', type: 'ip', verdict: 'malicious',
          sources: ['@SUM(1+1)'], malware: '+HYPERLINK("http://evil.test")',
          campaign: null, attack: [], added: Date.now()
        }]
      }
    });
    env.fire({ action: 'showCase' });
    await wait(80);

    let csh = null;
    for (const el of env.doc.body.children) {
      if (el.shadowRoot && el.shadowRoot.querySelector('.cbtn[data-x="csv"]')) csh = el.shadowRoot;
    }

    const blobs = [];
    const RealBlob = env.window.Blob;
    env.window.Blob = function (parts, opts2) { blobs.push(String(parts[0])); return new RealBlob(parts, opts2); };
    const origClick = env.window.HTMLAnchorElement.prototype.click;
    env.window.HTMLAnchorElement.prototype.click = function () {};
    csh.querySelector('.cbtn[data-x="csv"]').click();
    await wait(40);
    env.window.HTMLAnchorElement.prototype.click = origClick;

    const csv = blobs[0] || '';
    truthy('csv generated', csv.length > 0);
    truthy('leading = is neutralised', !/(^|\n)"=cmd/.test(csv) && csv.includes('"\'=cmd'));
    truthy('leading @ is neutralised', csv.includes("\"'@SUM"));
    truthy('leading + is neutralised', csv.includes("\"'+HYPERLINK"));
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
