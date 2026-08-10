// Probes every keyless source the extension depends on.
//
// Three sources went behind authentication while this extension was being
// built (abuse.ch's API, emailrep.io, and Spamhaus over public resolvers).
// Upstream decay is normal, so this runs on a schedule and reports rather
// than asserts — a dead source is news, not a broken build.

const SOURCES = [
  { name: 'ip-api',            url: 'http://ip-api.com/json/8.8.8.8?fields=status,country' },
  { name: 'Shodan InternetDB', url: 'https://internetdb.shodan.io/8.8.8.8' },
  { name: 'GreyNoise',         url: 'https://api.greynoise.io/v3/community/8.8.8.8', okStatus: [200, 404] },
  { name: 'Tor exit list',     url: 'https://check.torproject.org/torbulkexitlist' },
  { name: 'RDAP',              url: 'https://rdap.org/ip/8.8.8.8' },
  { name: 'crt.sh',            url: 'https://crt.sh/?q=example.com&output=json', slow: true, flaky: true },
  { name: 'Google DNS',        url: 'https://dns.google/resolve?name=example.com&type=A' },
  { name: 'CIRCL hashlookup',  url: 'https://hashlookup.circl.lu/lookup/md5/d41d8cd98f00b204e9800998ecf8427e' },
  { name: 'CVE-Search',        url: 'https://cve.circl.lu/api/cve/CVE-2021-44228' },
  { name: 'Cymru MHR (DNS)',   url: 'https://dns.google/resolve?name=44d88612fea8a8f36de82e1278abb02f.malware.hash.cymru.com&type=TXT' },
  { name: 'mailcheck.ai',      url: 'https://api.mailcheck.ai/email/test@gmail.com' },
  { name: 'URLScan.io',        url: 'https://urlscan.io/api/v1/search/?q=domain:example.com&size=1' },
  { name: 'AlienVault OTX',    url: 'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general' },
  { name: 'RIPEstat',          url: 'https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8' },
  { name: 'ThreatFox feed',    url: 'https://threatfox.abuse.ch/export/json/recent/', slow: true },
  { name: 'URLhaus hostfile',  url: 'https://urlhaus.abuse.ch/downloads/hostfile/' },
  { name: 'Feodo blocklist',   url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json' },
  { name: 'OpenPhish feed',    url: 'https://openphish.com/feed.txt' }
];

async function probe(s) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), s.slow ? 45000 : 15000);
  const t0 = Date.now();
  try {
    const r = await fetch(s.url, { signal: ctrl.signal });
    const ms = Date.now() - t0;
    const ok = (s.okStatus || [200]).includes(r.status);
    const size = (await r.text()).length;
    return { ...s, ok, status: r.status, ms, size };
  } catch (e) {
    return { ...s, ok: false, status: e.name === 'AbortError' ? 'timeout' : 'error', ms: Date.now() - t0, err: e.message };
  } finally {
    clearTimeout(tid);
  }
}

(async () => {
  console.log(`Probing ${SOURCES.length} keyless sources\n`);
  const results = [];
  for (const s of SOURCES) results.push(await probe(s));

  const pad = (s, n) => String(s).padEnd(n);
  for (const r of results) {
    const mark = r.ok ? 'ok  ' : r.flaky ? 'FLAKY' : 'DOWN';
    const size = r.size != null ? `${(r.size / 1024).toFixed(1)}KB` : '';
    console.log(`  ${pad(mark, 6)} ${pad(r.name, 20)} ${pad(r.status, 8)} ${pad((r.ms / 1000).toFixed(1) + 's', 7)} ${size}${r.err ? '  ' + r.err : ''}`);
  }

  const down = results.filter(r => !r.ok && !r.flaky);
  console.log(`\n${results.length - down.length}/${results.length} healthy`);

  if (down.length) {
    console.log('\nUnreachable:');
    down.forEach(r => console.log(`  - ${r.name}: ${r.status}`));
    // Informational only. The workflow marks this job continue-on-error so a
    // third party having a bad day never blocks a merge.
    process.exitCode = 0;
  }
})();
