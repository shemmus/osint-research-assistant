const DEFAULTS = {
  lang: 'en',
  theme: 'auto',
  disabled: {},
  rememberPanel: true,
  historyOn: true
};

// `nc` marks sources whose terms restrict them to non-commercial use. Read
// from each provider's own terms page, not assumed — see README "Licensing".
const SERVICES = [
  { id: 'ipapi',      label: 'IP-API',            types: 'IPv4, IPv6', nc: true },
  { id: 'internetdb', label: 'Shodan InternetDB', types: 'IPv4, IPv6' },
  { id: 'greynoise',  label: 'GreyNoise',         types: 'IPv4, IPv6' },
  { id: 'tor',        label: 'Tor Exit Nodes',    types: 'IPv4' },
  { id: 'rdap',       label: 'Whois / RDAP',      types: 'IP, Domain, URL' },
  { id: 'crtsh',      label: 'crt.sh',            types: 'Domain, URL' },
  { id: 'dns',        label: 'Google DNS',        types: 'Domain, URL' },
  { id: 'urlscan',    label: 'URLScan.io',        types: 'Domain, URL' },
  { id: 'feeds',      label: 'Threat Feeds',      types: 'IP, Domain, URL, Hash', nc: true },
  { id: 'otx',        label: 'AlienVault OTX',    types: 'IP, Domain, URL, Hash' },
  { id: 'ripe',       label: 'RIPEstat',          types: 'IPv4, IPv6', nc: true },
  { id: 'mhr',        label: 'Team Cymru MHR',    types: 'MD5, SHA-1', nc: true },
  { id: 'circl',      label: 'CIRCL HASHLOOKUP',  types: 'MD5, SHA-1, SHA-256' },
  { id: 'emailrep',   label: 'mailcheck.ai',      types: 'Email' }
];

const SVC_DESC = {
  en: {
    ipapi: 'Geolocation, ISP, proxy and VPN detection',
    internetdb: 'Open ports and known CVEs, enriched with CVSS scores',
    greynoise: 'Internet scanner classification',
    tor: 'Checks the IP against the public Tor exit node list',
    rdap: 'Registration dates, registrar and IP block owner',
    crtsh: 'Certificate Transparency logs and subdomains',
    dns: 'A, AAAA, MX, TXT, NS and CNAME records',
    urlscan: 'Past scan history and malicious verdicts',
    feeds: 'ThreatFox, URLhaus, Feodo and OpenPhish — matched locally, with malware family names',
    otx: 'Community threat reports: campaign names and MITRE ATT&CK techniques',
    ripe: 'Which AS announces this address, and how large that network is',
    mhr: 'Is this hash known malware? Returns the antivirus detection rate',
    circl: 'Is this hash a known legitimate file? (NSRL known-good database)',
    emailrep: 'Disposable address, spam and MX checks'
  },
  tr: {
    ipapi: 'Coğrafi konum, ISP, proxy ve VPN tespiti',
    internetdb: 'Açık portlar ve CVE\'ler, CVSS skorlarıyla zenginleştirilmiş',
    greynoise: 'İnternet tarayıcı sınıflandırması',
    tor: 'IP\'yi genel Tor çıkış nodu listesiyle karşılaştırır',
    rdap: 'Kayıt tarihleri, kayıt kuruluşu ve IP blok sahibi',
    crtsh: 'Sertifika Şeffaflığı kayıtları ve alt domainler',
    dns: 'A, AAAA, MX, TXT, NS ve CNAME kayıtları',
    urlscan: 'Geçmiş tarama kayıtları ve zararlı yargıları',
    feeds: 'ThreatFox, URLhaus, Feodo ve OpenPhish — yerelde eşleştirilir, zararlı ailesi adıyla',
    otx: 'Topluluk tehdit raporları: kampanya adları ve MITRE ATT&CK teknikleri',
    ripe: 'Bu adresi hangi AS duyuruyor ve o ağ ne kadar büyük',
    mhr: 'Bu hash bilinen zararlı yazılım mı? Antivirüs tespit oranını verir',
    circl: 'Bu hash bilinen meşru bir dosya mı? (NSRL temiz dosya veritabanı)',
    emailrep: 'Geçici adres, spam ve MX kontrolü'
  }
};

const UI = {
  en: {
    title: 'Settings', sub: 'OSINT Research Assistant',
    how: 'How it works',
    h1: 'Select an indicator on any page, then right-click or press Ctrl+Shift+O',
    h1d: 'Works with defanged text too — 185.220.101[.]45 and hxxps://evil[.]com are understood.',
    h2: 'Or type one straight into the toolbar popup',
    h2d: 'Results open in a floating panel on the page. The Summary tab answers the question; the other tabs show the detail.',
    h3: 'Scan a whole page for indicators',
    h3d: 'Ctrl+Shift+U, or the button in the popup. Every IP, domain, email and hash on the page gets underlined — click any to look it up.',
    h5: 'Walk the infrastructure with the pivot graph',
    h5d: 'Looking up an IP, domain, URL or ASN shows a highlighted Graph button next to the result. Opens a node map — IP → announcing AS → other prefixes on that AS; domain → resolved addresses → name servers → subdomains from certificate transparency. Double-click a node to expand it.',
    h4: 'Supported indicators',
    feeds: 'Threat feeds',
    feedName: 'Local threat index',
    feedDesc: 'Downloaded once and matched on your device, so page triage costs no API requests.',
    feedBtn: 'Refresh now', feedBusy: 'Refreshing…',
    feedStat: (n, when) => `${n} indicators · updated ${when}`,
    feedNone: 'Not built yet',
    healthLine: (rate, n, ms) => `${rate}% success over ${n} calls · ${ms}ms avg`,
    resetHealth: 'Reset source stats',
    keysLabel: 'Optional API keys',
    keysDesc: 'Everything works without these. A key only adds a source — nothing stops working if you leave them empty. Keys are stored on this device only and never synced.',
    vtDesc: '70+ antivirus engines for IPs, domains and file hashes. Free tier: 4 requests/min.',
    shodanDesc: 'Full host detail: banners, product versions and CVEs beyond the free InternetDB view.',
    general: 'General', services: 'Services', shortcuts: 'Keyboard shortcuts', data: 'Data',
    lang: 'Language', langD: 'Applies to the results panel and this page.',
    theme: 'Panel theme', themeD: 'Auto follows your system setting.',
    auto: 'Auto', dark: 'Dark', light: 'Light',
    remember: 'Remember panel position', rememberD: 'Reopen the panel where you last dragged it.',
    history: 'Keep lookup history', historyD: 'Stores the last 50 lookups on this device only.',
    sc1: 'Lookup selected text', sc2: 'Toggle page scanner',
    scD: 'Change these at <code>chrome://extensions/shortcuts</code>',
    clearCache: 'Clear cache', clearHistory: 'Clear history', reset: 'Reset settings',
    saved: 'Saved', cleared: 'Cleared',
    ncBadge: 'non-commercial',
    ncTitle: 'This provider\'s terms restrict it to non-commercial use. Using it at work may breach them — turn it off, or buy the provider\'s commercial tier.',
    ncNotice: 'Sources marked <b>non-commercial</b> are free only for personal and research use. Their terms do not cover use inside a company, even by a security team. Switch them off if that applies to you.',
    foot: 'Everything is stored on your device. No account, no server, no telemetry.'
  },
  tr: {
    title: 'Ayarlar', sub: 'OSINT Research Assistant',
    how: 'Nasıl çalışır',
    h1: 'Herhangi bir sayfada bir gösterge seçin, sağ tıklayın veya Ctrl+Shift+O yapın',
    h1d: 'Zararsızlaştırılmış metinle de çalışır — 185.220.101[.]45 ve hxxps://evil[.]com anlaşılır.',
    h2: 'Ya da doğrudan araç çubuğu penceresine yazın',
    h2d: 'Sonuçlar sayfada kayan bir panelde açılır. Özet sekmesi sorunun cevabını verir, diğer sekmeler ayrıntıyı gösterir.',
    h3: 'Tüm sayfayı göstergeler için tarayın',
    h3d: 'Ctrl+Shift+U veya penceredeki düğme. Sayfadaki her IP, domain, e-posta ve hash altı çizili olur — tıklayarak sorgularsınız.',
    h5: 'Pivot grafiği ile altyapıyı gezin',
    h5d: 'Bir IP, domain, URL veya ASN sorguladığınızda sonucun yanında vurgulanmış bir Grafik düğmesi belirir. Bir düğüm haritası açılır — IP → duyuran AS → o AS\'nin diğer prefix\'leri; domain → çözümlenen adresler → name server\'lar → sertifika şeffaflığından alt domainler. Bir düğüme çift tıklayarak genişletin.',
    h4: 'Desteklenen göstergeler',
    feeds: 'Tehdit feed\'leri',
    feedName: 'Yerel tehdit indeksi',
    feedDesc: 'Bir kez indirilip cihazınızda eşleştirilir, böylece sayfa triyajı hiç API isteği harcamaz.',
    feedBtn: 'Şimdi yenile', feedBusy: 'Yenileniyor…',
    feedStat: (n, when) => `${n} gösterge · güncelleme ${when}`,
    feedNone: 'Henüz oluşturulmadı',
    healthLine: (rate, n, ms) => `${n} çağrıda %${rate} başarı · ortalama ${ms}ms`,
    resetHealth: 'Kaynak istatistiklerini sıfırla',
    keysLabel: 'İsteğe bağlı API anahtarları',
    keysDesc: 'Bunlar olmadan her şey çalışır. Anahtar yalnızca kaynak ekler — boş bırakırsanız hiçbir şey bozulmaz. Anahtarlar yalnızca bu cihazda saklanır, senkronize edilmez.',
    vtDesc: 'IP, domain ve dosya hash\'leri için 70+ antivirüs motoru. Ücretsiz kota: dakikada 4 istek.',
    shodanDesc: 'Tam sunucu detayı: banner\'lar, ürün sürümleri ve ücretsiz InternetDB\'nin ötesinde CVE\'ler.',
    general: 'Genel', services: 'Servisler', shortcuts: 'Klavye kısayolları', data: 'Veri',
    lang: 'Dil', langD: 'Sonuç paneline ve bu sayfaya uygulanır.',
    theme: 'Panel teması', themeD: 'Otomatik, sistem ayarını takip eder.',
    auto: 'Oto', dark: 'Koyu', light: 'Açık',
    remember: 'Panel konumunu hatırla', rememberD: 'Paneli en son sürüklediğiniz yerde açar.',
    history: 'Sorgu geçmişini tut', historyD: 'Son 50 sorguyu yalnızca bu cihazda saklar.',
    sc1: 'Seçili metni sorgula', sc2: 'Sayfa taramasını aç/kapat',
    scD: '<code>chrome://extensions/shortcuts</code> adresinden değiştirebilirsiniz',
    clearCache: 'Önbelleği temizle', clearHistory: 'Geçmişi temizle', reset: 'Ayarları sıfırla',
    saved: 'Kaydedildi', cleared: 'Temizlendi',
    ncBadge: 'ticari değil',
    ncTitle: 'Bu sağlayıcının şartları yalnızca ticari olmayan kullanıma izin veriyor. İşyerinde kullanmak bunu ihlal edebilir — kapatın ya da sağlayıcının ticari paketini alın.',
    ncNotice: '<b>Ticari değil</b> işaretli kaynaklar yalnızca kişisel ve araştırma amaçlı kullanım için ücretsizdir. Şartları, bir güvenlik ekibi tarafından bile olsa şirket içi kullanımı kapsamaz. Durum sizin için geçerliyse bu kaynakları kapatın.',
    foot: 'Her şey cihazınızda saklanır. Hesap yok, sunucu yok, telemetri yok.'
  }
};

let settings = { ...DEFAULTS };

const $ = id => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

async function load() {
  try {
    const o = await chrome.storage.sync.get('osint_settings');
    Object.assign(settings, o.osint_settings || {});
  } catch (_) {}
  if (!settings.disabled) settings.disabled = {};
  render();
  showFeedStatus(false);
  wireKeys();
}

async function save() {
  try { await chrome.storage.sync.set({ osint_settings: settings }); } catch (_) {}
  flash((UI[settings.lang] || UI.en).saved);
}

let flashTimer = null;
function flash(text) {
  const el = $('saved');
  el.textContent = text;
  el.classList.add('show');
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => el.classList.remove('show'), 1600);
}

function render() {
  const u = UI[settings.lang] || UI.en;
  document.documentElement.lang = settings.lang;

  $('h-title').textContent     = u.title;
  $('h-sub').textContent       = u.sub;
  $('l-how').textContent  = u.how;
  $('n-h1').textContent   = u.h1;
  $('d-h1').textContent   = u.h1d;
  $('n-h2').textContent   = u.h2;
  $('d-h2').textContent   = u.h2d;
  $('n-h3').textContent   = u.h3;
  $('d-h3').textContent   = u.h3d;
  $('n-h5').textContent   = u.h5;
  $('d-h5').textContent   = u.h5d;
  $('n-h4').textContent   = u.h4;
  $('nc-notice').innerHTML  = u.ncNotice;
  $('l-keys').textContent   = u.keysLabel;
  $('d-keys').textContent   = u.keysDesc;
  $('d-vt').textContent     = u.vtDesc;
  $('d-shodan').textContent = u.shodanDesc;
  $('l-feeds').textContent  = u.feeds;
  $('n-feed').textContent   = u.feedName;
  $('d-feed').textContent   = u.feedDesc;
  $('btn-feed').textContent = u.feedBtn;
  $('l-general').textContent   = u.general;
  $('l-services').textContent  = u.services;
  $('l-shortcuts').textContent = u.shortcuts;
  $('l-data').textContent      = u.data;

  $('n-lang').textContent     = u.lang;
  $('d-lang').textContent     = u.langD;
  $('n-theme').textContent    = u.theme;
  $('d-theme').textContent    = u.themeD;
  $('th-auto').textContent    = u.auto;
  $('th-dark').textContent    = u.dark;
  $('th-light').textContent   = u.light;
  $('n-remember').textContent = u.remember;
  $('d-remember').textContent = u.rememberD;
  $('n-history').textContent  = u.history;
  $('d-history').textContent  = u.historyD;

  $('n-sc1').textContent     = u.sc1;
  $('n-sc2').textContent     = u.sc2;
  $('d-shortcuts').innerHTML = u.scD;

  $('btn-health').textContent  = u.resetHealth;
  $('btn-cache').textContent   = u.clearCache;
  $('btn-history').textContent = u.clearHistory;
  $('btn-reset').textContent   = u.reset;
  $('foot').textContent        = u.foot;

  $('cb-remember').checked = settings.rememberPanel !== false;
  $('cb-history').checked  = settings.historyOn !== false;

  document.querySelectorAll('#seg-lang button').forEach(b =>
    b.classList.toggle('active', b.dataset.v === settings.lang));
  document.querySelectorAll('#seg-theme button').forEach(b =>
    b.classList.toggle('active', b.dataset.v === settings.theme));

  const desc = SVC_DESC[settings.lang] || SVC_DESC.en;
  $('svc-list').innerHTML = SERVICES.map(s => `
    <div class="opt">
      <div class="opt-main">
        <div class="opt-name">${esc(s.label)}</div>
        <div class="opt-desc">${esc(desc[s.id] || '')}</div>
        <div class="types">${esc(s.types)}${s.nc ? ` <span class="nc" title="${esc(u.ncTitle)}">${esc(u.ncBadge)}</span>` : ''}</div>
      </div>
      <label class="sw">
        <input type="checkbox" data-svc="${esc(s.id)}"${settings.disabled[s.id] ? '' : ' checked'}>
        <span></span>
      </label>
    </div>`).join('');

  paintHealth();

  $('svc-list').querySelectorAll('input[data-svc]').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) delete settings.disabled[cb.dataset.svc];
      else settings.disabled[cb.dataset.svc] = true;
      save();
    });
  });
}

// ── Optional keys ───────────────────────────────────────────────────────────
// Stored in storage.local, not sync: a credential should not ride the profile
// to every machine signed into this browser.
async function loadKeys() {
  try {
    const o = await chrome.storage.local.get('osint_keys');
    return o.osint_keys || {};
  } catch (_) { return {}; }
}

async function wireKeys() {
  const keys = await loadKeys();
  for (const id of ['vt', 'shodan']) {
    const el = $(`key-${id}`);
    if (!el) continue;
    if (keys[id]) { el.value = keys[id]; el.classList.add('set'); }
    el.addEventListener('change', async () => {
      const cur = await loadKeys();
      const v = el.value.trim();
      if (v) cur[id] = v; else delete cur[id];
      try { await chrome.storage.local.set({ osint_keys: cur }); } catch (_) {}
      el.classList.toggle('set', !!v);
      flash((UI[settings.lang] || UI.en).saved);
    });
  }
}

// ── Source health ───────────────────────────────────────────────────────────
async function paintHealth() {
  let h = {};
  try {
    const res = await chrome.runtime.sendMessage({ action: 'health' });
    h = (res && res.health) || {};
  } catch (_) { return; }

  const u = UI[settings.lang] || UI.en;
  document.querySelectorAll('#svc-list .opt').forEach(row => {
    const cb = row.querySelector('input[data-svc]');
    if (!cb) return;
    const s = h[cb.dataset.svc];
    let el = row.querySelector('.health');
    if (!el) {
      el = document.createElement('div');
      el.className = 'health';
      row.querySelector('.opt-main').appendChild(el);
    }
    if (!s || (!s.ok && !s.fail)) { el.textContent = ''; return; }
    const total = s.ok + s.fail;
    const rate = Math.round((s.ok / total) * 100);
    const cls = s.streak >= 3 ? 'bad' : rate < 80 ? 'warn' : 'good';
    el.className = `health ${cls}`;
    el.textContent = u.healthLine(rate, total, s.ms || 0) +
      (s.streak >= 3 && s.lastError ? ` — ${s.lastError}` : '');
  });
}

// ── Threat feed index ───────────────────────────────────────────────────────
async function showFeedStatus(refresh) {
  const u = UI[settings.lang] || UI.en;
  const btn = $('btn-feed');
  if (refresh) { btn.disabled = true; btn.textContent = u.feedBusy; }
  let s;
  try { s = await chrome.runtime.sendMessage({ action: 'feedStatus', refresh: !!refresh }); }
  catch (_) { s = null; }
  btn.disabled = false;
  btn.textContent = u.feedBtn;

  if (!s || !s.at) { $('feed-stat').textContent = u.feedNone; return; }
  const when = new Date(s.at).toISOString().replace('T', ' ').slice(0, 16);
  const parts = Object.entries(s.counts || {}).map(([k, v]) => `${k} ${v}`).join(' · ');
  $('feed-stat').textContent = u.feedStat(s.total, when) + (parts ? `  (${parts})` : '');
}

// ── Wiring ──────────────────────────────────────────────────────────────────
$('btn-feed').addEventListener('click', () => showFeedStatus(true));
$('btn-health').addEventListener('click', async () => {
  try { await chrome.runtime.sendMessage({ action: 'resetHealth' }); } catch (_) {}
  paintHealth();
  flash((UI[settings.lang] || UI.en).cleared);
});
document.querySelectorAll('#seg-lang button').forEach(b => {
  b.addEventListener('click', () => { settings.lang = b.dataset.v; save(); render(); });
});
document.querySelectorAll('#seg-theme button').forEach(b => {
  b.addEventListener('click', () => { settings.theme = b.dataset.v; save(); render(); });
});
$('cb-remember').addEventListener('change', e => { settings.rememberPanel = e.target.checked; save(); });
$('cb-history').addEventListener('change',  e => { settings.historyOn     = e.target.checked; save(); });

$('btn-cache').addEventListener('click', async () => {
  try { await chrome.storage.session.clear(); } catch (_) {}
  flash((UI[settings.lang] || UI.en).cleared);
});
$('btn-history').addEventListener('click', async () => {
  try { await chrome.storage.local.remove('osint_history'); } catch (_) {}
  flash((UI[settings.lang] || UI.en).cleared);
});
$('btn-reset').addEventListener('click', async () => {
  settings = { ...DEFAULTS, disabled: {} };
  try { await chrome.storage.local.remove('osint_box'); } catch (_) {}
  await save();
  render();
});

load();
