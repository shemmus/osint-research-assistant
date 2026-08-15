const EN = {
  tagline:     'Threat Intelligence',
  qPlaceholder:'IP, domain, email or hash…',
  goBtn:       'Look up',
  histLabel:   'Recent',
  histEmpty:   'Nothing yet. Type an indicator above, or select one on any page and press Ctrl+Shift+O.',
  scanBtn:     'Triage this page',
  caseBtn:     'Case',
  settingsBtn: 'Settings',
  footer:      'Authorized security research only',
  errUnknown:  'Not a recognised indicator. Try an IP, domain, URL, email or file hash.',
  errPage:     'Chrome blocks extensions on this page. Open a normal web page and try again.',
  errTab:      'No active tab found.',
  scanning:    'Scanning the page…'
};

const TR = {
  tagline:     'Tehdit İstihbaratı',
  qPlaceholder:'IP, domain, e-posta veya hash…',
  goBtn:       'Sorgula',
  histLabel:   'Son sorgular',
  histEmpty:   'Henüz kayıt yok. Yukarıya bir gösterge yazın veya herhangi bir sayfada seçip Ctrl+Shift+O yapın.',
  scanBtn:     'Bu sayfayı triyaj et',
  caseBtn:     'Vaka',
  settingsBtn: 'Ayarlar',
  footer:      'Yalnızca yetkili güvenlik araştırmaları için',
  errUnknown:  'Tanınan bir gösterge değil. IP, domain, URL, e-posta veya dosya hash\'i deneyin.',
  errPage:     'Chrome bu sayfada uzantılara izin vermiyor. Normal bir web sayfası açıp tekrar deneyin.',
  errTab:      'Aktif sekme bulunamadı.',
  scanning:    'Sayfa taranıyor…'
};

const TYPE_LABEL = {
  ip: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  email: 'Email', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', unknown: '?'
};

const TYPE_DOT = {
  ip: 'var(--t-ip)', ipv6: 'var(--t-ip)', domain: 'var(--t-domain)', url: 'var(--t-url)',
  email: 'var(--t-email)', md5: 'var(--t-hash)', sha1: 'var(--t-hash)', sha256: 'var(--t-hash)'
};

let lang = 'en';
const S = () => (lang === 'tr' ? TR : EN);
const $ = id => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function applyLang(l) {
  lang = l;
  const s = S();
  $('tagline').textContent      = s.tagline;
  $('q').placeholder            = s.qPlaceholder;
  $('go').textContent           = s.goBtn;
  $('hist-label').textContent   = s.histLabel;
  $('hist-empty').textContent   = s.histEmpty;
  $('btn-scan').textContent     = s.scanBtn;
  $('btn-case').textContent     = s.caseBtn;
  $('btn-settings').textContent = s.settingsBtn;
  $('footer').textContent       = s.footer;
  $('btn-en').classList.toggle('active', l === 'en');
  $('btn-tr').classList.toggle('active', l === 'tr');
  document.documentElement.lang = l;
}

async function loadSettings() {
  try {
    const o = await chrome.storage.sync.get('osint_settings');
    return o.osint_settings || {};
  } catch (_) { return {}; }
}

async function saveLang(l) {
  try {
    const cur = await loadSettings();
    cur.lang = l;
    await chrome.storage.sync.set({ osint_settings: cur });
  } catch (_) {}
}

function say(text, bad) {
  const el = $('q-msg');
  el.textContent = text || '';
  el.classList.toggle('bad', !!bad);
}

function fail(code) {
  const s = S();
  say({ unrecognised: s.errUnknown, 'restricted-page': s.errPage, 'no-tab': s.errTab }[code] || s.errTab, true);
}

async function lookup(raw) {
  const q = String(raw || '').trim();
  if (!q) return;
  say('');
  let res;
  try { res = await chrome.runtime.sendMessage({ action: 'lookupActiveTab', raw: q }); }
  catch (_) { res = { error: 'no-tab' }; }
  if (!res || res.error) return fail(res && res.error);
  window.close();
}

async function scanPage() {
  say('');
  let res;
  try { res = await chrome.runtime.sendMessage({ action: 'scanActiveTab' }); }
  catch (_) { res = { error: 'no-tab' }; }
  if (!res || res.error) return fail(res && res.error);
  window.close();
}

async function renderHistory() {
  let hist = [];
  try {
    const o = await chrome.storage.local.get('osint_history');
    hist = o.osint_history || [];
  } catch (_) {}

  const list = $('hist-list');
  if (!hist.length) { list.innerHTML = ''; $('hist-empty').style.display = ''; return; }
  $('hist-empty').style.display = 'none';

  list.innerHTML = hist.slice(0, 6).map(h => `
    <div class="hist-item" role="button" tabindex="0" data-q="${esc(h.q)}">
      <span class="hist-t" style="--dot:${TYPE_DOT[h.type] || 'var(--text3)'}"><span class="hist-dot"></span>${esc(TYPE_LABEL[h.type] || h.type)}</span>
      <span class="hist-q" title="${esc(h.q)}">${esc(h.q)}</span>
    </div>`).join('');

  list.querySelectorAll('.hist-item').forEach(el => {
    const run = () => lookup(el.dataset.q);
    el.addEventListener('click', run);
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); run(); }
    });
  });
}

// ── Init ────────────────────────────────────────────────────────────────────
(async () => {
  const settings = await loadSettings();
  applyLang(settings.lang === 'tr' ? 'tr' : 'en');
  await renderHistory();
  $('q').focus();
})();

$('btn-en').onclick = () => { applyLang('en'); saveLang('en'); renderHistory(); };
$('btn-tr').onclick = () => { applyLang('tr'); saveLang('tr'); renderHistory(); };
$('btn-scan').onclick = scanPage;
$('btn-case').onclick = async () => {
  say('');
  let res;
  try { res = await chrome.runtime.sendMessage({ action: 'caseActiveTab' }); }
  catch (_) { res = { error: 'no-tab' }; }
  if (!res || res.error) return fail(res && res.error);
  window.close();
};
$('btn-settings').onclick = () => chrome.runtime.openOptionsPage();
$('go').onclick = () => lookup($('q').value);
$('q').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); lookup($('q').value); }
});
$('q').addEventListener('input', () => say(''));
