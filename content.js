(() => {
  if (window.__osintLoaded) return;
  window.__osintLoaded = true;

  // ── Settings ─────────────────────────────────────────────────────────────
  // Stored in chrome.storage.sync: previously localStorage, which is per-site —
  // the language reset on every new domain.
  const DEFAULTS = {
    lang: 'en',
    theme: 'auto',        // auto | dark | light
    disabled: {},         // { [serviceId]: true }
    rememberPanel: true,
    historyOn: true
  };

  const state = {
    lang: 'en',
    settings: { ...DEFAULTS },
    results: {},
    query: '', original: '', type: '', defanged: false,
    box: null,
    keys: {}          // which optional providers are configured, never the values
  };

  const ready = (async () => {
    let stored = null;
    try {
      const o = await chrome.storage.sync.get('osint_settings');
      stored = o.osint_settings || null;
    } catch (_) {}

    if (stored) {
      Object.assign(state.settings, stored);
    } else {
      // one-time migration from the old per-site value
      try {
        const old = localStorage.getItem('osint_lang');
        if (old === 'tr' || old === 'en') state.settings.lang = old;
      } catch (_) {}
      saveSettings();
    }
    state.lang = state.settings.lang;

    try {
      const p = await chrome.storage.local.get(['osint_box', 'osint_keys']);
      state.box = p.osint_box || null;
      const k = p.osint_keys || {};
      state.keys = { vt: !!k.vt, shodan: !!k.shodan };
    } catch (_) {}
  })();

  function saveSettings() {
    try { chrome.storage.sync.set({ osint_settings: state.settings }); } catch (_) {}
  }

  // The options page writes to storage.sync, but this script is injected once
  // per page — without these two paths an already-open tab keeps whatever
  // settings were current at injection time.
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'sync' && changes.osint_settings) {
        Object.assign(state.settings, changes.osint_settings.newValue || {});
        state.lang = state.settings.lang;
      }
      if (area === 'local' && changes.osint_box) {
        state.box = changes.osint_box.newValue || null;
      }
    });
  } catch (_) {}

  async function refreshSettings() {
    try {
      const o = await chrome.storage.sync.get('osint_settings');
      if (o.osint_settings) {
        Object.assign(state.settings, o.osint_settings);
        state.lang = state.settings.lang;
      }
      const p = await chrome.storage.local.get(['osint_box', 'osint_keys']);
      state.box = p.osint_box || null;
      const k = p.osint_keys || {};
      state.keys = { vt: !!k.vt, shodan: !!k.shodan };
    } catch (_) {}
  }

  async function addHistory(entry) {
    if (!state.settings.historyOn) return;
    try {
      const o = await chrome.storage.local.get('osint_history');
      const h = (o.osint_history || []).filter(x => x.q !== entry.q);
      h.unshift(entry);
      await chrome.storage.local.set({ osint_history: h.slice(0, 50) });
    } catch (_) {}
  }

  // ── Translations ─────────────────────────────────────────────────────────
  const L = {
    en: {
      subtitle: 'Threat Intelligence',
      copy: 'Copy', copied: 'Copied',
      minimize: '−', close: '×', restore: '+',
      langBtn: 'TR',
      loading: (s) => `Querying ${s}…`,
      noData: 'No records found.',
      naService: 'This service does not support this IOC type.',
      openIn: 'View full report',
      verdict: { clean: 'Clean', malicious: 'Malicious', suspicious: 'Suspicious', unknown: 'Unknown' },
      types: { ip:'IPv4', ipv6:'IPv6', md5:'MD5', sha1:'SHA-1', sha256:'SHA-256', domain:'Domain', url:'URL', email:'Email', unknown:'Unknown' },
      // row labels
      country: 'Country', region: 'Region / City', isp: 'ISP', org: 'Organization',
      as: 'AS', hostname: 'Hostname', timezone: 'Timezone', coordinates: 'Coordinates',
      flags: 'Flags', openPorts: 'Open Ports', cves: 'CVEs', cpes: 'CPEs',
      tags: 'Tags', hostnames: 'Hostnames', classification: 'Classification',
      name: 'Name', lastSeen: 'Last Seen', scanNoise: 'Scan Noise', knownGood: 'Known Good (RIOT)',
      domainName: 'Domain', registered: 'Registered', expires: 'Expires',
      lastChanged: 'Last Changed', registrar: 'Registrar', nameservers: 'Name Servers',
      status: 'Status', handle: 'Handle', ipVersion: 'IP Version',
      startAddr: 'Start Address', endAddr: 'End Address', type: 'Type',
      certCount: 'Total Certificates', subdomains: 'Subdomains', recentCerts: 'Recent Certificates',
      issuer: 'Issuer', validity: 'Validity', dnsRecords: 'DNS Records',
      fileName: 'File Name', mimeType: 'MIME Type', size: 'Size',
      knownMalicious: 'Known Malicious', product: 'Product', sourceDb: 'Source DB',
      trustScore: 'Trust Score', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256',
      newDomain: 'Newly registered domain',
      notInDb: (s) => `Not found in ${s} database.`,
      unseenIP: 'IP has not been observed by GreyNoise.',
      noRecords: 'No DNS records found.',
      noCerts: 'No certificates found for this domain.',
      hashNotFound: 'Hash not in CIRCL NSRL database. May be unknown or a new sample.',
      activeScanner: 'Yes — active scanner',
      yes: 'Yes', no: 'No',
      // emailrep
      reputation: 'Reputation', references: 'References', blacklisted: 'Blacklisted',
      maliciousActivity: 'Malicious Activity', credentialsLeaked: 'Credentials Leaked',
      dataBreach: 'Data Breach', spam: 'Spam', spoofable: 'Spoofable',
      disposable: 'Disposable', freeProvider: 'Free Provider', deliverable: 'Deliverable',
      profiles: 'Social Profiles', domainAge: 'Domain Age',
      // urlscan
      totalScans: 'Total Scans', recentScans: 'Recent Scans',
      // scan mode
      scanActive: (n) => `OSINT Scan active · ${n} IOC${n !== 1 ? 's' : ''} highlighted · click any to query`,
      // v1.4
      report: 'Report', reportCopied: 'Report copied',
      defangedFrom: (o) => `Defanged input detected — refanged from ${o}`,
      overall: 'Overall',
      overallDetail: (m, n) => `${m} of ${n} services flag this`,
      overallClean: 'No service flagged this indicator',
      overallUnknown: 'No records found — that is not proof of safety',
      cached: 'cached',
      torExit: 'Tor Exit Node', torListSize: 'Exit nodes in list',
      torYes: 'Yes — this IP is a Tor exit node',
      torNo: 'Not a known Tor exit node',
      cvss: 'CVSS', severity: 'Severity', highestCvss: 'Highest CVSS',
      kevWarn: (n) => `${n} of these CVEs ${n === 1 ? 'is' : 'are'} in CISA's Known Exploited Vulnerabilities catalog — actively exploited in the wild`,
      // v1.6
      summary: 'Summary', keyFacts: 'Key facts', findings: 'Service findings',
      pivotHint: 'Click any underlined value to look it up',
      waiting: 'Waiting for results…',
      location: 'Location', network: 'Network', exposure: 'Exposure',
      worstCve: 'Worst CVE', torNode: 'Tor exit node', scanner: 'Scanner activity',
      domainAgeK: 'Domain age', certs: 'Certificates', scans: 'URLScan verdicts',
      mailDomain: 'Mail domain', fileName2: 'File', pending: 'querying…',
      daysOld: (n) => `${n} days old`,
      detectionRate: 'AV detection rate',
      mhrHit: 'This hash is in the Team Cymru Malware Hash Registry — it is known malware.',
      mhrUnknown: 'Not in the malware registry. That is not proof the file is safe — it may simply be too new or too rare.',
      knownGoodFile: 'Known legitimate file (NSRL)',
      hashNotInNsrl: 'Not a known legitimate file.',
      sha256Note: 'The malware registry only covers MD5 and SHA-1.',
      // triage
      triage: 'Triage', indicators: 'indicators', checking: 'checking…',
      malicious2: 'malicious', suspicious2: 'suspicious',
      nothingFlagged: 'nothing flagged', showList: 'Show list',
      capped: (n) => n > 0 ? `${n} more not graded` : 'page truncated',
      moreRows: (n) => `${n} more not shown — use Report for the full list`,
      // action feedback
      copiedIndicator: 'Indicator copied to clipboard',
      reportCopiedN: (n) => `Report copied — ${n} ${n === 1 ? 'entry' : 'entries'}`,
      copyFailed: 'Could not write to the clipboard. The page may have blocked it — try again after clicking the page.',
      caseAdded: (v, n) => `${v} added — case now has ${n}`,
      caseAddedMany: (a, n) => `${a} added — case now has ${n}`,
      caseNothing: 'The case is empty, so there is nothing to do yet.',
      caseCleared: (n) => `Case cleared — ${n} removed`,
      exported: (f, n) => `Downloaded ${f} — ${n} indicators`,
      exportFailed: 'The export could not be generated.',
      noIndicators: 'No indicators found on this page',
      triageFailed: 'Could not reach the grading service',
      // threat feeds
      threatFeeds: 'Threat Feeds', malwareFamily: 'Malware family',
      threatType: 'Threat type', confidence: 'Confidence', firstSeen: 'First seen',
      listedIn: 'Listed in',
      feedClean: 'Not in any threat feed. These feeds carry a few thousand current indicators, so this is not evidence the indicator is safe.',
      feedNote: 'Feeds are downloaded once and matched on your device — lookups cost no requests.',
      indexedIocs: 'Indexed indicators', updated: 'Updated',
      // graph
      graph: 'Pivot graph', graphBtn: 'Graph', fit: 'Fit to view',
      graphHint: 'double-click a node to expand · drag to pan · scroll to zoom',
      flagged: 'In a threat feed',
      expand: 'Expand', expanding: 'Expanding…', expanded: 'Expanded',
      lookupBtn: 'Look up',
      // otx
      pulses: 'Reports', campaign: 'Campaign', adversary: 'Adversary',
      attack: 'MITRE ATT&CK', otxClean: 'Flagged as known-good infrastructure by OTX.',
      otxNone: 'No community reports mention this indicator.',
      // ripe
      routing: 'Routing', announcedBy: 'Announced by', prefix: 'Prefix',
      asnPrefixes: 'Prefixes in this AS', asnPeers: 'Peer networks',
      // case file
      caseFile: 'Case', addToCase: '+ Case', addedToCase: 'Added',
      caseEmpty: 'No indicators collected yet. Open any lookup and press “+ Case”.',
      caseCount: (n) => `${n} indicator${n === 1 ? '' : 's'}`,
      addAll: 'Add all to case', exportAs: 'Export',
      clearCase: 'Clear', removeItem: 'Remove',
      caseNamePh: 'Case name',
      dlStix: 'STIX 2.1', dlMisp: 'MISP', dlCsv: 'CSV', dlMd: 'Markdown',
      // optional providers
      needsKey: (p) => `Add a ${p} API key in Settings to enable this source.`,
      detections: 'Detections', engines: 'Flagging engines',
      maliciousL: 'malicious', suspiciousL: 'suspicious',
      vtNotFound: 'VirusTotal has never analysed this indicator.',
      services2: 'Services',
    },
    tr: {
      subtitle: 'Tehdit İstihbaratı',
      copy: 'Kopyala', copied: 'Kopyalandı',
      minimize: '−', close: '×', restore: '+',
      langBtn: 'EN',
      loading: (s) => `${s} sorgulanıyor…`,
      noData: 'Kayıt bulunamadı.',
      naService: 'Bu servis bu IOC tipi için kullanılamaz.',
      openIn: 'Tam raporu gör',
      verdict: { clean: 'Temiz', malicious: 'Tehlikeli', suspicious: 'Şüpheli', unknown: 'Bilinmiyor' },
      types: { ip:'IPv4', ipv6:'IPv6', md5:'MD5', sha1:'SHA-1', sha256:'SHA-256', domain:'Domain', url:'URL', email:'E-posta', unknown:'Bilinmiyor' },
      country: 'Ülke', region: 'Bölge / Şehir', isp: 'ISP', org: 'Organizasyon',
      as: 'AS', hostname: 'Hostname', timezone: 'Saat Dilimi', coordinates: 'Koordinat',
      flags: 'Bayraklar', openPorts: 'Açık Portlar', cves: 'CVE\'ler', cpes: 'CPE\'ler',
      tags: 'Etiketler', hostnames: 'Hostnames', classification: 'Sınıflandırma',
      name: 'İsim', lastSeen: 'Son Görülme', scanNoise: 'Tarama Gürültüsü', knownGood: 'Bilinen İyi (RIOT)',
      domainName: 'Domain', registered: 'Kayıt Tarihi', expires: 'Bitiş Tarihi',
      lastChanged: 'Son Güncelleme', registrar: 'Kayıt Kuruluşu', nameservers: 'Name Serverlar',
      status: 'Durum', handle: 'Handle', ipVersion: 'IP Versiyonu',
      startAddr: 'Başlangıç IP', endAddr: 'Bitiş IP', type: 'Tip',
      certCount: 'Toplam Sertifika', subdomains: 'Alt Domainler', recentCerts: 'Son Sertifikalar',
      issuer: 'Veren Kurum', validity: 'Geçerlilik', dnsRecords: 'DNS Kayıtları',
      fileName: 'Dosya Adı', mimeType: 'MIME Tipi', size: 'Boyut',
      knownMalicious: 'Bilinen Zararlı', product: 'Ürün', sourceDb: 'Kaynak DB',
      trustScore: 'Güven Skoru', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256',
      newDomain: 'Yeni kayıtlı domain',
      notInDb: (s) => `${s} veritabanında kayıt yok.`,
      unseenIP: 'Bu IP GreyNoise tarafından gözlemlenmedi.',
      noRecords: 'DNS kaydı bulunamadı.',
      noCerts: 'Bu domain için sertifika bulunamadı.',
      hashNotFound: 'Hash CIRCL NSRL\'de bulunamadı. Bilinmeyen veya yeni bir örnek olabilir.',
      activeScanner: 'Evet — aktif tarayıcı',
      yes: 'Evet', no: 'Hayır',
      // emailrep
      reputation: 'İtibar', references: 'Referans Sayısı', blacklisted: 'Kara Listede',
      maliciousActivity: 'Zararlı Aktivite', credentialsLeaked: 'Şifre Sızdırıldı',
      dataBreach: 'Veri İhlali', spam: 'Spam', spoofable: 'Taklit Edilebilir',
      disposable: 'Geçici Adres', freeProvider: 'Ücretsiz Servis', deliverable: 'Teslim Edilebilir',
      profiles: 'Sosyal Profiller', domainAge: 'Domain Yaşı',
      // urlscan
      totalScans: 'Toplam Tarama', recentScans: 'Son Taramalar',
      // scan mode
      scanActive: (n) => `OSINT Tarama aktif · ${n} IOC işaretlendi · tıklayarak sorgulayın`,
      // v1.4
      report: 'Rapor', reportCopied: 'Rapor kopyalandı',
      defangedFrom: (o) => `Zararsızlaştırılmış girdi — ${o} çözümlendi`,
      overall: 'Genel',
      overallDetail: (m, n) => `${n} servisten ${m} tanesi işaretledi`,
      overallClean: 'Hiçbir servis bu göstergeyi işaretlemedi',
      overallUnknown: 'Kayıt bulunamadı — bu güvenli olduğu anlamına gelmez',
      cached: 'önbellek',
      torExit: 'Tor Çıkış Nodu', torListSize: 'Listedeki çıkış nodu',
      torYes: 'Evet — bu IP bir Tor çıkış nodu',
      torNo: 'Bilinen bir Tor çıkış nodu değil',
      cvss: 'CVSS', severity: 'Önem', highestCvss: 'En yüksek CVSS',
      kevWarn: (n) => `Bu CVE'lerden ${n} tanesi CISA'nın Bilinen Sömürülen Zafiyetler kataloğunda — vahşi doğada aktif olarak sömürülüyor`,
      // v1.6
      summary: 'Özet', keyFacts: 'Öne çıkanlar', findings: 'Servis bulguları',
      pivotHint: 'Altı çizili değere tıklayarak sorgulayın',
      waiting: 'Sonuçlar bekleniyor…',
      location: 'Konum', network: 'Ağ', exposure: 'Açık yüzey',
      worstCve: 'En ağır CVE', torNode: 'Tor çıkış nodu', scanner: 'Tarayıcı aktivitesi',
      domainAgeK: 'Domain yaşı', certs: 'Sertifikalar', scans: 'URLScan yargıları',
      mailDomain: 'Posta domaini', fileName2: 'Dosya', pending: 'sorgulanıyor…',
      daysOld: (n) => `${n} günlük`,
      detectionRate: 'AV tespit oranı',
      mhrHit: 'Bu hash Team Cymru Malware Hash Registry\'de kayıtlı — bilinen zararlı yazılım.',
      mhrUnknown: 'Zararlı yazılım kaydı yok. Bu dosyanın temiz olduğunun kanıtı değildir — çok yeni veya çok nadir olabilir.',
      knownGoodFile: 'Bilinen meşru dosya (NSRL)',
      hashNotInNsrl: 'Bilinen meşru bir dosya değil.',
      sha256Note: 'Zararlı yazılım kaydı yalnızca MD5 ve SHA-1 kapsıyor.',
      // triage
      triage: 'Triyaj', indicators: 'gösterge', checking: 'kontrol ediliyor…',
      malicious2: 'zararlı', suspicious2: 'şüpheli',
      nothingFlagged: 'işaretlenen yok', showList: 'Listeyi göster',
      capped: (n) => n > 0 ? `${n} tanesi değerlendirilmedi` : 'sayfa kırpıldı',
      moreRows: (n) => `${n} tane daha var — tam liste için Rapor'u kullanın`,
      // action feedback
      copiedIndicator: 'Gösterge panoya kopyalandı',
      reportCopiedN: (n) => `Rapor kopyalandı — ${n} kayıt`,
      copyFailed: 'Panoya yazılamadı. Sayfa engellemiş olabilir — sayfaya tıklayıp tekrar deneyin.',
      caseAdded: (v, n) => `${v} eklendi — vakada artık ${n} kayıt var`,
      caseAddedMany: (a, n) => `${a} tane eklendi — vakada artık ${n} kayıt var`,
      caseNothing: 'Vaka boş, yapılacak bir şey yok.',
      caseCleared: (n) => `Vaka temizlendi — ${n} kayıt silindi`,
      exported: (f, n) => `${f} indirildi — ${n} gösterge`,
      exportFailed: 'Dışa aktarım oluşturulamadı.',
      noIndicators: 'Bu sayfada gösterge bulunamadı',
      triageFailed: 'Değerlendirme servisine ulaşılamadı',
      // threat feeds
      threatFeeds: 'Tehdit Feed\'leri', malwareFamily: 'Zararlı ailesi',
      threatType: 'Tehdit tipi', confidence: 'Güven', firstSeen: 'İlk görülme',
      listedIn: 'Kayıtlı olduğu liste',
      feedClean: 'Hiçbir tehdit feed\'inde yok. Bu feed\'ler birkaç bin güncel gösterge içerir, dolayısıyla bu güvenli olduğunun kanıtı değildir.',
      feedNote: 'Feed\'ler bir kez indirilip cihazınızda eşleştirilir — sorgular istek harcamaz.',
      indexedIocs: 'İndekslenen gösterge', updated: 'Güncellendi',
      // graph
      graph: 'Pivot grafiği', graphBtn: 'Grafik', fit: 'Ekrana sığdır',
      graphHint: 'düğüme çift tıkla genişlet · sürükle kaydır · tekerlekle yakınlaştır',
      flagged: 'Tehdit feed\'inde',
      expand: 'Genişlet', expanding: 'Genişletiliyor…', expanded: 'Genişletildi',
      lookupBtn: 'Sorgula',
      // otx
      pulses: 'Rapor', campaign: 'Kampanya', adversary: 'Aktör',
      attack: 'MITRE ATT&CK', otxClean: 'OTX bunu bilinen güvenli altyapı olarak işaretlemiş.',
      otxNone: 'Bu göstergeden bahseden topluluk raporu yok.',
      // ripe
      routing: 'Yönlendirme', announcedBy: 'Duyuran', prefix: 'Prefix',
      asnPrefixes: 'Bu AS\'nin prefix sayısı', asnPeers: 'Komşu ağ sayısı',
      // case file
      caseFile: 'Vaka', addToCase: '+ Vaka', addedToCase: 'Eklendi',
      caseEmpty: 'Henüz gösterge toplanmadı. Bir sorgu açıp “+ Vaka”ya basın.',
      caseCount: (n) => `${n} gösterge`,
      addAll: 'Hepsini vakaya ekle', exportAs: 'Dışa aktar',
      clearCase: 'Temizle', removeItem: 'Çıkar',
      caseNamePh: 'Vaka adı',
      dlStix: 'STIX 2.1', dlMisp: 'MISP', dlCsv: 'CSV', dlMd: 'Markdown',
      // optional providers
      needsKey: (p) => `Bu kaynağı açmak için Ayarlar'dan ${p} API anahtarı ekleyin.`,
      detections: 'Tespitler', engines: 'İşaretleyen motorlar',
      maliciousL: 'zararlı', suspiciousL: 'şüpheli',
      vtNotFound: 'VirusTotal bu göstergeyi hiç analiz etmemiş.',
      services2: 'Servisler',
    }
  };

  const t = (key, ...args) => {
    const v = L[state.lang][key];
    return typeof v === 'function' ? v(...args) : (v ?? L.en[key] ?? key);
  };

  // ── CSS ──────────────────────────────────────────────────────────────────
  const CSS = `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :host {
      /* Ground: cold near-black. Colour is reserved for verdicts only. */
      --bg:       #0a0b0d;
      --surface:  #101217;
      --surface2: #161920;
      --raise:    #1c2029;
      --hair:     #1e222b;
      --hair2:    #171b22;

      --text:     #e9ebef;
      --text2:    #969ead;
      --text3:    #596170;

      /* Steel blue — sits clear of the red/amber/green semantics. */
      --accent:   #6fa8d4;
      --accent-d: #1a2833;

      --clean:    #5cc98d;
      --susp:     #e0a45c;
      --mal:      #ec7a76;

      --clean-bg: #0f2018;
      --susp-bg:  #241b0f;
      --mal-bg:   #241414;

      --font: "Segoe UI Variable Text", "SF Pro Text", -apple-system,
              BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      --mono: "SF Mono", "Cascadia Code", "JetBrains Mono", ui-monospace,
              Consolas, monospace;

      --r:   12px;
      --r-s: 7px;
    }

    :host(.light) {
      --bg:       #ffffff;
      --surface:  #f7f8fa;
      --surface2: #f1f3f6;
      --raise:    #e9ecf1;
      --hair:     #e2e6ec;
      --hair2:    #eef1f5;

      --text:     #12151a;
      --text2:    #5a6474;
      --text3:    #8b95a5;

      --accent:   #2f6f9e;
      --accent-d: #e8f1f8;

      --clean:    #1d8a55;
      --susp:     #a76a12;
      --mal:      #c0433f;

      --clean-bg: #eaf6ef;
      --susp-bg:  #fbf2e4;
      --mal-bg:   #fdeceb;
    }

    /* ── Shell ───────────────────────────────────────────────────────────── */
    #panel {
      position: fixed; top: 18px; right: 18px;
      width: 404px; max-height: 86vh;
      background: var(--bg);
      border: 1px solid var(--hair);
      border-radius: var(--r);
      box-shadow: 0 1px 2px rgba(0,0,0,.28),
                  0 12px 28px -6px rgba(0,0,0,.5),
                  0 32px 64px -12px rgba(0,0,0,.55);
      z-index: 2147483647;
      display: flex; flex-direction: column;
      font-family: var(--font);
      font-size: 13px; color: var(--text);
      overflow: hidden;
      -webkit-font-smoothing: antialiased;
    }
    :host(.light) #panel {
      box-shadow: 0 1px 2px rgba(16,24,40,.05),
                  0 12px 28px -6px rgba(16,24,40,.12),
                  0 32px 64px -12px rgba(16,24,40,.14);
    }
    #panel.minimized #body,
    #panel.minimized #overall,
    #panel.minimized .defang-note { display: none; }

    /* ── Header ──────────────────────────────────────────────────────────── */
    #header {
      display: flex; align-items: center; gap: 9px;
      padding: 0 8px 0 14px; height: 38px;
      cursor: move; user-select: none; flex-shrink: 0;
      border-bottom: 1px solid var(--hair2);
    }
    #logo {
      font-size: 10px; font-weight: 600; letter-spacing: .16em;
      color: var(--text2); text-transform: uppercase;
    }
    #htitle { display: none; }

    .type-pill {
      margin-left: auto;
      font-size: 9px; font-weight: 600; letter-spacing: .1em;
      padding: 2px 7px; border-radius: 4px; text-transform: uppercase;
      background: var(--surface2); color: var(--text2);
      border: 1px solid var(--hair);
    }
    .pill-ip, .pill-ipv6, .pill-md5, .pill-sha1, .pill-sha256,
    .pill-domain, .pill-url, .pill-email, .pill-unknown {
      background: var(--surface2); color: var(--text2); border-color: var(--hair);
    }

    .hbtn {
      background: none; border: none; cursor: pointer;
      color: var(--text3); font-size: 13px; line-height: 1;
      width: 24px; height: 24px; border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      transition: color .14s, background .14s;
      font-family: var(--font);
    }
    .hbtn:hover { color: var(--text); background: var(--surface2); }
    .hbtn:focus-visible { outline: 1px solid var(--accent); outline-offset: -1px; }
    .hbtn#lang-btn { font-size: 9.5px; font-weight: 600; letter-spacing: .08em; width: auto; padding: 0 7px; }

    /* ── Query ───────────────────────────────────────────────────────────── */
    #qbar {
      display: flex; align-items: center; gap: 6px;
      padding: 13px 14px 12px;
      flex-shrink: 0;
    }
    #qtext {
      flex: 1; min-width: 0;
      font-family: var(--mono); font-size: 14px; letter-spacing: -.01em;
      color: var(--text); font-variant-numeric: tabular-nums;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    #copy-btn, #report-btn, #graph-btn, #case-btn {
      font-size: 10.5px; font-weight: 500;
      padding: 4px 9px; border-radius: 6px; white-space: nowrap;
      background: none; border: 1px solid transparent;
      color: var(--text3); cursor: pointer; transition: all .14s;
      font-family: var(--font);
    }
    #copy-btn:hover, #report-btn:hover, #graph-btn:hover, #case-btn:hover {
      color: var(--text); background: var(--surface2); border-color: var(--hair);
    }
    #copy-btn:focus-visible, #report-btn:focus-visible,
    #graph-btn:focus-visible, #case-btn:focus-visible {
      outline: 1px solid var(--accent); outline-offset: 1px;
    }
    /* Graph is a distinct feature (a whole pivot view), not a text action like
       copy/report/case — give it a filled chip + icon so it reads as its own
       affordance instead of blending into the row. */
    #graph-btn {
      display: inline-flex; align-items: center; gap: 5px;
      color: var(--accent);
      background: var(--accent-d);
      border-color: color-mix(in srgb, var(--accent) 35%, transparent);
    }
    #graph-btn:hover {
      background: var(--accent-d);
      border-color: var(--accent);
      color: var(--accent);
    }
    #graph-btn svg { flex-shrink: 0; display: block; }

    /* ── Defang note ─────────────────────────────────────────────────────── */
    .defang-note {
      margin: 0 14px 12px;
      padding: 7px 10px; border-radius: var(--r-s);
      background: var(--accent-d);
      color: var(--accent); font-size: 10.5px;
      font-family: var(--mono); flex-shrink: 0;
      word-break: break-all; line-height: 1.45;
    }

    /* ── Overall verdict — the headline answer ───────────────────────────── */
    .overall {
      display: flex; align-items: center; gap: 10px;
      margin: 0 14px 13px; padding: 11px 13px;
      border-radius: var(--r-s);
      background: var(--surface); border: 1px solid var(--hair);
      font-size: 12px; flex-shrink: 0;
    }
    .overall:empty { display: none; }
    .overall-dot {
      width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
      background: var(--text3);
      box-shadow: 0 0 0 3px transparent;
    }
    .overall-label { font-weight: 600; font-size: 13px; letter-spacing: -.005em; }
    .overall-detail { color: var(--text2); font-size: 11px; margin-left: auto; text-align: right; }

    .overall.clean      { background: var(--clean-bg); border-color: color-mix(in srgb, var(--clean) 26%, transparent); }
    .overall.clean      .overall-dot { background: var(--clean); box-shadow: 0 0 0 3px color-mix(in srgb, var(--clean) 16%, transparent); }
    .overall.clean      .overall-label { color: var(--clean); }
    .overall.suspicious { background: var(--susp-bg);  border-color: color-mix(in srgb, var(--susp) 26%, transparent); }
    .overall.suspicious .overall-dot { background: var(--susp); box-shadow: 0 0 0 3px color-mix(in srgb, var(--susp) 16%, transparent); }
    .overall.suspicious .overall-label { color: var(--susp); }
    .overall.malicious  { background: var(--mal-bg);   border-color: color-mix(in srgb, var(--mal) 26%, transparent); }
    .overall.malicious  .overall-dot { background: var(--mal); box-shadow: 0 0 0 3px color-mix(in srgb, var(--mal) 16%, transparent); }
    .overall.malicious  .overall-label { color: var(--mal); }
    .overall.unknown    .overall-label { color: var(--text2); }

    /* ── Tabs (status dots live here now — the chip row is gone) ─────────── */
    #body { display: flex; flex-direction: column; overflow: hidden; flex: 1; min-height: 0; }
    #tabs {
      display: flex; overflow-x: auto; flex-shrink: 0;
      border-bottom: 1px solid var(--hair);
      padding: 0 8px;
      scrollbar-width: none;
    }
    #tabs::-webkit-scrollbar { display: none; }
    .tab {
      display: flex; align-items: center; gap: 6px;
      padding: 9px 9px 8px; white-space: nowrap;
      background: none; border: none;
      border-bottom: 1.5px solid transparent;
      margin-bottom: -1px;
      color: var(--text3); cursor: pointer;
      font-size: 11.5px; font-weight: 500; letter-spacing: -.003em;
      transition: color .14s; font-family: var(--font);
    }
    .tab:hover { color: var(--text2); }
    .tab.active { color: var(--text); border-bottom-color: var(--text); }
    .tab:focus-visible { outline: 1px solid var(--accent); outline-offset: -2px; border-radius: 4px; }

    .chip-dot {
      width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0;
      background: var(--text3); transition: background .2s;
    }
    .chip-dot.loading    { background: var(--text3); animation: pulse 1.15s ease-in-out infinite; }
    .chip-dot.clean      { background: var(--clean); }
    .chip-dot.suspicious { background: var(--susp); }
    .chip-dot.malicious  { background: var(--mal); }
    .chip-dot.error, .chip-dot.na, .chip-dot.unknown { background: var(--text3); opacity: .5; }
    @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: .25 } }

    /* ── Content ─────────────────────────────────────────────────────────── */
    #content {
      overflow-y: auto; flex: 1;
      scrollbar-width: thin; scrollbar-color: var(--raise) transparent;
    }
    #content::-webkit-scrollbar { width: 8px; }
    #content::-webkit-scrollbar-track { background: transparent; }
    #content::-webkit-scrollbar-thumb {
      background: var(--raise); border-radius: 4px;
      border: 2px solid var(--bg); background-clip: padding-box;
    }
    .pane { padding: 14px; display: none; }
    .pane.active { display: block; }

    /* ── Per-service verdict — light, since .overall carries the headline ── */
    .verdict { display: flex; align-items: baseline; gap: 8px; margin-bottom: 14px; }
    .verdict-bar { display: none; }
    .verdict-body { display: flex; align-items: baseline; gap: 8px; flex: 1; min-width: 0; }
    .verdict-label {
      font-size: 11px; font-weight: 600;
      letter-spacing: .09em; text-transform: uppercase;
    }
    .verdict.clean      .verdict-label { color: var(--clean); }
    .verdict.malicious  .verdict-label { color: var(--mal); }
    .verdict.suspicious .verdict-label { color: var(--susp); }
    .verdict.unknown    .verdict-label { color: var(--text2); }
    .verdict-detail {
      font-size: 11px; color: var(--text2);
      margin-left: auto; text-align: right; flex-shrink: 0;
    }

    /* ── Data rows ───────────────────────────────────────────────────────── */
    .row {
      display: flex; gap: 14px; padding: 5px 0;
      font-size: 12.5px; align-items: baseline;
    }
    .row-key {
      color: var(--text3); min-width: 106px; flex-shrink: 0;
      font-size: 11px; letter-spacing: .005em;
    }
    .row-val {
      color: var(--text); word-break: break-word; flex: 1;
      line-height: 1.5; font-variant-numeric: tabular-nums;
    }
    .mono { font-family: var(--mono); font-size: 11.5px; letter-spacing: -.01em; }

    /* ── Section label ───────────────────────────────────────────────────── */
    .section {
      font-size: 9px; font-weight: 600; letter-spacing: .15em;
      text-transform: uppercase; color: var(--text3);
      margin: 18px 0 9px; padding-bottom: 7px;
      border-bottom: 1px solid var(--hair2);
    }
    .pane > .section:first-child { margin-top: 0; }

    /* ── Tags ────────────────────────────────────────────────────────────── */
    .tags { display: flex; flex-wrap: wrap; gap: 4px; }
    .tag {
      font-size: 10.5px; padding: 3px 7px; border-radius: 5px;
      background: var(--surface2); color: var(--text2);
      border: 1px solid var(--hair); font-family: var(--mono);
      letter-spacing: -.01em;
    }
    .tag.red    { background: var(--mal-bg);   color: var(--mal);   border-color: color-mix(in srgb, var(--mal) 22%, transparent); }
    .tag.yellow { background: var(--susp-bg);  color: var(--susp);  border-color: color-mix(in srgb, var(--susp) 22%, transparent); }
    .tag.green  { background: var(--clean-bg); color: var(--clean); border-color: color-mix(in srgb, var(--clean) 22%, transparent); }
    .tag.blue   { background: var(--accent-d); color: var(--accent); border-color: color-mix(in srgb, var(--accent) 22%, transparent); }

    /* ── Ports ───────────────────────────────────────────────────────────── */
    .ports { display: flex; flex-wrap: wrap; gap: 4px; }
    .port {
      font-family: var(--mono); font-size: 10.5px;
      font-variant-numeric: tabular-nums;
      padding: 3px 7px; border-radius: 5px;
      background: var(--surface2); color: var(--text2);
      border: 1px solid var(--hair);
    }

    /* ── Subdomains ──────────────────────────────────────────────────────── */
    .subdomain-list {
      display: flex; flex-direction: column; gap: 1px;
      max-height: 190px; overflow-y: auto;
      scrollbar-width: thin; scrollbar-color: var(--raise) transparent;
    }
    .subdomain-list::-webkit-scrollbar { width: 6px; }
    .subdomain-list::-webkit-scrollbar-thumb { background: var(--raise); border-radius: 3px; }
    .sub {
      font-family: var(--mono); font-size: 11px; color: var(--text2);
      padding: 4px 7px; border-radius: 4px;
    }
    .sub:nth-child(odd) { background: var(--surface); }

    /* ── DNS ─────────────────────────────────────────────────────────────── */
    .dns-group { margin-bottom: 12px; }
    .dns-type {
      font-size: 9px; font-weight: 600; letter-spacing: .15em;
      color: var(--text3); text-transform: uppercase; margin-bottom: 5px;
    }
    .dns-val {
      font-family: var(--mono); font-size: 11px; color: var(--text);
      padding: 5px 8px; border-radius: 5px;
      background: var(--surface); margin-bottom: 2px;
      word-break: break-all; line-height: 1.45;
    }

    /* ── Cards (certs, scans) ────────────────────────────────────────────── */
    .cert-card {
      background: var(--surface); border: 1px solid var(--hair);
      border-radius: var(--r-s); padding: 9px 11px; margin-bottom: 5px;
    }
    .cert-cn {
      font-size: 11.5px; color: var(--text); margin-bottom: 5px;
      font-family: var(--mono); word-break: break-all; line-height: 1.4;
    }
    .cert-meta {
      font-size: 10.5px; color: var(--text3);
      display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
    }

    /* ── CVE cards ───────────────────────────────────────────────────────── */
    .cve-card {
      background: var(--surface); border: 1px solid var(--hair);
      border-radius: var(--r-s); padding: 9px 11px; margin-bottom: 5px;
    }
    .cve-card.sev-critical { border-color: color-mix(in srgb, var(--mal) 34%, transparent); }
    .cve-card.sev-high     { border-color: color-mix(in srgb, var(--susp) 30%, transparent); }
    .cve-head { display: flex; align-items: center; gap: 6px; margin-bottom: 5px; flex-wrap: wrap; }
    .cve-id {
      font-family: var(--mono); font-size: 11px; color: var(--text);
      font-weight: 500; font-variant-numeric: tabular-nums;
    }
    .cve-score {
      font-family: var(--mono); font-size: 9.5px; font-weight: 600;
      padding: 2px 6px; border-radius: 4px;
      background: var(--surface2); border: 1px solid var(--hair); color: var(--text2);
      font-variant-numeric: tabular-nums;
    }
    .cve-card.sev-critical .cve-score { color: var(--mal);  border-color: color-mix(in srgb, var(--mal) 30%, transparent); }
    .cve-card.sev-high     .cve-score { color: var(--susp); border-color: color-mix(in srgb, var(--susp) 30%, transparent); }
    .cve-score.kev {
      background: var(--mal); color: #0a0b0d; border-color: var(--mal);
      letter-spacing: .06em;
    }
    .cve-card.sev-critical .cve-score.kev { color: #0a0b0d; }
    :host(.light) .cve-score.kev { color: #fff; }
    :host(.light) .cve-card.sev-critical .cve-score.kev { color: #fff; }
    .cve-summary { font-size: 11px; color: var(--text2); line-height: 1.5; }

    /* ── External link ───────────────────────────────────────────────────── */
    .ext-link {
      display: inline-flex; align-items: center; gap: 5px;
      color: var(--text2); text-decoration: none;
      font-size: 11px; font-weight: 500; margin-top: 16px;
      padding: 6px 11px; border-radius: var(--r-s);
      border: 1px solid var(--hair); transition: all .14s;
    }
    .ext-link:hover { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 45%, transparent); }
    .ext-link:focus-visible { outline: 1px solid var(--accent); outline-offset: 1px; }

    /* ── States ──────────────────────────────────────────────────────────── */
    .loading {
      display: flex; flex-direction: column; align-items: center;
      justify-content: center; gap: 11px; padding: 40px 16px;
      color: var(--text3); font-size: 11.5px;
    }
    .spinner {
      width: 16px; height: 16px; border-radius: 50%;
      border: 1.5px solid var(--hair);
      border-top-color: var(--text2);
      animation: spin .65s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .msg {
      padding: 11px 13px; border-radius: var(--r-s);
      font-size: 12px; line-height: 1.55;
      border: 1px solid var(--hair); background: var(--surface); color: var(--text2);
    }
    .msg.error { background: var(--mal-bg);   color: var(--mal);   border-color: color-mix(in srgb, var(--mal) 24%, transparent); }
    .msg.info  { background: var(--clean-bg); color: var(--clean); border-color: color-mix(in srgb, var(--clean) 24%, transparent); }

    /* ── Warning banner ──────────────────────────────────────────────────── */
    .warn-banner {
      display: flex; align-items: flex-start; gap: 8px;
      padding: 9px 11px; border-radius: var(--r-s);
      background: var(--susp-bg);
      border: 1px solid color-mix(in srgb, var(--susp) 24%, transparent);
      color: var(--susp); font-size: 11px; font-weight: 500;
      margin-bottom: 12px; line-height: 1.45;
    }
    .warn-dot {
      width: 5px; height: 5px; border-radius: 50%;
      background: var(--susp); flex-shrink: 0; margin-top: 5px;
    }

    /* ── Pivot targets ───────────────────────────────────────────────────── */
    .pv {
      cursor: pointer;
      border-bottom: 1px dashed color-mix(in srgb, var(--accent) 45%, transparent);
      transition: color .13s, border-color .13s, background .13s;
    }
    .pv:hover { color: var(--accent); border-bottom-color: var(--accent); }
    .tag.pv:hover, .sub.pv:hover { background: var(--accent-d); border-bottom-style: dashed; }
    .dns-val.pv:hover { background: var(--accent-d); }

    .pivot-hint {
      margin-top: 16px; padding-top: 11px;
      border-top: 1px solid var(--hair2);
      font-size: 10.5px; color: var(--text3);
    }

    /* ── Summary findings ────────────────────────────────────────────────── */
    .tab-summary { font-weight: 600; }
    .finding {
      display: flex; align-items: baseline; gap: 8px;
      padding: 6px 0; font-size: 12px;
    }
    .finding-name {
      color: var(--text2); min-width: 82px; flex-shrink: 0;
      font-size: 11px; font-weight: 500;
    }
    .finding-txt { color: var(--text); flex: 1; line-height: 1.45; word-break: break-word; }
    .finding .chip-dot { align-self: center; }

    /* ── Cached badge ────────────────────────────────────────────────────── */
    .cached-badge {
      font-size: 9px; letter-spacing: .12em; text-transform: uppercase;
      color: var(--text3); font-family: var(--mono);
    }

    /* ── Resize ──────────────────────────────────────────────────────────── */
    #resize { position: absolute; bottom: 0; left: 0; right: 0; height: 6px; cursor: ns-resize; }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
    }
  `;

  // ── Helpers ───────────────────────────────────────────────────────────────
  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  // Renders a value the user can click to run a fresh lookup on it.
  function pv(value, type) {
    if (!value) return '';
    const v = String(value).replace(/\.$/, '');
    return `<span class="pv" data-pv="${esc(v)}" data-pvt="${esc(type)}">${esc(v)}</span>`;
  }

  function pvList(arr, type, cls = '') {
    if (!arr?.length) return '';
    return `<div class="tags">${arr.map(v => {
      const s = String(v).replace(/\.$/, '');
      return `<span class="tag ${cls} pv" data-pv="${esc(s)}" data-pvt="${esc(type)}">${esc(s)}</span>`;
    }).join('')}</div>`;
  }

  // Every one of these renders data pulled from third-party APIs — WHOIS
  // registrant fields, certificate CN/O fields, OTX pulse names, scanned
  // URLs — none of which this extension controls. Escape by default; the
  // handful of call sites that intentionally pass pre-built HTML (pv()
  // output, or a static t('yes')/t('no') wrapped in a colored span) opt in
  // explicitly with `raw = true`.
  function row(label, value, cls = '', raw = false) {
    if (value === null || value === undefined || value === '' || value === '—') return '';
    const v = raw ? value : esc(value);
    return `<div class="row"><span class="row-key">${label}</span><span class="row-val ${cls}">${v}</span></div>`;
  }
  function section(label) { return `<div class="section">${label}</div>`; }
  function tagList(arr, cls = '') {
    if (!arr?.length) return '';
    return `<div class="tags">${arr.map(v => `<span class="tag ${cls}">${esc(v)}</span>`).join('')}</div>`;
  }
  function verdict(cls, label, detail = '') {
    return `<div class="verdict ${cls}">
      <div class="verdict-bar"></div>
      <div class="verdict-body">
        <span class="verdict-label">${esc(label)}</span>
        ${detail ? `<span class="verdict-detail">${esc(detail)}</span>` : ''}
      </div>
    </div>`;
  }
  function extLink(href, label) {
    return `<a href="${esc(href)}" target="_blank" class="ext-link">↗ ${esc(label)}</a>`;
  }
  function msg(text, type = 'neutral') { return `<div class="msg ${type}">${esc(text)}</div>`; }
  function loadingEl(name) {
    return `<div class="loading"><div class="spinner"></div><span>${t('loading', name)}</span></div>`;
  }

  // ── Renderers ─────────────────────────────────────────────────────────────
  function renderIPAPI(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    const vl = t('verdict')[d.verdict] || d.verdict;
    return `
      ${verdict(d.verdict, vl)}
      ${row(t('country'), d.country && d.countryCode ? `${d.country} (${d.countryCode})` : d.country)}
      ${row(t('region'), [d.region, d.city].filter(Boolean).join(', '))}
      ${row(t('isp'), d.isp)}
      ${row(t('org'), d.org)}
      ${row(t('as'), d.as, 'mono')}
      ${row(t('hostname'), d.hostname ? pv(d.hostname, 'domain') : null, 'mono', true)}
      ${row(t('timezone'), d.timezone)}
      ${row(t('coordinates'), d.lat && d.lon ? `${d.lat}, ${d.lon}` : null)}
      ${d.flags?.length ? section(t('flags')) + tagList(d.flags, 'yellow') : ''}
    `;
  }

  function renderInternetDB(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (!d.ports?.length && !d.vulns?.length) return msg(t('notInDb', 'InternetDB'), 'info');
    const vl = t('verdict')[d.verdict] || d.verdict;
    const vDetail = d.vulns?.length
      ? `${d.vulns.length} CVE${d.maxScore != null ? ` · ${t('highestCvss')} ${d.maxScore}` : ''}`
      : '';
    const kevBanner = d.kevCount
      ? `<div class="warn-banner" style="background:#2a1218;border-color:#ef444428;color:var(--danger)">
           <div class="warn-dot" style="background:var(--danger)"></div>${esc(t('kevWarn', d.kevCount))}
         </div>`
      : '';
    const detailed = (d.cveDetails || []).filter(c => c.score != null || c.summary);
    const plainIds = (d.vulns || []).filter(v => !detailed.some(c => c.id === v));
    return `
      ${verdict(d.verdict, vl, vDetail)}
      ${kevBanner}
      ${d.ports?.length ? section(`${t('openPorts')} (${d.ports.length})`) + `<div class="ports">${d.ports.map(p => `<span class="port">${esc(p)}</span>`).join('')}</div>` : ''}
      ${d.vulns?.length ? section(`${t('cves')} (${d.vulns.length})`) : ''}
      ${detailed.map(c => {
        const sev = c.kev ? 'critical'
                  : c.severity ? String(c.severity).toLowerCase()
                  : c.score >= 9 ? 'critical' : c.score >= 7 ? 'high' : c.score >= 4 ? 'medium' : 'low';
        return `<div class="cve-card sev-${esc(sev)}">
          <div class="cve-head">
            <span class="cve-id">${esc(c.id)}</span>
            ${c.score != null ? `<span class="cve-score">${esc(t('cvss'))} ${esc(c.score)}</span>` : ''}
            ${c.severity ? `<span class="cve-score">${esc(c.severity)}</span>` : ''}
            ${c.kev ? `<span class="cve-score kev">KEV</span>` : ''}
          </div>
          ${c.summary ? `<div class="cve-summary">${esc(c.summary)}</div>` : ''}
        </div>`;
      }).join('')}
      ${plainIds.length ? tagList(plainIds, 'red') : ''}
      ${d.cpes?.length ? section(t('cpes')) + tagList(d.cpes) : ''}
      ${d.tags?.length ? section(t('tags')) + tagList(d.tags, 'blue') : ''}
      ${d.hostnames?.length ? section(t('hostnames')) + pvList(d.hostnames, 'domain', 'green') : ''}
    `;
  }

  function renderGreyNoise(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (d.unseen) return msg(t('unseenIP'), 'info');
    const vl = t('verdict')[d.verdict] || d.verdict;
    const clsMap = { malicious: 'Malicious', benign: 'Benign', unknown: 'Unknown' };
    return `
      ${verdict(d.verdict, vl)}
      ${row(t('classification'), clsMap[d.classification] || d.classification)}
      ${row(t('name'), d.name && d.name !== 'unknown' ? d.name : null)}
      ${row(t('lastSeen'), d.lastSeen)}
      ${row(t('scanNoise'), d.noise ? t('activeScanner') : t('no'))}
      ${row(t('knownGood'), d.riot ? t('yes') : t('no'))}
      ${d.link ? extLink(d.link, 'GreyNoise') : ''}
    `;
  }

  function renderRDAP(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (d.domainName) {
      return `
        ${d.ageWarning ? `<div class="warn-banner"><div class="warn-dot"></div>${t('newDomain')}</div>` : ''}
        ${row(t('domainName'), d.domainName, 'mono')}
        ${row(t('registered'), d.registered)}
        ${row(t('expires'), d.expires)}
        ${row(t('lastChanged'), d.lastChanged)}
        ${row(t('registrar'), d.registrar)}
        ${d.nameservers?.length ? section(t('nameservers')) + pvList(d.nameservers, 'domain', 'green') : ''}
        ${d.status?.length ? section(t('status')) + tagList(d.status, 'blue') : ''}
        ${d.link ? extLink(d.link, 'RDAP') : ''}
      `;
    }
    return `
      ${row(t('handle'), d.handle, 'mono')}
      ${row(t('name'), d.name)}
      ${row(t('country'), d.country)}
      ${row(t('ipVersion'), d.ipVersion)}
      ${row(t('startAddr'), d.startAddress, 'mono')}
      ${row(t('endAddr'), d.endAddress, 'mono')}
      ${row(t('type'), d.type)}
    `;
  }

  function renderCrtSh(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (!d.certCount) return msg(t('noCerts'), 'neutral');
    return `
      ${verdict('unknown', t('certCount') + ': ' + d.certCount)}
      ${d.uniqueSubdomains?.length ? `
        ${section(`${t('subdomains')} (${d.uniqueSubdomains.length})`)}
        <div class="subdomain-list">${d.uniqueSubdomains.map(s =>
          `<div class="sub pv" data-pv="${esc(s)}" data-pvt="domain">${esc(s)}</div>`).join('')}</div>
      ` : ''}
      ${d.recentCerts?.length ? `
        ${section(t('recentCerts'))}
        ${d.recentCerts.map(c => `
          <div class="cert-card">
            <div class="cert-cn">${esc(c.cn)}</div>
            <div class="cert-meta">${esc(c.issuer)} &nbsp;·&nbsp; ${esc(c.notBefore)} → ${esc(c.notAfter)}</div>
          </div>
        `).join('')}
      ` : ''}
      ${d.link ? extLink(d.link, 'crt.sh') : ''}
    `;
  }

  function renderDNS(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    const types = Object.keys(d.records || {});
    if (!types.length) return msg(t('noRecords'), 'neutral');
    return `
      ${verdict('unknown', t('dnsRecords'))}
      ${types.map(rt => `
        <div class="dns-group">
          <div class="dns-type">${esc(rt)}</div>
          ${d.records[rt].map(v => {
            const s = String(v).trim();
            // A/AAAA give addresses; MX values carry a priority prefix.
            if (rt === 'A')    return `<div class="dns-val pv" data-pv="${esc(s)}" data-pvt="ip">${esc(s)}</div>`;
            if (rt === 'AAAA') return `<div class="dns-val pv" data-pv="${esc(s)}" data-pvt="ipv6">${esc(s)}</div>`;
            if (rt === 'NS' || rt === 'CNAME') {
              const h = s.replace(/\.$/, '');
              return `<div class="dns-val pv" data-pv="${esc(h)}" data-pvt="domain">${esc(s)}</div>`;
            }
            if (rt === 'MX') {
              const h = s.split(/\s+/).pop().replace(/\.$/, '');
              return `<div class="dns-val pv" data-pv="${esc(h)}" data-pvt="domain">${esc(s)}</div>`;
            }
            return `<div class="dns-val">${esc(s)}</div>`;
          }).join('')}
        </div>
      `).join('')}
    `;
  }

  function renderCIRCL(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (!d.found) return msg(t('hashNotInNsrl'), 'neutral');
    const vl = d.knownMalicious ? (t('verdict').malicious) : t('knownGoodFile');
    const detail = d.knownMalicious ? d.knownMalicious : '';
    return `
      ${verdict(d.verdict, vl, detail)}
      ${row(t('fileName'), d.fileName, 'mono')}
      ${row(t('mimeType'), d.mimeType, 'mono')}
      ${row(t('size'), d.fileSize ? `${d.fileSize} bytes` : null)}
      ${d.knownMalicious ? row(t('knownMalicious'), d.knownMalicious) : ''}
      ${row(t('product'), d.productName)}
      ${row(t('sourceDb'), d.source, 'mono')}
      ${row(t('trustScore'), d.trustScore !== undefined ? `${d.trustScore} / 100` : null)}
      ${section('Hashes')}
      ${row('MD5', d.md5, 'mono')}
      ${row('SHA-1', d.sha1, 'mono')}
      ${row('SHA-256', d.sha256 ? d.sha256.slice(0, 26) + '…' : null, 'mono')}
      ${d.link ? extLink(d.link, 'CIRCL HASHLOOKUP') : ''}
    `;
  }

  function renderEmailRep(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    const vl = t('verdict')[d.verdict] || d.verdict;
    const flag = (v, label) => v
      ? `<span style="color:var(--danger);font-weight:600">${label}</span>`
      : `<span style="color:var(--text2)">${t('no')}</span>`;
    return `
      ${verdict(d.verdict, vl)}
      ${d.didYouMean ? `<div class="warn-banner"><div class="warn-dot"></div>Did you mean: <strong>${esc(d.didYouMean)}</strong>?</div>` : ''}
      ${row('Domain', d.domain, 'mono')}
      ${row(t('domainAge'), d.domainAge)}
      ${row('MX Records', d.mx ? t('yes') : `<span style="color:var(--danger)">${t('no')}</span>`, '', true)}
      ${row('Mail Provider', d.mxProviders)}
      ${section('Flags')}
      ${row(t('disposable'),   flag(d.disposable,   t('yes')), '', true)}
      ${row(t('spam'),         flag(d.spam,         t('yes')), '', true)}
      ${row(t('freeProvider'), d.publicDomain ? t('yes') : t('no'))}
      ${row('Role Account',    d.roleAccount  ? t('yes') : t('no'))}
      ${row('Alias',           d.alias        ? t('yes') : t('no'))}
      ${d.link ? extLink(d.link, 'mailcheck.ai') : ''}
    `;
  }

  function renderURLScan(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (d.total === 0) return msg(t('notInDb', 'URLScan.io'), 'neutral');
    const vl = t('verdict')[d.verdict] || d.verdict;
    const detail = [
      d.maliciousCount  ? `${d.maliciousCount} malicious`  : '',
      d.suspiciousCount ? `${d.suspiciousCount} suspicious` : ''
    ].filter(Boolean).join(', ') || `${d.total} scans`;
    return `
      ${verdict(d.verdict, vl, detail)}
      ${row(t('totalScans'), String(d.total))}
      ${d.recentScans?.length ? `
        ${section(t('recentScans'))}
        ${d.recentScans.map(s => `
          <div class="cert-card">
            <div class="cert-cn" style="font-size:11px;word-break:break-all;">${esc(s.url) || '—'}</div>
            <div class="cert-meta" style="margin-top:4px;display:flex;gap:8px;align-items:center;">
              <span>${esc(s.time) || ''}</span>
              ${s.country ? `<span>${esc(s.country)}</span>` : ''}
              ${s.malicious  ? `<span style="color:var(--danger);font-weight:600">Malicious</span>`  : ''}
              ${s.suspicious ? `<span style="color:var(--warning);font-weight:600">Suspicious</span>` : ''}
              ${!s.malicious && !s.suspicious ? `<span style="color:var(--success)">Clean</span>` : ''}
              <a href="${esc(s.link)}" target="_blank" style="color:var(--accent);text-decoration:none;margin-left:auto;">↗</a>
            </div>
          </div>
        `).join('')}
      ` : ''}
      ${d.link ? extLink(d.link, 'URLScan.io') : ''}
    `;
  }

  function renderTor(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    const vl = t('verdict')[d.verdict] || d.verdict;
    return `
      ${verdict(d.verdict, vl, d.isExit ? t('torExit') : '')}
      ${msg(d.isExit ? t('torYes') : t('torNo'), d.isExit ? 'error' : 'info')}
      ${row(t('torListSize'), d.listSize != null ? String(d.listSize) : null)}
      ${d.link ? extLink(d.link, 'ExoneraTor') : ''}
    `;
  }

  // ── Summary — the screen you actually read; tabs are the drill-down ──────
  function renderSummary(_d, type) {
    const R = state.results;
    const has = Object.keys(R).length;
    if (!has) return `<div class="loading"><div class="spinner"></div><span>${esc(t('waiting'))}</span></div>`;

    const good = id => { const r = R[id]; return r && !r._na && !r.error ? r : null; };
    const facts = [];

    // A feed hit is the single most actionable thing we can say — lead with it.
    const fd = good('feeds');
    if (fd?.hits?.length) {
      facts.push([t('listedIn'), fd.hits.map(h => h.src).join(', ')]);
      const fam = fd.hits.map(h => h.malware).filter(Boolean)[0];
      if (fam) facts.push([t('malwareFamily'), fam]);
      const thr = fd.hits.map(h => h.threat).filter(Boolean)[0];
      if (thr) facts.push([t('threatType'), thr]);
    }

    if (type === 'ip' || type === 'ipv6') {
      const g = good('ipapi'), i = good('internetdb'), n = good('greynoise'), to = good('tor');
      if (g) {
        facts.push([t('location'), [g.city, g.region, g.country].filter(Boolean).join(', ')]);
        facts.push([t('network'), [g.isp, g.as].filter(Boolean).join(' · ')]);
        if (g.hostname) facts.push([t('hostname'), pv(g.hostname, 'domain'), true]);
        if (g.flags?.length) facts.push([t('flags'), g.flags.join(', ')]);
      }
      if (i) {
        if (i.ports?.length) facts.push([t('exposure'), `${i.ports.length} ports · ${i.ports.slice(0, 6).join(', ')}`]);
        if (i.vulns?.length) {
          const top = (i.cveDetails || []).find(c => c.score != null || c.kev);
          facts.push([t('worstCve'), top
            ? `${top.id}${top.score != null ? ` · CVSS ${top.score}` : ''}${top.kev ? ' · KEV' : ''}`
            : `${i.vulns.length} CVE`]);
        }
      }
      if (n && !n.unseen && n.classification) facts.push([t('scanner'), n.classification]);
      if (to) facts.push([t('torNode'), to.isExit ? t('yes') : t('no')]);
    } else if (type === 'domain' || type === 'url') {
      const w = good('rdap'), c = good('crtsh'), d = good('dns'), u = good('urlscan');
      if (w) {
        if (w.registrar) facts.push([t('registrar'), w.registrar]);
        if (w.registered) {
          const days = Math.floor((Date.now() - new Date(w.registered)) / 86400000);
          facts.push([t('domainAgeK'), isNaN(days) ? w.registered : `${t('daysOld', days)} (${w.registered})`]);
        }
        if (w.nameservers?.length) facts.push([t('nameservers'), w.nameservers.slice(0, 3).join(', ')]);
      }
      if (d?.records) {
        const a = [...(d.records.A || []), ...(d.records.AAAA || [])];
        if (a.length) facts.push(['A / AAAA', a.slice(0, 4).map(x => pv(x, x.includes(':') ? 'ipv6' : 'ip')).join(' '), true]);
        if (d.records.MX?.length) facts.push(['MX', d.records.MX.length + ' records']);
      }
      if (c?.certCount) facts.push([t('certs'), `${c.certCount} · ${c.uniqueSubdomains?.length || 0} subdomains`]);
      if (u && u.total) facts.push([t('scans'), `${u.total} scans${u.maliciousCount ? ` · ${u.maliciousCount} malicious` : ''}`]);
    } else if (['md5', 'sha1', 'sha256'].includes(type)) {
      const mal = good('mhr'), h = good('circl');
      if (mal) {
        facts.push([t('knownMalicious'), mal.known ? t('yes') : t('no')]);
        if (mal.detectionRate != null) facts.push([t('detectionRate'), `${mal.detectionRate} / 100`]);
        if (mal.lastSeen) facts.push([t('lastSeen'), mal.lastSeen]);
      } else if (type === 'sha256') {
        facts.push([t('knownMalicious'), t('sha256Note')]);
      }
      if (h) {
        if (h.fileName) facts.push([t('fileName2'), h.fileName]);
        if (h.found && !h.knownMalicious) facts.push([t('status'), t('knownGoodFile')]);
        if (h.trustScore !== undefined) facts.push([t('trustScore'), `${h.trustScore} / 100`]);
      }
    } else if (type === 'email') {
      const m = good('emailrep');
      if (m) {
        if (m.domain) facts.push([t('mailDomain'), pv(m.domain, 'domain'), true]);
        if (m.domainAge) facts.push([t('domainAgeK'), m.domainAge]);
        facts.push(['MX', m.mx ? t('yes') : t('no')]);
        const fl = [m.disposable && t('disposable'), m.spam && t('spam')].filter(Boolean);
        if (fl.length) facts.push([t('flags'), fl.join(', ')]);
      }
    }

    const lines = activeServices(type).map(s => {
      const r = R[s.id];
      if (!r) return { s, cls: 'loading', txt: t('pending') };
      if (r._na) return null;
      if (r.error) return { s, cls: 'error', txt: r.error };
      return { s, cls: r.verdict || 'unknown', txt: summarize(s.id, r).replace(/\*\*/g, '') };
    }).filter(Boolean);

    return `
      ${facts.length ? section(t('keyFacts')) + facts.map(([k, v, raw]) =>
        `<div class="row"><span class="row-key">${esc(k)}</span><span class="row-val">${raw ? v : esc(v)}</span></div>`
      ).join('') : ''}
      ${section(t('findings'))}
      ${lines.map(l => `
        <div class="finding">
          <span class="chip-dot ${esc(l.cls)}"></span>
          <span class="finding-name">${esc(l.s.label)}</span>
          <span class="finding-txt">${esc(l.txt)}</span>
        </div>`).join('')}
      <div class="pivot-hint">${esc(t('pivotHint'))}</div>
    `;
  }

  function renderMHR(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (!d.known) return msg(t('mhrUnknown'), 'neutral');
    return `
      ${verdict('malicious', t('verdict').malicious, d.detectionRate != null ? `${d.detectionRate}% AV` : '')}
      ${msg(t('mhrHit'), 'error')}
      ${row(t('detectionRate'), d.detectionRate != null ? `${d.detectionRate} / 100` : null)}
      ${row(t('lastSeen'), d.lastSeen)}
      ${d.link ? extLink(d.link, 'Team Cymru MHR') : ''}
    `;
  }

  function renderFeeds(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    const when = d.indexedAt ? new Date(d.indexedAt).toISOString().replace('T', ' ').slice(0, 16) : null;
    const foot = `
      ${section(t('sourceDb'))}
      ${row(t('indexedIocs'), d.indexSize ? String(d.indexSize) : null)}
      ${row(t('updated'), when)}
      <div class="pivot-hint">${esc(t('feedNote'))}</div>`;

    if (!d.hits?.length) return msg(t('feedClean'), 'info') + foot;

    return `
      ${verdict('malicious', t('verdict').malicious, d.hits.map(h => h.src).join(', '))}
      ${d.hits.map(h => `
        <div class="cve-card sev-critical">
          <div class="cve-head">
            <span class="cve-id">${esc(h.src)}</span>
            ${h.confidence ? `<span class="cve-score">${esc(h.confidence)}%</span>` : ''}
          </div>
          ${h.malware ? `<div class="row"><span class="row-key">${esc(t('malwareFamily'))}</span><span class="row-val">${esc(h.malware)}</span></div>` : ''}
          ${h.threat  ? `<div class="row"><span class="row-key">${esc(t('threatType'))}</span><span class="row-val mono">${esc(h.threat)}</span></div>` : ''}
          ${h.firstSeen ? `<div class="row"><span class="row-key">${esc(t('firstSeen'))}</span><span class="row-val">${esc(h.firstSeen)}</span></div>` : ''}
        </div>`).join('')}
      ${foot}
    `;
  }

  function renderOTX(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (d.whitelisted && !d.pulseCount) {
      return verdict('clean', t('verdict').clean) + msg(t('otxClean'), 'info') +
             (d.validation?.length ? section(t('sourceDb')) + tagList(d.validation, 'green') : '');
    }
    if (!d.pulseCount) return msg(t('otxNone'), 'neutral');
    const vl = t('verdict')[d.verdict] || d.verdict;
    return `
      ${verdict(d.verdict, vl, `${d.pulseCount} ${t('pulses').toLowerCase()}`)}
      ${d.families?.length ? section(t('malwareFamily')) + tagList(d.families, 'red') : ''}
      ${d.attack?.length ? section(t('attack')) + tagList(d.attack, 'yellow') : ''}
      ${section(t('pulses'))}
      ${d.pulses.map(p => `
        <div class="cve-card">
          <div class="cve-head">
            <span class="cve-id">${esc(p.name)}</span>
            ${p.created ? `<span class="cve-score">${esc(p.created)}</span>` : ''}
          </div>
          ${p.adversary ? `<div class="row"><span class="row-key">${esc(t('adversary'))}</span><span class="row-val">${esc(p.adversary)}</span></div>` : ''}
          ${p.tags?.length ? `<div class="cve-summary">${esc(p.tags.join(' · '))}</div>` : ''}
        </div>`).join('')}
      ${d.link ? extLink(d.link, 'AlienVault OTX') : ''}
    `;
  }

  function renderRIPE(d) {
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    const a = d.asns?.[0];
    return `
      ${verdict('unknown', t('routing'))}
      ${row(t('prefix'), d.prefix, 'mono')}
      ${row(t('announcedBy'), a ? `AS${a.asn}` : null, 'mono')}
      ${row(t('org'), a?.holder)}
      ${row(t('asnPrefixes'), d.prefixCount != null ? String(d.prefixCount) : null)}
      ${row(t('asnPeers'), d.neighbours != null ? String(d.neighbours) : null)}
      ${d.link ? extLink(d.link, 'RIPEstat') : ''}
    `;
  }

  function renderVT(d) {
    if (d._needsKey) return msg(t('needsKey', d._needsKey), 'neutral');
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (d.notFound) return msg(t('vtNotFound'), 'neutral');
    const vl = t('verdict')[d.verdict] || d.verdict;
    return `
      ${verdict(d.verdict, vl, d.total ? `${d.malicious} / ${d.total}` : '')}
      ${row(t('detections'), d.total ? `${d.malicious} ${t('maliciousL')}, ${d.suspicious} ${t('suspiciousL')} / ${d.total}` : null)}
      ${row(t('reputation'), d.reputation !== undefined ? String(d.reputation) : null)}
      ${row(t('fileName2'), d.names?.length ? d.names.join(', ') : null, 'mono')}
      ${row(t('type'), d.typeDesc)}
      ${d.engines?.length ? section(t('engines')) + tagList(d.engines, 'red') : ''}
      ${d.link ? extLink(d.link, 'VirusTotal') : ''}
    `;
  }

  function renderShodan(d) {
    if (d._needsKey) return msg(t('needsKey', d._needsKey), 'neutral');
    if (d._na) return msg(t('naService'));
    if (d.error) return msg(d.error, 'error');
    if (d.notFound) return msg(t('notInDb', 'Shodan'), 'neutral');
    const vl = t('verdict')[d.verdict] || d.verdict;
    return `
      ${verdict(d.verdict, vl, d.vulns?.length ? `${d.vulns.length} CVE` : '')}
      ${row(t('org'), d.org)}
      ${row(t('isp'), d.isp)}
      ${row('OS', d.os)}
      ${row(t('lastSeen'), d.lastUpdate)}
      ${d.ports?.length ? section(`${t('openPorts')} (${d.ports.length})`) + `<div class="ports">${d.ports.map(p => `<span class="port">${esc(p)}</span>`).join('')}</div>` : ''}
      ${d.services?.length ? section(t('services2')) + d.services.map(s => `
        <div class="row"><span class="row-key mono">${esc(s.port)}/${esc(s.transport || 'tcp')}</span>
        <span class="row-val">${esc([s.product, s.version].filter(Boolean).join(' ') || '—')}</span></div>`).join('') : ''}
      ${d.vulns?.length ? section(t('cves')) + tagList(d.vulns, 'red') : ''}
      ${d.tags?.length ? section(t('tags')) + tagList(d.tags, 'blue') : ''}
      ${d.hostnames?.length ? section(t('hostnames')) + pvList(d.hostnames, 'domain', 'green') : ''}
      ${d.link ? extLink(d.link, 'Shodan') : ''}
    `;
  }

  const SUMMARY = { id: 'summary', label: '', types: [], render: renderSummary, virtual: true };

  // ── Service definitions ───────────────────────────────────────────────────
  const SERVICES = [
    { id: 'feeds',      label: 'Threat Feeds', types: ['ip','ipv6','domain','url','md5','sha1','sha256'], render: renderFeeds },
    { id: 'otx',        label: 'OTX',          types: ['ip','ipv6','domain','url','md5','sha1','sha256'], render: renderOTX },
    { id: 'ripe',       label: 'Routing',      types: ['ip','ipv6'],                render: renderRIPE },
    { id: 'vt',         label: 'VirusTotal',   types: ['ip','ipv6','domain','md5','sha1','sha256'], render: renderVT, optional: true },
    { id: 'shodan',     label: 'Shodan',       types: ['ip','ipv6'],                render: renderShodan, optional: true },
    { id: 'ipapi',      label: 'IP-API',       types: ['ip','ipv6'],                render: renderIPAPI },
    { id: 'internetdb', label: 'InternetDB',   types: ['ip','ipv6'],                render: renderInternetDB },
    { id: 'greynoise',  label: 'GreyNoise',    types: ['ip','ipv6'],                render: renderGreyNoise },
    { id: 'tor',        label: 'Tor Exit',     types: ['ip'],                       render: renderTor },
    { id: 'rdap',       label: 'Whois / RDAP', types: ['ip','ipv6','domain','url'], render: renderRDAP },
    { id: 'crtsh',      label: 'crt.sh',       types: ['domain','url'],             render: renderCrtSh },
    { id: 'dns',        label: 'DNS',          types: ['domain','url'],             render: renderDNS },
    { id: 'mhr',        label: 'Malware DB',   types: ['md5','sha1'],                    render: renderMHR },
    { id: 'circl',      label: 'Known Files',  types: ['md5','sha1','sha256'],           render: renderCIRCL },
    { id: 'emailrep',   label: 'mailcheck.ai', types: ['email'],                         render: renderEmailRep },
    { id: 'urlscan',    label: 'URLScan.io',   types: ['domain','url'],                  render: renderURLScan },
  ];

  // Optional services only appear once their key exists — an empty tab that
  // just says "add a key" is noise on every single lookup.
  function activeServices(type) {
    return SERVICES.filter(s =>
      s.types.includes(type) &&
      !state.settings.disabled[s.id] &&
      (!s.optional || state.keys[s.id])
    );
  }

  // ── Aggregate verdict ─────────────────────────────────────────────────────
  const RANK = { unknown: 0, clean: 1, suspicious: 2, malicious: 3 };

  function aggregate() {
    const vals = Object.values(state.results).filter(r => r && !r._na && !r.error && r.verdict);
    if (!vals.length) return null;
    let worst = 'unknown', flagged = 0;
    vals.forEach(r => {
      if ((RANK[r.verdict] ?? 0) > RANK[worst]) worst = r.verdict;
      if (r.verdict === 'malicious' || r.verdict === 'suspicious') flagged++;
    });
    return { verdict: worst, flagged, total: vals.length };
  }

  function paintOverall(wrap) {
    const el = wrap.querySelector('#overall');
    const a  = aggregate();
    if (!el || !a) return;
    el.className = `overall ${a.verdict}`;
    const detail = a.flagged ? t('overallDetail', a.flagged, a.total)
                 : a.verdict === 'unknown' ? t('overallUnknown')
                 : t('overallClean');
    el.innerHTML =
      `<span class="overall-dot"></span>` +
      `<span class="overall-label">${esc(t('overall'))}: ${esc(t('verdict')[a.verdict] || a.verdict)}</span>` +
      `<span class="overall-detail">${esc(detail)}</span>`;
  }

  // ── Markdown report ───────────────────────────────────────────────────────
  function summarize(id, r) {
    if (r.error) return `error: ${r.error}`;
    const bits = [];
    if (r.verdict) bits.push(t('verdict')[r.verdict] || r.verdict);
    switch (id) {
      case 'ipapi':
        bits.push([r.country, r.city].filter(Boolean).join(' / '));
        if (r.isp) bits.push(r.isp);
        if (r.flags?.length) bits.push(r.flags.join(', '));
        break;
      case 'internetdb':
        if (r.ports?.length) bits.push(`ports ${r.ports.slice(0, 10).join(', ')}`);
        if (r.vulns?.length) bits.push(`${r.vulns.length} CVE${r.maxScore != null ? ` (max CVSS ${r.maxScore})` : ''}`);
        if (r.kevCount) bits.push(`**${r.kevCount} in CISA KEV**`);
        break;
      case 'greynoise':
        if (r.unseen) bits.push('not observed');
        else {
          if (r.classification) bits.push(r.classification);
          if (r.lastSeen) bits.push(`last seen ${r.lastSeen}`);
        }
        break;
      case 'tor':
        bits.push(r.isExit ? 'Tor exit node' : 'not a Tor exit node');
        break;
      case 'rdap':
        if (r.domainName) {
          if (r.registrar) bits.push(r.registrar);
          if (r.registered) bits.push(`registered ${r.registered}`);
        } else {
          if (r.name) bits.push(r.name);
          if (r.country) bits.push(r.country);
        }
        break;
      case 'crtsh':
        bits.push(`${r.certCount || 0} certs`);
        if (r.uniqueSubdomains?.length) bits.push(`${r.uniqueSubdomains.length} subdomains`);
        break;
      case 'dns': {
        const ks = Object.keys(r.records || {});
        if (ks.length) bits.push(ks.map(k => `${k} ${r.records[k].slice(0, 2).join(' ')}`).join(' · '));
        break;
      }
      case 'feeds':
        if (!r.hits?.length) bits.push('not in any threat feed');
        else bits.push(r.hits.map(h => `${h.src}${h.malware ? ` (${h.malware})` : ''}`).join(', '));
        break;
      case 'mhr':
        if (!r.known) bits.push('no malware record');
        else bits.push(`known malware${r.detectionRate != null ? ` · ${r.detectionRate}% AV detection` : ''}${r.lastSeen ? ` · last seen ${r.lastSeen}` : ''}`);
        break;
      case 'circl':
        if (!r.found) bits.push('not a known legitimate file');
        else {
          if (r.fileName) bits.push(r.fileName);
          if (r.knownMalicious) bits.push(`flagged by ${r.knownMalicious}`);
        }
        break;
      case 'emailrep':
        if (r.domain) bits.push(r.domain);
        if (r.disposable) bits.push('disposable');
        if (r.spam) bits.push('spam');
        if (!r.mx) bits.push('no MX record');
        break;
      case 'urlscan':
        bits.push(`${r.total || 0} scans`);
        if (r.maliciousCount) bits.push(`${r.maliciousCount} malicious`);
        break;
    }
    return (bits.filter(Boolean).join(' · ') || '—').replace(/\|/g, '\\|');
  }

  function buildReport() {
    const a = aggregate();
    const out = [];
    out.push(`## ${state.query}${a ? ` — ${t('verdict')[a.verdict] || a.verdict}` : ''}`);
    out.push('');
    if (state.defanged) { out.push(`_${t('defangedFrom', state.original)}_`); out.push(''); }
    if (a) { out.push(a.flagged ? `**${t('overallDetail', a.flagged, a.total)}**` : `**${t('overallClean')}**`); out.push(''); }
    out.push('| Service | Result |');
    out.push('|---------|--------|');
    activeServices(state.type).forEach(s => {
      const r = state.results[s.id];
      if (!r || r._na) return;
      out.push(`| ${s.label} | ${summarize(s.id, r)} |`);
    });
    out.push('');
    out.push(`_OSINT Research Assistant · ${new Date().toISOString().split('T')[0]}_`);
    return out.join('\n');
  }

  // ── Page Scanner ──────────────────────────────────────────────────────────
  let scanActive = false;
  let scanIndex  = -1;
  let scanCapped = false;
  const SCAN_CLS = '__osint_ioc__';
  const SCAN_BAR = '__osint_bar__';

  // Ceilings measured against a synthetic 4,000-paragraph page, where the
  // uncapped scan injected 16,000 spans and froze the tab for 1.4s.
  const MAX_MARKS  = 1500;   // spans injected into the page
  const MAX_TRIAGE = 400;    // unique indicators graded in one batch
  const MAX_ROWS   = 250;    // rows rendered in the triage list

  // Octet-validated so version strings (1.2.3.4) and invalid addresses
  // (999.1.1.1) no longer get highlighted as IOCs.
  const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
  const SCAN_PATTERNS = [
    // Trailing "." is allowed (sentence end) but ".<digit>" is not (version strings).
    { type: 'ip',     re: new RegExp(`(?<![\\w.])${OCTET}(?:\\.${OCTET}){3}(?![\\w])(?!\\.\\d)`, 'g') },
    { type: 'sha256', re: /(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])/g },
    { type: 'sha1',   re: /(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])/g },
    { type: 'md5',    re: /(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])/g },
    { type: 'email',  re: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g },
    { type: 'domain', re: /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|fr|jp|br|it|ca|au|nl|in|es|info|biz|onion|xyz|site|shop)\b/gi }
  ];

  function scanPage() {
    if (scanActive) {
      document.querySelectorAll('.' + SCAN_CLS).forEach(el => {
        el.replaceWith(document.createTextNode(el.textContent));
      });
      document.removeEventListener('click', onScanClick, true);
      const bar = document.getElementById(SCAN_BAR);
      if (bar) bar.remove();
      closeTriageList();
      scanActive = false;
      scanIndex  = -1;
      state.triage = null;
      return;
    }

    // Inject page-level styles for highlights
    if (!document.getElementById('__osint_scan_styles__')) {
      const s = document.createElement('style');
      s.id = '__osint_scan_styles__';
      s.textContent =
        `.${SCAN_CLS}{border-bottom:2px solid #6fa8d4;cursor:pointer;border-radius:2px;` +
        `transition:background .15s,border-color .15s}` +
        `.${SCAN_CLS}:hover{background:rgba(111,168,212,.18)}` +
        `.${SCAN_CLS}[data-v="malicious"]{border-bottom-color:#e0403a;background:rgba(224,64,58,.15)}` +
        `.${SCAN_CLS}[data-v="suspicious"]{border-bottom-color:#c47a12;background:rgba(196,122,18,.15)}` +
        `.${SCAN_CLS}[data-v="unknown"]{border-bottom-color:#9aa2b1}` +
        `.${SCAN_CLS}.__osint_focus__{outline:2px solid #6fa8d4;outline-offset:2px}`;
      document.head.appendChild(s);
    }

    scanActive = true;
    let found = 0;
    let capped = false;

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const tag = node.parentElement?.tagName?.toLowerCase();
        if (!tag) return NodeFilter.FILTER_REJECT;
        if (['script','style','noscript','textarea','input','code','pre'].includes(tag)) return NodeFilter.FILTER_REJECT;
        if (node.parentElement?.classList?.contains(SCAN_CLS)) return NodeFilter.FILTER_REJECT;
        if (node.parentElement?.closest?.('#' + SCAN_BAR)) return NodeFilter.FILTER_REJECT;
        return node.textContent.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });

    const nodes = [];
    let node;
    while ((node = walker.nextNode())) nodes.push(node);

    // Marking a text node is cheap; marking sixteen thousand of them is a
    // frozen tab. Work in slices, yielding between them, and stop at a cap.
    const markNode = (textNode) => {
      if (found >= MAX_MARKS) { capped = true; return; }
      const text = textNode.textContent;

      // Collect hits from every pattern — a single sentence can hold an IP,
      // an email and a domain at once.
      const hits = [];
      for (const pat of SCAN_PATTERNS) {
        pat.re.lastIndex = 0;
        let m;
        while ((m = pat.re.exec(text)) !== null) {
          if (!m[0]) { pat.re.lastIndex++; continue; }
          hits.push({ start: m.index, end: m.index + m[0].length, val: m[0], type: pat.type });
        }
      }
      if (!hits.length) return;

      // Earliest wins; on a tie the longer match wins, so admin@evil.com stays
      // one email rather than becoming a stray domain.
      hits.sort((a, b) => (a.start - b.start) || ((b.end - b.start) - (a.end - a.start)));
      const kept = [];
      let cursor = 0;
      for (const h of hits) {
        if (h.start < cursor) continue;
        kept.push(h);
        cursor = h.end;
      }

      const frag = document.createDocumentFragment();
      let last = 0;
      for (const h of kept) {
        if (found >= MAX_MARKS) { capped = true; break; }
        if (h.start > last) frag.appendChild(document.createTextNode(text.slice(last, h.start)));
        const span = document.createElement('span');
        span.className = SCAN_CLS;
        span.dataset.type = h.type;
        span.dataset.val  = h.val;
        span.textContent  = h.val;
        frag.appendChild(span);
        found++;
        last = h.end;
      }
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      textNode.parentNode?.replaceChild(frag, textNode);
    };

    const SLICE = 120;
    let i = 0;
    const step = () => {
      const end = Math.min(i + SLICE, nodes.length);
      for (; i < end; i++) markNode(nodes[i]);
      if (i < nodes.length && found < MAX_MARKS) {
        // Hand the frame back so the page keeps responding while we work.
        (window.requestIdleCallback || window.requestAnimationFrame || setTimeout)(step);
        return;
      }
      document.addEventListener('click', onScanClick, true);
      showScanBar(found, capped);
      runTriage();
    };
    step();
  }

  // ── Bulk triage ───────────────────────────────────────────────────────────
  // Every indicator on the page graded in one pass, against sources that cost
  // nothing per item — so a 200-IOC threat report is as cheap as a single one.
  function pageIOCs() {
    const seen = new Map();
    document.querySelectorAll('.' + SCAN_CLS).forEach(el => {
      const k = `${el.dataset.type}:${el.dataset.val}`;
      if (!seen.has(k)) seen.set(k, { value: el.dataset.val, type: el.dataset.type, els: [] });
      seen.get(k).els.push(el);
    });
    return [...seen.values()];
  }

  function runTriage() {
    const all = pageIOCs();
    if (!all.length) {
      // Otherwise the bar sits on "checking…" forever on a page with nothing
      // to grade, which reads as a hang.
      state.triage = { loading: false, items: [], total: 0, omitted: 0, empty: true };
      paintScanBar();
      return;
    }
    // A 443KB message and a 12,000-entry response is not a useful triage —
    // grade the first batch and say how many were left out.
    const items = all.slice(0, MAX_TRIAGE);
    const omitted = all.length - items.length;
    state.triage = { loading: true, items: [], total: items.length, omitted };
    paintScanBar();

    chrome.runtime.sendMessage(
      { action: 'triage', iocs: items.map(i => ({ value: i.value, type: i.type })) },
      (res) => {
        if (chrome.runtime.lastError || !res || res.error) {
          state.triage = { loading: false, items: [], total: items.length, omitted, failed: true };
          paintScanBar();
          return;
        }
        const byKey = new Map(res.results.map(r => [`${r.type}:${r.value}`, r]));
        items.forEach(it => {
          const r = byKey.get(`${it.type}:${it.value}`);
          if (!r) return;
          it.verdict = r.verdict;
          it.note = r.note;
          it.malware = r.malware;
          it.els.forEach(el => { el.dataset.v = r.verdict; });
        });
        const order = { malicious: 0, suspicious: 1, unknown: 2, clean: 3 };
        items.sort((a, b) => (order[a.verdict] ?? 9) - (order[b.verdict] ?? 9) ||
                             a.value.localeCompare(b.value));
        state.triage = { loading: false, items, total: items.length, omitted, indexedAt: res.indexedAt };
        paintScanBar();
      }
    );
  }

  function triageCounts() {
    const c = { malicious: 0, suspicious: 0, unknown: 0 };
    (state.triage?.items || []).forEach(i => { if (c[i.verdict] !== undefined) c[i.verdict]++; });
    return c;
  }

  function buildTriageReport() {
    const items = state.triage?.items || [];
    const c = triageCounts();
    const out = [];
    out.push(`## IOC triage — ${location.hostname}`);
    out.push('');
    out.push(`${items.length} indicators · ${c.malicious} malicious · ${c.suspicious} suspicious`);
    out.push('');
    out.push('| Verdict | Indicator | Type | Source |');
    out.push('|---------|-----------|------|--------|');
    items.forEach(i => {
      const src = [i.note, i.malware].filter(Boolean).join(' · ') || '—';
      out.push(`| ${i.verdict || 'unknown'} | \`${i.value}\` | ${i.type} | ${src.replace(/\|/g, '\\|')} |`);
    });
    out.push('');
    out.push(`_${location.href}_`);
    out.push(`_OSINT Research Assistant · ${new Date().toISOString().split('T')[0]}_`);
    return out.join('\n');
  }

  function navigateScan(dir) {
    const iocs = Array.from(document.querySelectorAll('.' + SCAN_CLS));
    if (!iocs.length) return;

    // Remove active styling from previous
    if (scanIndex >= 0 && iocs[scanIndex]) {
      iocs[scanIndex].style.outline = '';
      iocs[scanIndex].style.backgroundColor = '';
    }

    scanIndex = (scanIndex + dir + iocs.length) % iocs.length;
    const el = iocs[scanIndex];
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.outline = '2px solid #6366f1';
    el.style.backgroundColor = 'rgba(99,102,241,.25)';

    const counter = document.getElementById('__osint_nav_ctr__');
    if (counter) counter.textContent = `${scanIndex + 1} / ${iocs.length}`;
  }

  function onScanClick(e) {
    const span = e.target.closest?.('.' + SCAN_CLS);
    if (!span) return;
    // Highlights often sit inside an <a>; without preventDefault the browser
    // follows the link instead of showing the lookup.
    e.preventDefault();
    e.stopPropagation();
    lookup(span.dataset.val, span.dataset.type);
  }

  function lookup(query, type) {
    state.results  = {};
    state.query    = query;
    state.original = query;
    state.type     = type;
    state.defanged = false;
    buildPanel(query, type);
    addHistory({ q: query, type, at: Date.now() });
  }

  function showScanBar(count, capped) {
    const existing = document.getElementById(SCAN_BAR);
    if (existing) existing.remove();
    scanIndex = -1;
    scanCapped = !!capped;

    const bar = document.createElement('div');
    bar.id = SCAN_BAR;
    Object.assign(bar.style, {
      position: 'fixed', bottom: '20px', left: '50%', transform: 'translateX(-50%)',
      background: '#0a0b0d', border: '1px solid #1e222b',
      boxShadow: '0 1px 2px rgba(0,0,0,.3), 0 12px 32px -6px rgba(0,0,0,.55)',
      borderRadius: '10px',
      padding: '7px 8px 7px 14px', display: 'flex', alignItems: 'center', gap: '9px',
      zIndex: '2147483646',
      fontFamily: '"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif',
      fontSize: '12px', color: '#e9ebef', whiteSpace: 'nowrap', userSelect: 'none'
    });
    bar.dataset.count = String(count);
    document.body.appendChild(bar);
    paintScanBar();
  }

  function scanBtn(label, onClick, opts = {}) {
    const b = document.createElement('button');
    b.textContent = label;
    Object.assign(b.style, {
      background: opts.solid ? '#1c2029' : 'transparent',
      border: '1px solid ' + (opts.solid ? '#2a3038' : '#1e222b'),
      color: '#969ead', cursor: 'pointer', fontSize: '11.5px', fontWeight: '500',
      borderRadius: '7px', padding: '4px 10px', lineHeight: '1.5',
      fontFamily: 'inherit', transition: 'color .14s, border-color .14s'
    });
    b.addEventListener('mouseover', () => { b.style.color = '#e9ebef'; b.style.borderColor = '#3a4250'; });
    b.addEventListener('mouseout',  () => { b.style.color = '#969ead'; b.style.borderColor = opts.solid ? '#2a3038' : '#1e222b'; });
    b.addEventListener('click', e => { e.stopPropagation(); onClick(e); });
    return b;
  }

  function paintScanBar() {
    const bar = document.getElementById(SCAN_BAR);
    if (!bar) return;
    const total = Number(bar.dataset.count || 0);
    const tr = state.triage;
    bar.textContent = '';

    const dot = document.createElement('span');
    Object.assign(dot.style, {
      width: '7px', height: '7px', borderRadius: '50%', flexShrink: '0',
      display: 'inline-block', background: '#6fa8d4'
    });

    const label = document.createElement('span');
    label.style.color = '#969ead';

    if (tr && tr.empty) {
      dot.style.background = '#596170';
      label.textContent = t('noIndicators');
      bar.append(dot, label);
    } else if (tr && tr.failed) {
      dot.style.background = '#ec7a76';
      label.textContent = t('triageFailed');
      bar.append(dot, label);
    } else if (!tr || tr.loading) {
      dot.style.background = '#6fa8d4';
      label.innerHTML = `<strong style="color:#e9ebef">${total}</strong> ${t('indicators')} · ${esc(t('checking'))}`;
      bar.append(dot, label);
    } else {
      const c = triageCounts();
      dot.style.background = c.malicious ? '#e0403a' : c.suspicious ? '#e0a45c' : '#5cc98d';
      const parts = [`<strong style="color:#e9ebef">${total}</strong> ${t('indicators')}`];
      if (c.malicious)  parts.push(`<strong style="color:#ec7a76">${c.malicious}</strong> ${t('malicious2')}`);
      if (c.suspicious) parts.push(`<strong style="color:#e0a45c">${c.suspicious}</strong> ${t('suspicious2')}`);
      if (!c.malicious && !c.suspicious) parts.push(esc(t('nothingFlagged')));
      const left = (tr.omitted || 0) + (scanCapped ? 1 : 0);
      if (left > 0) parts.push(`<span style="color:#596170">${esc(t('capped', tr.omitted || 0))}</span>`);
      label.innerHTML = parts.join(' · ');

      const sep = document.createElement('span');
      sep.textContent = '';
      sep.style.cssText = 'width:1px;height:16px;background:#1e222b;margin:0 1px';

      bar.append(dot, label, sep,
        scanBtn(t('showList'), () => showTriageList(), { solid: true }),
        scanBtn(t('addAll'), async (e) => {
          const flagged = (state.triage?.items || []).filter(i => i.verdict === 'malicious' || i.verdict === 'suspicious');
          const pick = flagged.length ? flagged : (state.triage?.items || []);
          if (!pick.length) { toast(t('noIndicators'), 'info'); return; }
          let c;
          for (const i of pick) {
            c = await addToCase({
              value: i.value, type: i.type, verdict: i.verdict || 'unknown',
              sources: i.note ? [i.note] : [], malware: i.malware || null,
              campaign: null, attack: [], added: Date.now()
            });
          }
          e.target.textContent = t('addedToCase');
          setTimeout(() => { e.target.textContent = t('addAll'); }, 1600);
          toast(t('caseAddedMany', pick.length, c ? c.items.length : pick.length), 'ok');
        }),
        scanBtn(t('report'), (e) => {
          const n = (state.triage?.items || []).length;
          copyText(buildTriageReport(), t('reportCopiedN', n)).then(ok => {
            if (ok) { e.target.textContent = t('copied'); setTimeout(() => { e.target.textContent = t('report'); }, 1500); }
          });
        })
      );
    }

    const close = scanBtn('×', () => scanPage());
    close.style.padding = '4px 8px';
    close.style.fontSize = '14px';
    close.style.border = '1px solid transparent';
    bar.append(close);
  }

  // ── Triage list ───────────────────────────────────────────────────────────
  let triageHost = null;

  function closeTriageList() {
    if (triageHost) { triageHost.remove(); triageHost = null; }
  }

  function showTriageList() {
    closeTriageList();
    const items = state.triage?.items || [];
    if (!items.length) return;

    triageHost = document.createElement('div');
    if (resolveTheme() === 'light') triageHost.classList.add('light');
    const sh = triageHost.attachShadow({ mode: 'open' });
    document.body.appendChild(triageHost);

    const style = document.createElement('style');
    style.textContent = CSS + `
      #panel { left: 18px; right: auto; width: 380px; }
      .tri-row {
        display: flex; align-items: center; gap: 9px;
        padding: 8px 14px; cursor: pointer;
        border-bottom: 1px solid var(--hair2);
        transition: background .13s;
      }
      .tri-row:hover { background: var(--surface); }
      .tri-row:focus-visible { outline: 1px solid var(--accent); outline-offset: -2px; }
      .tri-val {
        font-family: var(--mono); font-size: 11.5px; color: var(--text);
        flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis;
        white-space: nowrap; letter-spacing: -.01em;
      }
      .tri-src { font-size: 10px; color: var(--text3); flex-shrink: 0; max-width: 42%;
                 overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: right; }
      .tri-head {
        display: flex; align-items: center; gap: 8px;
        padding: 10px 14px; border-bottom: 1px solid var(--hair);
        font-size: 11px; color: var(--text2);
      }
      .tri-legend { display: flex; gap: 10px; margin-left: auto; font-size: 10px; }
      .tri-legend span { display: flex; align-items: center; gap: 4px; color: var(--text3); }
    `;
    sh.appendChild(style);

    const c = triageCounts();
    const wrap = document.createElement('div');
    wrap.id = 'panel';
    wrap.innerHTML = `
      <div id="header">
        <span id="logo">OSINT</span>
        <span class="type-pill">${esc(t('triage'))}</span>
        <button class="hbtn" id="tri-close">×</button>
      </div>
      <div class="tri-head">
        <span>${items.length} ${esc(t('indicators'))}</span>
        <span class="tri-legend">
          <span><i class="chip-dot malicious"></i>${c.malicious}</span>
          <span><i class="chip-dot suspicious"></i>${c.suspicious}</span>
          <span><i class="chip-dot unknown"></i>${c.unknown}</span>
        </span>
      </div>
      <div id="content">
        ${items.slice(0, MAX_ROWS).map((i, n) => `
          <div class="tri-row" role="button" tabindex="0" data-n="${n}">
            <span class="chip-dot ${esc(i.verdict || 'unknown')}"></span>
            <span class="tri-val" title="${esc(i.value)}">${esc(i.value)}</span>
            <span class="tri-src">${esc([i.note, i.malware].filter(Boolean).join(' · '))}</span>
          </div>`).join('')}
        ${items.length > MAX_ROWS
          ? `<div class="tri-row" style="cursor:default;color:var(--text3);font-size:11px">${esc(t('moreRows', items.length - MAX_ROWS))}</div>`
          : ''}
      </div>
      <div id="resize"></div>
    `;
    sh.appendChild(wrap);

    wrap.querySelectorAll('.chip-dot').forEach(d => { d.style.display = 'inline-block'; });
    wrap.querySelector('#tri-close').onclick = closeTriageList;

    wrap.querySelectorAll('.tri-row').forEach(rowEl => {
      const go = () => {
        const it = items[Number(rowEl.dataset.n)];
        if (!it) return;
        focusIOC(it);
        lookup(it.value, it.type);
      };
      rowEl.addEventListener('click', go);
      rowEl.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
      });
    });

    makeDraggable(wrap, wrap.querySelector('#header'));
    makeResizable(wrap, wrap.querySelector('#resize'));
  }

  function focusIOC(it) {
    document.querySelectorAll('.__osint_focus__').forEach(e => e.classList.remove('__osint_focus__'));
    const el = it.els && it.els[0];
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('__osint_focus__');
  }

  // ── Toast ─────────────────────────────────────────────────────────────────
  // Every action that changes something or leaves the page — copying, saving to
  // the case, downloading an export — says so. A button that silently succeeds
  // is indistinguishable from one that silently failed.
  let toastHost = null;

  function toast(message, kind = 'ok') {
    if (!toastHost) {
      toastHost = document.createElement('div');
      const sh = toastHost.attachShadow({ mode: 'open' });
      const st = document.createElement('style');
      st.textContent = `
        :host { all: initial; }
        *, *::before, *::after { box-sizing: border-box; }
        .wrap {
          position: fixed; right: 18px; bottom: 18px;
          display: flex; flex-direction: column; gap: 8px;
          z-index: 2147483647; pointer-events: none;
          font-family: "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
        }
        /* Entrance is a CSS animation, not a JS-toggled class: rAF does not
           fire in a background or non-compositing tab, and a toast that never
           becomes visible is worse than no toast. */
        .t {
          display: flex; align-items: center; gap: 9px;
          min-width: 200px; max-width: 380px;
          padding: 11px 14px; border-radius: 9px;
          background: #0a0b0d; border: 1px solid #1e222b;
          box-shadow: 0 1px 2px rgba(0,0,0,.3), 0 10px 28px -8px rgba(0,0,0,.6);
          color: #e9ebef; font-size: 12.5px; line-height: 1.45;
          /* Opacity is never animated. If the tab is not compositing, an
             animation can stall on its first keyframe — and a feedback message
             that is permanently invisible is worse than one with no entrance.
             Only transform moves; a stalled 6px offset is still readable. */
          opacity: 1;
          animation: toast-in .16s ease;
        }
        .t.out { opacity: 0; transition: opacity .18s; }
        @keyframes toast-in {
          from { transform: translateY(6px); }
          to   { transform: none; }
        }
        .t i {
          width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
          background: #5cc98d;
        }
        .t.error i { background: #ec7a76; }
        .t.info  i { background: #6fa8d4; }
        .t.error { border-color: #4a2422; }
        @media (prefers-reduced-motion: reduce) {
          .t { animation: none; }
          .t.out { transition: none; }
        }
      `;
      const wrap = document.createElement('div');
      wrap.className = 'wrap';
      wrap.setAttribute('role', 'status');
      wrap.setAttribute('aria-live', 'polite');
      sh.append(st, wrap);
      document.body.appendChild(toastHost);
    }

    const wrap = toastHost.shadowRoot.querySelector('.wrap');
    const el = document.createElement('div');
    el.className = `t ${kind}`;
    const dot = document.createElement('i');
    const txt = document.createElement('span');
    txt.textContent = message;
    el.append(dot, txt);
    wrap.appendChild(el);

    while (wrap.children.length > 3) wrap.firstChild.remove();

    const life = kind === 'error' ? 4200 : 2600;
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => {
        el.remove();
        if (!wrap.children.length && toastHost) { toastHost.remove(); toastHost = null; }
      }, 220);
    }, life);
  }

  // Clipboard writes fail silently in a lot of real situations — an insecure
  // origin, a page that grabbed focus, a locked-down policy. Say so.
  function copyText(text, okMsg) {
    return navigator.clipboard.writeText(text)
      .then(() => { toast(okMsg, 'ok'); return true; })
      .catch(() => { toast(t('copyFailed'), 'error'); return false; });
  }

  // ── Case file ─────────────────────────────────────────────────────────────
  // Findings accumulate across lookups and pages, then leave as something a
  // real pipeline can ingest — not just a Markdown blob.
  const CASE_KEY = 'osint_case';

  async function loadCase() {
    try {
      const o = await chrome.storage.local.get(CASE_KEY);
      return o[CASE_KEY] || { name: '', created: Date.now(), items: [] };
    } catch (_) { return { name: '', created: Date.now(), items: [] }; }
  }

  async function saveCase(c) {
    try { await chrome.storage.local.set({ [CASE_KEY]: c }); } catch (_) {}
  }

  function caseEntry(value, type, results) {
    const R = results || {};
    const good = id => { const r = R[id]; return r && !r._na && !r.error ? r : null; };
    const fd = good('feeds'), ox = good('otx'), mh = good('mhr');

    const sources = [];
    let malware = null, campaign = null;
    const attack = [];

    if (fd?.hits?.length) {
      fd.hits.forEach(h => {
        sources.push(h.src);
        if (!malware && h.malware) malware = h.malware;
      });
    }
    if (ox?.pulseCount) {
      sources.push('AlienVault OTX');
      if (!campaign && ox.pulses?.[0]) campaign = ox.pulses[0].name;
      if (!malware && ox.families?.length) malware = ox.families[0];
      (ox.attack || []).forEach(a => { if (!attack.includes(a)) attack.push(a); });
    }
    if (mh?.known) sources.push('Team Cymru MHR');

    const ranked = Object.values(R)
      .filter(r => r && !r._na && !r.error && r.verdict)
      .map(r => r.verdict);
    const worst = ['malicious', 'suspicious', 'clean', 'unknown']
      .find(v => ranked.includes(v)) || 'unknown';

    return {
      value, type, verdict: worst,
      sources: [...new Set(sources)],
      malware, campaign, attack,
      added: Date.now()
    };
  }

  async function addToCase(entry) {
    const c = await loadCase();
    const k = `${entry.type}:${entry.value}`;
    c.items = c.items.filter(i => `${i.type}:${i.value}` !== k);
    c.items.push(entry);
    await saveCase(c);
    return c;
  }

  // ── Exports ───────────────────────────────────────────────────────────────
  const STIX_PATTERN = {
    ip:     v => `[ipv4-addr:value = '${v}']`,
    ipv6:   v => `[ipv6-addr:value = '${v}']`,
    domain: v => `[domain-name:value = '${v}']`,
    url:    v => `[url:value = '${v}']`,
    email:  v => `[email-addr:value = '${v}']`,
    md5:    v => `[file:hashes.'MD5' = '${v}']`,
    sha1:   v => `[file:hashes.'SHA-1' = '${v}']`,
    sha256: v => `[file:hashes.'SHA-256' = '${v}']`
  };

  const MISP_TYPE = {
    ip: 'ip-dst', ipv6: 'ip-dst', domain: 'domain', url: 'url',
    email: 'email-src', md5: 'md5', sha1: 'sha1', sha256: 'sha256'
  };
  const MISP_CATEGORY = {
    ip: 'Network activity', ipv6: 'Network activity', domain: 'Network activity',
    url: 'Network activity', email: 'Payload delivery',
    md5: 'Payload delivery', sha1: 'Payload delivery', sha256: 'Payload delivery'
  };

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, ch => {
      const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16;
      return (ch === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  function stixTime(ms) { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, '.000Z'); }

  function buildSTIX(c) {
    const now = stixTime(Date.now());
    const objects = [];
    const malwareRefs = new Map();

    const identity = {
      type: 'identity', spec_version: '2.1',
      id: `identity--${uuid()}`,
      created: now, modified: now,
      name: 'OSINT Research Assistant',
      identity_class: 'system'
    };
    objects.push(identity);

    for (const it of c.items) {
      const pat = STIX_PATTERN[it.type];
      if (!pat) continue;
      const created = stixTime(it.added || Date.now());
      const ind = {
        type: 'indicator', spec_version: '2.1',
        id: `indicator--${uuid()}`,
        created_by_ref: identity.id,
        created, modified: created,
        name: `${it.type} ${it.value}`,
        pattern: pat(it.value),
        pattern_type: 'stix',
        valid_from: created,
        labels: [it.verdict === 'malicious' ? 'malicious-activity'
               : it.verdict === 'suspicious' ? 'anomalous-activity'
               : 'unknown'],
        confidence: it.verdict === 'malicious' ? 85 : it.verdict === 'suspicious' ? 50 : 15
      };
      if (it.sources?.length) ind.external_references = it.sources.map(s => ({ source_name: s }));
      objects.push(ind);

      if (it.malware) {
        let mref = malwareRefs.get(it.malware);
        if (!mref) {
          mref = `malware--${uuid()}`;
          malwareRefs.set(it.malware, mref);
          objects.push({
            type: 'malware', spec_version: '2.1',
            id: mref, created: now, modified: now,
            name: it.malware, is_family: true
          });
        }
        objects.push({
          type: 'relationship', spec_version: '2.1',
          id: `relationship--${uuid()}`,
          created: now, modified: now,
          relationship_type: 'indicates',
          source_ref: ind.id, target_ref: mref
        });
      }
    }

    return JSON.stringify({ type: 'bundle', id: `bundle--${uuid()}`, objects }, null, 2);
  }

  function buildMISP(c) {
    const d = new Date();
    return JSON.stringify({
      Event: {
        info: c.name || `OSINT Assistant export ${d.toISOString().split('T')[0]}`,
        date: d.toISOString().split('T')[0],
        threat_level_id: c.items.some(i => i.verdict === 'malicious') ? '1' : '3',
        analysis: '1',
        distribution: '0',
        Attribute: c.items.filter(i => MISP_TYPE[i.type]).map(i => ({
          type: MISP_TYPE[i.type],
          category: MISP_CATEGORY[i.type] || 'Other',
          value: i.value,
          to_ids: i.verdict === 'malicious',
          comment: [i.malware, i.campaign, i.sources?.join(', ')].filter(Boolean).join(' | ')
        }))
      }
    }, null, 2);
  }

  function buildCSV(c) {
    // Malware family names and sources come from third-party feeds. A field
    // starting with =, +, -, @ or a tab is interpreted as a formula by Excel
    // and Sheets on open — prefix with an apostrophe to force plain text.
    const esc2 = s => {
      let v = String(s ?? '');
      if (/^[=+\-@\t]/.test(v)) v = `'${v}`;
      return `"${v.replace(/"/g, '""')}"`;
    };
    const rows = [['value', 'type', 'verdict', 'malware', 'campaign', 'attack', 'sources', 'added']];
    c.items.forEach(i => rows.push([
      i.value, i.type, i.verdict, i.malware || '', i.campaign || '',
      (i.attack || []).join(' '), (i.sources || []).join(' '),
      new Date(i.added).toISOString()
    ]));
    return rows.map(r => r.map(esc2).join(',')).join('\n');
  }

  function buildCaseMarkdown(c) {
    const out = [];
    out.push(`## ${c.name || 'OSINT case'}`);
    out.push('');
    out.push(`${c.items.length} indicators`);
    out.push('');
    out.push('| Verdict | Indicator | Type | Malware | Sources |');
    out.push('|---------|-----------|------|---------|---------|');
    c.items.forEach(i => out.push(
      `| ${i.verdict} | \`${i.value}\` | ${i.type} | ${i.malware || '—'} | ${(i.sources || []).join(', ') || '—'} |`
    ));
    out.push('');
    out.push(`_OSINT Research Assistant · ${new Date().toISOString().split('T')[0]}_`);
    return out.join('\n');
  }

  function downloadText(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  // ── Case panel ────────────────────────────────────────────────────────────
  let caseHost = null;

  function closeCase() { if (caseHost) { caseHost.remove(); caseHost = null; } }

  async function showCase() {
    closeCase();
    const c = await loadCase();

    caseHost = document.createElement('div');
    if (resolveTheme() === 'light') caseHost.classList.add('light');
    const sh = caseHost.attachShadow({ mode: 'open' });
    document.body.appendChild(caseHost);

    const style = document.createElement('style');
    style.textContent = CSS + `
      #panel { left: 18px; right: auto; width: 420px; }
      #cname {
        width: 100%; background: var(--surface); color: var(--text);
        border: 1px solid var(--hair); border-radius: var(--r-s);
        padding: 7px 10px; font-family: var(--font); font-size: 12px; outline: none;
      }
      #cname:focus { border-color: var(--accent); }
      .crow {
        display: flex; align-items: center; gap: 9px;
        padding: 8px 14px; border-bottom: 1px solid var(--hair2);
      }
      .cval { font-family: var(--mono); font-size: 11.5px; color: var(--text);
              flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .cmeta { font-size: 10px; color: var(--text3); flex-shrink: 0; max-width: 40%;
               overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .crm { background: none; border: none; color: var(--text3); cursor: pointer;
             font-size: 15px; line-height: 1; padding: 0 3px; }
      .crm:hover { color: var(--mal); }
      .cbar { display: flex; gap: 6px; flex-wrap: wrap; padding: 12px 14px;
              border-top: 1px solid var(--hair); flex-shrink: 0; }
      .cbtn {
        font-family: var(--font); font-size: 11.5px; font-weight: 500;
        padding: 6px 11px; border-radius: 7px; cursor: pointer;
        background: var(--surface2); border: 1px solid var(--hair); color: var(--text2);
        transition: .14s;
      }
      .cbtn:hover { color: var(--text); border-color: var(--raise); }
      .cbtn:focus-visible { outline: 1px solid var(--accent); outline-offset: 1px; }
      .cbtn.danger:hover { color: var(--mal); border-color: var(--mal); }
    `;
    sh.appendChild(style);

    const wrap = document.createElement('div');
    wrap.id = 'panel';
    wrap.innerHTML = `
      <div id="header">
        <span id="logo">OSINT</span>
        <span class="type-pill">${esc(t('caseFile'))}</span>
        <button class="hbtn" id="c-close">×</button>
      </div>
      <div style="padding:12px 14px 10px">
        <input id="cname" type="text" placeholder="${esc(t('caseNamePh'))}" value="${esc(c.name || '')}">
      </div>
      <div class="overall unknown" style="margin:0 14px 12px">
        <span class="overall-dot"></span>
        <span class="overall-label">${esc(t('caseCount', c.items.length))}</span>
      </div>
      <div id="content">
        ${c.items.length ? c.items.slice().reverse().map((i, n) => `
          <div class="crow" data-k="${esc(i.type + ':' + i.value)}">
            <span class="chip-dot ${esc(i.verdict || 'unknown')}"></span>
            <span class="cval" title="${esc(i.value)}">${esc(i.value)}</span>
            <span class="cmeta">${esc(i.malware || (i.sources || []).join(', ') || i.type)}</span>
            <button class="crm" title="${esc(t('removeItem'))}">×</button>
          </div>`).join('')
        : `<div style="padding:16px 14px">${msg(t('caseEmpty'), 'neutral')}</div>`}
      </div>
      <div class="cbar">
        <button class="cbtn" data-x="stix">${esc(t('dlStix'))}</button>
        <button class="cbtn" data-x="misp">${esc(t('dlMisp'))}</button>
        <button class="cbtn" data-x="csv">${esc(t('dlCsv'))}</button>
        <button class="cbtn" data-x="md">${esc(t('dlMd'))}</button>
        <button class="cbtn danger" id="c-clear" style="margin-left:auto">${esc(t('clearCase'))}</button>
      </div>
      <div id="resize"></div>
    `;
    sh.appendChild(wrap);

    wrap.querySelectorAll('.chip-dot').forEach(d => { d.style.display = 'inline-block'; });
    wrap.querySelector('#c-close').onclick = closeCase;

    const nameInput = wrap.querySelector('#cname');
    nameInput.addEventListener('change', async () => {
      const cur = await loadCase();
      cur.name = nameInput.value.trim();
      await saveCase(cur);
    });

    wrap.querySelectorAll('.crow .crm').forEach(btn => {
      btn.onclick = async () => {
        const k = btn.closest('.crow').dataset.k;
        const cur = await loadCase();
        cur.items = cur.items.filter(i => `${i.type}:${i.value}` !== k);
        await saveCase(cur);
        showCase();
      };
    });

    wrap.querySelector('#c-clear').onclick = async () => {
      const cur = await loadCase();
      if (!cur.items.length) { toast(t('caseNothing'), 'info'); return; }
      await saveCase({ name: '', created: Date.now(), items: [] });
      toast(t('caseCleared', cur.items.length), 'ok');
      showCase();
    };

    wrap.querySelectorAll('.cbtn[data-x]').forEach(btn => {
      btn.onclick = async () => {
        const cur = await loadCase();
        if (!cur.items.length) { toast(t('caseNothing'), 'info'); return; }

        const stamp = new Date().toISOString().split('T')[0];
        const base = (cur.name || 'osint-case').replace(/[^\w\-]+/g, '-').toLowerCase();
        const kind = btn.dataset.x;
        const spec = {
          stix: [`${base}-${stamp}.stix.json`, () => buildSTIX(cur),         'application/json'],
          misp: [`${base}-${stamp}.misp.json`, () => buildMISP(cur),         'application/json'],
          csv:  [`${base}-${stamp}.csv`,       () => buildCSV(cur),          'text/csv'],
          md:   [`${base}-${stamp}.md`,        () => buildCaseMarkdown(cur), 'text/markdown']
        }[kind];
        if (!spec) return;

        // A download that just happens, with no confirmation, reads as a
        // button that did nothing.
        try {
          downloadText(spec[0], spec[1](), spec[2]);
          toast(t('exported', spec[0], cur.items.length), 'ok');
        } catch (_) {
          toast(t('exportFailed'), 'error');
        }
      };
    });

    makeDraggable(wrap, wrap.querySelector('#header'));
    makeResizable(wrap, wrap.querySelector('#resize'));
  }

  // ── Pivot graph ───────────────────────────────────────────────────────────
  // Each lookup is an island until you can walk between them. Nodes expand on
  // demand so a wide fan-out never stalls the view, and the layout is a small
  // spring simulation rather than a library.
  let gHost = null, gState = null, gRaf = 0;

  const GRAPHABLE = ['ip', 'ipv6', 'domain', 'url', 'asn'];

  const NODE_COLOR = {
    ip: '#6fa8d4', ipv6: '#6fa8d4', domain: '#5cc98d', url: '#5cc98d',
    email: '#67e8f9', asn: '#c9a3e8', prefix: '#9aa5b4',
    md5: '#e0a45c', sha1: '#e0a45c', sha256: '#e0a45c'
  };

  function closeGraph() {
    if (gRaf) { cancelAnimationFrame(gRaf); gRaf = 0; }
    if (gHost) { gHost.remove(); gHost = null; }
    gState = null;
  }

  function openGraph(value, type) {
    closeGraph();

    gHost = document.createElement('div');
    if (resolveTheme() === 'light') gHost.classList.add('light');
    const sh = gHost.attachShadow({ mode: 'open' });
    document.body.appendChild(gHost);

    const style = document.createElement('style');
    style.textContent = CSS + `
      #panel { left: 50%; top: 50%; transform: translate(-50%,-50%);
               right: auto; width: min(860px, 92vw); height: min(620px, 84vh);
               max-height: none; }
      #gwrap { flex: 1; position: relative; min-height: 0; overflow: hidden; }
      canvas { display: block; width: 100%; height: 100%; cursor: grab; }
      canvas.dragging { cursor: grabbing; }
      #gsel {
        position: absolute; left: 12px; right: 12px; bottom: 12px;
        background: var(--surface); border: 1px solid var(--hair);
        border-radius: var(--r-s); padding: 10px 12px;
        display: flex; align-items: center; gap: 10px;
        box-shadow: 0 6px 20px -6px rgba(0,0,0,.45);
      }
      #gsel.hidden { display: none; }
      #gsel .v { font-family: var(--mono); font-size: 12px; color: var(--text);
                 flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis;
                 white-space: nowrap; }
      #gsel .k { font-size: 9.5px; letter-spacing: .12em; text-transform: uppercase;
                 color: var(--text3); font-family: var(--mono); }
      .gbtn {
        font-family: var(--font); font-size: 11.5px; font-weight: 500;
        padding: 5px 11px; border-radius: 6px; cursor: pointer; white-space: nowrap;
        background: var(--surface2); border: 1px solid var(--hair); color: var(--text2);
        transition: .14s;
      }
      .gbtn:hover { color: var(--text); border-color: var(--raise); }
      .gbtn:focus-visible { outline: 1px solid var(--accent); outline-offset: 1px; }
      #glegend {
        display: flex; gap: 12px; flex-wrap: wrap;
        padding: 8px 14px; border-bottom: 1px solid var(--hair2);
        font-size: 10px; color: var(--text3); flex-shrink: 0;
      }
      #glegend span { display: flex; align-items: center; gap: 5px; }
      #glegend i { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
      #ghint { margin-left: auto; }
    `;
    sh.appendChild(style);

    const wrap = document.createElement('div');
    wrap.id = 'panel';
    wrap.innerHTML = `
      <div id="header">
        <span id="logo">OSINT</span>
        <span class="type-pill">${esc(t('graph'))}</span>
        <button class="hbtn" id="g-fit" title="${esc(t('fit'))}">⤢</button>
        <button class="hbtn" id="g-close">×</button>
      </div>
      <div id="glegend">
        <span><i style="background:${NODE_COLOR.ip}"></i>IP</span>
        <span><i style="background:${NODE_COLOR.domain}"></i>Domain</span>
        <span><i style="background:${NODE_COLOR.asn}"></i>ASN</span>
        <span><i style="background:${NODE_COLOR.prefix}"></i>Prefix</span>
        <span><i style="background:var(--mal)"></i>${esc(t('flagged'))}</span>
        <span id="ghint">${esc(t('graphHint'))}</span>
      </div>
      <div id="gwrap">
        <canvas id="gcanvas"></canvas>
        <div id="gsel" class="hidden">
          <span class="k" id="gsel-k"></span>
          <span class="v" id="gsel-v"></span>
          <button class="gbtn" id="gsel-expand"></button>
          <button class="gbtn" id="gsel-lookup"></button>
        </div>
      </div>
      <div id="resize"></div>
    `;
    sh.appendChild(wrap);

    const canvas = wrap.querySelector('#gcanvas');
    gState = {
      sh, wrap, canvas,
      ctx: (() => { try { return canvas.getContext('2d'); } catch (_) { return null; } })(),
      nodes: [], edges: [], sel: null,
      cam: { x: 0, y: 0, k: 1 }, drag: null, dpr: window.devicePixelRatio || 1
    };

    addNode(value, type, 0, null, false);
    gState.nodes[0].x = 0; gState.nodes[0].y = 0;

    wrap.querySelector('#g-close').onclick = closeGraph;
    wrap.querySelector('#g-fit').onclick = fitGraph;
    wrap.querySelector('#gsel-expand').onclick = () => { if (gState.sel) expandGraphNode(gState.sel); };
    wrap.querySelector('#gsel-lookup').onclick = () => {
      if (gState.sel) lookup(gState.sel.value, gState.sel.type);
    };

    bindGraphInput();
    makeDraggable(wrap, wrap.querySelector('#header'));
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    expandGraphNode(gState.nodes[0]);
    tickGraph();
  }

  function addNode(value, type, depth, from, flagged, rel, label) {
    const id = `${type}:${String(value).toLowerCase()}`;
    let n = gState.nodes.find(x => x.id === id);
    if (!n) {
      const seed = gState.nodes.length;
      const ang = seed * 2.399;                      // golden angle keeps new nodes apart
      const rad = 60 + seed * 9;
      n = {
        id, value, type, depth, flagged: !!flagged, label: label || null,
        x: Math.cos(ang) * rad, y: Math.sin(ang) * rad, vx: 0, vy: 0,
        expanded: false, loading: false
      };
      gState.nodes.push(n);
    }
    if (from && from.id !== n.id) {
      const ek = [from.id, n.id].sort().join('|');
      if (!gState.edges.some(e => e.k === ek)) {
        gState.edges.push({ k: ek, a: from, b: n, rel: rel || '' });
      }
    }
    return n;
  }

  function expandGraphNode(node) {
    if (!node || node.loading || node.expanded) return;
    node.loading = true;
    paintSel();
    chrome.runtime.sendMessage({ action: 'expand', value: node.value, type: node.type }, (res) => {
      node.loading = false;
      node.expanded = true;
      if (!chrome.runtime.lastError && res && res.neighbours) {
        res.neighbours.forEach(nb => {
          const child = addNode(nb.value, nb.type, node.depth + 1, node, nb.flagged, nb.rel, nb.label);
          // start children near the parent so the simulation settles quickly
          if (child.vx === 0 && child.vy === 0 && !child.expanded) {
            child.x = node.x + (Math.random() - .5) * 90;
            child.y = node.y + (Math.random() - .5) * 90;
          }
        });
      }
      paintSel();
      kickGraph();
    });
  }

  function stepGraph() {
    const N = gState.nodes, E = gState.edges;
    // repulsion
    for (let i = 0; i < N.length; i++) {
      for (let j = i + 1; j < N.length; j++) {
        const a = N[i], b = N[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) { dx = (Math.random() - .5); dy = (Math.random() - .5); d2 = 1; }
        const d = Math.sqrt(d2);
        const f = 5200 / d2;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    // springs
    for (const e of E) {
      const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      const f = (d - 118) * 0.012;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      e.a.vx += fx; e.a.vy += fy; e.b.vx -= fx; e.b.vy -= fy;
    }
    // centring + damping
    let energy = 0;
    for (const n of N) {
      n.vx -= n.x * 0.0016;
      n.vy -= n.y * 0.0016;
      n.vx *= 0.86; n.vy *= 0.86;
      if (gState.drag && gState.drag.node === n) continue;
      n.x += n.vx; n.y += n.vy;
      energy += n.vx * n.vx + n.vy * n.vy;
    }
    return energy;
  }

  function drawGraph() {
    const { ctx, canvas, cam, nodes, edges, dpr } = gState;
    if (!ctx) return;   // no 2d context: keep the model alive, just don't paint
    const w = canvas.width / dpr, h = canvas.height / dpr;
    const cs = getComputedStyle(gState.wrap);
    const bg    = cs.getPropertyValue('--bg').trim() || '#0a0b0d';
    const hair  = cs.getPropertyValue('--hair').trim() || '#1e222b';
    const text  = cs.getPropertyValue('--text').trim() || '#e9ebef';
    const text3 = cs.getPropertyValue('--text3').trim() || '#596170';
    const mal   = cs.getPropertyValue('--mal').trim() || '#ec7a76';

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, w, h);
    ctx.translate(w / 2 + cam.x, h / 2 + cam.y);
    ctx.scale(cam.k, cam.k);

    ctx.lineWidth = 1 / cam.k;
    ctx.strokeStyle = hair;
    for (const e of edges) {
      ctx.beginPath();
      ctx.moveTo(e.a.x, e.a.y);
      ctx.lineTo(e.b.x, e.b.y);
      ctx.stroke();
    }

    ctx.font = `${11 / cam.k}px ui-monospace, "Cascadia Code", Consolas, monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    for (const n of nodes) {
      const r = (n.depth === 0 ? 9 : 6.5);
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = n.flagged ? mal : (NODE_COLOR[n.type] || text3);
      ctx.fill();

      if (n === gState.sel) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 4.5, 0, Math.PI * 2);
        ctx.strokeStyle = text;
        ctx.lineWidth = 1.5 / cam.k;
        ctx.stroke();
        ctx.lineWidth = 1 / cam.k;
      } else if (!n.expanded && !n.loading) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 3, 0, Math.PI * 2);
        ctx.strokeStyle = hair;
        ctx.stroke();
      }

      const label = n.value.length > 26 ? n.value.slice(0, 24) + '…' : n.value;
      ctx.fillStyle = n.flagged ? mal : text3;
      ctx.fillText(label, n.x, n.y + r + 4 / cam.k);
    }
  }

  // The layout settles, so park the loop instead of burning a frame budget
  // forever. Anything that disturbs the graph calls kickGraph() to wake it.
  function tickGraph() {
    gRaf = 0;
    if (!gState) return;
    const energy = stepGraph();
    drawGraph();
    if (energy > 0.05 || gState.drag) gRaf = requestAnimationFrame(tickGraph);
  }

  function kickGraph() {
    if (!gState) return;
    drawGraph();                       // never leave a stale frame on screen
    if (!gRaf) gRaf = requestAnimationFrame(tickGraph);
  }

  function resizeCanvas() {
    if (!gState) return;
    const { canvas, dpr } = gState;
    const r = canvas.getBoundingClientRect();
    canvas.width  = Math.max(1, Math.round(r.width  * dpr));
    canvas.height = Math.max(1, Math.round(r.height * dpr));
  }

  function fitGraph() {
    if (!gState || !gState.nodes.length) return;
    const xs = gState.nodes.map(n => n.x), ys = gState.nodes.map(n => n.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs);
    const minY = Math.min(...ys), maxY = Math.max(...ys);
    const r = gState.canvas.getBoundingClientRect();
    const k = Math.min(3, Math.max(0.25,
      Math.min((r.width - 90) / Math.max(60, maxX - minX),
               (r.height - 90) / Math.max(60, maxY - minY))));
    gState.cam.k = k;
    gState.cam.x = -((minX + maxX) / 2) * k;
    gState.cam.y = -((minY + maxY) / 2) * k;
  }

  function nodeAt(clientX, clientY) {
    const { canvas, cam } = gState;
    const r = canvas.getBoundingClientRect();
    const x = (clientX - r.left - r.width / 2 - cam.x) / cam.k;
    const y = (clientY - r.top - r.height / 2 - cam.y) / cam.k;
    let best = null, bestD = 16;
    for (const n of gState.nodes) {
      const d = Math.hypot(n.x - x, n.y - y);
      if (d < bestD) { bestD = d; best = n; }
    }
    return { node: best, x, y };
  }

  function paintSel() {
    if (!gState) return;
    const box = gState.wrap.querySelector('#gsel');
    const n = gState.sel;
    if (!n) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    gState.wrap.querySelector('#gsel-k').textContent = n.type;
    gState.wrap.querySelector('#gsel-v').textContent = n.label ? `${n.value} · ${n.label}` : n.value;
    const ex = gState.wrap.querySelector('#gsel-expand');
    ex.textContent = n.loading ? t('expanding') : n.expanded ? t('expanded') : t('expand');
    ex.disabled = n.loading || n.expanded;
    ex.style.opacity = (n.loading || n.expanded) ? '.5' : '1';
    gState.wrap.querySelector('#gsel-lookup').textContent = t('lookupBtn');
  }

  function bindGraphInput() {
    const { canvas } = gState;

    canvas.addEventListener('mousedown', e => {
      const hit = nodeAt(e.clientX, e.clientY);
      gState.drag = hit.node
        ? { node: hit.node, ox: hit.x - hit.node.x, oy: hit.y - hit.node.y, moved: false }
        : { pan: true, sx: e.clientX, sy: e.clientY, cx: gState.cam.x, cy: gState.cam.y, moved: false };
      canvas.classList.add('dragging');
    });

    window.addEventListener('mousemove', e => {
      if (!gState || !gState.drag) return;
      gState.drag.moved = true;
      if (gState.drag.pan) {
        gState.cam.x = gState.drag.cx + (e.clientX - gState.drag.sx);
        gState.cam.y = gState.drag.cy + (e.clientY - gState.drag.sy);
      } else {
        const p = nodeAt(e.clientX, e.clientY);
        gState.drag.node.x = p.x - gState.drag.ox;
        gState.drag.node.y = p.y - gState.drag.oy;
        gState.drag.node.vx = gState.drag.node.vy = 0;
      }
      kickGraph();
    });

    window.addEventListener('mouseup', () => {
      if (!gState || !gState.drag) return;
      const d = gState.drag;
      gState.drag = null;
      gState.canvas.classList.remove('dragging');
      kickGraph();
      if (!d.moved && d.node) { gState.sel = d.node; paintSel(); }
      else if (!d.moved && d.pan) { gState.sel = null; paintSel(); }
    });

    canvas.addEventListener('dblclick', e => {
      const hit = nodeAt(e.clientX, e.clientY);
      if (hit.node) { gState.sel = hit.node; paintSel(); expandGraphNode(hit.node); }
    });

    canvas.addEventListener('wheel', e => {
      e.preventDefault();
      const f = e.deltaY < 0 ? 1.12 : 1 / 1.12;
      gState.cam.k = Math.min(3, Math.max(0.2, gState.cam.k * f));
      kickGraph();
    }, { passive: false });
  }

  // ── Panel ─────────────────────────────────────────────────────────────────
  let host = null, shadow = null, activeTab = null;

  function resolveTheme() {
    const th = state.settings.theme;
    if (th === 'light') return 'light';
    if (th === 'dark')  return 'dark';
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function buildPanel(query, type, { fetch = true } = {}) {
    if (host) host.remove();
    host = document.createElement('div');
    if (resolveTheme() === 'light') host.classList.add('light');
    shadow = host.attachShadow({ mode: 'open' });
    document.body.appendChild(host);

    const style = document.createElement('style');
    style.textContent = CSS;
    shadow.appendChild(style);

    const services = activeServices(type);
    const summaryTab = { ...SUMMARY, label: t('summary') };
    const relevant = [summaryTab, ...services];
    const typeLabel = t('types')[type] || type.toUpperCase();

    const wrap = document.createElement('div');
    wrap.id = 'panel';
    wrap.innerHTML = `
      <div id="header">
        <span id="logo">OSINT</span>
        <span id="htitle">${esc(t('subtitle'))}</span>
        <span class="type-pill pill-${esc(type)}">${esc(typeLabel)}</span>
        <button class="hbtn" id="lang-btn">${esc(t('langBtn'))}</button>
        <button class="hbtn" id="min-btn">${t('minimize')}</button>
        <button class="hbtn" id="close-btn">${t('close')}</button>
      </div>
      <div id="qbar">
        <span id="qtext" title="${esc(query)}">${esc(query)}</span>
        ${GRAPHABLE.includes(type) ? `<button id="graph-btn"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="5" cy="6" r="3" fill="currentColor"/><circle cx="19" cy="6" r="3" fill="currentColor"/><circle cx="12" cy="19" r="3" fill="currentColor"/><path d="M7.5 7.5L10 16M16.5 7.5L14 16" stroke="currentColor" stroke-width="1.6"/></svg>${esc(t('graphBtn'))}</button>` : ''}
        <button id="case-btn">${esc(t('addToCase'))}</button>
        <button id="report-btn">${esc(t('report'))}</button>
        <button id="copy-btn">${esc(t('copy'))}</button>
      </div>
      ${state.defanged ? `<div class="defang-note">${esc(t('defangedFrom', state.original))}</div>` : ''}
      <div id="overall" class="overall unknown"></div>
      <div id="body">
        <div id="tabs">
          ${relevant.map(s => `
            <button class="tab${s.virtual ? ' tab-summary' : ''}" data-svc="${esc(s.id)}">
              ${s.virtual ? '' : `<span class="chip-dot loading" id="tdot-${esc(s.id)}"></span>`}${esc(s.label)}
            </button>`).join('')}
        </div>
        <div id="content">
          ${relevant.map(s => `<div class="pane" id="pane-${s.id}">${
            s.virtual ? renderSummary(null, type) : loadingEl(s.label)
          }</div>`).join('')}
        </div>
      </div>
      <div id="resize"></div>
    `;
    shadow.appendChild(wrap);

    // Restore the position and size the user last dragged it to
    if (state.settings.rememberPanel && state.box) {
      const b = state.box;
      if (b.left != null && b.left < window.innerWidth - 80) {
        wrap.style.left = b.left + 'px';
        wrap.style.top = Math.max(0, Math.min(b.top ?? 20, window.innerHeight - 60)) + 'px';
        wrap.style.right = 'auto';
      }
      if (b.height) wrap.style.maxHeight = b.height + 'px';
    }

    // Activate first tab
    const first = relevant[0];
    if (first) setActive(wrap, first.id);

    // Header controls
    wrap.querySelector('#close-btn').onclick = () => host.remove();
    wrap.querySelector('#min-btn').onclick = () => {
      const min = wrap.classList.toggle('minimized');
      wrap.querySelector('#min-btn').textContent = min ? t('restore') : t('minimize');
    };
    wrap.querySelector('#lang-btn').onclick = () => {
      state.lang = state.lang === 'en' ? 'tr' : 'en';
      state.settings.lang = state.lang;
      saveSettings();
      rebuildPanel(query, type);
    };
    wrap.querySelector('#copy-btn').onclick = (e) => {
      copyText(query, t('copiedIndicator')).then(ok => {
        if (ok) flash(e.target, t('copied'), t('copy'));
      });
    };
    const gBtn = wrap.querySelector('#graph-btn');
    if (gBtn) gBtn.onclick = () => openGraph(query, type);
    wrap.querySelector('#case-btn').onclick = (e) => {
      addToCase(caseEntry(query, type, state.results)).then(c => {
        flash(e.target, t('addedToCase'), t('addToCase'));
        toast(t('caseAdded', query, c.items.length), 'ok');
      });
    };
    wrap.querySelector('#report-btn').onclick = (e) => {
      const done = Object.keys(state.results).length;
      copyText(buildReport(), t('reportCopiedN', done)).then(ok => {
        if (ok) flash(e.target, t('reportCopied'), t('report'));
      });
    };

    wrap.querySelectorAll('.tab').forEach(el => {
      el.onclick = () => setActive(wrap, el.dataset.svc);
    });

    // Any underlined value in a result starts a fresh lookup — this is what
    // turns the panel from a readout into something you can investigate with.
    wrap.querySelector('#content').addEventListener('click', (e) => {
      const p = e.target.closest('.pv');
      if (!p || !p.dataset.pv) return;
      e.preventDefault();
      lookup(p.dataset.pv, p.dataset.pvt);
    });

    makeDraggable(wrap, wrap.querySelector('#header'));
    makeResizable(wrap, wrap.querySelector('#resize'));

    // `relevant` carries the virtual Summary tab; only real services get queried.
    if (fetch) services.forEach(s => fetchService(wrap, s, query, type));
  }

  function flash(btn, msgText, restore) {
    btn.textContent = msgText;
    btn.style.color = 'var(--accent)';
    btn.style.borderColor = 'var(--accent)';
    setTimeout(() => {
      btn.textContent = restore;
      btn.style.color = '';
      btn.style.borderColor = '';
    }, 1600);
  }

  function savePanelBox(wrap) {
    if (!state.settings.rememberPanel) return;
    const r = wrap.getBoundingClientRect();
    state.box = { left: Math.round(r.left), top: Math.round(r.top), height: Math.round(r.height) };
    try { chrome.storage.local.set({ osint_box: state.box }); } catch (_) {}
  }

  // Re-render in the other language using results we already have — services
  // still in flight keep their spinner and land through their own callback.
  function rebuildPanel(query, type) {
    buildPanel(query, type, { fetch: false });
    const wrap = shadow.querySelector('#panel');
    activeServices(type).forEach(s => {
      if (state.results[s.id] !== undefined) applyResult(wrap, s, state.results[s.id], type);
      else fetchService(wrap, s, query, type);
    });
  }

  function setActive(wrap, svcId) {
    activeTab = svcId;
    wrap.querySelectorAll('.tab').forEach(el => el.classList.toggle('active', el.dataset.svc === svcId));
    wrap.querySelectorAll('.pane').forEach(p => p.classList.toggle('active', p.id === `pane-${svcId}`));
  }

  function fetchService(wrap, svc, query, type) {
    chrome.runtime.sendMessage({ action: 'fetchAPI', service: svc.id, query, type }, result => {
      if (chrome.runtime.lastError) result = { error: chrome.runtime.lastError.message };
      if (!result) result = { error: 'No response.' };
      state.results[svc.id] = result;
      applyResult(wrap, svc, result, type);
    });
  }

  function applyResult(wrap, svc, result, type) {
    const pane = wrap.querySelector(`#pane-${svc.id}`);
    const tdot = wrap.querySelector(`#tdot-${svc.id}`);
    if (pane) {
      pane.innerHTML = svc.render(result, type) +
        (result._cached ? `<div style="margin-top:14px"><span class="cached-badge">${esc(t('cached'))}</span></div>` : '');
    }
    const cls = result._na ? 'na' : result.error ? 'error' : (result.verdict || 'unknown');
    if (tdot) tdot.className = `chip-dot ${cls}`;
    paintOverall(wrap);

    const sum = wrap.querySelector('#pane-summary');
    if (sum) sum.innerHTML = renderSummary(null, type);
  }

  // ── Drag ──────────────────────────────────────────────────────────────────
  function makeDraggable(panel, handle) {
    let ox, oy, sx, sy;
    handle.addEventListener('mousedown', e => {
      if (e.target.closest('.hbtn')) return;
      ox = e.clientX; oy = e.clientY;
      const r = panel.getBoundingClientRect();
      sx = r.left; sy = r.top;
      // The graph panel starts centered via `left:50%; transform:translate(-50%,-50%)`.
      // getBoundingClientRect() already accounts for that transform, but the
      // transform itself is still in the stylesheet — so pinning left/top to
      // the rect without clearing it applies the -50%/-50% shift a second
      // time, throwing the panel toward the top-left corner. Freeze the
      // transform away up front so left/top become the only source of truth.
      panel.style.transform = 'none';
      panel.style.left  = sx + 'px';
      panel.style.top   = sy + 'px';
      panel.style.right = 'auto';
      const mv = m => {
        panel.style.left  = (sx + m.clientX - ox) + 'px';
        panel.style.top   = (sy + m.clientY - oy) + 'px';
        panel.style.right = 'auto';
      };
      const up = () => {
        document.removeEventListener('mousemove', mv);
        document.removeEventListener('mouseup', up);
        savePanelBox(panel);
      };
      document.addEventListener('mousemove', mv);
      document.addEventListener('mouseup', up);
    });
  }

  // ── Resize ────────────────────────────────────────────────────────────────
  function makeResizable(panel, handle) {
    handle.addEventListener('mousedown', e => {
      const sy = e.clientY, sh = panel.getBoundingClientRect().height;
      const mv = m => { panel.style.maxHeight = Math.max(200, sh + m.clientY - sy) + 'px'; };
      const up = () => {
        document.removeEventListener('mousemove', mv);
        document.removeEventListener('mouseup', up);
        savePanelBox(panel);
      };
      document.addEventListener('mousemove', mv);
      document.addEventListener('mouseup', up);
    });
  }

  // ── Message listener ──────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.action === 'showPanel') {
      ready.then(refreshSettings).then(() => {
        state.results  = {};
        state.query    = msg.query;
        state.original = msg.original || msg.query;
        state.type     = msg.type;
        state.defanged = !!msg.defanged;
        buildPanel(msg.query, msg.type);
        addHistory({ q: msg.query, type: msg.type, at: Date.now() });
      });
    }
    if (msg.action === 'toggleScan') {
      ready.then(refreshSettings).then(scanPage);
    }
    if (msg.action === 'showCase') {
      ready.then(refreshSettings).then(showCase);
    }
  });
})();
