const fs = require('fs');
const vm = require('vm');

const src = fs.readFileSync(require('path').join(__dirname, '..', 'background.js'), 'utf8');

const noop = () => {};
const listener = { addListener: noop };
const sandbox = {
  chrome: {
    runtime: { onInstalled: listener, onMessage: listener, onStartup: listener },
    contextMenus: { removeAll: (cb) => cb && cb(), create: noop, onClicked: listener },
    commands: { onCommand: listener },
    scripting: {}, tabs: {},
    storage: {
      session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
      local:   { get: async () => ({}), set: async () => {}, remove: async () => {} }
    }
  },
  fetch: async () => ({ ok: true, status: 200, json: async () => ({}) }),
  setTimeout, clearTimeout, AbortController, console
};
vm.createContext(sandbox);
vm.runInContext(src + '\n;globalThis.__T = { refang, detectIOCType, analyze };', sandbox);
const { refang, detectIOCType, analyze } = sandbox.__T;

let pass = 0, fail = 0;
function eq(label, got, want) {
  if (got === want) { pass++; }
  else { fail++; console.log(`  FAIL  ${label}\n        got  ${JSON.stringify(got)}\n        want ${JSON.stringify(want)}`); }
}

console.log('\n=== refang ===');
eq('bracket dot',   refang('185.220.101[.]45'),      '185.220.101.45');
eq('paren dot',     refang('185.220.101(.)45'),      '185.220.101.45');
eq('brace dot',     refang('evil{.}com'),            'evil.com');
eq('hxxp',          refang('hxxp://evil.com'),       'http://evil.com');
eq('hxxps',         refang('hxxps://evil[.]com'),    'https://evil.com');
eq('HXXPS upper',   refang('hXXps://evil[.]com'),    'https://evil.com');
eq('email at',      refang('user[at]mail[.]com'),    'user@mail.com');
eq('email paren',   refang('user(at)mail(.)com'),    'user@mail.com');
eq('word dot',      refang('evil dot com'),          'evil.com');
eq('angle wrap',    refang('<185.220.101.45>'),      '185.220.101.45');
eq('colon',         refang('http[:]//evil.com'),     'http://evil.com');
eq('clean passes',  refang('8.8.8.8'),               '8.8.8.8');
eq('domain passes', refang('example.com'),           'example.com');

console.log('\n=== detectIOCType ===');
eq('ipv4',        detectIOCType('185.220.101.45'), 'ip');
eq('ipv4 edge',   detectIOCType('255.255.255.255'), 'ip');
eq('bad octet',   detectIOCType('999.1.1.1'),      'unknown');
eq('version num', detectIOCType('1.2.3.4'),        'ip');
eq('md5',         detectIOCType('d41d8cd98f00b204e9800998ecf8427e'), 'md5');
eq('sha1',        detectIOCType('da39a3ee5e6b4b0d3255bfef95601890afd80709'), 'sha1');
eq('sha256',      detectIOCType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'sha256');
eq('domain',      detectIOCType('example.com'),    'domain');
eq('url',         detectIOCType('https://evil.com/x'), 'url');
eq('email',       detectIOCType('a@b.com'),        'email');
eq('junk',        detectIOCType('hello world'),    'unknown');

console.log('\n=== analyze (end to end) ===');
const a1 = analyze('185.220.101[.]45');
eq('defanged ip value',    a1.value, '185.220.101.45');
eq('defanged ip type',     a1.type, 'ip');
eq('defanged ip flag',     a1.defanged, true);

const a2 = analyze('hxxps://evil[.]com/path');
eq('defanged url value',   a2.value, 'https://evil.com/path');
eq('defanged url type',    a2.type, 'url');

const a3 = analyze('  8.8.8.8  ');
eq('clean ip value',       a3.value, '8.8.8.8');
eq('clean ip not flagged', a3.defanged, false);

const a4 = analyze('user[at]evil[.]com');
eq('defanged email value', a4.value, 'user@evil.com');
eq('defanged email type',  a4.type, 'email');

console.log('\n=== scan-mode IP regex (octet validated) ===');
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IP_RE = new RegExp(`(?<![\\w.])${OCTET}(?:\\.${OCTET}){3}(?![\\w])(?!\\.\\d)`, 'g');
function m(s) { IP_RE.lastIndex = 0; return s.match(IP_RE) || []; }
eq('valid ip found',   m('connect to 185.220.101.45 now').join(), '185.220.101.45');
eq('invalid rejected', m('build 999.999.999.999 here').join(),    '');
eq('semver rejected',  m('version 1.2.3.4.5 released').join(),    '');
eq('sentence end',     m('IPs 8.8.8.8 and 1.1.1.1.').join(),      '8.8.8.8,1.1.1.1');
eq('parenthesised',    m('host (192.168.1.100) down').join(),     '192.168.1.100');
eq('v-prefix skipped', m('release v1.2.3.4 shipped').join(),      '');
eq('comma list',       m('1.1.1.1, 8.8.4.4').join(),              '1.1.1.1,8.8.4.4');

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
