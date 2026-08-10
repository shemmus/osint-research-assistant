# OSINT Research Assistant

A Chrome extension that grades indicators of compromise in the page you are
already reading. No account, no API key, no backend — everything runs on your
machine.

Select an IP, domain, URL, email or file hash and press `Ctrl+Shift+O`, or
triage a whole threat report with `Ctrl+Shift+U`.

---

## What it does

**Page triage.** One keystroke grades every indicator on a page and ranks them
worst-first. A 200-indicator report costs the same as a single lookup — zero
API requests — because matching happens against a locally held threat index.
See [ADR-001](docs/ADR-001-local-threat-index.md) for why.

**Pivot graph.** Walk the infrastructure: IP → announcing AS → that AS's other
prefixes → peer networks; domain → resolving addresses → name servers →
subdomains from certificate transparency. Nodes already in a threat feed are
red, so a bad neighbourhood is visible rather than inferred.

**Defanged input.** `185.220.101[.]45`, `hxxps://evil[.]com` and
`user[at]mail[.]com` are understood. Threat intelligence is never shared in
clickable form, so a tool that only accepts live indicators is unusable on the
documents analysts actually read.

**Case file.** Collect findings across pages and export as **STIX 2.1**,
**MISP event**, CSV or Markdown — formats a pipeline can ingest, not just a
human.

---

## Sources

All keyless. Probed on a schedule by CI; see `test/sources.js`.

| Source | Answers |
|---|---|
| ThreatFox, URLhaus, Feodo, OpenPhish | Is it in a current threat feed? Which malware family? |
| AlienVault OTX | Which campaign? Which MITRE ATT&CK techniques? |
| Team Cymru MHR | Is this hash known malware? What is the AV detection rate? |
| CIRCL hashlookup | Is this hash a known *legitimate* file? (NSRL) |
| Shodan InternetDB + CVE-Search | Open ports, CVEs enriched with CVSS and CISA KEV status |
| GreyNoise | Internet-wide scanner classification |
| Tor exit list | Is this a Tor exit node? |
| RIPEstat | Which AS announces this address; how large is that network |
| RDAP, crt.sh, Google DNS, URLScan.io | Registration, certificates, records, scan history |
| mailcheck.ai | Disposable address, spam and MX checks |

**Optional keys** (VirusTotal, Shodan) add depth. Nothing degrades without
them; those tabs simply do not appear. Keys are stored in `storage.local` and
never synced.

---

## Licensing of the data sources

The extension is a client. It does not redistribute anyone's data — each lookup
goes from your browser to the provider. But four providers restrict their free
tier to **non-commercial use**, quoted from their own terms:

| Source | Their wording |
|---|---|
| **ip-api.com** | *"The use of the API is strictly limited for a non-commercial purpose and in a non-commercial environment."* A Pro subscription is required in a commercial environment. |
| **OpenPhish** (inside Threat Feeds) | *"The Services are provided solely for your personal use. You agree not to use any part of the Services for any commercial purposes without the prior written consent of OpenPhish."* |
| **Team Cymru MHR** | *"MHR is free for non-commercial use."* |
| **RIPEstat** | Commercial use is not permitted, and *"combining the RIPEstat Data with other sources of data and packaging it as commercial product is not allowed"* without written permission. |

**Using the extension inside a company — including by a security team — is a
commercial environment.** ip-api's own documentation lists "fraud prevention
for online orders" as forbidden commercial usage, which is squarely the work a
SOC analyst does.

These four are labelled **non-commercial** in Settings and can be switched off
individually. With them off the extension still works: ThreatFox, URLhaus and
Feodo (feeds), OTX, Shodan InternetDB, GreyNoise, Tor exit list, RDAP, crt.sh,
Google DNS, URLScan.io, CIRCL and mailcheck.ai remain.

This is a summary written from the providers' terms pages, not legal advice.
Check the terms yourself before deploying this anywhere that matters.

## Known limits

Stated deliberately — a tool that hides its blind spots is worse than one that
names them.

- **Absence is not innocence.** The threat index holds a few thousand *current*
  indicators. A miss returns `unknown`, never `clean`, and the UI says so.
- **Team Cymru MHR covers MD5 and SHA-1 only.** SHA-256 hashes get no malware
  verdict from it, and the summary says that rather than implying safety.
- **CIRCL hashlookup is a known-*good* database (NSRL).** It answers "is this a
  legitimate file", not "is this malware". Both are shown, labelled separately.
- **crt.sh is intermittently unavailable**, returning `404` under load. One
  retry is attempted; a genuine empty result is `200` with `[]`.
- **Free sources decay.** Three went behind authentication during development.
  Source health is tracked per provider and shown in Settings.

---

## Development

```bash
cd test
npm install
node unit.js       # 40 tests — refang, IOC typing, scan patterns
node harness.js    # 81 tests — panel, triage, graph, exports (jsdom)
node sources.js    # probe every keyless source
```

CI runs both suites plus a manifest check on every push. The source probe runs
as a separate, non-blocking job: a third party having a bad day should not fail
a merge.

**Load locally:** `chrome://extensions` → Developer mode → *Load unpacked* →
select this folder.

---

## Design notes

- **Manifest V3**, no `<all_urls>`. Host permissions are limited to the API
  hosts actually called; page access comes from `activeTab`, granted by the
  user's own gesture.
- **Shadow DOM** for every injected surface, so page CSS cannot reach the panel
  and the panel cannot leak into the page.
- **`chrome.storage.session`** for the response cache — an MV3 service worker
  is killed after ~30 s idle, so an in-memory `Map` would be perpetually cold.
- **No dependencies.** The force-directed graph is ~120 lines of canvas and
  arithmetic.

For authorized security research only.
