# ADR-001: Match threat feeds locally instead of querying per indicator

**Status:** Accepted · **Date:** 2026-08-04

## Context

The extension grades indicators of compromise — IPs, domains, URLs, emails and
file hashes — using only sources that need no account and no API key.

The workload that broke the original design is **page triage**: an analyst
opens a threat-intelligence report containing 40–200 indicators and wants all
of them graded at once. The per-indicator design could not serve that:

- `ip-api.com` allows **45 requests per 45 seconds** (measured from its
  `X-Rl` / `X-Ttl` response headers). A 60-indicator page exhausts the budget
  before the first screen is graded.
- `crt.sh` answered in **20.4 s** in one measurement and intermittently returns
  `404` under load. It cannot sit on a hot path.
- Fan-out is multiplicative: 60 indicators × 8 relevant services = 480 requests
  for one page.

A second, harder constraint emerged during development: **free sources decay.**
Three sources went behind authentication or became unusable mid-project:

| Source | Was | Became |
|---|---|---|
| abuse.ch API (ThreatFox, URLhaus, MalwareBazaar) | keyless JSON API | `401`, requires an account key |
| emailrep.io | keyless reputation API | `401`, "unauthenticated API is currently disabled" |
| Spamhaus ZEN over public DNS | DNSBL lookup | blocked for open resolvers; even the `127.0.0.2` test address returns nothing |

Any design that assumes a stable set of live endpoints is wrong on a long
enough timescale.

## Decision

**Download the bulk feeds once, build a compact index, and match indicators
locally.** Reserve per-indicator network calls for the deep-dive view.

The index is built from four sources whose *download* endpoints remain open
even where their APIs do not:

| Feed | Contributes |
|---|---|
| ThreatFox | IPs, domains, URLs, hashes — with **malware family attribution** |
| URLhaus hostfile | hosts currently serving malware |
| Feodo Tracker | botnet command-and-control servers |
| OpenPhish | active phishing hosts |

Measured: **1.6 s to build, ~206 KB stored, 3 971 unique indicators.**
Stored in `chrome.storage.local` with a 6-hour TTL; a stale index is served
immediately while a refresh runs in the background.

Triage then uses only sources that cost nothing per item:

- the local index, for everything;
- DNS, for hash reputation (Team Cymru MHR) — effectively unmetered;
- a cached Tor exit-node list, matched in memory.

**Result: a 200-indicator page costs the same as a single indicator — zero
API requests.**

## Alternatives considered

**Query each indicator against each live API.**
Rejected: mathematically cannot work inside `ip-api`'s 45/45 s budget, and puts
`crt.sh`'s 20 s p50 on the critical path.

**Run a backend that pre-aggregates feeds.**
Rejected. It solves the rate limit but costs the property that makes this tool
defensible: nothing leaves the user's machine, there is no account, and there
is no service to keep alive. It would also make the extension a data-processor
for indicators an analyst may not be permitted to share.

**Cache per-indicator responses only.**
Rejected as insufficient. Caching helps repeat lookups; page triage is
dominated by *first* lookups, so the cache is cold exactly when it matters.

**Ship the index inside the extension package.**
Rejected: threat feeds go stale in hours, and the store review cycle is days.

## Consequences

**Good**

- Page triage is bounded by CPU, not by anyone's rate limit.
- Coverage improved qualitatively, not just quantitatively: ThreatFox supplies
  the malware family name, which no other keyless source here provides.
- The extension degrades gracefully — with a stale index it still answers.

**Bad / accepted**

- The index holds a few thousand *current* indicators, not the whole history of
  badness. **Absence from the index is not evidence of safety**, and the UI must
  say so. This is enforced in code: `feeds` returns `unknown`, never `clean`,
  when there is no hit, so a miss can never pull the overall verdict towards
  clean.
- ~206 KB of `storage.local` per profile.
- A feed changing schema breaks enrichment silently. Mitigated by ADR-002
  (source health) and a scheduled CI probe of every source.

## Validation

- Cobalt Strike C2 addresses from the live feed are matched correctly;
  `8.8.8.8`, `google.com` and `example.com` produce no false positives.
- 121 automated tests (40 unit, 81 integration) cover refang, IOC typing,
  scan-mode patterns, triage, and STIX/MISP export shape.
- A scheduled CI job probes all 18 keyless sources and reports failures without
  failing the build — upstream decay is expected, not exceptional.

## Follow-up

The CI source probe immediately paid for itself: it caught `cve.circl.lu`
returning `429` because CVE enrichment fired 8 parallel requests per lookup.
Fixed by bounding concurrency to 2 and caching CVE records for 24 h, since a
published CVE record is effectively static.
