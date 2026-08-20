# SOC Threat Intel — RO / US

Demo SOC threat-intelligence dashboard built entirely on free, unauthenticated public
feeds, with a regional focus on Romania and the United States.

**Live demo:** https://mihaicata.github.io/intel/

## Sources

- [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD](https://nvd.nist.gov/) — recent critical/high CVEs
- [URLhaus](https://urlhaus.abuse.ch/) and [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) — live IOC feed, geolocated
- [CISA Cybersecurity Advisories](https://www.cisa.gov/cybersecurity-advisories) (US)
- [DNSC](https://dnsc.ro/) — Romania's national cyber security directorate (RO)
- [Shodan InternetDB](https://internetdb.shodan.io/) + [ipwho.is](https://ipwho.is/) — live analyst IP lookup tool

## Architecture

GitHub Pages only serves static files, and several of the source feeds above don't send
CORS headers (or, in DNSC's case, block non-browser requests entirely) — so this isn't a
single-page app hitting those APIs directly. Instead:

- [`scripts/fetch-data.mjs`](scripts/fetch-data.mjs) fetches everything server-side and
  writes JSON snapshots into `docs/data/`.
- [`.github/workflows/refresh-data.yml`](.github/workflows/refresh-data.yml) runs that
  script on a schedule (every 30 min), commits any changed snapshots, and redeploys
  GitHub Pages from `docs/`.
- [`docs/app.js`](docs/app.js) is a static frontend that reads those JSON snapshots. The
  one exception is the IP lookup tool, which calls Shodan InternetDB and ipwho.is
  directly from the browser — both of those do send CORS headers.

### Running locally

```bash
npm install
npm start
```

Serves a live version (Express backend, real-time proxying, no snapshot staleness) at
`http://localhost:4173`. Useful for local development; not what's deployed to Pages.

To regenerate the static snapshots by hand:

```bash
node scripts/fetch-data.mjs
```

## Not for production

No auth, no rate-limit backoff/retry, no audit logging. The free-tier APIs used here
(especially NVD without a key, and ip-api.com) will throttle under real load.
