const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 4173;

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

// ---- tiny in-memory cache -------------------------------------------------
const cache = new Map();
async function cached(key, ttlMs, fn) {
  const hit = cache.get(key);
  const now = Date.now();
  if (hit && now - hit.time < ttlMs) return hit.data;
  const data = await fn();
  cache.set(key, { time: now, data });
  return data;
}

// ---- tiny RSS parser (no deps) --------------------------------------------
function parseRss(xml, limit = 10) {
  const items = [];
  const itemBlocks = xml.match(/<item\b[\s\S]*?<\/item>/gi) || [];
  for (const block of itemBlocks.slice(0, limit)) {
    const pick = (tag) => {
      const m = block.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"));
      if (!m) return "";
      return m[1]
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#13;/g, "")
        .replace(/&#039;|&apos;/g, "'")
        .replace(/<[^>]+>/g, "")
        .trim();
    };
    items.push({
      title: pick("title"),
      link: pick("link"),
      pubDate: pick("pubDate") || pick("dc:date"),
      description: pick("description").slice(0, 240),
    });
  }
  return items;
}

async function fetchText(url, extraHeaders = {}) {
  const res = await fetch(url, { headers: { "User-Agent": UA, ...extraHeaders } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.text();
}
async function fetchJson(url, extraHeaders = {}) {
  const res = await fetch(url, { headers: { "User-Agent": UA, ...extraHeaders } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

// ---- geolocation helper (ip-api.com batch, free tier) ---------------------
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
async function geolocateIps(ips) {
  const unique = [...new Set(ips)].filter((ip) => IPV4_RE.test(ip)).slice(0, 100);
  if (unique.length === 0) return {};
  const res = await fetch("http://ip-api.com/batch?fields=status,country,countryCode,city,query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(unique.map((query) => ({ query }))),
  });
  if (!res.ok) return {};
  const rows = await res.json();
  const map = {};
  for (const r of rows) {
    if (r.status === "success") {
      map[r.query] = { country: r.country, countryCode: r.countryCode, city: r.city };
    }
  }
  return map;
}

function extractIpFromUrl(url) {
  try {
    const host = new URL(url).hostname;
    return IPV4_RE.test(host) ? host : null;
  } catch {
    return null;
  }
}

// ---- routes ----------------------------------------------------------------

// CISA Known Exploited Vulnerabilities catalog (US authoritative source, no key)
app.get("/api/kev", async (req, res) => {
  try {
    const data = await cached("kev", 10 * 60 * 1000, async () => {
      const json = await fetchJson(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
      );
      const items = [...json.vulnerabilities]
        .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
        .slice(0, 25);
      return { catalogVersion: json.catalogVersion, count: json.vulnerabilities.length, items };
    });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Recent critical/high CVEs, last 7 days (NVD, no key required for low volume)
app.get("/api/cves", async (req, res) => {
  try {
    const data = await cached("cves", 15 * 60 * 1000, async () => {
      const end = new Date();
      const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
      const iso = (d) => d.toISOString().replace(/Z$/, "");
      const url =
        `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${iso(start)}&pubEndDate=${iso(end)}` +
        `&resultsPerPage=20`;
      const json = await fetchJson(url);
      const items = (json.vulnerabilities || []).map((v) => {
        const cve = v.cve;
        const metric =
          cve.metrics?.cvssMetricV31?.[0] ||
          cve.metrics?.cvssMetricV30?.[0] ||
          cve.metrics?.cvssMetricV2?.[0];
        return {
          id: cve.id,
          published: cve.published,
          description: (cve.descriptions?.find((d) => d.lang === "en") || {}).value || "",
          severity: metric?.cvssData?.baseSeverity || metric?.baseSeverity || "UNKNOWN",
          score: metric?.cvssData?.baseScore ?? null,
        };
      });
      items.sort((a, b) => (b.score || 0) - (a.score || 0));
      return { totalResults: json.totalResults, items };
    });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Live malicious URL / IOC feed, merged from URLhaus + ThreatFox (abuse.ch, no key)
// geolocated so RO/US-hosted infrastructure can be highlighted.
app.get("/api/iocs", async (req, res) => {
  try {
    const data = await cached("iocs", 5 * 60 * 1000, async () => {
      const [urlhausJson, threatfoxJson] = await Promise.all([
        fetchJson("https://urlhaus.abuse.ch/downloads/json_recent/"),
        fetchJson("https://threatfox.abuse.ch/export/json/recent/"),
      ]);

      // abuse.ch export objects use numeric-string keys, which JS engines auto-order
      // ascending regardless of insertion order — so Object.values() yields oldest-first.
      // Sort by actual timestamp before slicing, or "recent" ends up meaning "oldest in the batch".
      const urlhausItems = Object.values(urlhausJson)
        .flat()
        .map((e) => ({
          source: "URLhaus",
          value: e.url,
          type: "url",
          threat: e.threat,
          tags: e.tags || [],
          seen: e.dateadded,
          ip: extractIpFromUrl(e.url),
        }))
        .sort((a, b) => new Date(b.seen) - new Date(a.seen))
        .slice(0, 60);

      const threatfoxItems = Object.values(threatfoxJson)
        .flat()
        .map((e) => {
          let ip = null;
          if (e.ioc_type === "ip:port") ip = String(e.ioc_value).split(":")[0];
          else if (e.ioc_type === "ip") ip = e.ioc_value;
          return {
            source: "ThreatFox",
            value: e.ioc_value,
            type: e.ioc_type,
            threat: e.malware_printable || e.threat_type,
            tags: e.tags || [],
            seen: e.first_seen_utc,
            ip,
          };
        })
        .sort((a, b) => new Date(b.seen) - new Date(a.seen))
        .slice(0, 60);

      const merged = [...urlhausItems, ...threatfoxItems].sort(
        (a, b) => new Date(b.seen) - new Date(a.seen)
      );

      const geo = await geolocateIps(merged.map((m) => m.ip).filter(Boolean));
      for (const m of merged) {
        if (m.ip && geo[m.ip]) {
          m.country = geo[m.ip].country;
          m.countryCode = geo[m.ip].countryCode;
          m.city = geo[m.ip].city;
        }
      }
      return { items: merged.slice(0, 80) };
    });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Regional advisories: CISA (US) + DNSC (Romania) RSS feeds
app.get("/api/advisories/:region", async (req, res) => {
  const region = req.params.region;
  const feeds = {
    us: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ro: "https://www.dnsc.ro/feed",
  };
  const url = feeds[region];
  if (!url) return res.status(404).json({ error: "unknown region" });
  try {
    const data = await cached(`adv-${region}`, 15 * 60 * 1000, async () => {
      const xml = await fetchText(url);
      return { items: parseRss(xml, 10) };
    });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Ad-hoc IP lookup tool for analysts (Shodan InternetDB, no key)
app.get("/api/lookup/:ip", async (req, res) => {
  const ip = req.params.ip;
  if (!IPV4_RE.test(ip)) return res.status(400).json({ error: "invalid IPv4 address" });
  try {
    const [idb, geo] = await Promise.all([
      fetch(`https://internetdb.shodan.io/${ip}`).then((r) => (r.ok ? r.json() : null)),
      geolocateIps([ip]),
    ]);
    res.json({ ip, internetdb: idb, geo: geo[ip] || null });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

app.use(express.static(path.join(__dirname, "public")));
app.listen(PORT, () => console.log(`SOC threat-intel dashboard on http://localhost:${PORT}`));
