// Pulls all threat-intel feeds server-side (this runs in a GitHub Actions runner,
// not a browser, so CORS / WAF-vs-browser-UA issues that block a static Pages site
// don't apply here) and writes static JSON snapshots into docs/data/ for the
// GitHub Pages frontend to fetch directly.
import { writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "..", "docs", "data");

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

async function fetchJson(url, extraHeaders = {}) {
  const res = await fetch(url, { headers: { "User-Agent": UA, ...extraHeaders } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}
async function fetchText(url, extraHeaders = {}) {
  const res = await fetch(url, { headers: { "User-Agent": UA, ...extraHeaders } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.text();
}

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

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
function extractIpFromUrl(url) {
  try {
    const host = new URL(url).hostname;
    return IPV4_RE.test(host) ? host : null;
  } catch {
    return null;
  }
}
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
    if (r.status === "success") map[r.query] = { country: r.country, countryCode: r.countryCode, city: r.city };
  }
  return map;
}

async function fetchKev() {
  const json = await fetchJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const items = [...json.vulnerabilities].sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded)).slice(0, 25);
  return { catalogVersion: json.catalogVersion, count: json.vulnerabilities.length, items };
}

async function fetchCves() {
  const end = new Date();
  const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
  const iso = (d) => d.toISOString().replace(/Z$/, "");
  const url =
    `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${iso(start)}&pubEndDate=${iso(end)}` +
    `&resultsPerPage=20`;
  const json = await fetchJson(url);
  const items = (json.vulnerabilities || []).map((v) => {
    const cve = v.cve;
    const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
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
}

async function fetchIocs() {
  const [urlhausJson, threatfoxJson] = await Promise.all([
    fetchJson("https://urlhaus.abuse.ch/downloads/json_recent/"),
    fetchJson("https://threatfox.abuse.ch/export/json/recent/"),
  ]);

  // abuse.ch export objects use numeric-string keys, which JS engines auto-order
  // ascending regardless of insertion order — sort by real timestamp before slicing.
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

  const merged = [...urlhausItems, ...threatfoxItems].sort((a, b) => new Date(b.seen) - new Date(a.seen));
  const geo = await geolocateIps(merged.map((m) => m.ip).filter(Boolean));
  for (const m of merged) {
    if (m.ip && geo[m.ip]) {
      m.country = geo[m.ip].country;
      m.countryCode = geo[m.ip].countryCode;
      m.city = geo[m.ip].city;
    }
  }
  return { items: merged.slice(0, 80) };
}

async function fetchAdvisories() {
  const [usXml, roXml] = await Promise.all([
    fetchText("https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    fetchText("https://www.dnsc.ro/feed"),
  ]);
  return { us: { items: parseRss(usXml, 10) }, ro: { items: parseRss(roXml, 10) } };
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const jobs = [
    ["kev.json", fetchKev],
    ["cves.json", fetchCves],
    ["iocs.json", fetchIocs],
    ["advisories.json", fetchAdvisories],
  ];

  const results = {};
  for (const [file, fn] of jobs) {
    try {
      results[file] = await fn();
      console.log(`ok: ${file}`);
    } catch (e) {
      console.error(`FAILED: ${file}: ${e.message}`);
      results[file] = { error: e.message };
    }
  }

  for (const [file, data] of Object.entries(results)) {
    await writeFile(path.join(OUT_DIR, file), JSON.stringify(data, null, 2));
  }

  await writeFile(
    path.join(OUT_DIR, "meta.json"),
    JSON.stringify({ generatedAt: new Date().toISOString() }, null, 2)
  );

  console.log("Done.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
