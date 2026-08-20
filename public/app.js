const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

function timeAgo(dateStr) {
  if (!dateStr) return "";
  const d = new Date(dateStr.replace(" UTC", "Z").replace(" ", "T"));
  if (isNaN(d)) return dateStr;
  const diffMin = Math.round((Date.now() - d.getTime()) / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffMin < 1440) return `${Math.round(diffMin / 60)}h ago`;
  return `${Math.round(diffMin / 1440)}d ago`;
}

function severityBadge(sev) {
  const s = (sev || "").toUpperCase();
  const cls = s === "CRITICAL" ? "crit" : s === "HIGH" ? "high" : s === "MEDIUM" ? "med" : "low";
  return `<span class="badge ${cls}">${esc(s || "n/a")}</span>`;
}

function countryBadge(code, country) {
  if (!code) return `<span class="badge other">unresolved</span>`;
  if (code === "US") return `<span class="badge us">🇺🇸 US${country ? " · " + esc(country) : ""}</span>`;
  if (code === "RO") return `<span class="badge ro">🇷🇴 RO</span>`;
  return `<span class="badge other">${esc(code)}</span>`;
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

// ---- Advisories -------------------------------------------------------
function renderAdvisories(el, items, err) {
  if (err) { el.innerHTML = `<div class="err">Feed unavailable: ${esc(err)}</div>`; return; }
  if (!items || items.length === 0) { el.innerHTML = `<div class="empty">No items.</div>`; return; }
  el.innerHTML = items.map((it) => `
    <div class="row">
      <div class="row-title">
        <a href="${esc(it.link)}" target="_blank" rel="noopener">${esc(it.title)}</a>
        <div class="row-meta">${esc(it.pubDate || "")}</div>
      </div>
    </div>`).join("");
}

// ---- KEV ----------------------------------------------------------------
function renderKev(el, items, err) {
  if (err) { el.innerHTML = `<div class="err">Feed unavailable: ${esc(err)}</div>`; return; }
  if (!items || items.length === 0) { el.innerHTML = `<div class="empty">No items.</div>`; return; }
  el.innerHTML = `<table>
    <thead><tr><th>CVE</th><th>Vendor / Product</th><th>Vulnerability</th><th>Added</th><th>Due</th><th></th></tr></thead>
    <tbody>${items.map((v) => `
      <tr>
        <td><code>${esc(v.cveID)}</code></td>
        <td>${esc(v.vendorProject)} / ${esc(v.product)}</td>
        <td>${esc(v.vulnerabilityName)}</td>
        <td>${esc(v.dateAdded)}</td>
        <td>${esc(v.dueDate)}</td>
        <td>${v.knownRansomwareCampaignUse === "Known" ? '<span class="badge ransom">Ransomware</span>' : ""}</td>
      </tr>`).join("")}</tbody></table>`;
}

// ---- CVEs -----------------------------------------------------------------
function renderCves(el, items, err) {
  if (err) { el.innerHTML = `<div class="err">Feed unavailable: ${esc(err)}</div>`; return; }
  if (!items || items.length === 0) { el.innerHTML = `<div class="empty">No items.</div>`; return; }
  el.innerHTML = `<table>
    <thead><tr><th>CVE</th><th>Severity</th><th>Score</th><th>Published</th><th>Description</th></tr></thead>
    <tbody>${items.map((c) => `
      <tr>
        <td><code>${esc(c.id)}</code></td>
        <td>${severityBadge(c.severity)}</td>
        <td>${c.score ?? "–"}</td>
        <td>${esc((c.published || "").slice(0, 10))}</td>
        <td>${esc((c.description || "").slice(0, 160))}${(c.description || "").length > 160 ? "…" : ""}</td>
      </tr>`).join("")}</tbody></table>`;
}

// ---- IOCs -------------------------------------------------------------
let iocCache = [];
let iocFilterMode = "all";

function renderIocs() {
  const el = $("#iocTable");
  let items = iocCache;
  if (iocFilterMode === "us") items = items.filter((i) => i.countryCode === "US");
  if (iocFilterMode === "ro") items = items.filter((i) => i.countryCode === "RO");
  if (items.length === 0) { el.innerHTML = `<div class="empty">No IOCs match this filter.</div>`; return; }
  el.innerHTML = `<table>
    <thead><tr><th>Source</th><th>Indicator</th><th>Threat</th><th>Location</th><th>Seen</th></tr></thead>
    <tbody>${items.map((i) => `
      <tr>
        <td>${esc(i.source)}</td>
        <td><code>${esc(String(i.value).slice(0, 60))}</code></td>
        <td>${esc(i.threat || "")}</td>
        <td>${countryBadge(i.countryCode, i.country)}</td>
        <td>${timeAgo(i.seen)}</td>
      </tr>`).join("")}</tbody></table>`;
}

$("#iocFilter").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-f]");
  if (!btn) return;
  iocFilterMode = btn.dataset.f;
  document.querySelectorAll("#iocFilter button").forEach((b) => b.classList.toggle("active", b === btn));
  renderIocs();
});

// ---- Lookup tool --------------------------------------------------------
$("#lookupBtn").addEventListener("click", doLookup);
$("#lookupInput").addEventListener("keydown", (e) => { if (e.key === "Enter") doLookup(); });

async function doLookup() {
  const ip = $("#lookupInput").value.trim();
  const out = $("#lookupResult");
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) { out.textContent = "Enter a valid IPv4 address."; return; }
  out.textContent = "Looking up…";
  try {
    const data = await getJson(`/api/lookup/${encodeURIComponent(ip)}`);
    const geo = data.geo ? `${data.geo.country} (${data.geo.countryCode}) · ${data.geo.city || "?"}` : "unknown";
    const idb = data.internetdb;
    const ports = idb?.ports?.length ? idb.ports.join(", ") : "none observed";
    const vulns = idb?.vulns?.length ? idb.vulns.join(", ") : "none known";
    const hostnames = idb?.hostnames?.length ? idb.hostnames.join(", ") : "none";
    out.innerHTML = `<strong>${esc(ip)}</strong>  ·  ${esc(geo)}\nOpen ports: ${esc(ports)}\nKnown vulns: ${esc(vulns)}\nHostnames: ${esc(hostnames)}`;
  } catch (e) {
    out.textContent = `Lookup failed: ${e.message}`;
  }
}

// ---- Orchestration --------------------------------------------------------
async function loadAll() {
  $("#liveDot").style.background = "#f5b942";
  const results = await Promise.allSettled([
    getJson("/api/advisories/us"),
    getJson("/api/advisories/ro"),
    getJson("/api/kev"),
    getJson("/api/cves"),
    getJson("/api/iocs"),
  ]);

  const [advUs, advRo, kev, cves, iocs] = results;

  renderAdvisories($("#advUs"), advUs.value?.items, advUs.status === "rejected" ? advUs.reason.message : null);
  renderAdvisories($("#advRo"), advRo.value?.items, advRo.status === "rejected" ? advRo.reason.message : null);
  renderKev($("#kevTable"), kev.value?.items, kev.status === "rejected" ? kev.reason.message : null);
  renderCves($("#cveTable"), cves.value?.items, cves.status === "rejected" ? cves.reason.message : null);

  if (iocs.status === "fulfilled") {
    iocCache = iocs.value.items || [];
    renderIocs();
  } else {
    $("#iocTable").innerHTML = `<div class="err">Feed unavailable: ${esc(iocs.reason.message)}</div>`;
  }

  $("#statKev").textContent = kev.value?.count ?? "–";
  $("#statCve").textContent = cves.value?.items?.length ?? "–";
  $("#statIoc").textContent = iocCache.length || "–";
  $("#statRegional").textContent = iocCache.filter((i) => i.countryCode === "US" || i.countryCode === "RO").length;

  $("#lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  $("#liveDot").style.background = "#33d17a";
}

$("#refreshBtn").addEventListener("click", loadAll);
loadAll();
setInterval(loadAll, 5 * 60 * 1000);
