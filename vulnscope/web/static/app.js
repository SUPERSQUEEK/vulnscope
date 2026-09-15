const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const el = (sel) => document.querySelector(sel);
const main = el("#main");
const historyEl = el("#history");

let currentScanId = null;
let currentReport = null;
let activeFilters = new Set(SEVERITIES);
let checkerFilter = "";
let searchText = "";
let currentSource = null;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function timeAgo(iso) {
  if (!iso) return "";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// ---------- history sidebar ----------

async function loadHistory() {
  try {
    const res = await fetch("/api/scans");
    const scans = await res.json();
    renderHistory(scans);
  } catch (e) {
    historyEl.innerHTML = `<p class="history-empty">Could not load history.</p>`;
  }
}

function renderHistory(scans) {
  if (!scans.length) {
    historyEl.innerHTML = `<p class="history-empty">No scans yet.</p>`;
    return;
  }
  historyEl.innerHTML = scans.map((s) => {
    const active = s.id === currentScanId ? "active" : "";
    const badge = s.status === "running" ? `<span class="badge running">running</span>`
      : s.status === "error" ? `<span class="badge error">error</span>`
      : `<span class="badge ${s.worst}">${s.worst}</span>`;
    return `<div class="history-item ${active}" data-id="${s.id}">
      <div class="targets">${escapeHtml(s.targets.join(", "))}</div>
      <div class="meta"><span>${timeAgo(s.created_at)}</span>${badge}</div>
    </div>`;
  }).join("");
  historyEl.querySelectorAll(".history-item").forEach((node) => {
    node.addEventListener("click", () => openScan(node.dataset.id));
  });
}

// ---------- starting a scan ----------

el("#scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = el("#scan-submit");
  const errEl = el("#form-error");
  errEl.style.display = "none";

  const targets = el("#targets").value.split("\n").map((t) => t.trim()).filter(Boolean);
  const scope = el("#scope").value;
  const authorized_by = el("#authorized-by").value.trim();
  const timeout = parseFloat(el("#timeout").value) || 6.0;
  const ingest = el("#ingest").value.trim() || null;

  btn.disabled = true;
  btn.textContent = "Starting...";
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets, scope, authorized_by, timeout, ingest }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "failed to start scan");
    await loadHistory();
    openScan(data.id);
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "Start scan";
  }
});

// ---------- viewing a scan ----------

async function openScan(id) {
  currentScanId = id;
  if (currentSource) { currentSource.close(); currentSource = null; }
  document.querySelectorAll(".history-item").forEach((n) => {
    n.classList.toggle("active", n.dataset.id === id);
  });

  const res = await fetch(`/api/scan/${id}`);
  if (!res.ok) { renderMissing(); return; }
  const status = await res.json();

  if (status.status === "running") {
    renderRunning(status);
    watchEvents(id);
  } else if (status.status === "error") {
    renderError(status);
  } else {
    await loadReport(id);
  }
}

function renderMissing() {
  main.innerHTML = `<div class="empty-state"><h2>Scan not found</h2></div>`;
}

function renderError(status) {
  main.innerHTML = `
    <div class="run-header">
      <p class="meta targets">${escapeHtml((status.targets || []).join(", "))}</p>
      <p class="meta">authorized by: ${escapeHtml(status.authorized_by || "")}</p>
    </div>
    <div class="log"><span class="badge error">error</span> ${escapeHtml(status.error || "scan failed")}</div>`;
}

function renderRunning(status) {
  main.innerHTML = `
    <div class="run-header">
      <p class="meta targets">${escapeHtml((status.targets || []).join(", "))}</p>
      <p class="meta">authorized by: ${escapeHtml(status.authorized_by || "")}</p>
      <p class="meta"><span class="spinner"></span>scanning...</p>
    </div>
    <div class="log" id="log"></div>`;
}

function watchEvents(id) {
  const logEl = el("#log");
  const source = new EventSource(`/api/scan/${id}/events`);
  currentSource = source;
  source.onmessage = (ev) => {
    if (!logEl) return;
    const line = document.createElement("div");
    line.className = "line";
    line.textContent = JSON.parse(ev.data);
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  };
  source.addEventListener("done", async (ev) => {
    source.close();
    currentSource = null;
    const summary = JSON.parse(ev.data);
    await loadHistory();
    if (summary.status === "error") {
      renderError(summary);
    } else {
      await loadReport(id);
    }
  });
  source.onerror = () => {
    // connection drop mid-scan; the scan itself keeps running server-side,
    // reopening the page and clicking history will pick it back up.
    source.close();
    currentSource = null;
  };
}

async function loadReport(id) {
  const res = await fetch(`/api/scan/${id}/report`);
  if (!res.ok) { renderMissing(); return; }
  currentReport = await res.json();
  activeFilters = new Set(SEVERITIES);
  checkerFilter = "";
  searchText = "";
  renderReport(id, currentReport);
}

function renderReport(id, report) {
  const c = report.counts;
  const checkers = [...new Set(report.findings.map((f) => f.check))].sort();

  main.innerHTML = `
    <div class="run-header">
      <p class="meta targets">${escapeHtml(report.targets.join(", "))}</p>
      <p class="meta">authorized by: ${escapeHtml(report.authorized_by || "(unnamed)")} &middot; scope: ${escapeHtml(report.scope_summary)}</p>
      <p class="meta">${escapeHtml(report.started_at)}</p>
    </div>

    <div class="summary">
      <div class="chips" id="chips">
        ${SEVERITIES.map((s) => `<span class="chip" data-sev="${s}">${s}<b>${c[s] ?? 0}</b></span>`).join("")}
      </div>
      <div class="actions">
        <a href="/api/scan/${id}/report" download="vulnscope-${id}.json"><button class="small">Download JSON</button></a>
        <a href="/api/scan/${id}/report.html" download="vulnscope-${id}.html"><button class="small">Download HTML</button></a>
      </div>
    </div>

    <div class="toolbar">
      <input type="text" id="search" placeholder="Search findings...">
      <select id="checker-filter">
        <option value="">All checkers</option>
        ${checkers.map((ch) => `<option value="${ch}">${ch}</option>`).join("")}
      </select>
      <div class="spacer"></div>
    </div>

    <div class="findings" id="findings"></div>
    ${report.errors && report.errors.length ? `
      <div class="errors">
        <div class="section-title">Refusals &amp; errors</div>
        <ul>${report.errors.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>
      </div>` : ""}
  `;

  el("#chips").querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const sev = chip.dataset.sev;
      if (activeFilters.has(sev)) activeFilters.delete(sev); else activeFilters.add(sev);
      renderFindings();
    });
  });
  el("#search").addEventListener("input", (e) => { searchText = e.target.value.toLowerCase(); renderFindings(); });
  el("#checker-filter").addEventListener("change", (e) => { checkerFilter = e.target.value; renderFindings(); });

  renderFindings();
}

function renderFindings() {
  const container = el("#findings");
  if (!container || !currentReport) return;

  el("#chips")?.querySelectorAll(".chip").forEach((chip) => {
    chip.classList.toggle("off", !activeFilters.has(chip.dataset.sev));
  });

  const findings = currentReport.findings.filter((f) => {
    if (!activeFilters.has(f.severity)) return false;
    if (checkerFilter && f.check !== checkerFilter) return false;
    if (searchText) {
      const hay = `${f.title} ${f.detail} ${f.target} ${f.check}`.toLowerCase();
      if (!hay.includes(searchText)) return false;
    }
    return true;
  });

  if (!findings.length) {
    container.innerHTML = `<div class="no-results">No findings match the current filters.</div>`;
    return;
  }

  container.innerHTML = findings.map((f, i) => {
    const loc = f.port ? `${f.target}:${f.port}` : f.target;
    const extra = [];
    if (f.evidence) extra.push(`<p class="ev">evidence: ${escapeHtml(f.evidence)}</p>`);
    if (f.remediation) extra.push(`<p class="fix">fix: ${escapeHtml(f.remediation)}</p>`);
    if (f.reference) extra.push(`<p><a href="${escapeHtml(f.reference)}" target="_blank" rel="noopener">${escapeHtml(f.reference)}</a></p>`);
    return `<div class="finding ${f.severity}" data-idx="${i}">
      <h3><span class="badge ${f.severity}">${f.severity}</span> ${escapeHtml(f.title)} <span class="loc">${escapeHtml(loc)} &middot; ${escapeHtml(f.check)}</span></h3>
      <p class="detail">${escapeHtml(f.detail)}</p>
      <div class="extra">${extra.join("")}</div>
    </div>`;
  }).join("");

  container.querySelectorAll(".finding").forEach((node) => {
    node.addEventListener("click", () => node.classList.toggle("expanded"));
  });
}

loadHistory();
