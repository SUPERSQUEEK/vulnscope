const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ICONS = {
  rerun: '<svg class="icon" viewBox="0 0 24 24"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>',
  trash: '<svg class="icon" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>',
  copy: '<svg class="icon" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  chevron: '<svg class="icon chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>',
};

const el = (sel) => document.querySelector(sel);
const main = el("#main");
const historyEl = el("#history");
const statsEl = el("#stats-row");
const modalOverlay = el("#modal-overlay");

let currentScanId = null;
let currentReport = null;
let activeFilters = new Set(SEVERITIES);
let checkerFilter = "";
let targetFilter = "";
let searchText = "";
let groupByTarget = false;
let currentSource = null;
let timerInterval = null;
let scanStartedAt = null;
let historyCache = [];

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function timeAgo(iso) {
  if (!iso) return "";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function fmtElapsed(seconds) {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${String(s).padStart(2, "0")}`;
}

function showToast(msg) {
  const t = el("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => t.classList.remove("show"), 1800);
}

function normalizeTarget(raw) {
  let t = raw.trim();
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ""); // strip scheme://
  t = t.split(/[/?#]/, 1)[0];                    // strip path/query/fragment
  if (!t.startsWith("[")) t = t.split(":", 1)[0]; // strip :port (but keep bracketed IPv6)
  else t = t.replace(/\]:\d+$/, "]");
  return t;
}

function statusOf(s) {
  if (s.status === "running") return "running";
  if (s.status === "error") return "error";
  return s.worst || "info";
}

// ---------- modal ----------

function openModal(prefill) {
  el("#form-error").style.display = "none";
  el("#modal-title").textContent = prefill ? "Re-run scan" : "New scan";
  el("#targets").value = prefill ? prefill.targets.join("\n") : "";
  el("#scope").value = prefill ? prefill.scope_text : "";
  el("#authorized-by").value = prefill ? prefill.authorized_by : "";
  el("#timeout").value = prefill ? prefill.timeout : 6;
  el("#ingest").value = prefill ? prefill.ingest_text || "" : "";
  el("#ingest-details").open = !!(prefill && prefill.ingest_text);
  modalOverlay.classList.remove("hidden");
  el("#targets").focus();
}

function closeModal() {
  modalOverlay.classList.add("hidden");
}

el("#open-new-scan").addEventListener("click", () => openModal(null));
el("#close-modal").addEventListener("click", closeModal);
el("#cancel-modal").addEventListener("click", closeModal);
modalOverlay.addEventListener("click", (e) => { if (e.target === modalOverlay) closeModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !modalOverlay.classList.contains("hidden")) closeModal();
});

// ---------- history sidebar ----------

async function loadHistory() {
  try {
    const res = await fetch("/api/scans");
    historyCache = await res.json();
    renderHistory();
    renderStats();
  } catch (e) {
    historyEl.innerHTML = `<p class="history-empty">Could not load history.</p>`;
  }
}

function renderStats() {
  if (!historyCache.length) { statsEl.innerHTML = ""; return; }
  const done = historyCache.filter((s) => s.status === "done");
  const critHigh = done.reduce((n, s) => n + (s.counts?.critical || 0) + (s.counts?.high || 0), 0);
  statsEl.innerHTML = `
    <div class="stat"><div class="n">${historyCache.length}</div><div class="l">Scans</div></div>
    <div class="stat"><div class="n" style="color:${critHigh ? 'var(--critical)' : 'inherit'}">${critHigh}</div><div class="l">Crit/High</div></div>
  `;
}

function renderHistory() {
  if (!historyCache.length) {
    historyEl.innerHTML = `<p class="history-empty">No scans yet.</p>`;
    return;
  }
  historyEl.innerHTML = historyCache.map((s) => {
    const active = s.id === currentScanId ? "active" : "";
    const sev = statusOf(s);
    const badge = s.status === "running" ? `<span class="badge running">running</span>`
      : s.status === "error" ? `<span class="badge error">error</span>`
      : `<span class="badge ${s.worst}">${s.worst}</span>`;
    return `<div class="history-item sev-${sev} ${active}" data-id="${s.id}">
      <div class="item-actions">
        <button type="button" class="rerun" title="Re-run with same settings" data-id="${s.id}">${ICONS.rerun}</button>
        <button type="button" class="del" title="Delete" data-id="${s.id}">${ICONS.trash}</button>
      </div>
      <div class="targets">${escapeHtml(s.targets.join(", "))}</div>
      <div class="meta"><span>${timeAgo(s.created_at)}</span>${badge}</div>
    </div>`;
  }).join("");

  historyEl.querySelectorAll(".history-item").forEach((node) => {
    node.addEventListener("click", (e) => {
      if (e.target.closest(".item-actions")) return;
      openScan(node.dataset.id);
    });
  });
  historyEl.querySelectorAll(".rerun").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const config = await fetch(`/api/scan/${btn.dataset.id}/config`).then((r) => r.ok ? r.json() : null);
      if (config) openModal(config); else showToast("No saved settings for this scan");
    });
  });
  historyEl.querySelectorAll(".del").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const node = btn.closest(".history-item");
      node.style.opacity = "0.4";
      await fetch(`/api/scan/${btn.dataset.id}`, { method: "DELETE" });
      if (btn.dataset.id === currentScanId) {
        currentScanId = null;
        renderEmpty();
      }
      await loadHistory();
    });
  });
}

// ---------- starting a scan ----------

el("#scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = el("#scan-submit");
  const errEl = el("#form-error");
  errEl.style.display = "none";

  const targets = el("#targets").value.split("\n").map((t) => t.trim()).filter(Boolean).map(normalizeTarget);
  const scope = el("#scope").value;
  const authorized_by = el("#authorized-by").value.trim();
  const timeout = parseFloat(el("#timeout").value) || 6.0;
  const ingest = el("#ingest").value.trim() || null;

  btn.disabled = true;
  btn.innerHTML = "Starting...";
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets, scope, authorized_by, timeout, ingest }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "failed to start scan");
    closeModal();
    await loadHistory();
    openScan(data.id);
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><path d="m5 3 14 9-14 9V3z"/></svg> Start scan';
  }
});

// ---------- viewing a scan ----------

async function openScan(id) {
  currentScanId = id;
  stopTimer();
  if (currentSource) { currentSource.close(); currentSource = null; }
  document.querySelectorAll(".history-item").forEach((n) => {
    n.classList.toggle("active", n.dataset.id === id);
  });

  const res = await fetch(`/api/scan/${id}`);
  if (!res.ok) { renderMissing(); return; }
  const status = await res.json();

  if (status.status === "running") {
    scanStartedAt = new Date(status.created_at).getTime();
    renderRunning(status);
    startTimer();
    watchEvents(id);
  } else if (status.status === "error") {
    renderError(status);
  } else {
    await loadReport(id);
  }
}

function renderEmpty() {
  main.innerHTML = `<div class="empty-state">
    <div class="mark-lg">V</div>
    <h2>No scan selected</h2>
    <p>Start a new scan to assess a target you're authorized to test, or pick a past scan from the history on the left.</p>
  </div>`;
}

function renderMissing() {
  main.innerHTML = `<div class="empty-state"><h2>Scan not found</h2></div>`;
}

function renderError(status) {
  main.innerHTML = `
    <div class="run-header">
      <div class="title-row"><h2>${escapeHtml((status.targets || []).join(", "))}</h2><span class="badge error">error</span></div>
      <p class="meta">authorized by: <b>${escapeHtml(status.authorized_by || "")}</b></p>
    </div>
    <div class="log"><span class="line err">${escapeHtml(status.error || "scan failed")}</span></div>`;
}

function renderRunning(status) {
  main.innerHTML = `
    <div class="run-header">
      <div class="title-row"><h2>${escapeHtml((status.targets || []).join(", "))}</h2><span class="badge running">running</span><span class="timer" id="timer">0:00</span></div>
      <p class="meta">authorized by: <b>${escapeHtml(status.authorized_by || "")}</b></p>
    </div>
    <div class="log" id="log"><div class="line"><span class="spinner"></span>starting scan...</div></div>`;
}

function startTimer() {
  stopTimer();
  timerInterval = setInterval(() => {
    const t = el("#timer");
    if (!t || !scanStartedAt) return;
    t.textContent = fmtElapsed((Date.now() - scanStartedAt) / 1000);
  }, 1000);
}
function stopTimer() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
}

function watchEvents(id) {
  const logEl = el("#log");
  const source = new EventSource(`/api/scan/${id}/events`);
  currentSource = source;
  source.onmessage = (ev) => {
    if (!logEl) return;
    const text = JSON.parse(ev.data);
    const line = document.createElement("div");
    line.className = "line" + (text.startsWith("refused") ? " refused" : text.trim().startsWith("scanning") ? " scan" : "");
    line.textContent = text;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  };
  source.addEventListener("done", async (ev) => {
    source.close();
    currentSource = null;
    stopTimer();
    const summary = JSON.parse(ev.data);
    await loadHistory();
    if (summary.status === "error") {
      renderError(summary);
    } else {
      await loadReport(id);
    }
  });
  source.onerror = () => {
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
  targetFilter = "";
  searchText = "";
  groupByTarget = currentReport.targets.length > 1;
  renderReport(id, currentReport);
}

function renderReport(id, report) {
  const c = report.counts;
  const checkers = [...new Set(report.findings.map((f) => f.check))].sort();
  const targets = report.targets;

  const refusals = (report.errors || []).filter((e) => e.startsWith("REFUSED"));

  main.innerHTML = `
    <div class="run-header">
      <div class="title-row"><h2>${escapeHtml(targets.join(", "))}</h2><span class="badge ${report.worst}">${report.worst}</span></div>
      <p class="meta">authorized by: <b>${escapeHtml(report.authorized_by || "(unnamed)")}</b> &middot; scope: ${escapeHtml(report.scope_summary)}</p>
      <p class="meta">${escapeHtml(report.started_at)}</p>
    </div>

    ${refusals.length ? `<div class="warning-banner">
      <svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>
      <div>${refusals.length} of ${targets.length} target(s) were refused by scope and not scanned. Check the target spelling and your scope's allow rules below.</div>
    </div>` : ""}

    <div class="summary-bar">
      <div class="chips" id="chips">
        ${SEVERITIES.map((s) => `<span class="chip" data-sev="${s}"><span class="dot"></span>${s}<b>${c[s] ?? 0}</b></span>`).join("")}
      </div>
      <div class="actions">
        <a href="/api/scan/${id}/report" download="vulnscope-${id}.json"><button class="small" type="button">Download JSON</button></a>
        <a href="/api/scan/${id}/report.html" download="vulnscope-${id}.html"><button class="small" type="button">Download HTML</button></a>
      </div>
    </div>

    ${targets.length > 1 ? `<div class="target-chips" id="target-chips">
      <span class="target-chip" data-target="">All targets</span>
      ${targets.map((t) => `<span class="target-chip" data-target="${escapeHtml(t)}">${escapeHtml(t)}</span>`).join("")}
    </div>` : ""}

    <div class="toolbar">
      <input type="text" id="search" placeholder="Search findings...">
      <select id="checker-filter">
        <option value="">All checkers</option>
        ${checkers.map((ch) => `<option value="${ch}">${ch}</option>`).join("")}
      </select>
      <div class="spacer"></div>
      ${targets.length > 1 ? `<div class="seg">
        <button type="button" class="small ${groupByTarget ? "active" : ""}" id="group-on">Group by target</button>
        <button type="button" class="small ${groupByTarget ? "" : "active"}" id="group-off">Flat list</button>
      </div>` : ""}
    </div>

    <div id="findings-root"></div>
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
  el("#target-chips")?.querySelectorAll(".target-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      targetFilter = chip.dataset.target;
      el("#target-chips").querySelectorAll(".target-chip").forEach((c) => c.classList.toggle("active", c === chip));
      renderFindings();
    });
  });
  el("#target-chips")?.querySelector(".target-chip")?.classList.add("active");
  el("#group-on")?.addEventListener("click", () => { groupByTarget = true; renderReport(id, currentReport); });
  el("#group-off")?.addEventListener("click", () => { groupByTarget = false; renderReport(id, currentReport); });

  renderFindings();
}

function matchesFilters(f) {
  if (!activeFilters.has(f.severity)) return false;
  if (checkerFilter && f.check !== checkerFilter) return false;
  if (targetFilter && f.target !== targetFilter) return false;
  if (searchText) {
    const hay = `${f.title} ${f.detail} ${f.target} ${f.check}`.toLowerCase();
    if (!hay.includes(searchText)) return false;
  }
  return true;
}

function findingCard(f) {
  const loc = f.port ? `${f.target}:${f.port}` : f.target;
  const extra = [];
  if (f.evidence) extra.push(`<p class="ev"><span class="txt">evidence: ${escapeHtml(f.evidence)}</span><button type="button" class="ghost icon-only small copy-btn" title="Copy evidence">${ICONS.copy}</button></p>`);
  if (f.remediation) extra.push(`<p class="fix">fix: ${escapeHtml(f.remediation)}</p>`);
  if (f.reference) extra.push(`<p><a href="${escapeHtml(f.reference)}" target="_blank" rel="noopener">${escapeHtml(f.reference)}</a></p>`);
  return `<div class="finding ${f.severity}">
    <h3><span class="badge ${f.severity}">${f.severity}</span> ${escapeHtml(f.title)} <span class="loc">${escapeHtml(loc)} &middot; ${escapeHtml(f.check)}</span>${ICONS.chevron}</h3>
    <p class="detail">${escapeHtml(f.detail)}</p>
    <div class="extra">${extra.join("")}</div>
  </div>`;
}

function wireFindingCards(root) {
  root.querySelectorAll(".finding").forEach((node) => {
    node.addEventListener("click", (e) => {
      if (e.target.closest(".copy-btn")) return;
      node.classList.toggle("expanded");
    });
  });
  root.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const text = btn.previousElementSibling.textContent;
      navigator.clipboard?.writeText(text).then(() => showToast("Evidence copied"));
    });
  });
}

function renderFindings() {
  const root = el("#findings-root");
  if (!root || !currentReport) return;

  el("#chips")?.querySelectorAll(".chip").forEach((chip) => {
    chip.classList.toggle("off", !activeFilters.has(chip.dataset.sev));
  });

  const findings = currentReport.findings.filter(matchesFilters);

  if (!findings.length) {
    root.innerHTML = `<div class="no-results">No findings match the current filters.</div>`;
    return;
  }

  if (groupByTarget) {
    const byTarget = {};
    findings.forEach((f) => { (byTarget[f.target] ||= []).push(f); });
    root.innerHTML = Object.entries(byTarget).map(([target, items]) => `
      <div class="findings-group">
        <div class="group-title">${escapeHtml(target)} <span style="color:var(--dim)">(${items.length})</span></div>
        <div class="findings">${items.map(findingCard).join("")}</div>
      </div>`).join("");
  } else {
    root.innerHTML = `<div class="findings">${findings.map(findingCard).join("")}</div>`;
  }

  wireFindingCards(root);
}

loadHistory();
