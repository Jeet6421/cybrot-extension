// CYBROT popup: detects the domain of the active tab, asks the local engine
// to scan it, and shows progress, failures and results.
// Text from the engine is always written with textContent, never innerHTML.

(() => {
  "use strict";

  const STORAGE_KEY = "cybrot.lastScan";
  const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;
  const MODULE_LABELS = { dns: "DNS records", subdomains: "Subdomains", ssl: "SSL / TLS", whois: "WHOIS" };
  const STEP_STATES = ["queued", "running", "done", "failed", "skipped"];
  const VIEWS = ["unsupported", "idle", "scanning", "failed", "results"];
  const WARN_LABEL_RE = /^(dev|staging|stage|test|uat|qa|old|admin|internal)$/i;

  const state = {
    domain: null,
    engineOnline: false,
    scanId: null,
    modules: [],
    passive: true,
    startedAt: null,
    lastModules: {},
    shownResults: null,
    lastScan: null,
    pollTimer: null,
    clockTimer: null,
    pollFailures: 0,
  };

  // Scans are passive-only in this version. Active checks are not offered.
  const PASSIVE_ONLY = true;
  const REQUEST_TIMEOUT_MS = 10000;
  const MAX_POLL_FAILURES = 3;

  const $ = (id) => document.getElementById(id);

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  // ---------- Views ----------

  function showView(name) {
    for (const view of VIEWS) {
      $("view-" + view).hidden = view !== name;
    }
    $("export-json").hidden = name !== "results";
  }

  function setDomainLabels(domain) {
    for (const id of ["idle-domain", "scan-domain", "failed-domain", "result-domain"]) {
      $(id).textContent = domain || "—";
    }
  }

  function setIdleMessage(text) {
    const node = $("idle-message");
    node.textContent = text || "";
    node.hidden = !text;
  }

  function showIdle() {
    stopClock();
    state.scanId = null;
    showView("idle");
    $("start-scan").disabled = !state.engineOnline;
    $("view-last").hidden = true;
    $("last-scan-note").textContent = "";
  }

  // ---------- Engine connection ----------

  async function engineFetch(path, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let response;
    try {
      response = await fetch(CYBROT_CONFIG.engineUrl + path, {
        method: options.method || "GET",
        headers: { "Content-Type": "application/json" },
        body: options.body,
        signal: controller.signal,
      });
    } catch (err) {
      if (err.name === "AbortError") {
        const timeout = new Error("The CYBROT engine did not respond in time.");
        timeout.code = "ENGINE_TIMEOUT";
        throw timeout;
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch (_) {
      payload = null;
    }
    if (!response.ok) {
      const error = new Error((payload && payload.error && payload.error.message) || `Engine returned HTTP ${response.status}.`);
      error.code = (payload && payload.error && payload.error.code) || `HTTP_${response.status}`;
      throw error;
    }
    return payload;
  }

  function friendlyError(err) {
    if (err instanceof TypeError) {
      return `Can't reach the CYBROT engine at ${CYBROT_CONFIG.engineUrl}. Start the engine, then select the engine status to check again.`;
    }
    return err.message || "Something went wrong.";
  }

  function setEngineStatus(stateName, text) {
    $("engine-status").dataset.state = stateName;
    $("engine-status-text").textContent = text;
  }

  async function checkEngine() {
    setEngineStatus("checking", "Checking engine…");
    try {
      await engineFetch("/api/health");
      state.engineOnline = true;
      setEngineStatus("online", "Engine online");
    } catch (_) {
      state.engineOnline = false;
      setEngineStatus("offline", "Engine offline");
      setIdleMessage(
        "The CYBROT engine isn't running on this computer. Start it using SETUP.md in the extension folder, then click the Engine offline status to check again."
      );
    }
    $("start-scan").disabled = !state.engineOnline;
    return state.engineOnline;
  }

  // ---------- Domain detection ----------

  async function detectActiveDomain() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return null;
    let url;
    try {
      url = new URL(tab.url);
    } catch (_) {
      return null;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const host = url.hostname.toLowerCase();
    if (!DOMAIN_RE.test(host)) return null;
    return { domain: host, protocol: url.protocol.replace(":", "").toUpperCase() };
  }

  // ---------- Scan lifecycle ----------

  function selectedModules() {
    return [...document.querySelectorAll('input[name="module"]:checked')].map((input) => input.value);
  }

  async function startScan(modules) {
    const chosen = modules && modules.length ? modules : selectedModules();
    if (!chosen.length) {
      setIdleMessage("Select at least one scan module.");
      return;
    }
    setIdleMessage("");
    state.modules = chosen;
    state.passive = PASSIVE_ONLY;
    $("start-scan").disabled = true;
    try {
      const { scan_id } = await engineFetch("/api/scans", {
        method: "POST",
        body: JSON.stringify({ domain: state.domain, modules: chosen, passive_only: PASSIVE_ONLY }),
      });
      state.scanId = scan_id;
      state.startedAt = Date.now();
      await saveLastScan({
        scanId: scan_id,
        status: "running",
        modules: chosen,
        passive: state.passive,
        startedAt: state.startedAt,
      });
      startClock();
      await poll();
    } catch (err) {
      showIdle();
      setIdleMessage(friendlyError(err));
    } finally {
      $("start-scan").disabled = !state.engineOnline;
    }
  }

  async function poll() {
    clearTimeout(state.pollTimer);
    if (!state.scanId) return;
    const scanId = state.scanId;
    try {
      const scan = await engineFetch(`/api/scans/${encodeURIComponent(scanId)}`);
      if (scanId !== state.scanId) return; // a newer scan replaced this one
      state.pollFailures = 0;
      handleScan(scan);
    } catch (err) {
      if (scanId !== state.scanId) return;
      // Retry a few times before giving up, so one slow response does not fail the scan.
      state.pollFailures += 1;
      if (state.pollFailures < MAX_POLL_FAILURES) {
        state.pollTimer = setTimeout(poll, CYBROT_CONFIG.pollIntervalMs);
        return;
      }
      finishWithFailure({ message: friendlyError(err), code: err.code || "ENGINE_UNREACHABLE" });
    }
  }

  function handleScan(scan) {
    if (scan.status === "running" || scan.status === "queued") {
      showView("scanning");
      renderProgress(scan);
      state.pollTimer = setTimeout(poll, CYBROT_CONFIG.pollIntervalMs);
      return;
    }

    if (scan.status === "completed") {
      stopClock();
      renderResults(scan);
      saveLastScan({
        scanId: state.scanId,
        status: "completed",
        finishedAt: scan.finished_at,
        durationSeconds: scan.duration_seconds,
        results: scan.results,
      });
      return;
    }

    if (scan.status === "cancelled") {
      stopClock();
      saveLastScan({ scanId: state.scanId, status: "cancelled" });
      showIdle();
      setIdleMessage("Scan stopped. Start a new scan when you're ready.");
      return;
    }

    finishWithFailure({
      message: (scan.error && scan.error.message) || "The scan failed.",
      code: (scan.error && scan.error.code) || "SCAN_FAILED",
      modules: scan.modules,
    });
  }

  function finishWithFailure(info) {
    clearTimeout(state.pollTimer);
    stopClock();
    setDomainLabels(state.domain);
    $("error-message").textContent = info.message;
    $("error-code").textContent = info.code;
    renderModuleList($("failed-modules"), info.modules || state.lastModules);
    showView("failed");
    saveLastScan({ scanId: state.scanId, status: "failed", error: { code: info.code, message: info.message } });
  }

  async function stopScan() {
    if (!state.scanId) return;
    $("stop-scan").disabled = true;
    try {
      await engineFetch(`/api/scans/${encodeURIComponent(state.scanId)}/cancel`, { method: "POST" });
    } catch (_) {
      // If the cancel did not go through, the next poll shows the real status.
    }
    $("stop-scan").disabled = false;
    await poll();
  }

  // ---------- Progress rendering ----------

  function renderProgress(scan) {
    state.lastModules = scan.modules || {};
    const pct = typeof scan.progress === "number" ? Math.max(0, Math.min(100, Math.round(scan.progress))) : 0;
    $("progress-fill").style.width = pct + "%";
    $("progress-bar").setAttribute("aria-valuenow", String(pct));
    $("progress-text").textContent = pct + "%";
    setDomainLabels(scan.domain || state.domain);
    renderModuleList($("module-list"), state.lastModules);
  }

  function renderModuleList(listEl, modules) {
    const info = modules || {};
    const names = state.modules.length ? state.modules : Object.keys(info);
    listEl.replaceChildren();
    for (const name of names) {
      const step = info[name] || { status: "queued" };
      const status = STEP_STATES.includes(step.status) ? step.status : "queued";
      const row = el("li", "step step-" + status);
      row.append(
        el("span", "step-icon"),
        el("span", "step-name", MODULE_LABELS[name] || name),
        el("span", "step-meta", moduleMeta(status, step))
      );
      listEl.append(row);
    }
  }

  function moduleMeta(status, step) {
    if ((status === "done" || status === "running") && typeof step.count === "number") {
      return `${step.count} found`;
    }
    return status;
  }

  // ---------- Clock ----------

  function startClock() {
    stopClock();
    updateElapsed();
    state.clockTimer = setInterval(updateElapsed, 1000);
  }

  function stopClock() {
    clearInterval(state.clockTimer);
    state.clockTimer = null;
  }

  function updateElapsed() {
    if (!state.startedAt) return;
    const seconds = Math.floor((Date.now() - state.startedAt) / 1000);
    $("scan-elapsed").textContent = `Elapsed ${formatDuration(seconds)} · ${state.modules.length} modules`;
  }

  // ---------- Results ----------

  function renderResults(scan) {
    const r = scan.results || {};
    const details = r.domain_details || {};
    const subdomains = Array.isArray(r.subdomains) ? r.subdomains : [];
    const dns = Array.isArray(r.dns) ? r.dns : [];
    const ssl = r.ssl || {};
    const domain = scan.domain || state.domain;

    setDomainLabels(domain);
    $("result-meta").textContent = `Scanned ${formatDateTime(scan.finished_at)} · took ${formatDuration(scan.duration_seconds || 0)}`;
    $("stat-subdomains").textContent = String(subdomains.length);
    $("stat-dns").textContent = String(dns.length);
    $("stat-ssl").textContent = ssl.grade || "—";

    fillDefinitionList($("details"), [
      ["Registrar", details.registrar],
      ["Created", details.created],
      ["Expires", details.expires],
      ["Name servers", Array.isArray(details.name_servers) ? details.name_servers.join(", ") : details.name_servers],
    ]);

    renderDns(dns);
    renderSubdomains(subdomains);

    fillDefinitionList($("ssl-details"), [
      ["Issuer", ssl.issuer],
      ["Valid until", ssl.valid_until ? `${formatDate(ssl.valid_until)} · ${daysUntil(ssl.valid_until)}` : null],
      ["Protocol", ssl.protocol],
    ]);

    state.shownResults = {
      domain,
      scan_id: scan.scan_id || state.scanId,
      finished_at: scan.finished_at,
      duration_seconds: scan.duration_seconds,
      results: r,
    };
    showView("results");
  }

  function fillDefinitionList(dl, rows) {
    dl.replaceChildren();
    for (const [term, value] of rows) {
      dl.append(el("dt", "", term), el("dd", "", value || "—"));
    }
  }

  function renderDns(records) {
    const body = $("dns-rows");
    body.replaceChildren();
    if (!records.length) {
      const row = el("tr");
      const cell = el("td", "muted", "No DNS records found.");
      cell.colSpan = 3;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const record of records) {
      const row = el("tr");
      row.append(el("td", "rtype", record.type), el("td", "", record.value), el("td", "", record.ttl));
      body.append(row);
    }
  }

  function renderSubdomains(names) {
    const wrap = $("subdomain-list");
    wrap.replaceChildren();
    $("subdomain-count").textContent = `Subdomains (${names.length})`;
    if (!names.length) {
      wrap.append(el("span", "muted", "None found."));
      return;
    }
    for (const name of names) {
      const firstLabel = String(name).split(".")[0];
      wrap.append(el("span", WARN_LABEL_RE.test(firstLabel) ? "chip warn" : "chip", name));
    }
  }

  function showLastResults() {
    if (!state.lastScan) return;
    renderResults({
      domain: state.lastScan.domain,
      scan_id: state.lastScan.scanId,
      finished_at: state.lastScan.finishedAt,
      duration_seconds: state.lastScan.durationSeconds,
      results: state.lastScan.results,
    });
  }

  // ---------- Export and dashboard ----------

  function exportJson() {
    const data = state.shownResults;
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = el("a");
    link.href = url;
    link.download = `cybrot-${data.domain}-${data.scan_id || "scan"}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function openDashboard() {
    const scanId = state.scanId || (state.shownResults && state.shownResults.scan_id);
    const url = CYBROT_CONFIG.dashboardUrl + (scanId ? `?scan=${encodeURIComponent(scanId)}` : "");
    chrome.tabs.create({ url });
  }

  // ---------- Storage (survives the popup closing) ----------

  async function loadLastScan() {
    const stored = await chrome.storage.local.get(STORAGE_KEY);
    return stored[STORAGE_KEY] || null;
  }

  // Replace the stored record rather than merging into the old one, so a new
  // scan never keeps results or errors from an earlier scan of another site.
  async function saveLastScan(record) {
    await chrome.storage.local.set({
      [STORAGE_KEY]: { ...record, domain: state.domain },
    });
  }

  async function restore() {
    const last = await loadLastScan();
    const sameSite = Boolean(last && last.domain === state.domain);

    // A scan for this site is still running: pick it up where it is.
    if (sameSite && last.status === "running" && last.scanId) {
      state.scanId = last.scanId;
      state.modules = last.modules || [];
      state.passive = PASSIVE_ONLY;
      state.startedAt = last.startedAt || Date.now();
      showView("scanning");
      startClock();
      await poll();
      return;
    }

    showIdle();
    if (sameSite && last.status === "completed" && last.results) {
      state.lastScan = last;
      const count = Array.isArray(last.results.subdomains) ? last.results.subdomains.length : 0;
      $("last-scan-note").textContent = `Last scan ${formatRelative(last.finishedAt)} · ${count} subdomains`;
      $("view-last").hidden = false;
    }
  }

  // ---------- Formatting ----------

  function formatDuration(totalSeconds) {
    const s = Math.max(0, Math.floor(Number(totalSeconds) || 0));
    const hours = Math.floor(s / 3600);
    const minutes = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
    const seconds = String(s % 60).padStart(2, "0");
    return hours ? `${hours}:${minutes}:${seconds}` : `${minutes}:${seconds}`;
  }

  function formatDateTime(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "time unknown";
    return date.toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  }

  function formatDate(iso) {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? String(iso) : date.toISOString().slice(0, 10);
  }

  function daysUntil(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "";
    const days = Math.floor((date.getTime() - Date.now()) / 86400000);
    return days < 0 ? "expired" : `${days} days left`;
  }

  function formatRelative(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "earlier";
    const minutes = Math.round((Date.now() - date.getTime()) / 60000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${hours} h ago`;
    return `${Math.round(hours / 24)} d ago`;
  }

  // ---------- Start-up ----------

  async function init() {
    $("start-scan").addEventListener("click", () => startScan());
    $("stop-scan").addEventListener("click", stopScan);
    $("retry-scan").addEventListener("click", () => startScan(state.modules));
    $("back-to-idle").addEventListener("click", showIdle);
    $("view-last").addEventListener("click", showLastResults);
    $("export-json").addEventListener("click", exportJson);
    $("open-dashboard").addEventListener("click", openDashboard);
    $("engine-status").addEventListener("click", () => checkEngine());

    const detected = await detectActiveDomain();
    await checkEngine();

    if (!detected) {
      showView("unsupported");
      return;
    }

    state.domain = detected.domain;
    setDomainLabels(detected.domain);
    $("idle-meta").textContent = `${detected.protocol} · Active tab`;
    await restore();
  }

  init();
})();
