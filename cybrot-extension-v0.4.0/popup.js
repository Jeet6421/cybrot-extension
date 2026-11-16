// CYBROT popup: detects the domain of the active tab, asks the local engine
// to scan it, and shows progress, failures and results.
// Text from the engine is always written with textContent, never innerHTML.

(() => {
  "use strict";

  const STORAGE_KEY = "cybrot.lastScan";
  const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;
  const MODULE_LABELS = {
    dns: "DNS records",
    subdomains: "Subdomains",
    hosts: "Name resolution",
    ssl: "SSL / TLS",
    whois: "WHOIS",
    threat: "Threat intel",
    headers: "Security headers",
  };
  const STEP_STATES = ["queued", "running", "done", "failed", "skipped"];
  const VIEWS = ["unsupported", "idle", "scanning", "failed", "results"];
  const WARN_LABEL_RE = /^(dev|staging|stage|test|uat|qa|old|admin|internal)$/i;
  const REPORT_FORMATS = ["html", "pdf", "csv", "json"];
  const MAX_CHIPS = 60;
  const MAX_DNS_ROWS = 25;
  const MAX_CERTS = 5;

  // Threat verdicts as the engine reports them. "tone" sets the colour in the popup.
  const THREAT_STATES = {
    flagged: { short: "Flagged", tone: "danger", text: "Flagged by at least one provider" },
    mentioned: { short: "Mentioned", tone: "warn", text: "Mentioned in threat reports, not confirmed malicious" },
    no_findings: { short: "Clear", tone: "ok", text: "No flags from the providers that returned data" },
    no_data: { short: "No record", tone: "muted", text: "No record of this domain at the providers" },
    not_configured: { short: "No key", tone: "muted", text: "Not run: the engine has no threat intelligence key" },
  };

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
    if (name === "results") setReportStatus("");
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
    const domain = scan.domain || state.domain;
    const details = r.domain_details || {};
    const hosts = r.hosts || null;
    // Older engines sent only names; newer ones send one record per name.
    const subs = Array.isArray(r.subdomain_details)
      ? r.subdomain_details
      : (Array.isArray(r.subdomains) ? r.subdomains.map((name) => ({ name })) : []);
    const dns = Array.isArray(r.dns) ? r.dns : [];
    const certs = Array.isArray(r.certificates) ? r.certificates : [];
    const email = r.email_security || null;
    const ssl = r.ssl || {};
    const threat = r.threat_intel || null;

    setDomainLabels(domain);
    $("result-meta").textContent = `Scanned ${formatDateTime(scan.finished_at)} · took ${formatDuration(scan.duration_seconds || 0)}`;

    $("stat-subdomains").textContent = String(subs.length);
    $("stat-resolving").textContent = hosts ? String(hosts.resolving) : "—";
    $("stat-certs").textContent = String(certs.length);
    const verdict = threatVerdict(threat);
    $("stat-threat").textContent = verdict.short;
    $("stat-threat").dataset.tone = verdict.tone;

    renderObservations(r.observations || []);
    renderThreat(threat);

    fillDefinitionList($("facts"), [
      ["Registrar", details.registrar],
      ["Registered", details.created ? formatDate(details.created) : null],
      ["Expires", details.expires ? `${formatDate(details.expires)} · ${daysUntil(details.expires)}` : null],
      ["Domain status", listText(details.status)],
      ["Name servers", listText(details.name_servers)],
      ["Email", email ? emailSummary(email) : null],
      ["Latest certificate", ssl.issuer ? certificateSummary(ssl) : null],
    ]);

    renderSubdomains(subs);
    renderDns(dns);
    renderCertificates(certs);
    renderWarnings(r.warnings || []);

    state.shownResults = {
      domain,
      scan_id: scan.scan_id || state.scanId,
      finished_at: scan.finished_at,
      duration_seconds: scan.duration_seconds,
      results: r,
    };
    showView("results");
  }

  function threatVerdict(threat) {
    if (!threat) return { short: "Not run", tone: "muted", text: "Threat intelligence was not requested for this scan." };
    return THREAT_STATES[threat.verdict] || { short: "—", tone: "muted", text: "Unknown result." };
  }

  function renderThreat(threat) {
    const verdict = threatVerdict(threat);
    const box = $("threat-verdict");
    box.textContent = verdict.text;
    box.dataset.tone = verdict.tone;

    const list = $("threat-providers");
    list.replaceChildren();
    if (threat && threat.verdict === "not_configured") {
      list.append(el("li", "muted", "Set CYBROT_VT_API_KEY or CYBROT_OTX_API_KEY on the engine's computer to enable this check."));
    }
    for (const provider of (threat && threat.providers) || []) {
      list.append(el("li", "", providerLine(provider)));
    }
    for (const error of (threat && threat.errors) || []) {
      list.append(el("li", "warn-text", `Provider problem: ${error}`));
    }
  }

  function providerLine(provider) {
    if (provider.found === false) return `${provider.provider}: no record of this domain`;
    if (typeof provider.malicious === "number") {
      return `${provider.provider}: ${provider.malicious} malicious, ${provider.suspicious} suspicious, ${provider.harmless} harmless of ${provider.engines_total} engines`;
    }
    return `${provider.provider}: listed in ${provider.pulses} threat report(s)`;
  }

  function renderObservations(items) {
    const list = $("observations");
    list.replaceChildren();
    if (!items.length) {
      list.append(el("li", "muted", "No observations were raised by the collected data."));
      return;
    }
    for (const item of items) list.append(el("li", "", item));
  }

  function renderWarnings(items) {
    const list = $("result-warnings");
    const label = $("warnings-label");
    list.replaceChildren();
    for (const item of items) list.append(el("li", "", item));
    list.hidden = !items.length;
    label.hidden = !items.length;
  }

  function fillDefinitionList(dl, rows) {
    dl.replaceChildren();
    for (const [term, value] of rows) {
      dl.append(el("dt", "", term), el("dd", "", value || "—"));
    }
  }

  function emailSummary(email) {
    const spf = email.spf ? "SPF found" : "no SPF";
    let dmarc = "no DMARC";
    if (email.dmarc) dmarc = email.dmarc_policy ? `DMARC p=${email.dmarc_policy}` : "DMARC found";
    return `${spf} · ${dmarc}`;
  }

  function certificateSummary(ssl) {
    const expiry = ssl.valid_until ? ` · expires ${formatDate(ssl.valid_until)} (${daysUntil(ssl.valid_until)})` : "";
    return `${shortIssuer(ssl.issuer)}${expiry}`;
  }

  function shortIssuer(text) {
    if (!text) return "Unknown issuer";
    const org = /O=([^,]+)/.exec(text);
    const common = /CN=([^,]+)/.exec(text);
    const name = (org && org[1]) || (common && common[1]) || text;
    return name.length > 60 ? `${name.slice(0, 57)}…` : name;
  }

  function listText(value) {
    return Array.isArray(value) ? value.join(", ") : value;
  }

  function renderSubdomains(items) {
    const wrap = $("subdomain-list");
    wrap.replaceChildren();
    $("subdomain-count").textContent = `Names found (${items.length})`;
    if (!items.length) {
      wrap.append(el("span", "muted", "None found in certificate logs."));
      return;
    }
    const shown = items.slice(0, MAX_CHIPS);
    for (const item of shown) {
      const name = String(item.name || "");
      const classes = ["chip"];
      if (WARN_LABEL_RE.test(name.split(".")[0])) classes.push("warn");
      if (item.resolves === true) classes.push("ok");
      const chip = el("span", classes.join(" "), name);
      if (item.resolves === true) {
        chip.title = `Resolves to ${(item.addresses || []).join(", ")}`;
      } else if (item.resolves === false) {
        chip.title = "Does not resolve in DNS";
      } else {
        chip.title = "Not checked";
      }
      wrap.append(chip);
    }
    if (items.length > shown.length) {
      wrap.append(el("span", "muted", `…and ${items.length - shown.length} more. The reports list every name.`));
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
    for (const record of records.slice(0, MAX_DNS_ROWS)) {
      const row = el("tr");
      row.append(el("td", "rtype", record.type), el("td", "", record.value), el("td", "", record.ttl));
      body.append(row);
    }
    if (records.length > MAX_DNS_ROWS) {
      const row = el("tr");
      const cell = el("td", "muted", `…and ${records.length - MAX_DNS_ROWS} more. The reports list every record.`);
      cell.colSpan = 3;
      row.append(cell);
      body.append(row);
    }
  }

  function renderCertificates(certs) {
    const list = $("cert-list");
    list.replaceChildren();
    if (!certs.length) {
      list.append(el("li", "muted", "No certificates found in certificate logs."));
      return;
    }
    for (const cert of certs.slice(0, MAX_CERTS)) {
      const row = el("li", "cert");
      row.append(
        el("span", "cert-issuer", shortIssuer(cert.issuer)),
        el("span", "cert-meta", cert.not_after ? `expires ${formatDate(cert.not_after)} · ${daysUntil(cert.not_after)}` : "expiry unknown")
      );
      list.append(row);
    }
    if (certs.length > MAX_CERTS) {
      list.append(el("li", "muted", `…and ${certs.length - MAX_CERTS} more`));
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

  // ---------- Report download and dashboard ----------

  function setReportStatus(text, tone) {
    const node = $("report-status");
    node.textContent = text || "";
    node.hidden = !text;
    node.dataset.state = tone || "";
  }

  function setReportBusy(busy) {
    for (const button of $("report-buttons").querySelectorAll("button")) {
      button.disabled = busy;
    }
  }

  function reportFailure(err) {
    if (err && err.name === "AbortError") return "The engine did not respond in time.";
    if (err instanceof TypeError) return friendlyError(err);
    return err && err.message ? err.message : "The report could not be downloaded.";
  }

  function reportHttpError(status) {
    if (status === 404) {
      return new Error("This scan is no longer on the engine. The engine may have restarted, so run the scan again.");
    }
    if (status === 409) return new Error("The scan is not finished yet. Reports are ready once it completes.");
    return new Error(`The engine could not create the report (HTTP ${status}).`);
  }

  function saveBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = el("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function downloadReport(format) {
    const data = state.shownResults;
    if (!data || !data.scan_id || !REPORT_FORMATS.includes(format)) {
      setReportStatus("Run a scan first, then download its report.", "error");
      return;
    }
    const label = format.toUpperCase();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    setReportBusy(true);
    setReportStatus(`Preparing the ${label} report…`);
    try {
      const path = `/api/scans/${encodeURIComponent(data.scan_id)}/report.${format}`;
      const response = await fetch(CYBROT_CONFIG.engineUrl + path, { signal: controller.signal });
      if (!response.ok) throw reportHttpError(response.status);
      const blob = await response.blob();
      saveBlob(blob, `cybrot-${data.domain}-${data.scan_id}.${format}`);
      setReportStatus(`${label} report downloaded.`, "ok");
    } catch (err) {
      setReportStatus(reportFailure(err), "error");
    } finally {
      clearTimeout(timer);
      setReportBusy(false);
    }
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
      const count = Array.isArray(last.results.subdomain_details)
        ? last.results.subdomain_details.length
        : (Array.isArray(last.results.subdomains) ? last.results.subdomains.length : 0);
      $("last-scan-note").textContent = `Last scan ${formatRelative(last.finishedAt)} · ${count} names found`;
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
    $("report-buttons").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-format]");
      if (button) downloadReport(button.dataset.format);
    });
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
