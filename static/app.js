(() => {
  const $ = (selector) => document.querySelector(selector);
  const form = $("#lookup-form");
  const domainInput = $("#domain");
  const button = $("#submit-button");
  const error = $("#form-error");
  const loading = $("#loading");
  const result = $("#result");

  async function apiFetch(path, options) {
    let response = await fetch(`/api/v1${path}`, options);
    if (response.status === 404) response = await fetch(`/api${path}`, options);
    if (response.status === 404 && path === "/health") response = await fetch("/health", options);
    return response;
  }

  function normaliseDomain(value) {
    const candidate = value.trim().toLowerCase();
    if (!candidate) return null;
    try {
      const parsed = new URL(candidate.includes("://") ? candidate : `https://${candidate}`);
      const host = parsed.hostname.replace(/^www\./, "");
      return host.includes(".") && !host.includes(" ") ? host : null;
    } catch { return null; }
  }
  function valueOf(object, keys, fallback = "—") {
    for (const key of keys) if (object?.[key] !== undefined && object[key] !== null) return object[key];
    return fallback;
  }
  function formatMetric(value) {
    if (typeof value === "number") return new Intl.NumberFormat("it-IT", { maximumFractionDigits: 1 }).format(value);
    return value ?? "—";
  }
  function signalClass(value) {
    const text = String(value).toLowerCase();
    if (["bad", "fail", "risky", "malicious", "no", "false"].some(x => text.includes(x))) return "bad";
    if (["warn", "unknown", "pending", "n/a"].some(x => text.includes(x))) return "warn";
    return "good";
  }
  function renderResult(data, requestedDomain) {
    const payload = data?.result || data;
    const score = Number(valueOf(payload, ["trust_score", "score", "trustLevel"], NaN));
    const verdict = valueOf(payload, ["verdict", "risk_level", "riskLevel", "classification", "rating"], score >= 80 ? "Affidabile" : score >= 55 ? "Da verificare" : "Rischio elevato");
    $("#score").textContent = Number.isFinite(score) ? Math.round(score) : "—";
    $("#score").className = `score ${score >= 80 ? "high" : score >= 55 ? "medium" : "low"}`;
    $("#verdict").textContent = verdict;
    $("#result-domain").textContent = valueOf(payload, ["domain", "hostname"], requestedDomain);
    $("#summary").textContent = valueOf(payload, ["summary", "explanation", "message"], "Il report combina fonti pubbliche e segnali tecnici disponibili.");
    const checkedAt = valueOf(payload, ["checked_at", "created_at", "timestamp"], null);
    $("#checked-at").textContent = checkedAt ? `Verificato: ${new Date(checkedAt).toLocaleString("it-IT")}` : "Verifica appena completata";
    $("#cache-badge").hidden = !Boolean(valueOf(payload, ["cached", "from_cache", "cache_hit"], false));
    const report = payload.report || {};
    const signals = report.signals || payload.signals || payload.factors || payload.checks || payload.evidence || {};
    const entries = Array.isArray(signals) ? signals.map(s => [s.name || s.label, s.value ?? s.status ?? s.score]) : Object.entries(signals);
    $("#signals").innerHTML = entries.length ? entries.map(([name, value]) => `<div class="signal"><small>${escapeHtml(pretty(name))}</small><b class="${signalClass(value)}">${escapeHtml(summarise(value))}</b></div>`).join("") : "<p class=\"muted\">Nessun dettaglio di segnale disponibile.</p>";
    const details = report.details || payload.details || payload.raw_signals;
    $("#details-wrap").hidden = !details;
    if (details) $("#details").textContent = JSON.stringify(details, null, 2);
    result.hidden = false;
  }
  function pretty(value) { return String(value).replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase()); }
  function summarise(value) {
    if (Array.isArray(value)) return value.length ? `${value.length} rilevat${value.length === 1 ? "o" : "i"}` : "Nessuno";
    if (value && typeof value === "object") {
      if (value.status) return value.status;
      if (value.valid !== undefined) return value.valid ? "Valido" : "Non valido";
      return `${Object.keys(value).length} attributi`;
    }
    return formatMetric(value);
  }
  function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[c])); }
  async function checkApi() {
    const status = $("#api-status");
    try { const res = await apiFetch("/health"); if (!res.ok) throw Error(); status.className = "status ok"; status.innerHTML = "<i></i> API operativa"; }
    catch { status.className = "status offline"; status.innerHTML = "<i></i> API non raggiungibile"; }
  }
  async function loadMetrics() {
    const box = $("#metric-cards");
    try {
      const res = await apiFetch("/metrics"); if (!res.ok) throw new Error("Metriche non disponibili");
      const data = await res.json(); const metrics = data.metrics || data;
      const labels = { total_checks: "Analisi totali", total_queries: "Analisi totali", cached_checks: "Risposte da cache", cached_queries: "Risposte da cache", cache_hit_rate: "Tasso cache", unique_domains: "Domini unici", average_score: "Trust medio", sources_available: "Fonti attive", errors: "Errori" };
      const entries = Object.entries(metrics).filter(([, value]) => typeof value !== "object").slice(0, 6);
      box.innerHTML = entries.length ? entries.map(([key, value]) => `<div class="metric"><span>${labels[key] || pretty(key)}</span><b>${escapeHtml(formatMetric(value))}</b></div>`).join("") : "<p class=\"muted\">Ancora nessuna metrica.</p>";
    } catch { box.innerHTML = "<p class=\"muted\">Metriche non ancora disponibili.</p>"; }
  }
  form.addEventListener("submit", async event => {
    event.preventDefault(); error.hidden = true;
    const domain = normaliseDomain(domainInput.value);
    if (!domain) { error.textContent = "Inserisci un dominio valido, ad esempio example.com."; error.hidden = false; return; }
    button.disabled = true; loading.hidden = false; result.hidden = true;
    try {
      const response = await apiFetch("/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || data.error || "Analisi non riuscita.");
      renderResult(data, domain); loadMetrics();
    } catch (err) { error.textContent = err.message || "Impossibile contattare il servizio."; error.hidden = false; }
    finally { button.disabled = false; loading.hidden = true; }
  });
  $("#refresh-metrics").addEventListener("click", loadMetrics);
  checkApi(); loadMetrics();
})();
