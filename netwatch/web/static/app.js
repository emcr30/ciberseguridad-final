// NetWatch panel. Network data is only ever written with textContent, never parsed as HTML.
"use strict";

const REFRESH_MS = 2000;
const $ = (id) => document.getElementById(id);
let refreshing = false;
let currentSession = null;

// ---------- helpers ----------

async function api(path, options = {}) {
  const res = await fetch(path, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Error HTTP ${res.status}`);
  return body;
}

function postJSON(path, data) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
}

function showMessage(text, isError = false) {
  const el = $("message");
  el.textContent = text;
  el.className = "message " + (isError ? "error" : "ok");
}

function fmtTime(ts, withMs = false) {
  if (ts === null || ts === undefined) return "";
  const d = new Date(ts * 1000);
  const base = d.toLocaleTimeString("es", { hour12: false });
  return withMs ? `${base}.${String(d.getMilliseconds()).padStart(3, "0")}` : base;
}

function endpoint(ip, port) {
  return port === null || port === undefined ? ip : `${ip}:${port}`;
}

// Fill a <tbody> with rows; each cell value is set with textContent.
function fillTable(tbodyId, rows, cells, rowClass) {
  const tbody = $(tbodyId);
  const columns = tbody.closest("table").querySelectorAll("th").length;
  const trs = rows.map((row) => {
    const tr = document.createElement("tr");
    if (rowClass) tr.className = rowClass(row) || "";
    for (const value of cells(row)) {
      const td = document.createElement("td");
      td.textContent = value === null || value === undefined ? "" : String(value);
      tr.appendChild(td);
    }
    return tr;
  });
  if (trs.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = columns;
    td.className = "empty";
    td.textContent = "Sin datos";
    tr.appendChild(td);
    trs.push(tr);
  }
  tbody.replaceChildren(...trs);
}

function option(value, text) {
  const opt = document.createElement("option");
  opt.value = value;
  opt.textContent = text;
  return opt;
}

// ---------- charts (RF10) ----------

const ppsChart = new Chart($("pps-chart"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "Paquetes/s", data: [], borderColor: "#1f6feb",
    backgroundColor: "rgba(31,111,235,.15)", fill: true, tension: 0.2, pointRadius: 2 }] },
  options: { animation: false, maintainAspectRatio: false, plugins: { legend: { display: false } },
    scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
});

const protoChart = new Chart($("proto-chart"), {
  type: "bar",
  data: { labels: [], datasets: [{ label: "Paquetes", data: [], backgroundColor: "#1f6feb" }] },
  options: { animation: false, maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { display: false } },
    scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } },
});

function updateCharts(stats) {
  ppsChart.data.labels = stats.packets_per_second.map((p) => fmtTime(p.second));
  ppsChart.data.datasets[0].data = stats.packets_per_second.map((p) => p.packets);
  ppsChart.update("none");
  protoChart.data.labels = Object.keys(stats.protocols);
  protoChart.data.datasets[0].data = Object.values(stats.protocols);
  protoChart.update("none");
}

// ---------- status, settings, capture ----------

function renderStatus(status) {
  $("warning-text").textContent = status.warning;
  $("accept-warning").checked = status.warning_accepted;
  $("privileges").textContent = status.privileges
    ? "Sí"
    : "No (Mac: sudo; Windows: Npcap + administrador). El análisis de .pcap sigue disponible.";

  const running = status.capture.running;
  $("capture-state").textContent = running ? `Capturando en ${status.capture.iface}` : "Detenida";
  $("capture-state").className = "pill" + (running ? " on" : "");
  $("capture-start").disabled = running || !status.warning_accepted || status.networks.length === 0;
  $("capture-stop").disabled = !running;
  $("capture-start").title = !status.warning_accepted ? "Acepte la advertencia primero"
    : status.networks.length === 0 ? "Declare al menos una red de laboratorio" : "";

  const select = $("session");
  const chosen = select.value;
  select.replaceChildren(option("", "Última (automático)"), ...status.sessions.map((s) =>
    option(String(s.id), `#${s.id} · ${s.name} (${s.source === "live" ? "en vivo" : "archivo"})`)));
  select.value = status.sessions.some((s) => String(s.id) === chosen) ? chosen : "";

  return select.value ? Number(select.value) : (status.capture.session_id || status.latest_session_id);
}

async function loadSettings() {
  const s = await api("/api/settings");
  $("networks").value = s.networks.join("\n");
  $("gateway").value = s.gateway || "";
}

async function loadInterfaces() {
  const list = await api("/api/interfaces");
  list.sort((a, b) => Number(b.in_lab) - Number(a.in_lab));
  $("iface").replaceChildren(...list.map((i) =>
    option(i.name, `${i.in_lab ? "★ " : ""}${i.name}${i.ip ? " — " + i.ip : ""}`)));
}

$("save-settings").addEventListener("click", async () => {
  const networks = $("networks").value.split(/[\n,]+/).map((n) => n.trim()).filter(Boolean);
  try {
    await postJSON("/api/settings", { networks, gateway: $("gateway").value.trim() });
    await Promise.all([loadSettings(), loadInterfaces()]);
    showMessage("Configuración guardada.");
    refresh();
  } catch (e) { showMessage(e.message, true); }
});

$("accept-warning").addEventListener("change", async (ev) => {
  try {
    await postJSON("/api/settings", { warning_accepted: ev.target.checked });
    refresh();
  } catch (e) { showMessage(e.message, true); }
});

$("capture-start").addEventListener("click", async () => {
  try {
    const r = await postJSON("/api/capture/start", { iface: $("iface").value });
    $("session").value = "";
    showMessage(`Captura iniciada en ${r.iface} (sesión #${r.session_id}).`);
    refresh();
  } catch (e) { showMessage(e.message, true); }
});

$("capture-stop").addEventListener("click", async () => {
  try {
    const r = await postJSON("/api/capture/stop", {});
    showMessage(`Captura detenida: ${r.summary.analyzed} paquetes analizados, ${r.summary.alerts} alertas.`);
    refresh();
  } catch (e) { showMessage(e.message, true); }
});

$("upload").addEventListener("click", async () => {
  const file = $("pcap-file").files[0];
  if (!file) { showMessage("Seleccione un archivo .pcap.", true); return; }
  const form = new FormData();
  form.append("file", file);
  $("upload").disabled = true;
  showMessage("Analizando…");
  try {
    const r = await api("/api/upload", { method: "POST", body: form });
    $("session").value = "";
    showMessage(`Archivo analizado (sesión #${r.session_id}): ${r.analyzed} paquetes, ` +
      `${r.discarded} descartados, ${r.alerts} alertas.`);
    refresh();
  } catch (e) { showMessage(e.message, true); }
  finally { $("upload").disabled = false; }
});

$("session").addEventListener("change", () => refresh());
$("packet-filters").addEventListener("submit", (ev) => { ev.preventDefault(); refresh(); });
$("packet-filters").addEventListener("reset", () => setTimeout(refresh, 0));

// ---------- data tables ----------

function packetsQuery(sid) {
  const params = new URLSearchParams({ session: sid, limit: 200 });
  const ip = $("f-ip").value.trim();
  const protocol = $("f-protocol").value.trim();
  const port = $("f-port").value.trim();
  if (ip) params.set("ip", ip);
  if (protocol) params.set("protocol", protocol);
  if (port) params.set("port", port);
  return "/api/packets?" + params;
}

function setExportLinks(sid) {
  for (const a of document.querySelectorAll("[data-export]")) {
    if (sid) a.href = `/api/export/${a.dataset.export}?session=${sid}`;
    else a.removeAttribute("href");
  }
}

function clearData() {
  for (const id of ["alerts-body", "conversations-body", "ipmac-body", "credentials-body", "packets-body"]) {
    fillTable(id, [], () => []);
  }
  for (const id of ["c-total", "c-analyzed", "c-discarded", "c-alerts", "c-credentials"]) $(id).textContent = "0";
  updateCharts({ packets_per_second: [], protocols: {} });
}

async function loadSessionData(sid) {
  const q = `?session=${sid}`;
  const [stats, alerts, convs, ipmac, creds] = await Promise.all([
    api("/api/stats" + q), api("/api/alerts" + q), api("/api/conversations" + q),
    api("/api/ip-mac" + q), api("/api/credentials" + q),
  ]);

  const live = stats.live;
  const total = live ? live.total : stats.session.total;
  const discarded = live ? live.discarded : stats.session.discarded;
  $("c-total").textContent = total;
  $("c-analyzed").textContent = total - discarded;
  $("c-discarded").textContent = discarded;
  $("c-alerts").textContent = stats.alerts;
  $("c-credentials").textContent = stats.credentials;
  updateCharts(stats);

  fillTable("alerts-body", [...alerts].reverse(), (a) => [fmtTime(a.ts), a.severity.toUpperCase(), a.type, a.detail],
    (a) => (a.severity === "crítica" ? "sev-critica" : "sev-alta"));
  fillTable("conversations-body", convs, (c) => [c.ip_a, c.ip_b, c.packets, c.bytes]);
  const macsPerIp = {};
  for (const r of ipmac) macsPerIp[r.ip] = (macsPerIp[r.ip] || 0) + 1;
  fillTable("ipmac-body", ipmac, (r) => [r.ip, r.mac, fmtTime(r.first_seen), fmtTime(r.last_seen)],
    (r) => (macsPerIp[r.ip] > 1 ? "conflict" : ""));
  fillTable("credentials-body", creds, (c) => [fmtTime(c.ts), c.protocol, c.src_ip, endpoint(c.dst_ip, c.dport),
    c.username || "(desconocido)", c.password_masked]);

  try {
    const packets = await api(packetsQuery(sid));
    fillTable("packets-body", packets, (p) => [fmtTime(p.ts, true), p.protocol, endpoint(p.src_ip, p.sport),
      endpoint(p.dst_ip, p.dport), p.tcp_flags, p.length]);
  } catch (e) {
    showMessage(e.message, true);  // e.g. invalid filter
  }
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const sid = renderStatus(await api("/api/status"));
    if (sid !== currentSession && sid) setExportLinks(sid);
    currentSession = sid;
    if (sid) await loadSessionData(sid);
    else { clearData(); setExportLinks(null); }
  } catch (e) {
    showMessage("No se pudo actualizar: " + e.message, true);
  } finally {
    refreshing = false;
  }
}

// ---------- start ----------

Promise.all([loadSettings(), loadInterfaces()]).catch((e) => showMessage(e.message, true));
refresh();
setInterval(refresh, REFRESH_MS);
