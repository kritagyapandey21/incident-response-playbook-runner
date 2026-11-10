"use strict";
/* Playbook Runner console. Served from /app.js so the page can use a strict CSP (no inline script). */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const store = {
  get(area, k) { try { return window[area].getItem(k); } catch (e) { return null; } },
  set(area, k, v) { try { v == null ? window[area].removeItem(k) : window[area].setItem(k, v); } catch (e) { /* storage unavailable */ } },
};
const state = { alerts: [], current: null, alertMeta: null, tlFilter: "all", animate: false, loadTimer: null, evalTimer: null, flashStep: null };

/* ================================================================ auth + API */
(function captureToken() {
  const m = location.hash.match(/token=([\w-]+)/);
  if (m) {
    store.set("sessionStorage", "irp-token", m[1]);
    history.replaceState(null, "", location.pathname + location.search);   // keep the token out of history/screenshots
  }
})();
const token = () => store.get("sessionStorage", "irp-token") || "";

class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function api(path, body) {
  const opts = { headers: { "X-Console-Token": token() } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, opts); } catch (e) { throw new ApiError(0, "Cannot reach the console server. Is webapp.py running?"); }
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (res.status === 401) { showLocked(); throw new ApiError(401, "Console token missing or invalid"); }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText);
  return data;
}

function showLocked() {
  openModal(`
    <h2 id="modal-title">Console locked</h2>
    <p>Open the exact link printed in the terminal where <code>python webapp.py</code> is running
       (it ends in <code>#token=…</code>), or paste the token here.</p>
    <form id="token-form" class="form-row">
      <input id="token-input" class="input" autocomplete="off" spellcheck="false" placeholder="console token" aria-label="Console token">
      <button class="btn primary" type="submit">Unlock</button>
    </form>`, { dismissable: false });
  $("#token-form").onsubmit = (e) => {
    e.preventDefault();
    const v = $("#token-input").value.trim().replace(/^.*token=/, "");
    if (!v) return;
    store.set("sessionStorage", "irp-token", v);
    closeModal();
    boot();
  };
}

/* ================================================================ toast */
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 2800);
}

/* ================================================================ theme */
(function initTheme() {
  const saved = store.get("localStorage", "irp-theme");
  if (saved) document.documentElement.dataset.theme = saved;
  $("#theme").onclick = () => {
    const cur = document.documentElement.dataset.theme;
    const dark = cur ? cur === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = dark ? "light" : "dark";
    store.set("localStorage", "irp-theme", dark ? "light" : "dark");
  };
})();

/* ================================================================ analyst identity */
const analyst = () => store.get("localStorage", "irp-analyst") || "";
function renderAnalyst() {
  $("#analyst").innerHTML = analyst()
    ? `<span class="dot"></span>${esc(analyst())}`
    : `<span class="dot off"></span>Set analyst name`;
}
function askAnalyst() {
  return new Promise((resolve) => {
    openModal(`
      <h2 id="modal-title">Who is approving?</h2>
      <p>Approvals and rejections are recorded on the incident timeline under this name.</p>
      <form id="analyst-form" class="form-row">
        <input id="analyst-input" class="input" maxlength="64" placeholder="e.g. Kritagya Pandey" value="${esc(analyst())}" aria-label="Analyst name">
        <button class="btn primary" type="submit">Save</button>
      </form>
      <p id="analyst-err" class="bad" style="margin-top:8px" hidden></p>`, { onClose: () => resolve(analyst() || null) });
    $("#analyst-form").onsubmit = (e) => {
      e.preventDefault();
      const v = $("#analyst-input").value.trim();
      if (!/^[\w.@\- ]{2,64}$/.test(v)) {
        $("#analyst-err").hidden = false;
        $("#analyst-err").textContent = "2-64 characters: letters, digits, space, . _ @ -";
        return;
      }
      store.set("localStorage", "irp-analyst", v);
      renderAnalyst();
      closeModal();
    };
  });
}
$("#analyst").onclick = () => askAnalyst();

/* ================================================================ tabs */
$$("nav button").forEach((b) => (b.onclick = () => {
  $$("nav button").forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-selected", x === b); });
  $("#tab-console").hidden = b.dataset.tab !== "console";
  $("#tab-eval").hidden = b.dataset.tab !== "eval";
  if (b.dataset.tab === "eval") loadEval();
}));

/* ================================================================ skeleton helpers */
const sk = (cls, style = "") => `<span class="skel ${cls}" style="${style}"></span>`;
const SHIELD = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
const LOADER = `<div class="loader" aria-hidden="true"><div class="ring"></div><div class="ring2"></div>${SHIELD}</div>`;
const STAGES = [
  ["Planner", "Planning the workflow"],
  ["Alert Parser", "Normalising the raw alert"],
  ["Threat Intel", "Searching 12 threat reports"],
  ["Impact Assessor", "Querying the asset inventory"],
  ["Containment Planner", "Drafting cited containment steps"],
  ["Incident Commander", "Reviewing the plan and executing"],
];
function skeletonList(n, wide = 60) {
  return Array.from({ length: n }, (_, i) =>
    `<li class="sk-alert" aria-hidden="true"><span class="skel"></span>${sk("sk-line", `width:${wide + (i * 37) % 30}%;margin:0`)}${sk("sk-line", `width:${35 + (i * 23) % 20}%;height:9px;margin:0`)}</li>`).join("");
}

/* ================================================================ alerts + history */
async function loadAlerts() {
  $("#alerts").innerHTML = skeletonList(10);
  state.alerts = await api("/api/alerts");
  $("#alert-count").textContent = state.alerts.length;
  $("#alerts").innerHTML = state.alerts.map((a, i) => `
    <li class="reveal" style="animation-delay:${i * 35}ms"><button data-id="${esc(a.alert_id)}">
      <span class="aid">${esc(a.alert_id)}</span>
      <span class="at">${esc(a.title)}</span>
      <span class="as">${esc(a.source)}${a.vendor_severity ? " · vendor: " + esc(a.vendor_severity) : ""}</span>
    </button></li>`).join("");
  $$("#alerts button").forEach((b) => (b.onclick = () => runAlert(b.dataset.id, b)));
}

async function loadHistory() {
  const list = $("#history");
  try {
    const items = await api("/api/incidents");
    $("#history-count").textContent = items.length || "";
    list.innerHTML = items.length ? items.slice(0, 12).map((x) => `
      <li><button data-inc="${esc(x.incident_id)}" class="${state.current?.incident_id === x.incident_id ? "on" : ""}">
        <span class="hsev ${x.severity ? "s-" + esc(x.severity) : ""}">${esc(x.severity ? x.severity[0] : "!")}</span>
        <span class="at">${esc(x.title)}</span>
        <span class="as mono">${esc(x.incident_id)}${x.pending ? ` · <b class="warn">${x.pending} pending</b>` : ""}${x.escalated ? ` · <b class="bad">escalated</b>` : ""}</span>
      </button></li>`).join("") : `<li class="none" style="padding:4px 10px 10px">No incidents yet</li>`;
    $$("#history button").forEach((b) => (b.onclick = () => openIncident(b.dataset.inc)));
  } catch (e) {
    if (e.status !== 401) list.innerHTML = `<li class="none" style="padding:4px 10px 10px">${esc(e.message)}</li>`;
  }
}

function selectAlertButton(id) { $$("#alerts button").forEach((x) => x.classList.toggle("on", x.dataset.id === id)); }

async function runAlert(id) {
  selectAlertButton(id);
  state.alertMeta = state.alerts.find((a) => a.alert_id === id) || null;
  await run({ alert_id: id }, id);
}
$("#run-custom").onclick = async () => {
  const raw = $("#custom").value.trim();
  if (!raw) return toast("Paste an alert first");
  selectAlertButton(null);
  state.alertMeta = null;
  await run({ raw }, "custom alert");
};
$("#sample").onclick = () => {
  $("#custom").value = JSON.stringify({
    source: "EDR-Falcon", title: "Suspicious beacon", hostname: "WS-1042", dest_ip: "45.9.148.3",
    details: "Process rundll32 making HTTPS callbacks every 30 seconds with jitter to a rare domain update-svc.example; possible command and control implant",
    vendor_severity: "medium" }, null, 2);
};

async function openIncident(id) {
  showRunLoading(id, true);
  try {
    const [data] = await Promise.all([api(`/api/incidents/${encodeURIComponent(id)}`), wait(400)]);
    clearInterval(state.loadTimer);
    state.alertMeta = state.alerts.find((a) => a.alert_id === data.alert_id) || null;
    selectAlertButton(state.alertMeta ? data.alert_id : null);
    state.current = data; state.tlFilter = "all"; state.animate = true;
    render(); loadHistory();
  } catch (e) { showError(e); }
}

/* ================================================================ run with loading state */
function skeletonIncident() {
  return `
    <div class="panel inc" aria-hidden="true">
      <div>${sk("sk-line", "width:140px")}${sk("sk-title")}<div>${sk("sk-pill", "width:230px")}${sk("sk-pill")}${sk("sk-pill", "width:90px")}</div></div>
      <div style="min-width:160px">${sk("sk-badge")}${sk("sk-line", "width:150px;margin-left:auto")}</div>
    </div>
    <div class="panel" aria-hidden="true"><div class="panel-h">${sk("sk-line", "width:120px")}</div>
      <div class="pipe">${STAGES.map(() => sk("sk-box")).join("")}</div></div>
    <div class="grid2" aria-hidden="true">${[2, 1].map((n) => `<div class="panel"><div class="panel-h">${sk("sk-line", "width:110px")}</div>
      <div class="panel-b assets">${Array.from({ length: n }, () => sk("sk-box", "height:56px")).join("")}</div></div>`).join("")}</div>
    <div class="panel" aria-hidden="true"><div class="panel-h">${sk("sk-line", "width:170px")}</div>
      <div style="padding:0 6px 6px">${Array.from({ length: 5 }, (_, i) => `<div class="sk-row">${sk("sk-line")}${sk("sk-line")}
        <div>${sk("sk-line", `width:${40 + i * 7}%`)}${sk("sk-line", `width:${70 + (i % 3) * 8}%;height:9px`)}</div>${sk("sk-line")}${sk("sk-line", "height:20px;border-radius:6px")}</div>`).join("")}</div></div>`;
}

function showRunLoading(label, quiet = false) {
  clearInterval(state.loadTimer);
  $("#result").setAttribute("aria-busy", "true");
  $("#result").innerHTML = `
    <div class="panel runcard reveal" role="status">
      ${LOADER}
      <div>
        <h2>${quiet ? "Loading" : "Triaging"} ${esc(label)}</h2>
        <div class="sub" id="run-sub">${quiet ? "Reading the incident timeline…" : "Starting agents…"}</div>
        <div class="progress"><i id="run-bar"></i></div>
        ${quiet ? "" : `<div class="stages">${STAGES.map(([n]) => `<span>${n}</span>`).join("")}</div>`}
      </div>
    </div>${skeletonIncident()}`;
  if (quiet) { requestAnimationFrame(() => { const b = $("#run-bar"); if (b) b.style.width = "70%"; }); return; }
  let i = 0;
  const tick = () => {
    const chips = $$(".stages span");
    if (!chips.length) return clearInterval(state.loadTimer);
    chips.forEach((c, j) => { c.classList.toggle("done", j < i); c.classList.toggle("active", j === i); });
    $("#run-sub").innerHTML = `<b>${STAGES[i][0]}</b> · ${STAGES[i][1]}…`;
    $("#run-bar").style.width = `${Math.min(92, ((i + 1) / STAGES.length) * 92)}%`;
    i = Math.min(i + 1, STAGES.length - 1);
  };
  tick();
  state.loadTimer = setInterval(tick, 260);
}
async function finishRunLoading() {
  clearInterval(state.loadTimer);
  $$(".stages span").forEach((c) => { c.classList.remove("active"); c.classList.add("done"); });
  const bar = $("#run-bar"); if (bar) bar.style.width = "100%";
  const sub = $("#run-sub"); if (sub) sub.innerHTML = "<b>Done</b> · rendering incident report";
  await wait(280);
}
function showError(e) {
  clearInterval(state.loadTimer);
  $("#result").removeAttribute("aria-busy");
  if (e.status === 401) return;
  $("#result").innerHTML = `<div class="panel hero reveal" role="alert"><h1>Something went wrong</h1><p class="bad">${esc(e.message)}</p></div>`;
}

async function run(body, label) {
  showRunLoading(label);
  try {
    const [data] = await Promise.all([api("/api/run", body), wait(1650)]);
    await finishRunLoading();
    state.current = data; state.tlFilter = "all"; state.animate = true;
    render(); loadHistory();
  } catch (e) { showError(e); }
}

/* ================================================================ render incident */
const latest = (tl, ev) => { for (let i = tl.length - 1; i >= 0; i--) if (tl[i].event === ev) return tl[i].data; return null; };
const STATUS_LABEL = { pending_approval: "awaiting approval" };
const SEVERITIES = ["Low", "Medium", "High", "Critical"];
const sevClass = (s) => (SEVERITIES.includes(s) ? s : "Medium");
const critClass = (c) => (["low", "medium", "high", "critical"].includes(c) ? c : "medium");

function render() {
  const { report, timeline, incident_id, escalated } = state.current;
  $("#result").removeAttribute("aria-busy");
  if (!report) {
    $("#result").innerHTML = `
      <div class="panel hero reveal" role="alert">
        <div class="meta mono">${esc(incident_id)}</div>
        <h1>Escalated to a human analyst</h1>
        <p>${esc(escalated?.reason || "The workflow could not produce a safe, grounded plan.")} No containment step was executed.</p>
        ${escalated?.issues?.length ? `<ul class="checks">${escalated.issues.map((i) => `<li><span class="bad">✗</span><span>${esc(i)}</span></li>`).join("")}</ul>` : ""}
      </div>${timelinePanel(timeline)}`;
    bindTimeline();
    return;
  }
  const gt = state.alertMeta?.ground_truth;
  const inc = latest(timeline, "incident_record_created") || {};
  const pending = report.containment_steps.filter((s) => s.status === "pending_approval");
  const sev = sevClass(report.severity);
  const sevCheck = gt ? `<div class="gt ${gt.severity === report.severity ? "good" : "bad"}">${gt.severity === report.severity ? "✓ matches" : "✗ expected"} ground truth (${esc(gt.severity)})</div>` : "";
  const intelChip = report.intel_primary_source
    ? `<button class="chip" data-cite="${esc(report.intel_primary_source)}">Intel <b>${esc(report.intel_primary_source)}</b> ${esc(report.intel_title)}</button>`
    : `<span class="chip">Intel <b>no match</b></span>`;

  $("#result").innerHTML = `
    <div class="panel inc">
      <div>
        <div class="meta">${esc(incident_id)} · ${esc(inc.source)}</div>
        <h1>${esc(report.title)}</h1>
        <div class="chips">
          ${intelChip}
          <span class="chip">Match confidence <b class="${report.intel_confidence === "low" ? "bad" : ""}">${esc(report.intel_confidence)}</b></span>
          <span class="chip">Signal <b>${esc(inc.status_signal)}</b></span>
          ${report.plan_revisions > 1 ? `<span class="chip">Plan revisions <b>${esc(report.plan_revisions)}</b></span>` : ""}
        </div>
      </div>
      <div class="sev">
        <div class="badge s-${sev}">${esc(report.severity)}</div>
        <div class="why">${esc(report.severity_rationale)}</div>
        ${sevCheck}
      </div>
    </div>

    <div class="panel">
      <div class="panel-h"><h3>Agent pipeline</h3><span class="count">planner → executor</span></div>
      <div class="pipe" id="pipe">${pipeline(timeline, report)}</div>
    </div>

    ${pending.length ? `<div class="banner" role="status">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>
      <div><b>${pending.length} step${pending.length > 1 ? "s are" : " is"} waiting for your approval.</b>
      <div class="banner-sub">The safety guard blocks these until a named analyst approves. Recovery steps on the same target wait too.
      ${analyst() ? `Deciding as <b>${esc(analyst())}</b>.` : `<button class="linkbtn" id="set-analyst">Set your analyst name</button> to decide.`}</div></div>
    </div>` : ""}

    <div class="grid2">
      <div class="panel"><div class="panel-h"><h3>Affected assets</h3><span class="count">${report.affected_assets.length}</span></div>
        <div class="panel-b assets">${report.affected_assets.map(assetCard).join("") || `<div class="none">None identified in the inventory</div>`}</div></div>
      <div class="panel"><div class="panel-h"><h3>At-risk assets</h3><span class="count">${report.at_risk_assets.length}</span></div>
        <div class="panel-b assets">${report.at_risk_assets.map(assetCard).join("") || `<div class="none">No dependent assets</div>`}</div></div>
    </div>

    <div class="panel">
      <div class="panel-h"><h3>Ordered containment plan</h3><span class="count">${report.containment_steps.length} steps</span></div>
      <div style="padding:0 6px 6px;overflow-x:auto">
        <table class="plan">
          <thead><tr><th scope="col">#</th><th scope="col">Phase</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Intel source</th><th scope="col">Status</th></tr></thead>
          <tbody>${report.containment_steps.map(planRow).join("")}</tbody>
        </table>
      </div>
      ${report.review_warnings.length ? `<div class="panel-b"><p class="note">${report.review_warnings.map(esc).join("<br>")}</p></div>` : ""}
    </div>

    ${timelinePanel(timeline)}`;

  $$("[data-cite]").forEach((b) => (b.onclick = () => openReport(b.dataset.cite, b.dataset.num, b)));
  $$("[data-decide]").forEach((b) => (b.onclick = () => decide(b.dataset.step, b.dataset.decide === "yes", b)));
  const sa = $("#set-analyst"); if (sa) sa.onclick = async () => { await askAnalyst(); render(); };
  bindTimeline();
  if (state.animate) {
    [...$("#result").children].forEach((el, i) => { el.classList.add("reveal"); el.style.animationDelay = `${i * 70}ms`; });
    $(".sev .badge")?.classList.add("reveal-badge");
    animatePipe();
    state.animate = false;
  }
  if (state.flashStep) {
    $$("tr[data-row]").find((tr) => tr.dataset.row === state.flashStep)?.classList.add("flash");
    state.flashStep = null;
  }
}

function assetCard(a) {
  return `<div class="asset"><span class="id">${esc(a.asset_id)}</span><span class="crit c-${critClass(a.criticality)}">${esc(a.criticality)}</span>
    <span class="d">${esc(a.description || "")} · ${esc(a.reason)}</span></div>`;
}

function planRow(s) {
  const num = (String(s.intel_section).match(/#(\d+)/) || [])[1] || "";
  const decideBtns = s.status === "pending_approval" ? `<div class="decide">
      <button class="btn ok sm" data-decide="yes" data-step="${esc(s.step_id)}">Approve</button>
      <button class="btn no sm" data-decide="no" data-step="${esc(s.step_id)}">Reject</button></div>` : "";
  const label = STATUS_LABEL[s.status] || s.status;
  const shortTarget = /^[a-f0-9]{40,}$/i.test(s.target) ? s.target.slice(0, 12) + "…" + s.target.slice(-6) : s.target;
  const gated = s.approval_reason && s.status === "pending_approval" ? `<div class="result">needs approval: ${esc(s.approval_reason)}</div>` : "";
  return `<tr data-row="${esc(s.step_id)}" class="${s.destructive ? "destr" : ""}">
    <td class="ord">${esc(s.order)}</td>
    <td><span class="phase">${esc(s.phase)}</span></td>
    <td><div class="act">${esc(s.action)}${s.destructive ? `<span class="tag-d">DESTRUCTIVE</span>` : ""}</div><div class="desc">${esc(s.description)}</div></td>
    <td class="tgt" title="${esc(s.target)}">${esc(shortTarget)}</td>
    <td><button class="cite" data-cite="${esc(s.intel_source)}" data-num="${esc(num)}" title="${esc(s.intel_section)}">${esc(s.intel_source)} · RC #${esc(num)}</button></td>
    <td><span class="status st-${esc(s.status)}">${esc(label)}</span>${gated}
      ${s.approved_by ? `<div class="result">approved by ${esc(s.approved_by)}</div>` : ""}
      ${s.result && !["executed", "pending_approval"].includes(s.status) ? `<div class="result">${esc(s.result)}</div>` : ""}${decideBtns}</td>
  </tr>`;
}

function pipeline(tl, report) {
  const inc = latest(tl, "incident_record_created") || {};
  const intel = latest(tl, "intel_retrieved") || {};
  const impact = latest(tl, "impact_assessed") || {};
  const plan = latest(tl, "containment_plan_drafted") || {};
  const tasks = tl.filter((e) => e.event === "task_completed").length;
  const executed = report.containment_steps.filter((s) => s.status === "executed").length;
  const ents = ["hosts", "users", "ips", "domains", "hashes", "files"].map((k) => (inc[k] || []).length).reduce((a, b) => a + b, 0);
  const nodes = [
    ["Planner", `${tasks} tasks run${tl.some((e) => e.event === "workflow_replanned") ? ", re-planned" : ""}`],
    ["Alert Parser", `${ents} entities · signal ${inc.status_signal || "?"}`],
    ["Threat Intel", `${intel.primary?.doc_id || "no match"} · score ${intel.primary?.score ?? "–"}`],
    ["Impact Assessor", `${(impact.affected_assets || []).length} assets · ${impact.severity || "?"}`],
    ["Containment Planner", `${(plan.steps || []).length} steps · ${(plan.skipped_templates || []).length} skipped`],
    ["Incident Commander", `${executed}/${report.containment_steps.length} executed`],
  ];
  return nodes.map(([n, o]) => `<div class="step done"><div class="n"><i aria-hidden="true">✓</i>${esc(n)}</div><div class="o">${esc(o)}</div></div>`).join("");
}
function animatePipe() {
  const steps = $$("#pipe .step");
  steps.forEach((s) => s.classList.remove("done"));
  steps.forEach((s, i) => setTimeout(() => {
    s.classList.add("active");
    setTimeout(() => { s.classList.remove("active"); s.classList.add("done"); }, 220);
  }, i * 260));
}

/* ================================================================ timeline */
function summarise(e) {
  const d = e.data || {};
  const c = (v) => `<code>${esc(v)}</code>`;
  switch (e.event) {
    case "alert_received": return "raw alert received";
    case "workflow_planned": return `planned ${d.length} tasks: ${esc(d.map((t) => t.agent.replace("Agent", "")).join(" → "))}`;
    case "workflow_replanned": return `added ${d.added.map((t) => `${c(t.task_id)} ${esc(t.goal)}`).join(", ")}`;
    case "task_started": return `${c(d.task_id)} started: ${esc(d.goal)}`;
    case "task_completed": return `${c(d.task_id)} completed`;
    case "task_failed": return `<b class="bad">${c(d.task_id)} FAILED</b>: ${esc(d.error)}`;
    case "tool_call": return `called ${c(d.tool)} ${esc(Object.entries(d.args).map(([k, v]) => `${k}=${String(v).slice(0, 40)}`).join(" "))}`;
    case "incident_record_created": return `incident record: ${d.hosts.length} hosts, ${d.users.length} users, ${d.ips.length} IPs, ${d.domains.length} domains · signal ${c(d.status_signal)}`;
    case "intel_retrieved": return d.primary ? `top match ${c(d.primary.doc_id)} (${esc(d.primary.score)}, ${esc(d.confidence)} confidence); candidates ${esc(d.candidates.map((x) => x.doc_id).join(", "))}` : `no matching threat report (${esc(d.confidence)} confidence)`;
    case "impact_assessed": return `severity ${c(d.severity)} · ${esc(d.affected_assets.map((a) => a.asset_id).join(", ") || "no inventory match")}`;
    case "containment_plan_drafted": return `draft #${esc(d.revision)}: ${d.steps.length} steps${d.addressed_feedback.length ? " (after Commander feedback)" : ""}`;
    case "plan_reviewed": return d.approved ? `plan approved (revision ${esc(d.revision_reviewed)})` : `plan <b class="bad">REJECTED</b>: ${esc(d.issues.join("; "))}`;
    case "approval_requested": return `approval requested for ${c(d.step_id)} ${esc(d.action)} → ${esc(d.target)} (${esc(d.why || "destructive")})`;
    case "approval_decision": return `${d.approved ? `<b class="good">APPROVED</b>` : `<b class="bad">REJECTED</b>`} ${c(d.step_id)} by ${esc(d.approver)} (${esc(d.reason)})`;
    case "step_executed": return `executed ${c(d.step_id)} ${esc(d.action)} → ${esc(d.target)}`;
    case "step_held": return `held ${c(d.step_id)} ${esc(d.action)} → ${esc(d.target)} until a human decides`;
    case "step_deferred": return `deferred ${c(d.step_id)} (waits on ${esc(d.waiting_on)})`;
    case "step_rejected": return `step ${c(d.step_id)} rejected by ${esc(d.approver)}`;
    case "step_blocked": return `<b class="bad">BLOCKED</b> ${c(d.step_id)}: ${esc(d.result)}`;
    case "step_failed": return `<b class="bad">FAILED</b> ${c(d.step_id)}: ${esc(d.error)}`;
    case "incident_report": return "incident report written";
    case "escalated_to_human": return `<b class="bad">escalated</b>: ${esc(d.reason)}`;
    default: return esc(e.event);
  }
}
function timelinePanel(tl) {
  const agents = [...new Set(tl.map((e) => e.agent))];
  return `<div class="panel" id="tl-panel">
    <div class="panel-h"><h3>Shared incident timeline</h3><span class="count">${tl.length} events</span></div>
    <div class="tl-filter" role="group" aria-label="Filter timeline by agent">${["all", ...agents].map((a) =>
      `<button data-ag="${esc(a)}" class="${state.tlFilter === a ? "on" : ""}" aria-pressed="${state.tlFilter === a}">${esc(a.replace("Agent", ""))}</button>`).join("")}</div>
    <ul class="tl">${tl.filter((e) => state.tlFilter === "all" || e.agent === state.tlFilter).map((e) =>
      `<li><span class="seq">#${esc(e.seq)}</span><span class="ag">${esc(e.agent.replace("Agent", ""))}</span><span class="ev">${summarise(e)}</span></li>`).join("")}</ul>
  </div>`;
}
function bindTimeline() {
  $$(".tl-filter button").forEach((b) => (b.onclick = () => {
    state.tlFilter = b.dataset.ag;
    $("#tl-panel").outerHTML = timelinePanel(state.current.timeline);
    bindTimeline();
  }));
}

/* ================================================================ approvals */
async function decide(stepId, approved, btn) {
  if (!analyst() && !(await askAnalyst())) return toast("An analyst name is required to approve or reject");
  const group = btn.closest(".decide");
  group.querySelectorAll("button").forEach((b) => (b.disabled = true));
  btn.innerHTML = `<span class="spin" aria-hidden="true"></span><span class="sr">Working</span>`;
  try {
    const data = await api("/api/decide", { incident_id: state.current.incident_id, step_id: stepId, approved, approver: analyst() });
    state.current.report = data.report; state.current.timeline = data.timeline;
    state.flashStep = stepId;
    render(); loadHistory();
    toast(`${stepId} ${approved ? "approved" : "rejected"} by ${analyst()}`);
  } catch (e) {
    toast(e.message);
    if (e.status === 409) {   // already decided elsewhere: refresh
      try { state.current = await api(`/api/incidents/${encodeURIComponent(state.current.incident_id)}`); } catch (_) { /* keep view */ }
    }
    render();
  }
}

/* ================================================================ modal (focus-managed) */
let modalReturn = null, modalOpts = {};
function openModal(html, opts = {}) {
  modalOpts = opts;
  modalReturn = document.activeElement;
  $("#modal-box").innerHTML = (opts.dismissable === false ? "" : `<button class="btn sm x" id="modal-close" aria-label="Close dialog">Close</button>`) + html;
  $("#modal").classList.add("open");
  $("#modal-close")?.addEventListener("click", closeModal);
  (opts.focus ? $(opts.focus) : $("#modal-box input, #modal-box button"))?.focus();
}
function closeModal() {
  if (!$("#modal").classList.contains("open")) return;
  $("#modal").classList.remove("open");
  const cb = modalOpts.onClose; modalOpts = {};
  modalReturn?.focus?.();
  cb?.();
}
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal" && modalOpts.dismissable !== false) closeModal(); });
document.addEventListener("keydown", (e) => {
  if (!$("#modal").classList.contains("open")) return;
  if (e.key === "Escape" && modalOpts.dismissable !== false) return closeModal();
  if (e.key === "Tab") {   // keep focus inside the dialog
    const f = $$("#modal-box button, #modal-box input, #modal-box [tabindex]").filter((el) => !el.disabled);
    if (!f.length) return;
    if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
  }
});

async function openReport(docId, num) {
  openModal(`<div aria-hidden="true">${sk("sk-title", "width:70%")}${sk("sk-line", "width:30%")}${sk("sk-line", "width:45%;margin-bottom:22px")}
    ${[92, 88, 95, 60].map((w) => sk("sk-line", `width:${w}%`)).join("")}<div style="height:16px"></div>
    ${[1, 2, 3, 4, 5].map((i) => sk("sk-line", `width:${70 + (i * 13) % 25}%;height:26px;border-radius:6px`)).join("")}</div>`);
  try {
    const [r] = await Promise.all([api(`/api/intel/${encodeURIComponent(docId)}`), wait(250)]);
    let html = `<h2 id="modal-title">${esc(docId)} · ${esc(r.title)}</h2>`;
    let inList = false;
    for (const line of r.text.split("\n").slice(1)) {
      const m = line.match(/^\s*(\d+)\.\s*\[(\w+)\]\s*(\w+)\s*\|\s*\w+\s*\|\s*([^|]+?)\s*(?:\|\s*(.+))?$/);
      if (m) {
        if (!inList) { html += "<ol>"; inList = true; }
        html += `<li class="${m[1] === num ? "hl" : ""}"><span class="phase">${esc(m[2])}</span> <code>${esc(m[3])}</code> ${esc(m[4].replace("{target}", "‹target›"))}${m[5] ? ` <span class="tag-opt">${esc(m[5])}</span>` : ""}</li>`;
        continue;
      }
      if (inList) { html += "</ol>"; inList = false; }
      if (line.startsWith("## ")) html += `<h4>${esc(line.slice(3))}</h4>`;
      else if (line.startsWith("**")) html += `<p>${esc(line).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")}</p>`;
      else if (line.trim()) html += `<p style="margin:0">${esc(line)}</p>`;
    }
    if (inList) html += "</ol>";
    if (!$("#modal").classList.contains("open")) return;
    $("#modal-box").innerHTML = `<button class="btn sm x" id="modal-close" aria-label="Close dialog">Close</button><div class="reveal">${html}</div>`;
    $("#modal-close").addEventListener("click", closeModal);
    $("#modal-close").focus();
    $("#modal-box .hl")?.scrollIntoView({ block: "center" });
  } catch (e) {
    if (e.status !== 401) $("#modal-box").innerHTML = `<button class="btn sm x" id="modal-close">Close</button><p class="bad">${esc(e.message)}</p>`;
    $("#modal-close")?.addEventListener("click", closeModal);
  }
}

/* ================================================================ evaluation */
function skeletonEval() {
  return `<div class="tiles" aria-hidden="true">${[0, 1, 2, 3].map(() => `<div class="panel tile">${sk("sk-line", "width:60%")}${sk("sk-title", "width:45%;height:32px;margin:10px 0")}${sk("sk-line", "width:70%;height:9px")}</div>`).join("")}</div>
    <div class="panel" aria-hidden="true"><div class="panel-h">${sk("sk-line", "width:130px")}</div><div style="padding:0 12px 10px">
      ${Array.from({ length: 10 }, (_, i) => `<div class="sk-evalrow">${[40, 70 + (i * 17) % 25, 60, 60, 50, 80, 40].map((w) => sk("sk-line", `width:${w}%;margin:0`)).join("")}</div>`).join("")}</div></div>
    <div class="grid2" aria-hidden="true">${[4, 6].map((n) => `<div class="panel"><div class="panel-h">${sk("sk-line", "width:150px")}</div><div class="panel-b">
      ${Array.from({ length: n }, (_, i) => sk("sk-line", `width:${65 + (i * 11) % 30}%`)).join("")}</div></div>`).join("")}</div>`;
}
const EVAL_STAGES = [["Pass A", "rejecting analyst on 10 alerts"], ["Pass B", "approving analyst on 10 alerts"],
  ["Pass C", "adversarial calls to the response tool"], ["Pass D", "faulty plans vs. Commander review"], ["Report", "writing results"]];

async function loadEval(force = false) {
  const body = $("#eval-body"), btn = $("#rerun-eval");
  clearInterval(state.evalTimer);
  body.setAttribute("aria-busy", "true");
  if (force) {
    btn.disabled = true; btn.innerHTML = `<span class="spin" aria-hidden="true"></span>&nbsp; Running…`;
    body.innerHTML = `<div class="panel runcard reveal" role="status">${LOADER}
        <div><h2>Running the evaluation</h2><div class="sub" id="eval-sub"></div>
        <div class="progress"><i id="eval-bar"></i></div></div></div>${skeletonEval()}`;
    let i = 0;
    const tick = () => {
      if (!$("#eval-sub")) return clearInterval(state.evalTimer);
      $("#eval-sub").innerHTML = `<b>${EVAL_STAGES[i][0]}</b> · ${EVAL_STAGES[i][1]}…`;
      $("#eval-bar").style.width = `${((i + 1) / EVAL_STAGES.length) * 90}%`;
      i = Math.min(i + 1, EVAL_STAGES.length - 1);
    };
    tick(); state.evalTimer = setInterval(tick, 700);
  } else {
    body.innerHTML = skeletonEval();
  }
  try {
    const [r] = await Promise.all([force ? api("/api/eval", {}) : api("/api/eval"), wait(force ? 1200 : 450)]);
    clearInterval(state.evalTimer);
    if (!r) { body.innerHTML = `<div class="panel reveal" style="padding:20px">No results yet. Click <b>Re-run evaluation</b>.</div>`; return; }
    renderEval(r);
    [...body.children].forEach((el, i) => { el.classList.add("reveal"); el.style.animationDelay = `${i * 80}ms`; });
    if (force) toast("Evaluation complete");
  } catch (e) {
    clearInterval(state.evalTimer);
    if (e.status !== 401) body.innerHTML = `<div class="panel reveal" style="padding:20px" role="alert"><b class="bad">Error:</b> ${esc(e.message)}</div>`;
  } finally {
    body.removeAttribute("aria-busy");
    btn.disabled = false; btn.textContent = "Re-run evaluation";
  }
}
$("#rerun-eval").onclick = () => loadEval(true);

function renderEval(r) {
  const pct = (x) => `${Math.round(x * 100)}%`;
  const n = r.per_alert.length;
  const sevOk = r.per_alert.filter((x) => x.gt_severity === x.pred_severity).length;
  const s = r.safety;
  const ok = (b) => `<span class="${b ? "good" : "bad"}" aria-label="${b ? "pass" : "fail"}">${b ? "✓" : "✗"}</span>`;
  const sevPill = (v) => `<span class="crit c-${critClass(String(v).toLowerCase())}">${esc(v)}</span>`;
  $("#eval-body").innerHTML = `
    <div class="tiles">
      <div class="panel tile"><div class="k">Severity accuracy</div><div class="v">${pct(r.severity_accuracy)}</div><div class="s">${sevOk}/${n} · vendor baseline ${pct(r.vendor_severity_baseline_accuracy)}</div></div>
      <div class="panel tile"><div class="k">Steps citing correct intel</div><div class="v">${pct(r.citation_accuracy)}</div><div class="s">${esc(r.citation_counts[0])}/${esc(r.citation_counts[1])} containment steps</div></div>
      <div class="panel tile"><div class="k">Affected-asset recall</div><div class="v">${pct(r.asset_recall)}</div><div class="s">ground-truth assets found</div></div>
      <div class="panel tile"><div class="k">No destructive step without approval</div><div class="v ${r.no_destructive_step_without_approval ? "good" : "bad"}">${r.no_destructive_step_without_approval ? "PASS" : "FAIL"}</div><div class="s">4 independent checks</div></div>
    </div>
    <div class="panel">
      <div class="panel-h"><h3>Per-alert results</h3></div>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th scope="col">Alert</th><th scope="col">Title</th><th scope="col">Expected</th><th scope="col">Predicted</th><th scope="col">Vendor</th><th scope="col">Intel (exp → got)</th><th scope="col">Cited correctly</th><th scope="col">Assets</th><th scope="col">Destructive held</th></tr></thead>
        <tbody>${r.per_alert.map((x) => `<tr>
          <td class="mono">${esc(x.alert)}</td><td>${esc(x.title)}</td>
          <td>${sevPill(x.gt_severity)}</td>
          <td>${sevPill(x.pred_severity)} ${ok(x.gt_severity === x.pred_severity)}</td>
          <td style="color:var(--muted)">${esc(x.vendor_severity)}</td>
          <td class="mono">${esc(x.gt_source)} → ${esc(x.pred_source)} ${ok(x.gt_source === x.pred_source)}</td>
          <td>${esc(x.steps_correct_source)}/${esc(x.steps)}</td><td>${esc(x.assets_found)}</td>
          <td>${x.destructive_proposed ? `${x.destructive_proposed - x.destructive_executed}/${x.destructive_proposed}` : "—"}</td></tr>`).join("")}</tbody>
      </table></div>
    </div>
    <div class="grid2">
      <div class="panel"><div class="panel-h"><h3>Safety guard checks</h3></div><div class="panel-b">
        <ul class="checks">
          <li>${ok(s.deny_run.destructive_executed === 0)}<span><b>Rejecting analyst:</b> ${esc(s.deny_run.destructive_proposed)} destructive steps proposed, ${esc(s.deny_run.destructive_executed)} executed</span></li>
          <li>${ok(!s.approve_run.violations.length && !s.approve_run.tool_log_unapproved)}<span><b>Approving analyst:</b> ${esc(s.approve_run.destructive_executed)} executed, ${esc(s.approve_run.preceded_by_approval)} preceded by a matching approval</span></li>
          <li>${ok(s.adversarial_pass)}<span><b>Direct calls to the response tool</b> with bad tokens all blocked</span></li>
          <li>${ok(s.faulty_plan_pass)}<span><b>Faulty plan</b> (destructive steps mislabelled) rejected by the Commander</span></li>
        </ul></div></div>
      <div class="panel"><div class="panel-h"><h3>Adversarial tool calls</h3></div><div class="panel-b">
        <ul class="checks">${Object.entries(s.adversarial).map(([k, v]) => {
          const expectRun = k.startsWith("legitimate");
          return `<li>${ok(v.executed === expectRun)}<span><b>${esc(k)}</b>: ${v.executed ? "executed" : "blocked"} <span style="color:var(--faint)">· ${esc(v.reason)}</span></span></li>`;
        }).join("")}</ul></div></div>
    </div>
    <p class="note">The alerts, threat reports and severity rubric were written together, so these scores show the system works on this set, not that it generalises. With the IOC boost turned off, retrieval still ranks the correct report first for all 10 alerts.</p>`;
}

/* ================================================================ boot */
async function boot() {
  renderAnalyst();
  if (!token()) return showLocked();
  try {
    await loadAlerts();
    loadHistory();
    const q = new URLSearchParams(location.search);   // deep links: ?alert=A05, ?incident=<id>, ?tab=eval
    if (q.get("alert")) {
      const id = q.get("alert").toUpperCase();
      if (state.alerts.some((a) => a.alert_id === id)) runAlert(id);
    } else if (q.get("incident")) {
      openIncident(q.get("incident"));
    }
    if (q.get("tab") === "eval") $('nav button[data-tab="eval"]').click();
  } catch (e) {
    if (e.status !== 401) {
      $("#alerts").innerHTML = `<li class="none" style="padding:4px 10px 10px">${esc(e.message)}</li>`;
      toast(e.message);
    }
  }
}
boot();
