// BlueCell - runs & cost dashboard
// WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
// Built by Harikishore Karunanithi. MIT - attribution required.
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => Number(n || 0);
const money = (n) => "$" + num(n).toFixed(4);
const tokTotal = (s) => num((s.tokens || {}).total);
const secs = (ms) => (num(ms) / 1000).toFixed(1);

function inputLabel(inputs) {
  inputs = (inputs || []).map((p) => String(p).replace(/\/+$/, ""));
  if (!inputs.length) return "-";
  const base = (p) => p.split("/").pop() || p;
  if (inputs.length === 1) return base(inputs[0]);
  const parents = new Set(inputs.map((p) => p.slice(0, p.lastIndexOf("/"))));
  if (parents.size === 1) return base([...parents][0]) + "/ (" + inputs.length + " files)";
  return base(inputs[0]) + " +" + (inputs.length - 1);
}

function costCell(s) {
  return esc(num(s.total_cost_usd).toFixed(4) + (s.cost_estimated ? "~" : ""));
}

let RUNS = [];

async function load() {
  $("runs-body").innerHTML = "";
  try {
    const r = await fetch("/api/runs?limit=200");
    const data = await r.json();
    RUNS = Array.isArray(data.runs) ? data.runs : [];
  } catch (e) {
    RUNS = [];
    $("kpis").innerHTML = `<div class="empty">Could not load runs: ${esc(e.message)}</div>`;
    return;
  }
  renderKpis(); renderChart(); renderTable();
  if (RUNS.length) select(RUNS[0].run_id);
}

function renderKpis() {
  const n = RUNS.length;
  const cost = RUNS.reduce((a, s) => a + num(s.total_cost_usd), 0);
  const tokens = RUNS.reduce((a, s) => a + tokTotal(s), 0);
  const tools = RUNS.reduce((a, s) => a + num(s.tool_calls), 0);
  const meanMs = n ? RUNS.reduce((a, s) => a + num(s.duration_ms), 0) / n : 0;
  const est = RUNS.some((s) => s.cost_estimated);
  const k = (label, value, note) =>
    `<div class="kpi glass"><div class="k">${esc(label)}</div><div class="v">${esc(value)}</div>` +
    (note ? `<div class="n">${esc(note)}</div>` : "") + `</div>`;
  $("kpis").innerHTML =
    k("Runs", String(n), "most recent 200") +
    k("Total cost", money(cost), est ? "includes estimates (~)" : "reported / none") +
    k("Tokens", tokens.toLocaleString(), "input + output + cache") +
    k("Tool calls", tools.toLocaleString(), "by agents") +
    k("Mean duration", secs(meanMs) + " s", "per run");
}

function renderChart() {
  const host = $("chart-body");
  const runs = RUNS.slice().reverse();          // oldest -> newest
  if (!runs.length) { host.innerHTML = '<div class="empty">No traced runs yet. Run <code>bluecell analyze</code>.</div>'; return; }
  const W = 900, H = 220, L = 52, R = 10, T = 12, B = 28;
  const max = Math.max(...runs.map((s) => num(s.total_cost_usd)), 0);
  const top = max > 0 ? max * 1.1 : 1;
  const bw = (W - L - R) / runs.length;
  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Cost per run over time">`;
  svg += `<line class="axis" x1="${L}" y1="${H - B}" x2="${W - R}" y2="${H - B}"/>`;
  svg += `<line class="axis" x1="${L}" y1="${T}" x2="${L}" y2="${H - B}"/>`;
  for (const f of [0, 0.5, 1]) {
    const y = H - B - f * (H - B - T);
    svg += `<text x="${L - 6}" y="${y + 3}" text-anchor="end">${esc("$" + (top * f).toFixed(max > 0 && top < 0.1 ? 4 : 2))}</text>`;
  }
  runs.forEach((s, i) => {
    const c = num(s.total_cost_usd);
    const h = c > 0 ? Math.max(1.5, (c / top) * (H - B - T)) : 1.5;
    const x = L + i * bw + bw * 0.15;
    svg += `<rect class="bar${c > 0 ? "" : " zero"}" x="${x.toFixed(1)}" y="${(H - B - h).toFixed(1)}" ` +
      `width="${Math.max(1, bw * 0.7).toFixed(1)}" height="${h.toFixed(1)}">` +
      `<title>${esc((s.started || "").slice(0, 19) + " · " + money(c) + (s.cost_estimated ? " (estimated)" : "") + " · " + inputLabel(s.inputs))}</title></rect>`;
  });
  const first = (runs[0].started || "").slice(0, 10), last = (runs[runs.length - 1].started || "").slice(0, 10);
  svg += `<text x="${L}" y="${H - 8}">${esc(first)}</text>`;
  svg += `<text x="${W - R}" y="${H - 8}" text-anchor="end">${esc(last)}</text>`;
  svg += `</svg>`;
  host.innerHTML = svg;
  $("chart-sub").textContent = max > 0 ? `max ${money(max)} per run` : "no LLM spend recorded (rules-only runs)";
}

function renderTable() {
  const body = $("runs-body");
  if (!RUNS.length) { body.innerHTML = '<tr><td colspan="10" class="empty">No runs.</td></tr>'; return; }
  body.innerHTML = RUNS.map((s) => {
    const v = s.verdict || "-";
    return `<tr data-id="${esc(s.run_id)}">` +
      `<td>${esc((s.started || "").slice(0, 19).replace("T", " "))}</td>` +
      `<td title="${esc((s.inputs || []).join(", "))}">${esc(inputLabel(s.inputs))}</td>` +
      `<td><span class="vd ${esc(v)}">${esc(v)}</span></td>` +
      `<td>${esc(s.backbone || "-")}</td>` +
      `<td class="num">${esc(num(s.agents))}</td>` +
      `<td class="num">${esc(num(s.tool_calls))}</td>` +
      `<td class="num">${esc(num(s.llm_calls))}</td>` +
      `<td class="num">${esc(tokTotal(s).toLocaleString())}</td>` +
      `<td class="num">${costCell(s)}</td>` +
      `<td class="num">${esc(secs(s.duration_ms))}</td></tr>`;
  }).join("");
  body.querySelectorAll("tr[data-id]").forEach((tr) =>
    tr.addEventListener("click", () => select(tr.dataset.id)));
}

async function select(id) {
  document.querySelectorAll("#runs-body tr").forEach((tr) =>
    tr.classList.toggle("sel", tr.dataset.id === id));
  const host = $("detail-body");
  host.className = ""; host.textContent = "loading…";
  let run;
  try {
    const r = await fetch("/api/runs/" + encodeURIComponent(id));
    run = await r.json();
    if (!r.ok) throw new Error(run.error || r.status);
  } catch (e) {
    host.className = "empty"; host.textContent = "Could not load run: " + e.message; return;
  }
  const s = run.summary || {};
  $("detail-sub").textContent = `${s.run_id || id} · ${s.cost_note || ""}`;
  const agents = (s.per_agent || []).map((a) =>
    `<tr><td>T${esc(a.tier)}</td><td>${esc(a.agent)}</td><td>${esc(a.mode || "-")}</td>` +
    `<td class="num">${esc(num(a.tool_calls))}</td><td class="num">${esc(num(a.llm_calls))}</td>` +
    `<td class="num">${esc(num((a.tokens || {}).total).toLocaleString())}</td>` +
    `<td class="num">${esc(num(a.cost_usd).toFixed(4))}</td>` +
    `<td class="num">${esc(secs(a.duration_ms))}</td></tr>`).join("");
  host.innerHTML =
    `<div class="detail-grid"><div>` +
    `<p>${esc(inputLabel(s.inputs))} · verdict <span class="vd ${esc(s.verdict || "")}">${esc(s.verdict || "-")}</span> · ` +
    `${esc(secs(s.duration_ms))} s · ${esc(tokTotal(s).toLocaleString())} tokens · ${costCell(s)} USD</p>` +
    `<div class="tbl-wrap"><table class="runs"><thead><tr><th>Tier</th><th>Agent</th><th>Mode</th>` +
    `<th class="num">Tools</th><th class="num">LLM</th><th class="num">Tokens</th><th class="num">Cost $</th>` +
    `<th class="num">Secs</th></tr></thead><tbody>${agents || '<tr><td colspan="8" class="empty">no agents</td></tr>'}</tbody></table></div>` +
    `</div><div><div class="tree" id="tree"></div></div></div>`;
  renderTree(run, $("tree"));
}

function renderTree(run, host) {
  const spans = run.spans || [];
  const usageBy = {};
  (run.usage || []).forEach((u) => { (usageBy[u.span] = usageBy[u.span] || []).push(u); });
  const kids = {};
  spans.forEach((sp) => { (kids[sp.parent] = kids[sp.parent] || []).push(sp); });
  const lines = [];
  const walk = (parent, depth) => {
    (kids[parent] || []).forEach((sp) => {
      const a = sp.attributes || {};
      const us = usageBy[sp.id] || [];
      let extra = "";
      if (us.length) {
        const tok = us.reduce((x, u) => x + num((u.tokens || {}).total), 0);
        const cost = us.reduce((x, u) => x + num(u.cost_usd), 0);
        extra = ` · ${tok} tok · ${money(cost)}`;
      }
      const dur = sp.duration_ms == null ? "" : ` ${Math.round(sp.duration_ms)}ms`;
      const mode = a.mode ? ` mode=${a.mode}` : "";
      const err = a.error ? `<span class="err"> error=${esc(String(a.error).slice(0, 120))}</span>` : "";
      lines.push(`<div style="padding-left:${depth * 16}px"><span class="kind">[${esc(sp.kind)}]</span> ` +
        `${esc(sp.name)}${esc(dur + mode + extra)}${err}</div>`);
      walk(sp.id, depth + 1);
    });
  };
  walk(null, 0);
  host.innerHTML = lines.join("") || '<div class="empty">no spans</div>';
}

$("reload").addEventListener("click", load);
load();
