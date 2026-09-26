// BlueCell — futuristic command deck
// WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
// Built by Harikishore Karunanithi. MIT - attribution required.
"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => { const n = document.createElement(tag);
  if (cls) n.className = cls; if (html !== undefined) n.innerHTML = html; return n; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const toast = (m) => { const t = $("toast"); t.textContent = m; t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2500); };

/* ---------- animated particle-network background ---------- */
(function bg() {
  const c = $("bg"), x = c.getContext("2d");
  let w, h, pts;
  const resize = () => { w = c.width = innerWidth; h = c.height = innerHeight;
    pts = Array.from({ length: Math.min(90, Math.floor(w * h / 18000)) }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - .5) * .35, vy: (Math.random() - .5) * .35 })); };
  resize(); addEventListener("resize", resize);
  (function draw() {
    x.clearRect(0, 0, w, h);
    for (const p of pts) {
      p.x = (p.x + p.vx + w) % w; p.y = (p.y + p.vy + h) % h;
      x.beginPath(); x.arc(p.x, p.y, 1.4, 0, 7); x.fillStyle = "rgba(38,230,255,.7)"; x.fill();
    }
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i], b = pts[j], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d < 130) { x.strokeStyle = `rgba(120,170,255,${(1 - d / 130) * .18})`;
        x.beginPath(); x.moveTo(a.x, a.y); x.lineTo(b.x, b.y); x.stroke(); }
    }
    requestAnimationFrame(draw);
  })();
})();

/* ---------- count-up ---------- */
function countUp(node, to, unit) {
  const dur = 900, t0 = performance.now();
  (function step(t) {
    const k = Math.min(1, (t - t0) / dur), v = Math.round(to * (1 - Math.pow(1 - k, 3)));
    node.innerHTML = v.toLocaleString() + (unit ? `<span class="munit">${unit}</span>` : "");
    if (k < 1) requestAnimationFrame(step);
  })(t0);
}

function metric(val, lbl, cls, unit) {
  const m = el("div", "metric " + (cls || ""));
  const v = el("div", "mval", "0"); m.appendChild(v);
  m.appendChild(el("div", "mlbl", esc(lbl)));
  countUp(v, val, unit || "");
  return m;
}

function fmtTime(ms) {
  if (ms == null) return { v: 0, u: "ms" };
  if (ms < 1000) return { v: ms, u: "ms" };
  return { v: +(ms / 1000).toFixed(ms < 10000 ? 2 : 1), u: "s" };
}

/* ---------- hero ---------- */
function renderHero(r) {
  const host = $("hero"); host.innerHTML = "";
  const m = r.meta || {}, sw = r.swarm || { agent_count: 0 };
  const t = fmtTime((m.timing_ms || {}).total);
  // time-to-deduce needs float support; render manually.
  host.appendChild(metric(m.agents_deployed ?? sw.agent_count ?? 0, "Agents Deployed", "v"));
  const tm = el("div", "metric p");
  const tv = el("div", "mval", "0"); tm.appendChild(tv);
  tm.appendChild(el("div", "mlbl", "Time to Deduce"));
  host.appendChild(tm);
  // animate float time
  (function () { const dur = 900, t0 = performance.now();
    (function s(now) { const k = Math.min(1, (now - t0) / dur);
      const val = (t.v * (1 - Math.pow(1 - k, 3)));
      tv.innerHTML = (t.u === "ms" ? Math.round(val) : val.toFixed(2)) + `<span class="munit">${t.u}</span>`;
      if (k < 1) requestAnimationFrame(s); })(t0); })();
  host.appendChild(metric(m.events_ingested ?? 0, "Events Ingested", ""));
  host.appendChild(metric((r.incidents || []).length, "Incidents", "g"));
  $("backbone").textContent = "backbone: " + (m.backbone || "unknown");
  $("ver").textContent = "v" + (m.version || "");
}

/* ---------- RCA pinpointer ---------- */
function renderPinpointer(r) {
  const host = $("pinpointer"); host.innerHTML = "";
  const inc = (r.incidents || [])[0];
  if (!inc) { host.appendChild(el("p", "empty", "No incident to pinpoint.")); return; }
  const s = inc.storyline.structured;
  const cross = el("div", "crosshair", `
    <div class="sweep"></div><div class="ring"></div><div class="ring r2"></div>
    <div class="ring r3"></div><div class="cross cx"></div><div class="cross cy"></div>
    <div class="dot"></div>`);
  const info = el("div", "pin-info");
  info.appendChild(el("div", "pin-title", `${esc(s.incident_id)} · ${s.severity.toUpperCase()} (${s.score}/100)`));
  info.appendChild(el("div", "pin-row",
    `<span class="k">ROOT CAUSE / PATIENT-ZERO</span><br><span class="pin-target">${esc(s.patient_zero || "n/a")}</span>`));
  info.appendChild(el("div", "pin-row", `<span class="k">OBJECTIVE</span><span class="pin-obj">${esc(s.likely_objective)}</span>`));
  info.appendChild(el("div", "pin-row",
    `<span class="k">BLAST RADIUS</span>${esc((s.affected_hosts || []).join(", ") || "n/a")} · ${(s.affected_users || []).length} users`));
  info.appendChild(el("div", "pin-row",
    `<span class="k">WINDOW</span>${esc(s.window.start)} → ${esc(s.window.end)}`));
  host.appendChild(cross); host.appendChild(info);
}

/* ---------- 3D layered storyline ---------- */
function renderStage(r) {
  const stage = $("stage"); stage.innerHTML = "";
  const inc = (r.incidents || [])[0];
  const sub = $("story-sub");
  if (!inc) { stage.innerHTML = '<p class="empty">No storyline.</p>'; sub.textContent = ""; return; }
  const s = inc.storyline.structured;
  sub.textContent = `${s.incident_id} · ${(s.phases || []).length} phases · source: ${inc.storyline.narrative_source}`;
  (s.phases || []).forEach((p, i) => {
    if (i) stage.appendChild(el("div", "beam"));
    const isImpact = /impact/.test(p.tactic), isCC = /command-and-control/.test(p.tactic);
    const layer = el("div", "layer" + (isImpact ? " sev-impact" : isCC ? " sev-cc" : ""));
    layer.style.animationDelay = (i * 90) + "ms";
    layer.appendChild(el("div", "tnum", i + 1));
    layer.appendChild(el("div", "tac", esc(p.tactic)));
    layer.appendChild(el("div", "tt", "first seen " + esc((p.first_seen || "").replace("T", " ").slice(0, 19)) + ` · ${p.count} ev`));
    const techs = el("div", "techs");
    (p.techniques || []).forEach((t) => techs.appendChild(el("span", "tech", esc(t.id))));
    layer.appendChild(techs);
    stage.appendChild(layer);
  });
}

/* ---------- swarm orbit ---------- */
function renderSwarm(r) {
  const orbit = $("orbit"), side = $("swarm-side");
  orbit.innerHTML = ""; side.innerHTML = "";
  const sw = r.swarm;
  $("swarm-sub").textContent = sw ? `${sw.agent_count} agents · ${sw.counts.confirmed_incidents} confirmed` : "";
  if (!sw) { orbit.appendChild(el("p", "empty", "Swarm did not run.")); return; }
  orbit.appendChild(el("div", "core", "SOC<br>CORE"));
  const rings = { 1: 44, 2: 104, 3: 156 }, bucket = { 1: [], 2: [], 3: [] };
  (sw.roster || []).forEach((a) => (bucket[a.tier] || bucket[3]).push(a));
  [1, 2, 3].forEach((tier) => {
    const ring = el("div", "ringpath t" + tier); orbit.appendChild(ring);
    const spinner = el("div", null); spinner.style.cssText = "position:absolute;inset:0;";
    spinner.classList.add(tier === 2 ? "spin2" : "spin1");
    const arr = bucket[tier], R = rings[tier], cx = 170, cy = 170;
    arr.forEach((a, i) => {
      const ang = (i / Math.max(1, arr.length)) * Math.PI * 2;
      const node = el("div", "node t" + tier,
        `${esc(a.name.replace("soc1-", "").replace("soc2-", "").slice(0, 4).toUpperCase())}
         <span class="tip">${esc(a.role)} · ${esc(a.name)}</span>`);
      node.style.left = (cx + R * Math.cos(ang)) + "px";
      node.style.top = (cy + R * Math.sin(ang)) + "px";
      spinner.appendChild(node);
    });
    orbit.appendChild(spinner);
  });
  (sw.consensus || []).forEach((c) => side.appendChild(el("div", "cons",
    `${esc(c.incident_id)} — <span class="${c.confirmed_by_tier2 ? "ok" : "no"}">${c.confirmed_by_tier2 ? "✅ CONFIRMED" : "⏳ uncorroborated"}</span><br>
     <span class="meta-line">${c.agents_involved} agents · tiers ${JSON.stringify(c.tiers_involved)} · conf ${c.consensus_confidence}</span>`)));
  const t3 = (sw.findings || []).filter((f) => f.tier === 3);
  if (t3.length) { side.appendChild(el("div", "meta-line", "SPECIALIST FINDINGS"));
    t3.forEach((f) => { const d = el("div", "spec",
      `<b>[${esc(f.severity.toUpperCase())}]</b> <span class="who">${esc(f.role)}</span>: ${esc(f.title)}`);
      if (f.recommended_action) d.appendChild(el("div", "meta-line", esc(f.recommended_action)));
      side.appendChild(d); }); }
}

/* ---------- incidents / iocs / hunt / intel ---------- */
function renderIncidents(r) {
  const host = $("incidents"); host.innerHTML = "";
  const incs = r.incidents || [];
  if (!incs.length) { host.appendChild(el("p", "empty", "No incidents.")); return; }
  incs.forEach((inc) => {
    const s = inc.storyline.structured, box = el("div", "incident");
    const row = el("div", "row");
    row.appendChild(el("span", "id", esc(s.incident_id)));
    row.appendChild(el("span", "sev " + s.severity, `${s.severity.toUpperCase()} · ${s.score}`));
    box.appendChild(row);
    const bar = el("div", "scorebar"), fill = el("i"); bar.appendChild(fill); box.appendChild(bar);
    requestAnimationFrame(() => { fill.style.width = Math.max(4, s.score) + "%"; });
    box.appendChild(el("div", "meta-line", `hosts: ${esc((s.affected_hosts || []).join(", ") || "n/a")}`));
    box.appendChild(el("div", "meta-line", "obj: " + esc(s.likely_objective)));
    host.appendChild(box);
  });
}

function renderIocs(r) {
  const host = $("iocs"); host.innerHTML = ""; const iocs = r.iocs || {}; let any = false;
  ["hash", "domain", "ip", "process", "user"].forEach((kind) => {
    const items = (iocs[kind] || []).filter((x) => x.suspicious);
    const show = items.length ? items : (iocs[kind] || []).slice(0, 3);
    if (!show.length) return; any = true;
    host.appendChild(el("h2", null, `<span style="color:var(--cyan);font-size:11px;letter-spacing:1px">${kind.toUpperCase()}</span>`));
    const t = el("table"); t.appendChild(el("tr", null, "<th>value</th><th>×</th><th>hosts</th>"));
    show.slice(0, 10).forEach((x) => t.appendChild(el("tr", null,
      `<td><code>${esc(x.value)}</code> ${x.suspicious ? '<span class="flag">⚠</span>' : ""}</td><td>${x.count}</td><td>${esc((x.hosts || []).join(", "))}</td>`)));
    host.appendChild(t);
  });
  if (!any) host.appendChild(el("p", "empty", "No IOCs."));
}

function renderHunt(r) {
  const host = $("hunt"); host.innerHTML = ""; const checks = r.hunt_checklist || [];
  if (!checks.length) { host.appendChild(el("p", "empty", "No hunt actions.")); return; }
  checks.forEach((c) => { const d = el("div", "hunt-item " + c.priority);
    d.appendChild(el("div", "p", c.priority));
    d.appendChild(el("div", null, "<b>" + esc(c.action) + "</b>"));
    if ((c.targets || []).length) d.appendChild(el("div", "meta-line", "targets: " + esc(c.targets.slice(0, 20).join(", "))));
    d.appendChild(el("div", "meta-line", esc(c.why))); host.appendChild(d); });
}

function renderIntel(r) {
  const host = $("intel"); host.innerHTML = ""; const intel = r.intel_used || [];
  if (!intel.length) { host.appendChild(el("p", "empty", "No threat intel matched.")); return; }
  const t = el("table"); t.appendChild(el("tr", null, "<th>id</th><th>title</th><th>sev</th><th>src</th>"));
  intel.forEach((e) => t.appendChild(el("tr", null,
    `<td><code>${esc(e.id)}</code></td><td>${esc(e.title)}</td><td>${esc(e.severity || "?")}</td><td>${esc(e.source || "?")}</td>`)));
  host.appendChild(t);
}

function renderAll(r) {
  if (r.error) { toast("Analysis error: " + r.error); return; }
  renderHero(r); renderPinpointer(r); renderStage(r); renderSwarm(r);
  renderIncidents(r); renderIocs(r); renderHunt(r); renderIntel(r);
}

async function load(url) {
  const data = await (await fetch(url)).json();
  try { const m = await (await fetch("/api/meta")).json(); data.meta = Object.assign({}, m, data.meta); } catch (e) {}
  renderAll(data); return data;
}

$("refresh").addEventListener("click", async () => {
  $("refresh").disabled = true; toast("Re-analyzing…");
  try { await load("/api/refresh"); toast("Updated."); }
  catch (e) { toast("Failed: " + e); } finally { $("refresh").disabled = false; }
});

load("/api/report").catch((e) => toast("Load failed: " + e));
