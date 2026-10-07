// BlueCell - dashboard command deck
// WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
// Built by Harikishore Karunanithi. MIT - attribution required.
"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => { const n = document.createElement(tag);
  if (cls) n.className = cls; if (html !== undefined) n.innerHTML = html; return n; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const toast = (m) => { const t = $("toast"); t.innerHTML = m; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), 3000); };

/* ================= animated particle-network background ================= */
(function bg() {
  const c = $("bg"), x = c.getContext("2d"); let w, h, pts;
  const resize = () => { w = c.width = innerWidth; h = c.height = innerHeight;
    pts = Array.from({ length: Math.min(90, Math.floor(w * h / 18000)) }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - .5) * .35, vy: (Math.random() - .5) * .35 })); };
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const reduce = matchMedia("(prefers-reduced-motion: reduce)");
  resize(); addEventListener("resize", resize);
  (function draw() {
    x.clearRect(0, 0, w, h);
    const node = css("--bg-node"), edge = css("--bg-edge");
    for (const p of pts) { p.x = (p.x + p.vx + w) % w; p.y = (p.y + p.vy + h) % h;
      x.beginPath(); x.arc(p.x, p.y, 1.4, 0, 7); x.fillStyle = `rgba(${node},.55)`; x.fill(); }
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i], b = pts[j], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d < 130) { x.strokeStyle = `rgba(${edge},${(1 - d / 130) * .16})`;
        x.beginPath(); x.moveTo(a.x, a.y); x.lineTo(b.x, b.y); x.stroke(); } }
    if (!reduce.matches) requestAnimationFrame(draw);
  })();
})();

/* ================= file intake (drag & drop) ================= */
const pending = new Map();   // name -> {name, content, size}
const MAX_FILE = 256 * 1024 * 1024;   // per-file cap (matches server default)

function humanSize(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

function renderFileList() {
  const host = $("filelist"); host.innerHTML = "";
  pending.forEach((f) => {
    const chip = el("div", "fchip",
      `<span>${esc(f.name)}</span><span class="sz">${humanSize(f.size)}</span><span class="x" data-n="${esc(f.name)}">&times;</span>`);
    host.appendChild(chip);
  });
  host.querySelectorAll(".x").forEach((b) => b.addEventListener("click", () => {
    pending.delete(b.dataset.n); renderFileList(); updateAnalyzeBtn(); }));
  updateAnalyzeBtn();
}
function updateAnalyzeBtn() {
  $("analyze").disabled = pending.size === 0;
  $("status").textContent = pending.size ? `${pending.size} file(s) staged` : "";
}

function addFiles(fileList) {
  const arr = Array.from(fileList);
  let done = 0;
  if (!arr.length) return;
  arr.forEach((file) => {
    if (file.size > MAX_FILE) {
      toast(`${esc(file.name)} is ${humanSize(file.size)}, over the ${MAX_FILE / (1024*1024)} MB per-file limit`);
      done++; if (done === arr.length) renderFileList(); return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      pending.set(file.name, { name: file.name, content: reader.result, size: file.size });
      done++; if (done === arr.length) renderFileList();
    };
    reader.onerror = () => { done++; toast("Could not read " + esc(file.name));
      if (done === arr.length) renderFileList(); };
    reader.readAsText(file);
  });
}

(function intake() {
  const dz = $("dropzone"), pick = $("filepick");
  $("browse").addEventListener("click", (e) => { e.stopPropagation(); pick.click(); });
  dz.addEventListener("click", () => pick.click());
  pick.addEventListener("change", () => addFiles(pick.files));
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); if (ev !== "dragover") dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => {
    const items = e.dataTransfer;
    if (items && items.files && items.files.length) addFiles(items.files);
  });
  $("analyze").addEventListener("click", analyzeUploads);
  $("loadsample").addEventListener("click", () => { pending.clear(); renderFileList();
    $("status").innerHTML = '<span class="spinner"></span> loading sample…'; load("/api/refresh"); });
})();

async function postJSON(url, obj) {
  const res = await fetch(url, { method: "POST",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

async function analyzeUploads() {
  if (!pending.size) return;
  $("analyze").disabled = true;
  const win = parseInt($("window").value, 10) || 120;
  const files = Array.from(pending.values());
  try {
    // Staged upload: one file per request, so total batch size never matters.
    await postJSON("/api/stage/reset", {});
    let i = 0;
    for (const f of files) {
      i++;
      $("status").innerHTML = `<span class="spinner"></span> uploading ${i}/${files.length}: ${esc(f.name)}`;
      await postJSON("/api/stage/add", { name: f.name, content: f.content });
    }
    $("status").innerHTML = '<span class="spinner"></span> analyzing ' + files.length + ' file(s)…';
    const data = await postJSON("/api/stage/run", { window: win });
    await mergeMetaAndRender(data);
    $("status").textContent = "analysis complete";
    toast("Analyzed " + files.length + " file(s)");
  } catch (e) {
    toast("" + (e.message || e)); $("status").textContent = "error: " + (e.message || e);
  } finally { $("analyze").disabled = false; }
}

/* ================= count-up ================= */
function countUp(node, to, unit) {
  const dur = 900, t0 = performance.now();
  (function step(t) { const k = Math.min(1, (t - t0) / dur), v = Math.round(to * (1 - Math.pow(1 - k, 3)));
    node.innerHTML = v.toLocaleString() + (unit ? `<span class="munit">${unit}</span>` : "");
    if (k < 1) requestAnimationFrame(step); })(t0);
}
function metric(val, lbl, cls, unit) {
  const m = el("div", "metric " + (cls || "")); const v = el("div", "mval", "0"); m.appendChild(v);
  m.appendChild(el("div", "mlbl", esc(lbl))); countUp(v, val, unit || ""); return m;
}
function fmtTime(ms) { if (ms == null) return { v: 0, u: "ms" };
  return ms < 1000 ? { v: ms, u: "ms" } : { v: +(ms / 1000).toFixed(ms < 10000 ? 2 : 1), u: "s" }; }

function renderHero(r) {
  const host = $("hero"); host.innerHTML = "";
  const m = r.meta || {}, sw = r.swarm || { agent_count: 0 };
  const t = fmtTime((m.timing_ms || {}).total);
  host.appendChild(metric(m.agents_deployed ?? sw.agent_count ?? 0, "Agents Deployed", "v"));
  const tm = el("div", "metric p"); const tv = el("div", "mval", "0"); tm.appendChild(tv);
  tm.appendChild(el("div", "mlbl", "Time to Deduce")); host.appendChild(tm);
  (function () { const dur = 900, t0 = performance.now();
    (function s(now) { const k = Math.min(1, (now - t0) / dur), val = t.v * (1 - Math.pow(1 - k, 3));
      tv.innerHTML = (t.u === "ms" ? Math.round(val) : val.toFixed(2)) + `<span class="munit">${t.u}</span>`;
      if (k < 1) requestAnimationFrame(s); })(t0); })();
  host.appendChild(metric(m.events_ingested ?? 0, "Events Ingested", ""));
  host.appendChild(metric((r.incidents || []).length, "Incidents", "g"));
  $("backbone").textContent = "backbone: " + (m.backbone || "unknown");
  $("hc-backbone").textContent = (m.backbone || "unknown").split(" ")[0];
  $("hc-agents").textContent = (m.agents_deployed ?? sw.agent_count ?? 0) + " deployed";
  $("ver").textContent = "v" + (m.version || "");
}

/* ================= RCA pinpointer ================= */
function renderPinpointer(r) {
  const host = $("pinpointer"); host.innerHTML = "";
  const inc = (r.incidents || [])[0];
  if (!inc) { host.appendChild(el("p", "empty", "No incident to pinpoint.")); return; }
  const s = inc.storyline.structured;
  host.appendChild(el("div", "crosshair", `
    <div class="sweep"></div><div class="ring"></div><div class="ring r2"></div>
    <div class="ring r3"></div><div class="cross cx"></div><div class="cross cy"></div><div class="dot"></div>`));
  const info = el("div", "pin-info");
  info.appendChild(el("div", "pin-title", `${esc(s.incident_id)} · ${s.severity.toUpperCase()} (${s.score}/100)`));
  info.appendChild(el("div", "pin-row", `<span class="k">ROOT CAUSE / PATIENT-ZERO</span><br><span class="pin-target">${esc(s.patient_zero || "n/a")}</span>`));
  info.appendChild(el("div", "pin-row", `<span class="k">${(s.attack_summary || {}).framing === "benign" ? "ASSESSMENT" : "OBJECTIVE"}</span><span class="pin-obj">${esc(s.likely_objective)}</span>`));
  info.appendChild(el("div", "pin-row", `<span class="k">BLAST RADIUS</span>${esc((s.affected_hosts || []).join(", ") || "n/a")} · ${(s.affected_users || []).length} users`));
  info.appendChild(el("div", "pin-row", `<span class="k">WINDOW</span>${esc(s.window.start)} → ${esc(s.window.end)}`));
  host.appendChild(info);
}

/* ================= analyst verdict ================= */
function renderVerdict(r) {
  const host = $("verdict");
  const inc = (r.incidents || [])[0];
  if (!inc || !inc.verdict) { host.style.display = "none"; return; }
  host.style.display = "block";
  const v = inc.verdict;
  const cls = v.level === "likely-malicious" ? "malicious"
    : v.level === "likely-benign" ? "benign" : "review";
  const label = v.level === "likely-malicious" ? "LIKELY REAL ATTACK"
    : v.level === "likely-benign" ? "LIKELY BENIGN / NOISE" : "NEEDS REVIEW";
  host.className = "verdict " + cls;
  document.body.dataset.threat = cls;
  $("hc-verdict").textContent = label.toLowerCase();
  host.innerHTML = "";
  const top = el("div", "vtop");
  top.appendChild(el("span", "vlabel", label));
  top.appendChild(el("span", "vhead", esc(v.headline)));
  top.appendChild(el("span", "vconf", "VERDICT CONFIDENCE " + Math.round((v.confidence || 0) * 100) + "%"));
  host.appendChild(top);
  if (v.overrides_rules && v.rule_verdict) {
    host.appendChild(el("div", "voverride", esc("Tier-2 agent overruled the rule-based score, which said "
      + (v.rule_verdict.level || "unknown").replace("-", " ") + " ("
      + Math.round((v.rule_verdict.confidence || 0) * 100) + "%).")));
  }
  host.appendChild(el("div", "vwhy", esc(v.why)));
  host.appendChild(el("div", "vchecks-h", "WHAT TO DO NEXT"));
  const ul = el("ul", "vchecks");
  (v.recommended_checks || []).forEach((c) => ul.appendChild(el("li", null, esc(c))));
  host.appendChild(ul);
}

/* ================= attack summary ================= */
function renderSummary(r) {
  const host = $("summary"); host.innerHTML = "";
  const inc = (r.incidents || [])[0];
  if (!inc) { host.appendChild(el("p", "empty", "No attack to summarize.")); return; }
  const a = inc.storyline.structured.attack_summary || {};
  const benign = a.framing === "benign";
  const left = el("div", "sum-block");
  left.appendChild(el("h3", null, benign ? "HOW IT STARTED" : "HOW THEY GOT IN"));
  left.appendChild(el("div", "sum-in", esc(a.how_they_got_in || "Unknown.")));
  left.appendChild(el("div", "sum-obj", (benign ? "ASSESSMENT: <b>" : "OBJECTIVE: <b>") + esc(a.objective || "unknown") + "</b>"));
  const right = el("div", "sum-block");
  right.appendChild(el("h3", null, benign ? "WHAT HAPPENED" : "WHAT THEY DID"));
  const ol = el("ul", "sum-steps");
  (a.what_they_did || []).forEach((step) => ol.appendChild(el("li", null, esc(step))));
  if (!(a.what_they_did || []).length) ol.appendChild(el("li", null, "No discrete actions reconstructed."));
  right.appendChild(ol);
  host.appendChild(left); host.appendChild(right);

  // Analyst narrative, richer when an LLM backbone produced it.
  const src = inc.storyline.narrative_source, txt = inc.storyline.narrative;
  if (txt) {
    const nb = el("div", "narrative");
    const isAI = src === "llm";
    nb.appendChild(el("h3", null,
      "ANALYST NARRATIVE" + (isAI
        ? '<span class="badge ai">AI-GENERATED</span>'
        : '<span class="badge rule">RULE-BASED · run with --llm auto for AI</span>')));
    if ((inc.storyline.structured.attack_summary || {}).framing === "benign") {
      nb.appendChild(el("div", "voverride", "Written before the final verdict, so it describes the rule matches as an attack. The verdict is that this activity is benign."));
    }
    nb.appendChild(el("div", "ntext", esc(txt)));
    host.appendChild(nb);
  }
}

/* ================= 3D storyline + drag-to-rotate + clickable ================= */
let _phases = [];
function renderStage(r) {
  const stage = $("stage"); stage.innerHTML = "";
  $("stage-detail").innerHTML = '<div class="detail-hint">Click any phase above to see its techniques and the exact events.</div>';
  const inc = (r.incidents || [])[0], sub = $("story-sub");
  if (!inc) { stage.innerHTML = '<p class="empty">No storyline.</p>'; sub.textContent = ""; return; }
  const s = inc.storyline.structured; _phases = s.phases || [];
  sub.textContent = `${s.incident_id} · ${_phases.length} phases · ${inc.storyline.narrative_source}`;
  _phases.forEach((p, i) => {
    if (i) stage.appendChild(el("div", "beam"));
    const isImpact = /impact/.test(p.tactic), isCC = /command-and-control/.test(p.tactic);
    const layer = el("div", "layer" + (isImpact ? " sev-impact" : isCC ? " sev-cc" : ""));
    layer.dataset.i = i; layer.style.animationDelay = (i * 90) + "ms";
    layer.appendChild(el("div", "tnum", i + 1));
    layer.appendChild(el("div", "tac", esc(p.tactic)));
    layer.appendChild(el("div", "tt", "first seen " + esc((p.first_seen || "").replace("T", " ").slice(0, 19)) + ` · ${p.count} ev`));
    const techs = el("div", "techs");
    (p.techniques || []).forEach((t) => techs.appendChild(el("span", "tech", esc(t.id))));
    layer.appendChild(techs); stage.appendChild(layer);
  });
}

function showPhaseDetail(i) {
  const p = _phases[i]; if (!p) return;
  document.querySelectorAll(".layer").forEach((l) => l.classList.toggle("active", l.dataset.i == i));
  const card = el("div", "detail-card");
  card.appendChild(el("h3", null, `PHASE ${i + 1} · ${esc(p.tactic.toUpperCase())}`));
  card.appendChild(el("div", "meta-line",
    `${p.count} event(s) · ${esc((p.first_seen || "").replace("T", " ").slice(0, 19))} → ${esc((p.last_seen || "").replace("T", " ").slice(11, 19))}`
    + (p.hosts && p.hosts.length ? ` · hosts: ${esc(p.hosts.join(", "))}` : "")
    + (p.users && p.users.length ? ` · users: ${esc(p.users.join(", "))}` : "")));
  const tw = el("div", null);
  (p.techniques || []).forEach((t) => tw.appendChild(el("span", "dt-tech", `${esc(t.id)} - ${esc(t.name)}`)));
  card.appendChild(tw);
  card.appendChild(el("div", "meta-line", "EVENTS"));
  (p.events || []).forEach((line) => card.appendChild(el("div", "evline", esc(line))));
  const host = $("stage-detail"); host.innerHTML = ""; host.appendChild(card);
  host.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

(function stageControls() {
  const wrap = $("stage-wrap"), stage = $("stage");
  const DEF_RX = 26, DEF_RZ = 0;
  let rx = DEF_RX, rz = DEF_RZ, drag = false, px = 0, py = 0, moved = 0;
  const apply = () => { stage.style.setProperty("--rx", rx + "deg"); stage.style.setProperty("--rz", rz + "deg"); };
  apply();
  const down = (e) => { drag = true; moved = 0; wrap.classList.add("grabbing");
    const pt = e.touches ? e.touches[0] : e; px = pt.clientX; py = pt.clientY; };
  const move = (e) => { if (!drag) return; const pt = e.touches ? e.touches[0] : e;
    const dx = pt.clientX - px, dy = pt.clientY - py; moved += Math.abs(dx) + Math.abs(dy);
    rz += dx * 0.3; rx -= dy * 0.3; rx = Math.max(-5, Math.min(75, rx));
    px = pt.clientX; py = pt.clientY; apply(); };
  const up = () => { drag = false; wrap.classList.remove("grabbing"); };
  wrap.addEventListener("mousedown", down); addEventListener("mousemove", move); addEventListener("mouseup", up);
  wrap.addEventListener("touchstart", down, { passive: true });
  wrap.addEventListener("touchmove", move, { passive: true });
  wrap.addEventListener("touchend", up);
  // Click a layer (only if it wasn't a drag) -> open its details.
  stage.addEventListener("click", (e) => {
    if (moved > 6) return;                       // was a rotate, not a click
    const layer = e.target.closest(".layer");
    if (layer) showPhaseDetail(parseInt(layer.dataset.i, 10));
  });
  $("resetview").addEventListener("click", () => { rx = DEF_RX; rz = DEF_RZ; apply(); });

  // Explicit left/right navigation + mouse-wheel -> horizontal scroll.
  const step = () => Math.max(260, wrap.clientWidth * 0.6);
  $("stage-left").addEventListener("click", () => wrap.scrollBy({ left: -step(), behavior: "smooth" }));
  $("stage-right").addEventListener("click", () => wrap.scrollBy({ left: step(), behavior: "smooth" }));
  wrap.addEventListener("wheel", (e) => {
    // Vertical wheel scrolls the chain horizontally when there is overflow.
    if (wrap.scrollWidth > wrap.clientWidth && Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
      wrap.scrollLeft += e.deltaY; e.preventDefault();
    }
  }, { passive: false });
})();

/* ================= swarm constellation ================= */
function renderSwarm(r) {
  const orbit = $("orbit"), side = $("swarm-side"); orbit.innerHTML = ""; side.innerHTML = "";
  const sw = r.swarm;
  $("swarm-sub").textContent = sw ? `${sw.agent_count} agents · ${sw.counts.confirmed_incidents} confirmed` : "";
  if (!sw) { orbit.appendChild(el("p", "empty", "Swarm did not run.")); return; }
  orbit.appendChild(el("div", "core", "SOC<br>CORE"));
  const rings = { 1: 44, 2: 104, 3: 156 }, bucket = { 1: [], 2: [], 3: [] };
  (sw.roster || []).forEach((a) => (bucket[a.tier] || bucket[3]).push(a));
  [1, 2, 3].forEach((tier) => {
    orbit.appendChild(el("div", "ringpath t" + tier));
    const spinner = el("div", null); spinner.style.cssText = "position:absolute;inset:0;";
    spinner.classList.add(tier === 2 ? "spin2" : "spin1");
    const arr = bucket[tier], R = rings[tier], cx = 170, cy = 170;
    arr.forEach((a, i) => {
      const ang = (i / Math.max(1, arr.length)) * Math.PI * 2;
      const node = el("div", "node t" + tier,
        `${esc(a.name.replace("soc1-", "").replace("soc2-", "").slice(0, 4).toUpperCase())}<span class="tip">${esc(a.role)} · ${esc(a.name)}</span>`);
      node.style.left = (cx + R * Math.cos(ang)) + "px"; node.style.top = (cy + R * Math.sin(ang)) + "px";
      spinner.appendChild(node);
    });
    orbit.appendChild(spinner);
  });
  (sw.consensus || []).forEach((c) => side.appendChild(el("div", "cons",
    `${esc(c.incident_id)}: <span class="${c.confirmed_by_tier2 ? "ok" : "no"}">${c.confirmed_by_tier2 ? "CONFIRMED" : "uncorroborated"}</span><br><span class="meta-line">${c.agents_involved} agents · tiers ${JSON.stringify(c.tiers_involved)} · conf ${c.consensus_confidence}</span>`)));
  const t3 = (sw.findings || []).filter((f) => f.tier === 3);
  if (t3.length) { side.appendChild(el("div", "meta-line", "SPECIALIST FINDINGS"));
    t3.forEach((f) => { const d = el("div", "spec", `<b>[${esc(f.severity.toUpperCase())}]</b> <span class="who">${esc(f.role)}</span>: ${esc(f.title)}`);
      if (f.recommended_action) d.appendChild(el("div", "meta-line", esc(f.recommended_action))); side.appendChild(d); }); }
}

/* ================= incidents / iocs / hunt / intel ================= */
function renderIncidents(r) {
  const host = $("incidents"); host.innerHTML = ""; const incs = r.incidents || [];
  if (!incs.length) { host.appendChild(el("p", "empty", "No incidents.")); return; }
  incs.forEach((inc) => {
    const s = inc.storyline.structured, box = el("div", "incident");
    const row = el("div", "row"); row.appendChild(el("span", "id", esc(s.incident_id)));
    row.appendChild(el("span", "sev " + s.severity, `${s.severity.toUpperCase()} · ${s.score}`)); box.appendChild(row);
    // Verdict badge: is it real, noise, or unclear?
    const v = inc.verdict;
    if (v) {
      const vcls = v.level === "likely-malicious" ? "malicious"
        : v.level === "likely-benign" ? "benign" : "review";
      const vtxt = v.level === "likely-malicious" ? "LIKELY REAL ATTACK"
        : v.level === "likely-benign" ? "LIKELY BENIGN / NOISE" : "NEEDS REVIEW";
      const vb = el("div", "vbadge " + vcls,
        `${vtxt} <span class="vbc">${Math.round((v.confidence || 0) * 100)}%</span>`);
      vb.title = v.headline || "";
      box.appendChild(vb);
    }
    const bar = el("div", "scorebar"), fill = el("i"); bar.appendChild(fill); box.appendChild(bar);
    requestAnimationFrame(() => { fill.style.width = Math.max(4, s.score) + "%"; });
    box.appendChild(el("div", "meta-line", `hosts: ${esc((s.affected_hosts || []).join(", ") || "n/a")}`));
    box.appendChild(el("div", "meta-line", "obj: " + esc(s.likely_objective))); host.appendChild(box);
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
      `<td><code>${esc(x.value)}</code> ${x.suspicious ? '<span class="flag" title="suspicious">!</span>' : ""}</td><td>${x.count}</td><td>${esc((x.hosts || []).join(", "))}</td>`)));
    host.appendChild(t);
  });
  if (!any) host.appendChild(el("p", "empty", "No IOCs."));
}
function renderHunt(r) {
  const host = $("hunt"); host.innerHTML = ""; const checks = r.hunt_checklist || [];
  if (!checks.length) { host.appendChild(el("p", "empty", "No hunt actions.")); return; }
  checks.forEach((c) => { const d = el("div", "hunt-item " + c.priority);
    d.appendChild(el("div", "p", c.priority)); d.appendChild(el("div", null, "<b>" + esc(c.action) + "</b>"));
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
  if (r.error) { toast("" + esc(r.error)); return; }
  $("results").classList.add("show");
  renderVerdict(r); renderHero(r); renderPinpointer(r); renderSummary(r); renderStage(r); renderSwarm(r);
  renderIncidents(r); renderIocs(r); renderHunt(r); renderIntel(r);
}
async function mergeMetaAndRender(data) {
  try { const m = await (await fetch("/api/meta")).json(); data.meta = Object.assign({}, m, data.meta); } catch (e) {}
  renderAll(data); return data;
}
async function load(url) {
  try { const data = await (await fetch(url)).json(); await mergeMetaAndRender(data);
    if ($("status").textContent.includes("loading")) $("status").textContent = "sample loaded";
    return data;
  } catch (e) { toast("Load failed: " + e); }
}

/* ================= download IR report ================= */
async function downloadIR() {
  const btn = $("download-ir"); if (!btn) return;
  btn.disabled = true; toast("Building IR report…");
  try {
    const res = await fetch("/api/report.md");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const blob = await res.blob();
    let fname = "bluecell_IR_report.md";
    const m = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    if (m) fname = m[1];
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = fname; document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
    toast("IR report downloaded");
  } catch (e) { toast("report failed: " + (e.message || e)); }
  finally { btn.disabled = false; }
}
(function () { const b = $("download-ir"); if (b) b.addEventListener("click", downloadIR); })();

// On first open, show whatever the server was launched with (samples), so the
// deck isn't empty, but the drop zone is the primary call to action.
load("/api/report");


/* ================= hero shortcuts ================= */
$("hs-drop").addEventListener("click", () => {
  $("intake").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  $("dropzone").classList.add("drag"); setTimeout(() => $("dropzone").classList.remove("drag"), 900);
});
$("hs-sample").addEventListener("click", () => $("loadsample").click());
