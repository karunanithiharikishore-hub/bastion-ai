// Bastion AI - dashboard command deck
// WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
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
// The server caps each upload *request body* (--max-upload-mb; exact bytes from /api/meta).
let MAX_UPLOAD_MB = 256, MAX_UPLOAD_BYTES = 256 * 1048576;
const TOKEN_LEN = 32;   // /api/stage/reset returns a uuid4 hex token (32 chars)
// Exact UTF-8 size of the /api/stage/add body postJSON() sends (JSON escaping included).
function uploadBodyBytes(name, content) {
  return new TextEncoder().encode(JSON.stringify({ token: "0".repeat(TOKEN_LEN), name, content })).length;
}
let resultId = null;   // id of the analysis on screen (for the IR report download)

function humanSize(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

function renderFileList() {
  const host = $("filelist"); host.innerHTML = "";
  pending.forEach((f) => {
    const chip = el("div", "fchip",
      `<span>${esc(f.name)}</span><span class="sz">${humanSize(f.size)}</span><span class="x" role="button" tabindex="0" aria-label="remove ${esc(f.name)}" data-n="${esc(f.name)}">&times;</span>`);
    host.appendChild(chip);
  });
  host.querySelectorAll(".x").forEach((b) => {
    const rm = () => { pending.delete(b.dataset.n); renderFileList(); updateAnalyzeBtn(); };
    b.addEventListener("click", rm);
    b.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); rm(); } });
  });
  updateAnalyzeBtn();
}
function updateAnalyzeBtn() {
  $("analyze").disabled = $("deep").disabled = pending.size === 0;
  $("status").textContent = pending.size ? `${pending.size} file(s) staged` : "";
}

// Same-named drops (e.g. two auth.log from different hosts) get " (2)" before the extension so neither is lost.
function uniqueName(name) {
  const dot = name.lastIndexOf("."), stem = dot > 0 ? name.slice(0, dot) : name, ext = dot > 0 ? name.slice(dot) : "";
  let out = name;
  for (let n = 2; pending.has(out); n++) out = `${stem} (${n})${ext}`;
  return out;
}

function addFiles(fileList) {
  const arr = Array.from(fileList);
  let done = 0;
  if (!arr.length) return;
  arr.forEach((file) => {
    const overCap = (bytes) => toast(`${esc(file.name)} is ${humanSize(bytes)} as an upload request, over the ${humanSize(MAX_UPLOAD_BYTES)} limit (server --max-upload-mb ${MAX_UPLOAD_MB})`);
    // readAsText drops a UTF-8 BOM (3 bytes), so the JSON body is at least file.size - 3.
    if (file.size - 3 > MAX_UPLOAD_BYTES) {
      overCap(file.size);
      done++; if (done === arr.length) renderFileList(); return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      // The exact same file picked again is skipped; only different files sharing a name get " (2)".
      if ([...pending.values()].some((p) => p.size === file.size && p.content === reader.result)) {
        toast(esc(file.name) + " is already staged");
        done++; if (done === arr.length) renderFileList(); return;
      }
      const name = uniqueName(file.name);
      const bytes = uploadBodyBytes(name, reader.result);
      if (bytes > MAX_UPLOAD_BYTES) overCap(bytes);
      else pending.set(name, { name, content: reader.result, size: file.size });
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
  // Clear the picker after reading so re-picking the same file (e.g. after removing it) fires "change" again.
  pick.addEventListener("change", () => { const files = Array.from(pick.files); pick.value = ""; addFiles(files); });
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); if (ev !== "dragover") dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => {
    const items = e.dataTransfer;
    if (items && items.files && items.files.length) addFiles(items.files);
  });
  $("analyze").addEventListener("click", () => analyzeUploads("quick"));
  $("deep").addEventListener("click", () => analyzeUploads("deep"));
  $("loadsample").addEventListener("click", () => { pending.clear(); renderFileList();
    $("status").innerHTML = '<span class="spinner"></span> loading sample…'; withPoll(load("/api/refresh", { method: "POST" })); });
})();

async function postJSON(url, obj) {
  const res = await fetch(url, { method: "POST",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

async function analyzeUploads(mode) {
  if (!pending.size) return;
  $("analyze").disabled = $("deep").disabled = true;
  const win = parseInt($("window").value, 10) || 120;
  const files = Array.from(pending.values());
  try {
    // Staged upload: one file per request, so total batch size never matters.
    // The token keeps this tab's staged files separate from other tabs/clients.
    const { token } = await postJSON("/api/stage/reset", {});
    let i = 0;
    for (const f of files) {
      i++;
      $("status").innerHTML = `<span class="spinner"></span> uploading ${i}/${files.length}: ${esc(f.name)}`;
      await postJSON("/api/stage/add", { token, name: f.name, content: f.content });
    }
    $("status").innerHTML = '<span class="spinner"></span> ' + (mode === "deep"
      ? "deep investigation: AI agent team, takes several minutes…" : "quick analysis…")
      + " (" + files.length + " file(s))";
    const data = await withPoll(postJSON("/api/stage/run", { token, window: win, mode }), mode);
    await mergeMetaAndRender(data);
    $("status").textContent = (mode === "deep" ? "deep investigation" : "quick analysis") + " complete";
    toast("Analyzed " + files.length + " file(s)");
  } catch (e) {
    toast(esc(e.message || e)); $("status").textContent = "error: " + (e.message || e);
  } finally { $("analyze").disabled = $("deep").disabled = pending.size === 0; }
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
  const quick = m.mode === "quick";   // quick mode has no swarm: one AI analyst desk
  const agents = quick ? 1 : sw.worker_count ?? m.agents_deployed ?? sw.agent_count ?? 0;
  host.appendChild(metric(agents, quick ? "AI analyst" : sw.orchestrator ? "Workers (+ Commander)" : "Agents Deployed", "v"));
  const tm = el("div", "metric p"); const tv = el("div", "mval", "0"); tm.appendChild(tv);
  tm.appendChild(el("div", "mlbl", "Time to Deduce")); host.appendChild(tm);
  (function () { const dur = 900, t0 = performance.now();
    (function s(now) { const k = Math.min(1, (now - t0) / dur), val = t.v * (1 - Math.pow(1 - k, 3));
      tv.innerHTML = (t.u === "ms" ? Math.round(val) : val.toFixed(2)) + `<span class="munit">${t.u}</span>`;
      if (k < 1) requestAnimationFrame(s); })(t0); })();
  host.appendChild(metric(m.events_ingested ?? 0, "Events Ingested", ""));
  host.appendChild(metric((r.incidents || []).length, "Incidents", "g"));
  $("backbone").textContent = "backbone: " + (m.backbone || "unknown") + (m.mode ? " · " + m.mode + " mode" : "");
  $("hc-backbone").textContent = (m.backbone || "unknown").split(" ")[0];
  $("hc-agents").textContent = quick ? "1 AI analyst" : esc(agents) + " deployed";
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
  if (!inc || !inc.verdict) { host.style.display = "none";
    delete document.body.dataset.threat; $("hc-verdict").textContent = "no incidents"; return; }
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
  // Log text written to steer an AI analyst is evidence of an attacker, not an instruction: show it.
  const pi = r.prompt_injection || {};
  if (pi.count) {
    const box = el("div", "vinject");
    box.setAttribute("role", "alert");
    box.appendChild(el("div", "vinject-h", "PROMPT-INJECTION ATTEMPT · " + pi.count
      + " log event(s) contain text aimed at an AI analyst. Treated as untrusted data, never as instructions."));
    (pi.events || []).slice(0, 3).forEach((e) => box.appendChild(el("div", "vinject-ev",
      esc((e.ts || "").replace("T", " ").slice(0, 19) + " · " + (e.source || "") + " · " + (e.host || "?")
        + " — \u201c" + (e.excerpt || "").slice(0, 160) + "\u201d"))));
    host.appendChild(box);
  }
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
    layer.setAttribute("role", "button"); layer.tabIndex = 0;
    layer.setAttribute("aria-label", `phase ${i + 1}: ${p.tactic}`);
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
  stage.addEventListener("keydown", (e) => {        // keyboard: Enter/Space open a phase like a click
    const layer = e.target.closest(".layer");
    if (layer && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); showPhaseDetail(parseInt(layer.dataset.i, 10)); }
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

/* ================= swarm: isometric SOC floor ================= */
/*FLOOR-PURE-START*/
const FLOOR_W = 960, FLOOR_TOP = 144, FLOOR_STEP = 96, HUD_BOX = { x: 776, y: 8, w: 176, h: 74 };
const FLOOR_SHORT = [[/edr/i, "EDR"], [/dns/i, "DNS"], [/firewall/i, "Firewall"], [/cloud/i, "Cloud"], [/respon/i, "Responder"],
  [/forens/i, "Forensics"], [/hunt/i, "Hunter"], [/malware/i, "Malware"], [/intel/i, "Intel"], [/engineer|architect/i, "Engineer"], [/vuln/i, "Vuln"]];
function floorLabel(name, tier) {
  if (tier === 0) return "Commander"; if (tier === 2) return "Lead";
  const n = String(name || "?"), hit = FLOOR_SHORT.find((x) => x[0].test(n));
  if (hit) return hit[1];
  const s = n.replace(/^soc[12]-/, ""); return s.length > 14 ? s.slice(0, 13) + "…" : s;
}
// Pure layout: lists of {id,label} per tier -> node positions plus the collision boxes the test checks.
// Tier-1 column left, specialists right, commander + lead in the centre. Coordinates sit on the centres of a
// 96x48 diamond tile grid (x multiple of 48, y multiple of 24, matching parity).
function floorLayout(t0, t1, t2, t3) {
  const nodes = [], rect = (x, y, w, h) => ({ x, y, w, h });
  const add = (it, tier, x, y, side) => { const lw = it.label.length * 7.8 + 8; nodes.push({ id: it.id, tier, x, y, side,
    node: rect(x - 42, y - 58, 84, 78), label: rect(x - lw / 2, y + 22, lw, 15),
    bubble: side === "u" ? rect(x - 56, y - 78, 112, 16) : rect(side === "r" ? x + 50 : x - 50 - 112, y - 50, 112, 16) }); };
  t1.forEach((it, i) => add(it, 1, 144, FLOOR_TOP + i * FLOOR_STEP, "r"));
  t3.forEach((it, i) => add(it, 3, FLOOR_W - 144, FLOOR_TOP + i * FLOOR_STEP, "l"));
  if (t0.length) add(t0[0], 0, 480, 120, "u");
  t0.slice(1).concat(t2).forEach((it, i) => add(it, t0.includes(it) ? 0 : 2, 480, 264 + i * 144, "u"));
  const H = Math.max(560, ...nodes.map((n) => n.y + 37)) + 16;
  return { W: FLOOR_W, H, nodes, hud: rect(HUD_BOX.x, HUD_BOX.y, HUD_BOX.w, HUD_BOX.h) };
}
/*FLOOR-PURE-END*/

const NS = "http://www.w3.org/2000/svg";
const S = (tag, attrs, parent, text) => { const n = document.createElementNS(NS, tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  if (text != null) n.textContent = text; if (parent) parent.appendChild(n); return n; };
const TIER_COL = { 0: "#a98bff", 1: "#43d3a3", 2: "#6fb1ff", 3: "#ffb15c" };
const floor = { agents: new Map(), live: false, note: "", quick: false, sel: null, report: null,
  svg: null, packets: [], bubbles: [], hud: null, counts: null };
const reduceMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const floorStatus = (a) => a.status === "finding" ? "filed a finding" : a.status;

function floorReset() { floor.agents.clear(); floor.packets = []; floor.bubbles = []; floor.sel = null;
  floor.quick = false; floor.note = ""; floor.counts = null; floor.prep = false; floor.stage = ""; floor.pmode = null; }
/* A run just started: show the requested mode's empty layout (dimmed desks) under a "Preparing evidence" banner until the first agent event. */
function floorPrep(mode) {
  floor.agents.clear(); floor.pmode = mode; floor.prep = true; floor.quick = mode === "quick";
  if (mode === "quick") floorAgent("analyst", 0, "Quick analysis");
  else if (mode === "deep") { floorAgent("commander", 0, "Commander"); floorAgent("lead", 2, "Lead"); }
  floor.agents.forEach((a) => { a.dim = true; });
  drawFloor();
}
function floorAgent(id, tier, role) {
  let a = floor.agents.get(id);
  if (!a) { a = { id, name: id, role: role || "", tier: [0, 1, 2, 3].includes(tier) ? tier : 3, status: "idle",
      tools: 0, findings: [], used: [], dim: false }; floor.agents.set(id, a); drawFloor(); }
  return a;
}
const floorTier = (t) => [...floor.agents.values()].filter((a) => a.tier === t);
const floorLabelOf = (a) => floor.quick && a.tier === 0 ? "Quick analysis" : floorLabel(a.name, a.tier);
function paintAgent(a) {
  if (!a.g) return;
  a.g.setAttribute("class", `fd t${a.tier} st-${a.status}${a.dim ? " dim" : ""}${floor.sel === a.id ? " sel" : ""}`);
  a.g.setAttribute("aria-label", `${a.name} — ${floorStatus(a)}`);
  a.g.firstChild.textContent = `${a.name}${a.role ? " · " + a.role : ""}`;
}
function refreshHud() {
  if (!floor.hud) return;
  const all = [...floor.agents.values()], c = floor.counts || {};
  const active = c.agents_active != null ? c.agents_active : all.filter((a) => a.status === "working").length;
  const total = floor.prep ? "–" : c.agents_total != null ? c.agents_total : all.length;
  const tools = c.tool_calls != null ? c.tool_calls : all.reduce((s, a) => s + a.tools, 0);
  const uniq = new Set(all.flatMap((a) => a.findings)).size, finds = uniq || (c.findings != null ? c.findings : 0);
  floor.hud.title.textContent = "Investigation · " + (floor.live ? "live" : all.length ? "final" : "idle");
  floor.hud.rows.forEach((t, i) => { t.textContent = [`Agents active ${active}/${total}`, `Tool calls ${tools}`, `Findings filed ${finds}`][i]; });
}
function drawFloor() {
  const host = $("orbit"); if (!host) return;
  const L = floor.agents.size && floorLayout(
    floorTier(0).map((a) => ({ id: a.id, label: floorLabelOf(a) })), floorTier(1).map((a) => ({ id: a.id, label: floorLabelOf(a) })),
    floorTier(2).map((a) => ({ id: a.id, label: floorLabelOf(a) })), floorTier(3).map((a) => ({ id: a.id, label: floorLabelOf(a) })))
    || floorLayout([], [], [], []);
  floor.layout = L; host.textContent = "";
  const svg = floor.svg = S("svg", { viewBox: `0 0 ${L.W} ${L.H}`, class: "floor-svg", role: "group",
    "aria-label": "Agent swarm SOC floor" }, host);
  // isometric diamond floor grid
  const grid = S("g", { class: "fgrid" }, svg), TW = 96;   // 2:1 diamond tiles
  for (let k = -2 * L.H; k <= L.W + 2 * L.H; k += TW) {
    S("line", { x1: k, y1: 0, x2: k + 2 * L.H, y2: L.H }, grid); S("line", { x1: k, y1: 0, x2: k - 2 * L.H, y2: L.H }, grid); }
  const pos = (id) => L.nodes.find((n) => n.id === id);
  const cmd = floorTier(0)[0], lead = floorTier(2)[0], hub = lead || cmd;
  const links = S("g", { class: "flinks" }, svg);
  const link = (a, b) => { const p = a && pos(a.id), q = b && pos(b.id);
    if (p && q) S("line", { x1: p.x, y1: p.y - 4, x2: q.x, y2: q.y - 4 }, links); };
  floorTier(1).forEach((a) => { link(cmd, a); link(a, lead); });
  floorTier(3).forEach((a) => link(hub, a));
  if (!floor.agents.size) S("text", { x: L.W / 2, y: 200, class: "fnote" }, svg, floor.note || "Agents appear here while an analysis runs.");
  else if (floor.note) S("text", { x: L.W / 2, y: L.H - 6, class: "fnote" }, svg, floor.note);
  floor.banner = null;
  if (floor.prep) {   // over the floor: spinner + latest pipeline stage (text only, no animation under reduced motion)
    const b = S("g", { class: "fbanner", role: "status", transform: `translate(${L.W / 2} 400)` }, svg);
    S("rect", { x: -190, y: -34, width: 380, height: 68, rx: 10 }, b);
    S("circle", { class: "fspin", cx: -160, cy: -8, r: 7 }, b);
    S("text", { class: "ftitle", x: -142, y: -4 }, b, "Preparing evidence…");
    floor.banner = S("text", { class: "fstage", x: -142, y: 16 }, b, floor.stage || "starting");
  }
  L.nodes.forEach((n) => {
    const a = floor.agents.get(n.id), g = a.g = S("g", { transform: `translate(${n.x} ${n.y})`, tabindex: 0, role: "button" }, svg);
    g.style.setProperty("--c", TIER_COL[a.tier]);
    S("title", {}, g, ""); g.insertBefore(g.lastChild, g.firstChild);
    S("polygon", { class: "desk", points: "-40,0 0,-20 40,0 0,20" }, g);
    S("polygon", { class: "mat", points: "-24,0 0,-12 24,0 0,12" }, g);
    S("line", { class: "stand", x1: -24, y1: -14, x2: -24, y2: -6 }, g);
    S("rect", { class: "mon", x: -33, y: -29, width: 18, height: 14, rx: 2 }, g);
    const r = S("g", { class: "robot", transform: "translate(12 -2)" }, g);
    S("line", { class: "ant", x1: 0, y1: -50, x2: 0, y2: -44 }, r);
    S("circle", { class: "light", cx: 0, cy: -52, r: 3.5 }, r);
    S("rect", { class: "head", x: -11, y: -44, width: 22, height: 18, rx: 5 }, r);
    S("rect", { class: "eye", x: -7, y: -39, width: 4, height: 4 }, r); S("rect", { class: "eye", x: 3, y: -39, width: 4, height: 4 }, r);
    S("line", { class: "mouth", x1: -4, y1: -30, x2: 4, y2: -30 }, r);
    S("rect", { class: "body", x: -8, y: -25, width: 16, height: 13, rx: 3 }, r);
    S("rect", { class: "body", x: -6, y: -12, width: 4, height: 4, rx: 1 }, r); S("rect", { class: "body", x: 2, y: -12, width: 4, height: 4, rx: 1 }, r);
    S("text", { class: "flabel", y: 34 }, g, floorLabelOf(a));
    const pick = () => { floor.sel = floor.sel === a.id ? null : a.id; floor.agents.forEach(paintAgent); renderSide(); };
    g.addEventListener("click", pick);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    paintAgent(a);
  });
  const pk = floor.pk = S("g", {}, svg), bb = floor.bb = S("g", {}, svg);
  floor.packets.forEach((p) => pk.appendChild(p.node)); floor.bubbles.forEach((b) => bb.appendChild(b.node));
  const h = S("g", { class: "hud" }, svg);
  S("rect", { x: L.hud.x, y: L.hud.y, width: L.hud.w, height: L.hud.h, rx: 8 }, h);
  floor.hud = { title: S("text", { class: "ht", x: L.hud.x + 10, y: L.hud.y + 18 }, h),
    rows: [0, 1, 2].map((i) => S("text", { class: "hr" + (i === 2 ? " red" : ""), x: L.hud.x + 10, y: L.hud.y + 36 + i * 15 }, h)) };
  refreshHud();
}
function floorPacket(from, to) {
  if (reduceMotion() || !floor.layout) return;
  const p = floor.layout.nodes.find((n) => n.id === from.id), q = floor.layout.nodes.find((n) => n.id === to.id);
  if (!p || !q || p === q) return;
  const node = S("circle", { r: 3, fill: TIER_COL[from.tier], cx: p.x, cy: p.y - 4 }, floor.pk);
  floor.packets.push({ node, p, q, t0: performance.now(), dur: 900 });
  if (floor.packets.length === 1) requestAnimationFrame(packetLoop);
}
function packetLoop(now) {
  floor.packets = floor.packets.filter((k) => { const t = (now - k.t0) / k.dur;
    if (t >= 1) { k.node.remove(); return false; }
    k.node.setAttribute("cx", k.p.x + (k.q.x - k.p.x) * t); k.node.setAttribute("cy", k.p.y - 4 + (k.q.y - k.p.y) * t); return true; });
  if (floor.packets.length) requestAnimationFrame(packetLoop);
}
function floorBubble(a, text) {
  const n = floor.layout && floor.layout.nodes.find((x) => x.id === a.id); if (!n || !floor.bb) return;
  while (floor.bubbles.length >= 4) floor.bubbles.shift().node.remove();
  const t = text.length > 16 ? text.slice(0, 15) + "…" : text, w = t.length * 6.6 + 12, b = n.bubble;
  const x = n.side === "u" ? n.x - w / 2 : n.side === "r" ? b.x : b.x + b.w - w;
  const node = S("g", { class: "bub" }, floor.bb);
  S("rect", { x, y: b.y, width: w, height: b.h, rx: 5 }, node); S("text", { x: x + w / 2, y: b.y + 12 }, node, t);
  const rec = { node }; floor.bubbles.push(rec);
  setTimeout(() => node.classList.add("fade"), 1000);
  setTimeout(() => { node.remove(); floor.bubbles = floor.bubbles.filter((k) => k !== rec); }, 1400);
}
function floorEvents(d) {
  if (floor.prep && !d.running) return;   // still the previous run's snapshot
  if (floor.prep && d.mode !== floor.pmode) floorPrep(d.mode);
  else if (d.mode === "quick" && !floor.quick) { floor.quick = true; drawFloor(); }
  if (d.stage && d.stage !== floor.stage) { floor.stage = d.stage; if (floor.banner) floor.banner.textContent = d.stage; }
  (d.events || []).forEach((ev) => {
    if (ev.kind === "stage") return;
    if (floor.prep) { floor.agents.clear(); floor.prep = false; drawFloor(); }
    const a = floorAgent(String(ev.agent || "agent"), ev.tier, ev.role); if (ev.role && !a.role) a.role = String(ev.role);
    const cmd = floorTier(0)[0], lead = floorTier(2)[0], hub = lead || cmd;
    if (ev.kind === "deploy") { a.status = "working"; if (a.tier === 1) floorPacket(cmd || a, a); else if (a.tier === 3) floorPacket(hub || a, a); }
    else if (ev.kind === "tool") { a.status = a.status === "finding" ? a.status : "working"; a.tools++;
      const t = String(ev.tool || "tool"); if (!a.used.includes(t)) a.used.push(t);
      floorBubble(a, t.endsWith(")") ? t : t + "()"); }
    else if (ev.kind === "finding") { a.status = "finding"; a.findings.push(String(ev.detail || "finding #" + ev.seq));
      if (a.tier === 1 || a.tier === 3) floorPacket(a, hub || a); }
    else if (ev.kind === "error") a.status = "finding";
    else if (ev.kind === "done" || ev.kind === "verdict") { if (a.status !== "finding") a.status = "done";
      if (ev.kind === "done" && a.tier === 1) floorPacket(a, lead || cmd || a); }
    paintAgent(a);
  });
  floor.counts = d.counts || null; refreshHud();
}
/* Final state from the report: lights green/red per agent, static HUD. */
function floorFromReport(r) {
  stopPoll(); floorReset(); floor.report = r;
  const sw = r.swarm, roster = (sw && sw.roster) || [];
  if (!roster.length) {   // quick mode: only the analyst desk
    floor.quick = true; floor.counts = { agents_active: 1, agents_total: 1 };
    const a = floorAgent("analyst", 0, "Quick analysis"); a.status = "done";
    a.findings = (r.incidents || []).map((i) => i.storyline.structured.incident_id);
  } else {
    const runs = new Map((sw.agent_runs || []).map((x) => [x.agent, x]));
    roster.forEach((x) => { const a = floorAgent(x.name, x.tier, x.role), run = runs.get(x.name);
      a.findings = (sw.findings || []).filter((f) => f.agent === x.name).map((f) => f.title);
      a.tools = run ? run.tool_calls || 0 : 0; a.used = run ? run.tools_used || [] : [];
      a.dim = !run; a.status = !run ? "idle" : run.error || a.findings.length || run.findings_filed ? "finding" : "done"; });
  }
  drawFloor();
}
function renderSide() {
  const side = $("swarm-side"), r = floor.report; side.textContent = "";
  const a = floor.sel && floor.agents.get(floor.sel);
  if (a) { const d = el("div", "cons"); d.appendChild(el("b")).textContent = a.name;
    [a.role, `status: ${floorStatus(a)} · tool calls: ${a.tools}`, a.used.length ? "tools: " + a.used.join(", ") : "",
      a.findings.length ? "findings:" : "no findings"].filter(Boolean).forEach((t) => d.appendChild(el("div", "meta-line")).textContent = t);
    a.findings.forEach((t) => d.appendChild(el("div", "spec")).textContent = t); side.appendChild(d); }
  const sw = r && r.swarm; if (!sw) return;
  (sw.consensus || []).forEach((c) => side.appendChild(el("div", "cons",
    `${esc(c.incident_id)}: <span class="${c.confirmed_by_tier2 ? "ok" : "no"}">${c.confirmed_by_tier2 ? "CONFIRMED" : "uncorroborated"}</span><br><span class="meta-line">${c.agents_involved} agents · tiers ${JSON.stringify(c.tiers_involved)} · conf ${c.consensus_confidence}</span>`)));
  const t3 = (sw.findings || []).filter((f) => f.tier === 3);
  if (t3.length) { side.appendChild(el("div", "meta-line", "SPECIALIST FINDINGS"));
    t3.forEach((f) => { const d = el("div", "spec", `<b>[${esc(f.severity.toUpperCase())}]</b> <span class="who">${esc(f.role)}</span>: ${esc(f.title)}`);
      if (f.recommended_action) d.appendChild(el("div", "meta-line", esc(f.recommended_action))); side.appendChild(d); }); }
}
function renderSwarm(r) {
  const sw = r.swarm;
  $("swarm-sub").textContent = sw ? `${esc(sw.worker_count)} ${sw.orchestrator ? "workers + commander" : "agents"} · ${esc(sw.counts.confirmed_incidents)} confirmed` : "";
  floorFromReport(r); renderSide();
}

/* live progress polling: GET /api/progress?since=<seq> every 1s while an analysis runs */
const poll = { on: false, seq: 0, gen: 0, timer: null };
function startPoll(mode) {
  if (poll.on) return; poll.on = true; poll.seq = 0; const gen = ++poll.gen;
  floorReset(); floor.live = true; floor.report = null; floorPrep(mode); renderSide();
  (async function tick() {
    if (!poll.on || gen !== poll.gen) return;
    try {
      const res = await fetch("/api/progress?since=" + poll.seq);
      if (!poll.on || gen !== poll.gen) return;
      if (res.status === 404) { poll.on = false; floor.live = false; floor.note = "live feed unavailable"; drawFloor(); return; }
      const d = await res.json();
      if (!poll.on || gen !== poll.gen) return;
      (d.events || []).forEach((e) => { if (e.seq > poll.seq) poll.seq = e.seq; });
      floorEvents(d);
    } catch (e) { /* transient: retry next tick */ }
    poll.timer = setTimeout(tick, 1000);
  })();
}
function stopPoll() { poll.on = false; clearTimeout(poll.timer); floor.live = false; floor.prep = false;
  if (floor.banner) { floor.banner.parentNode.remove(); floor.banner = null; } refreshHud(); }
const withPoll = (p, mode) => { startPoll(mode); return p.finally(stopPoll); };
setInterval(() => {   // gentle random eye blink
  if (reduceMotion() || document.hidden) return;
  const gs = [...floor.agents.values()].filter((a) => a.g); if (!gs.length) return;
  const g = gs[Math.floor(Math.random() * gs.length)].g; g.classList.add("blink"); setTimeout(() => g.classList.remove("blink"), 160);
}, 2600);

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
  resultId = (r.meta || {}).result_id || null;
  renderVerdict(r); renderHero(r); renderPinpointer(r); renderSummary(r); renderStage(r); renderSwarm(r);
  renderIncidents(r); renderIocs(r); renderHunt(r); renderIntel(r);
}
async function mergeMetaAndRender(data) {
  try { const m = await (await fetch("/api/meta")).json(); data.meta = Object.assign({}, m, data.meta);
    if (m.max_upload_bytes) { MAX_UPLOAD_MB = m.max_upload_mb; MAX_UPLOAD_BYTES = m.max_upload_bytes; } } catch (e) {}
  renderAll(data); return data;
}
async function load(url, init) {
  try { const res = await fetch(url, init), data = await res.json().catch(() => ({}));
    if (!res.ok || data.error) throw new Error(data.error || ("HTTP " + res.status));
    await mergeMetaAndRender(data);
    if ($("status").textContent.includes("loading")) $("status").textContent = "sample loaded";
    return data;
  } catch (e) { toast("Load failed: " + esc(e.message || e));
    if ($("status").textContent.includes("loading")) $("status").textContent = "error: " + (e.message || e); }
}

/* ================= download IR report ================= */
async function downloadIR() {
  const btn = $("download-ir"); if (!btn) return;
  btn.disabled = true; toast("Building IR report…");
  try {
    const res = await fetch("/api/report.md" + (resultId ? "?id=" + encodeURIComponent(resultId) : ""));
    if (!res.ok) throw new Error("HTTP " + res.status);
    const blob = await res.blob();
    let fname = "bastion_IR_report.md";
    const m = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    if (m) fname = m[1];
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = fname; document.body.appendChild(a); a.click();
    a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000);   // revoking at once can cancel it in Safari/Firefox
    toast("IR report downloaded");
  } catch (e) { toast("report failed: " + esc(e.message || e)); }
  finally { btn.disabled = false; }
}
(function () { const b = $("download-ir"); if (b) b.addEventListener("click", downloadIR); })();

// On first open, show whatever the server was launched with (samples), so the
// deck isn't empty, but the drop zone is the primary call to action.
(async function boot() {  // startup analysis may still be running: poll until GET /api/report stops answering 202
  let waited = false;
  while ((await fetch("/api/report").then(r => r.status, () => 0)) === 202) {
    if (!waited) startPoll();
    waited = true; $("status").innerHTML = '<span class="spinner"></span> startup analysis in progress…';
    await new Promise(r => setTimeout(r, 2000));
  }
  stopPoll();
  if (waited) $("status").textContent = "";
  load("/api/report").then(d => d || load("/api/refresh", { method: "POST" })); // GET no longer analyzes
})();


/* ================= hero shortcuts ================= */
$("hs-drop").addEventListener("click", () => {
  $("intake").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  $("dropzone").classList.add("drag"); setTimeout(() => $("dropzone").classList.remove("drag"), 900);
});
$("hs-sample").addEventListener("click", () => $("loadsample").click());

// mobile nav menu: button toggles the dropdown, Escape closes (no inline script, CSP-safe)
(function menu() {
  const b = document.getElementById("menu-btn"), bar = b && b.closest && b.closest(".topbar");
  if (!bar) return;   // no menu on this page (or a non-DOM test harness)
  const set = (o) => { bar.classList.toggle("open", o); b.setAttribute("aria-expanded", String(o)); };
  b.addEventListener("click", () => set(b.getAttribute("aria-expanded") !== "true"));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && bar.classList.contains("open")) { set(false); b.focus(); } });
  bar.querySelectorAll(".topnav a").forEach((a) => a.addEventListener("click", () => set(false)));
})();
