// BlueCell dashboard app
// WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
// Built by Harikishore Karunanithi. MIT - attribution required.
"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html !== undefined) n.innerHTML = html;
  return n;
};
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function toast(msg) {
  const t = $("toast");
  t.textContent = msg; t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2500);
}

function card(num, lbl) {
  const c = el("div", "card");
  c.appendChild(el("div", "num", esc(num)));
  c.appendChild(el("div", "lbl", esc(lbl)));
  return c;
}

function renderStats(r) {
  const host = $("stat-cards"); host.innerHTML = "";
  const m = r.meta || {};
  const sw = r.swarm || { agent_count: 0, counts: {} };
  const crit = (r.incidents || []).filter(
    (i) => (i.storyline.structured.severity === "critical")).length;
  host.appendChild(card(m.events_ingested ?? 0, "Events ingested"));
  host.appendChild(card((r.incidents || []).length, "Incidents"));
  host.appendChild(card(sw.agent_count ?? 0, "Agents deployed"));
  host.appendChild(card(crit, "Critical incidents"));
  $("backbone").textContent = "backbone: " + (m.backbone || "unknown");
  $("ver").textContent = "v" + (m.version || "");
}

function renderIncidents(r) {
  const host = $("incidents"); host.innerHTML = "";
  const incs = r.incidents || [];
  if (!incs.length) { host.appendChild(el("p", "empty", "No incidents crossed the threshold.")); return; }
  incs.forEach((inc) => {
    const s = inc.storyline.structured;
    const box = el("div", "incident");
    const row = el("div", "row");
    row.appendChild(el("span", "id", esc(s.incident_id)));
    row.appendChild(el("span", "sev " + s.severity, s.severity.toUpperCase() + " · " + s.score + "/100"));
    box.appendChild(row);
    const bar = el("div", "scorebar"); const fill = el("i");
    fill.style.width = Math.max(4, s.score) + "%"; bar.appendChild(fill); box.appendChild(bar);
    box.appendChild(el("div", "meta-line",
      `${esc(s.window.start)} → ${esc(s.window.end)} · hosts: ${esc((s.affected_hosts || []).join(", ") || "n/a")} · sources: ${esc((s.sources_involved || []).join(", "))}`));
    box.appendChild(el("div", "meta-line", "Objective: <b>" + esc(s.likely_objective) + "</b>"));
    const phases = el("div", "phases");
    (s.phases || []).forEach((p) => {
      phases.appendChild(el("span", "chip tactic", esc(p.tactic)));
      (p.techniques || []).forEach((t) => phases.appendChild(el("span", "chip", esc(t.id))));
    });
    box.appendChild(phases);
    const story = el("div", "story",
      `RCA (${esc(inc.storyline.narrative_source)}):\n` + esc(inc.storyline.narrative));
    box.appendChild(story);
    host.appendChild(box);
  });
}

function renderSwarm(r) {
  const host = $("swarm"); host.innerHTML = "";
  const sw = r.swarm;
  if (!sw) { host.appendChild(el("p", "empty", "Swarm did not run.")); return; }
  (sw.roster || []).forEach((a) => {
    const it = el("div", "roster-item");
    it.appendChild(el("span", "tier", "T" + a.tier));
    it.appendChild(el("span", null, `<b>${esc(a.name)}</b> — ${esc(a.role)}`));
    host.appendChild(it);
  });
  const cons = el("div", "consensus", "<h2 style='margin-top:12px'>Consensus</h2>");
  (sw.consensus || []).forEach((c) => {
    cons.appendChild(el("div", null,
      `${esc(c.incident_id)} — <span class="${c.confirmed_by_tier2 ? "confirmed" : "unconf"}">${c.confirmed_by_tier2 ? "✅ CONFIRMED" : "⏳ uncorroborated"}</span> · ${c.agents_involved} agents · conf ${c.consensus_confidence}`));
  });
  host.appendChild(cons);
  const t3 = (sw.findings || []).filter((f) => f.tier === 3);
  if (t3.length) {
    host.appendChild(el("h2", null, "Specialist findings"));
    t3.forEach((f) => {
      const d = el("div", "spec",
        `<b>[${esc(f.severity.toUpperCase())}]</b> <span class="who">${esc(f.role)}</span>: ${esc(f.title)}`);
      if (f.recommended_action) d.appendChild(el("div", "meta-line", esc(f.recommended_action)));
      host.appendChild(d);
    });
  }
}

function renderIocs(r) {
  const host = $("iocs"); host.innerHTML = "";
  const iocs = r.iocs || {};
  let any = false;
  ["hash", "domain", "ip", "process", "user"].forEach((kind) => {
    const items = (iocs[kind] || []).filter((x) => x.suspicious);
    const show = items.length ? items : (iocs[kind] || []).slice(0, 3);
    if (!show.length) return;
    any = true;
    host.appendChild(el("h2", null, kind.toUpperCase()));
    const t = el("table");
    t.appendChild(el("tr", null, "<th>value</th><th>×</th><th>hosts</th>"));
    show.slice(0, 12).forEach((x) => {
      t.appendChild(el("tr", null,
        `<td><code>${esc(x.value)}</code> ${x.suspicious ? '<span class="flag">⚠</span>' : ""}</td>` +
        `<td>${x.count}</td><td>${esc((x.hosts || []).join(", "))}</td>`));
    });
    host.appendChild(t);
  });
  if (!any) host.appendChild(el("p", "empty", "No IOCs extracted."));
}

function renderHunt(r) {
  const host = $("hunt"); host.innerHTML = "";
  const checks = r.hunt_checklist || [];
  if (!checks.length) { host.appendChild(el("p", "empty", "No hunt actions.")); return; }
  checks.forEach((c) => {
    const d = el("div", "hunt-item " + c.priority);
    d.appendChild(el("div", "p", c.priority));
    d.appendChild(el("div", null, "<b>" + esc(c.action) + "</b>"));
    if ((c.targets || []).length) d.appendChild(el("div", "meta-line", "targets: " + esc(c.targets.slice(0, 20).join(", "))));
    d.appendChild(el("div", "meta-line", esc(c.why)));
    host.appendChild(d);
  });
}

function renderIntel(r) {
  const host = $("intel"); host.innerHTML = "";
  const intel = r.intel_used || [];
  if (!intel.length) { host.appendChild(el("p", "empty", "No threat intel matched.")); return; }
  const t = el("table");
  t.appendChild(el("tr", null, "<th>id</th><th>title</th><th>sev</th><th>src</th>"));
  intel.forEach((e) => t.appendChild(el("tr", null,
    `<td><code>${esc(e.id)}</code></td><td>${esc(e.title)}</td><td>${esc(e.severity || "?")}</td><td>${esc(e.source || "?")}</td>`)));
  host.appendChild(t);
}

function renderAll(r) {
  if (r.error) { toast("Analysis error: " + r.error); return; }
  renderStats(r); renderIncidents(r); renderSwarm(r);
  renderIocs(r); renderHunt(r); renderIntel(r);
}

async function load(url) {
  const res = await fetch(url);
  const data = await res.json();
  // fold /api/meta version in for the footer
  try { const m = await (await fetch("/api/meta")).json(); data.meta = Object.assign({}, m, data.meta); } catch (e) {}
  renderAll(data);
  return data;
}

$("refresh").addEventListener("click", async () => {
  $("refresh").disabled = true; toast("Re-analyzing…");
  try { await load("/api/refresh"); toast("Updated."); }
  catch (e) { toast("Failed: " + e); }
  finally { $("refresh").disabled = false; }
});

load("/api/report").catch((e) => toast("Load failed: " + e));
