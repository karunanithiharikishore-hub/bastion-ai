// BlueCell sentinel: procedural 3D hero visual (wireframe shell, core, orbiting nodes, targeting eye).
// WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
// Built by Harikishore Karunanithi. MIT - attribution required.
// Pure canvas, no dependencies, so it works offline. Motion: ambient rotation plus pointer parallax.
"use strict";
(function sentinel() {
  const c = document.getElementById("sentinel");
  if (!c) return;
  const x = c.getContext("2d");
  const hero = c.closest(".hero-stage") || c.parentElement;
  const reduce = matchMedia("(prefers-reduced-motion: reduce)");
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

  let S = 0, dpr = 1, yaw = 0.6, pitch = 0.32, ty = 0.6, tp = 0.32, running = true, raf = 0;
  const T0 = performance.now();

  /* ---- geometry (unit sphere) ---- */
  const poly = (n, f) => Array.from({ length: n + 1 }, (_, i) => f((i / n) * Math.PI * 2));
  const lats = [-60, -40, -20, 0, 20, 40, 60].map((d) => {
    const a = (d * Math.PI) / 180, r = Math.cos(a), y = Math.sin(a);
    return poly(56, (t) => [r * Math.cos(t), y, r * Math.sin(t)]);
  });
  const lons = Array.from({ length: 14 }, (_, k) => {
    const o = (k / 14) * Math.PI;
    return poly(48, (t) => [Math.cos(t) * Math.cos(o), Math.sin(t), Math.cos(t) * Math.sin(o)]);
  });
  const OCT = [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]];
  const OCT_E = [[0, 2], [0, 3], [0, 4], [0, 5], [1, 2], [1, 3], [1, 4], [1, 5], [2, 4], [4, 3], [3, 5], [5, 2]];
  const ORBITS = [
    { tilt: 0.5, roll: 0.2, rad: 1.38, sats: [0, 2.4], spd: 0.35 },
    { tilt: 1.15, roll: 1.6, rad: 1.52, sats: [1.1, 4.2], spd: -0.27 },
    { tilt: -0.7, roll: 0.9, rad: 1.66, sats: [3.3], spd: 0.2 },
  ];

  const rot = (p, ya, pi) => {
    const cy = Math.cos(ya), sy = Math.sin(ya), cp = Math.cos(pi), sp = Math.sin(pi);
    const x1 = p[0] * cy + p[2] * sy, z1 = -p[0] * sy + p[2] * cy;
    return [x1, p[1] * cp - z1 * sp, p[1] * sp + z1 * cp];
  };
  const tiltRing = (a, rad, tilt, roll) => {  // point on an inclined ring, pre-rotation
    let p = [rad * Math.cos(a), 0, rad * Math.sin(a)];
    const ct = Math.cos(tilt), st = Math.sin(tilt), cr = Math.cos(roll), sr = Math.sin(roll);
    p = [p[0], p[1] * ct - p[2] * st, p[1] * st + p[2] * ct];
    return [p[0] * cr - p[1] * sr, p[0] * sr + p[1] * cr, p[2]];
  };

  function resize() {
    const r = c.getBoundingClientRect();
    S = r.width; dpr = Math.min(2, window.devicePixelRatio || 1);
    c.width = Math.round(S * dpr); c.height = Math.round(r.height * dpr);
    if (reduce.matches) frame(performance.now());
  }

  function frame(now) {
    const t = (now - T0) / 1000;
    if (!reduce.matches) { yaw += (ty - yaw) * 0.04 + 0.0026; pitch += (tp - pitch) * 0.04; }
    const ink = css("--ink"), acc = css("--accent"), acc2 = css("--accent-2"), bg = css("--bg");
    const threat = document.body.dataset.threat;
    const eyeCol = threat === "malicious" ? css("--crit") : threat === "benign" ? css("--low") : acc;

    x.setTransform(dpr, 0, 0, dpr, 0, 0);
    x.clearRect(0, 0, S, S);
    const cx = S / 2, cy = S / 2, R = S * 0.265, F = 3.4;
    const P = (p) => { const k = F / (F + p[2]); return [cx + p[0] * R * k, cy - p[1] * R * k, p[2], k]; };

    /* outer dashed ring + tick ring (screen plane) */
    x.save(); x.translate(cx, cy);
    x.strokeStyle = ink; x.globalAlpha = 0.28; x.lineWidth = 1;
    x.setLineDash([3, 9]); x.lineDashOffset = -t * 6;
    x.beginPath(); x.arc(0, 0, S * 0.455, 0, 7); x.stroke();
    x.setLineDash([]); x.globalAlpha = 0.5;
    x.rotate(t * 0.05);
    for (let i = 0; i < 120; i++) {
      const a = (i / 120) * Math.PI * 2, long = i % 10 === 0, r0 = S * 0.43, r1 = r0 + (long ? 10 : 4);
      x.globalAlpha = long ? 0.7 : 0.3;
      x.beginPath(); x.moveTo(Math.cos(a) * r0, Math.sin(a) * r0); x.lineTo(Math.cos(a) * r1, Math.sin(a) * r1); x.stroke();
    }
    x.restore();

    /* orbit rings (back half dim, front half bright) */
    ORBITS.forEach((o) => {
      x.lineWidth = 1; x.strokeStyle = acc2;
      let prev = null;
      for (let i = 0; i <= 90; i++) {
        const q = P(rot(tiltRing((i / 90) * Math.PI * 2, o.rad, o.tilt, o.roll), yaw, pitch));
        if (prev) { x.globalAlpha = q[2] > 0 ? 0.08 : 0.3; x.beginPath(); x.moveTo(prev[0], prev[1]); x.lineTo(q[0], q[1]); x.stroke(); }
        prev = q;
      }
    });

    /* shell mesh */
    x.strokeStyle = ink; x.lineWidth = 1;
    const drawLine = (pts) => {
      let prev = null;
      for (const p of pts) {
        const q = P(rot(p, yaw, pitch));
        if (prev) { const f = (q[2] + prev[2]) / 2; x.globalAlpha = f > 0 ? 0.07 : 0.1 + (0.5 * (1 - (f + 1) / 2)) * 0.9; x.beginPath(); x.moveTo(prev[0], prev[1]); x.lineTo(q[0], q[1]); x.stroke(); }
        prev = q;
      }
    };
    // z>0 is away from camera in this projection: the near side reads brighter
    lats.forEach(drawLine); lons.forEach(drawLine);

    /* inner core: counter-rotating octahedron */
    x.strokeStyle = acc; x.lineWidth = 1.4;
    const cp = OCT.map((v) => P(rot(v.map((n) => n * 0.46), -yaw * 1.6 + t * 0.4, pitch * 0.5 + 0.4)));
    OCT_E.forEach(([a, b]) => { x.globalAlpha = 0.85; x.beginPath(); x.moveTo(cp[a][0], cp[a][1]); x.lineTo(cp[b][0], cp[b][1]); x.stroke(); });

    /* orbiting nodes with short trails */
    x.fillStyle = ink;
    ORBITS.forEach((o) => o.sats.forEach((s0) => {
      for (let k = 0; k < 12; k++) {
        const a = s0 + t * o.spd - k * 0.035 * Math.sign(o.spd);
        const q = P(rot(tiltRing(a, o.rad, o.tilt, o.roll), yaw, pitch));
        x.globalAlpha = (1 - k / 12) * (q[2] > 0 ? 0.35 : 1);
        x.beginPath(); x.arc(q[0], q[1], k === 0 ? 3.2 : 1.6 * (1 - k / 14), 0, 7); x.fill();
      }
    }));

    /* sentinel eye: lens, aperture rings, scan arc, pupil, lock brackets (fixed to screen) */
    x.save(); x.translate(cx, cy);
    x.globalAlpha = 0.9; x.fillStyle = bg; x.beginPath(); x.arc(0, 0, R * 0.2, 0, 7); x.fill();
    x.strokeStyle = eyeCol; x.lineWidth = 1.5; x.globalAlpha = 0.95;
    x.beginPath(); x.arc(0, 0, R * 0.2, 0, 7); x.stroke();
    x.globalAlpha = 0.5; x.lineWidth = 1;
    x.beginPath(); x.arc(0, 0, R * 0.135, 0, 7); x.stroke();
    x.globalAlpha = 1; x.lineWidth = 2.2;
    x.beginPath(); x.arc(0, 0, R * 0.17, t * 1.8, t * 1.8 + 1.1); x.stroke();
    x.globalAlpha = 0.9; x.fillStyle = eyeCol;
    const pulse = 1 + 0.12 * Math.sin(t * 3);
    x.beginPath(); x.arc(0, 0, R * 0.055 * pulse, 0, 7); x.fill();
    const bk = R * (0.36 + 0.02 * Math.sin(t * 1.5)), bl = R * 0.09;
    x.globalAlpha = 0.9; x.lineWidth = 1.5;
    [[-1, -1], [1, -1], [1, 1], [-1, 1]].forEach(([sx, sy]) => {
      x.beginPath(); x.moveTo(sx * bk, sy * (bk - bl)); x.lineTo(sx * bk, sy * bk); x.lineTo(sx * (bk - bl), sy * bk); x.stroke();
    });
    x.restore();
    x.globalAlpha = 1;
  }

  function loop(now) { frame(now); if (running && !reduce.matches) raf = requestAnimationFrame(loop); }
  function start() { cancelAnimationFrame(raf); running = true; raf = requestAnimationFrame(loop); }

  hero.addEventListener("pointermove", (e) => {
    const r = hero.getBoundingClientRect();
    ty = 0.6 + ((e.clientX - r.left) / r.width - 0.5) * 1.1;
    tp = 0.32 + ((e.clientY - r.top) / r.height - 0.5) * 0.5;
  }, { passive: true });
  new IntersectionObserver(([en]) => { running = en.isIntersecting; if (running) start(); }).observe(c);
  addEventListener("resize", resize);
  reduce.addEventListener("change", () => { resize(); if (!reduce.matches) start(); });
  resize(); reduce.matches ? frame(performance.now()) : start();
})();
