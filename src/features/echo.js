/**
 * diatom/src/features/echo.js  — v7
 *
 * The Echo: weekly persona-evolution panel.
 *
 * Triggered by: clicking the 🍃 glyph in the Notes zone (homepage.html).
 * Never pushed, never badged, never modal.
 *
 * Renders:
 *   1. Persona Spectrum (colour gradient bar — no pie chart)
 *   2. Generative Diatom canvas (WebGPU shader or SVG fallback)
 *   3. Information Nutrition breakdown
 *   4. War Report (anti-tracking narrative)
 */

'use strict';

import { invoke } from '../browser/ipc.js';
import { escHtml, el, qs } from '../browser/utils.js';
import { renderDiatomSvg } from './diatom-engine.js';

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Check if there is a pending Echo for this ISO week.
 * If yes, display the 🍃 glyph in the Notes zone.
 */
export async function maybeShowEchoHint() {
  const now     = Date.now();
  // [FIX-S5] Use cmd_setting_get instead of localStorage — keeps all state in SQLite,
  // consistent with Diatom's zero-localStorage-in-chrome principle.
  let lastRun = 0;
  try {
    const raw = await invoke('cmd_setting_get', { key: 'echo:last_run_timestamp' });
    if (raw) lastRun = Number(raw);
  } catch (_) { /* first run */ }

  const WEEK_MS = 7 * 24 * 3600 * 1000;

  // Only show hint once per week, on Monday
  const dayOfWeek = new Date().getDay(); // 0=Sun, 1=Mon
  if (dayOfWeek !== 1) return;
  if (now - lastRun < WEEK_MS) return;

  const notesZone = qs('#notes-zone');
  if (!notesZone) return;

  const hint = el('span', 'echo-hint');
  hint.textContent = '🍃';
  hint.title = 'Your Diatom Echo is ready';
  hint.style.cssText = 'opacity:.5;cursor:pointer;font-size:1.1rem;margin-left:.5rem;transition:opacity .2s';
  hint.addEventListener('mouseenter', () => hint.style.opacity = '1');
  hint.addEventListener('mouseleave', () => hint.style.opacity = '.5');
  hint.addEventListener('click', () => openEchoPanel());
  notesZone.appendChild(hint);
}

/**
 * Open the Echo panel inline (no modal, no navigation).
 */
export async function openEchoPanel() {
  // Compute the Echo from backend
  let echo, warReport;
  try {
    [echo, warReport] = await Promise.all([
      invoke('cmd_echo_compute'),
      invoke('cmd_war_report'),
    ]);
  } catch (err) {
    console.error('[Echo] compute failed:', err);
    return;
  }

  // [FIX-S5] Persist last_run timestamp via IPC, not localStorage
  try {
    await invoke('cmd_setting_set', { key: 'echo:last_run_timestamp', value: String(Date.now()) });
  } catch (_) { /* non-fatal */ }

  const panel = buildPanel(echo, warReport);
  document.body.appendChild(panel);

  // Animate in
  requestAnimationFrame(() => {
    panel.style.opacity = '1';
    panel.style.transform = 'translateY(0)';
  });
}

// ── Panel builder ─────────────────────────────────────────────────────────────

function buildPanel(echo, war) {
  const panel = el('div', 'echo-panel');
  panel.style.cssText = `
    position:fixed; inset:0; z-index:9000;
    background:rgba(10,10,14,.96); color:#e8e8f0;
    font-family:'Inter',system-ui,sans-serif;
    display:flex; flex-direction:column; align-items:center;
    overflow-y:auto; padding:3rem 1.5rem 4rem;
    opacity:0; transform:translateY(1.5rem);
    transition:opacity .35s ease, transform .35s ease;
  `;

  // Close button
  const closeBtn = el('button', 'echo-close');
  closeBtn.textContent = '✕';
  closeBtn.style.cssText = 'position:absolute;top:1.5rem;right:1.5rem;background:none;border:none;color:#888;font-size:1.2rem;cursor:pointer;';
  closeBtn.addEventListener('click', () => {
    panel.style.opacity = '0';
    panel.style.transform = 'translateY(1.5rem)';
    setTimeout(() => panel.remove(), 350);
  });
  panel.appendChild(closeBtn);

  const wrap = el('div', 'echo-wrap');
  wrap.style.cssText = 'width:100%;max-width:700px;';
  panel.appendChild(wrap);

  // Header
  wrap.innerHTML += `
    <div class="echo-header" style="margin-bottom:2.5rem">
      <p style="font-family:'Playfair Display',Georgia,serif;font-size:2rem;font-weight:700;
                color:#e8e8f0;margin:0 0 .25rem">${escHtml(echo.week_iso)} Echo</p>
      <p style="color:#888;font-size:.85rem;margin:0;letter-spacing:.06em">PERSONA · NUTRITION · WAR REPORT</p>
    </div>
  `;

  // 1. Persona Spectrum
  wrap.appendChild(buildSpectrumSection(echo.spectrum));

  // 2. Generative Diatom
  wrap.appendChild(buildDiatomSection(echo));

  // 3. Information Nutrition
  wrap.appendChild(buildNutritionSection(echo.nutrition));

  // 4. War Report
  wrap.appendChild(buildWarSection(war));

  return panel;
}

// ── Persona Spectrum ──────────────────────────────────────────────────────────

function buildSpectrumSection(spectrum) {
  const sec = sectionEl('Persona Spectrum');

  // Continuous gradient bar — NO pie chart, NO bar chart
  const barWrap = el('div');
  barWrap.style.cssText = 'margin:1rem 0;';

  const bar = el('div');
  bar.style.cssText = `
    height:12px; border-radius:6px; width:100%;
    background: linear-gradient(to right,
      rgba(96,165,250,${spectrum.scholar}) 0%,
      rgba(167,139,250,${spectrum.builder}) 50%,
      rgba(251,146,60,${spectrum.leisure}) 100%
    );
    box-shadow:0 0 12px rgba(96,165,250,.2);
  `;
  barWrap.appendChild(bar);

  // Labels
  const labels = el('div');
  labels.style.cssText = 'display:flex;justify-content:space-between;margin-top:.4rem;font-size:.75rem;color:#888;';
  labels.innerHTML = `
    <span>🎓 Scholar  ${pct(spectrum.scholar)}</span>
    <span>⚙️ Builder  ${pct(spectrum.builder)}</span>
    <span>🌿 Leisure  ${pct(spectrum.leisure)}</span>
  `;
  barWrap.appendChild(labels);

  // Delta indicators
  if (Math.abs(spectrum.scholar_delta) > 0.02) {
    const delta = el('p');
    delta.style.cssText = 'font-size:.8rem;color:#94a3b8;margin:.6rem 0 0;';
    const dir = spectrum.scholar_delta > 0 ? '↑' : '↓';
    const ppp = Math.abs(Math.round(spectrum.scholar_delta * 100));
    delta.textContent = `${dir} Scholar weight shifted by ${ppp} percentage points compared to last week.`;
    barWrap.appendChild(delta);
  }

  sec.appendChild(barWrap);
  return sec;
}

// ── Generative Diatom ─────────────────────────────────────────────────────────

function buildDiatomSection(echo) {
  const sec = sectionEl('This Week\'s Form');

  const canvas = el('canvas', 'diatom-canvas');
  canvas.width  = 320;
  canvas.height = 320;
  canvas.style.cssText = 'display:block;margin:1rem auto;border-radius:50%;';

  // Attempt WebGPU; fall back to SVG if unavailable
  requestAnimationFrame(() => {
    renderDiatomSvg(canvas, {
      focus:   echo.focus_score,
      breadth: echo.breadth_score,
      density: echo.density_score,
    });
  });

  sec.appendChild(canvas);
  return sec;
}

// ── Information Nutrition ─────────────────────────────────────────────────────

function buildNutritionSection(n) {
  const sec = sectionEl('Information Nutrition');

  const rows = [
    { label: 'Deep Reading',   value: n.deep_ratio,        color: '#60a5fa', icon: '📗' },
    { label: 'Intentional Reading',   value: n.intentional_ratio,  color: '#a78bfa', icon: '🎯' },
    { label: 'Shallow Consumption',   value: n.shallow_ratio,      color: '#fb923c', icon: '📱' },
    { label: 'Noise Blocked',   value: n.noise_ratio,        color: '#f87171', icon: '🚫' },
  ];

  const grid = el('div');
  grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin:.75rem 0;';

  for (const row of rows) {
    const cell = el('div');
    cell.style.cssText = `
      background:rgba(255,255,255,.04); border-radius:.5rem; padding:.75rem;
      border-left:3px solid ${row.color};
    `;
    cell.innerHTML = `
      <div style="font-size:.7rem;color:#888;margin-bottom:.25rem">${row.icon} ${escHtml(row.label)}</div>
      <div style="font-size:1.4rem;font-weight:600;color:#e8e8f0">${pct(row.value)}</div>
    `;
    grid.appendChild(cell);
  }

  sec.appendChild(grid);

  const suggestion = el('p');
  suggestion.style.cssText = 'color:#94a3b8;font-size:.85rem;margin:.5rem 0 0;line-height:1.6;font-style:italic;';
  suggestion.textContent = n.suggestion;
  sec.appendChild(suggestion);

  return sec;
}

// ── War Report ────────────────────────────────────────────────────────────────

function buildWarSection(war) {
  const sec = sectionEl('Diatom War Report');

  const stats = [
    { value: war.tracking_blocks,  narrative: war.block_narrative  },
    { value: war.noise_injections, narrative: war.noise_narrative  },
    { value: `${war.ram_saved_mb.toFixed(0)} MB`, narrative: war.ram_narrative  },
    { value: `${war.time_saved_min.toFixed(0)} min`, narrative: war.time_narrative },
  ];

  for (const s of stats) {
    const row = el('div');
    row.style.cssText = 'margin-bottom:1rem;padding-bottom:1rem;border-bottom:1px solid rgba(255,255,255,.06);';
    row.innerHTML = `
      <p style="font-family:'Playfair Display',Georgia,serif;font-size:1.4rem;
                color:#e8e8f0;margin:0 0 .25rem;font-weight:600">${escHtml(String(s.value))}</p>
      <p style="color:#64748b;font-size:.82rem;margin:0;line-height:1.5">${escHtml(s.narrative)}</p>
    `;
    sec.appendChild(row);
  }

  const headline = el('p');
  headline.style.cssText = 'font-size:.9rem;color:#94a3b8;font-style:italic;margin-top:.5rem;';
  headline.textContent = war.summary_headline;
  sec.appendChild(headline);

  return sec;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function sectionEl(title) {
  const s = el('div', 'echo-section');
  s.style.cssText = 'margin-bottom:2.5rem;';
  const h = el('h2');
  h.style.cssText = `
    font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;
    color:#475569;border-bottom:1px solid rgba(255,255,255,.06);
    padding-bottom:.5rem;margin:0 0 1rem;
  `;
  h.textContent = title;
  s.appendChild(h);
  return s;
}

function pct(v) { return `${Math.round((v ?? 0) * 100)}%`; }
