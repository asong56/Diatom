
'use strict';

import { invoke } from '../browser/ipc.js';
import { escHtml } from '../browser/utils.js';

const PANEL_ID        = '__diatom_tos_panel';
const TRIGGER_KEY     = 'T'; // ⌘⇧T or Ctrl⇧T

const TOS_URL_SIGNALS = [
  'terms', 'tos', 'privacy', 'policy', 'legal', 'eula',
  'user-agreement', 'conditions', 'gdpr', 'cookie', 'consent',
];

const REG_URL_SIGNALS = [
  'signup', 'sign-up', 'register', 'create-account', 'join', 'onboard',
];

const CONTENT_SELECTORS = [
  '[data-testid*="privacy"]', '[data-testid*="terms"]',
  '.privacy-policy', '.terms-of-service', '.legal-content',
  '.tos-content', '.policy-content', '#privacy-policy',
  '#terms-of-service', '#legal', 'article', 'main',
];

const MIN_TEXT_LENGTH = 400;

const SEV_CONFIG = {
  critical: { icon: '🚨', label: 'Critical', color: 'oklch(50% 0.18 15)',  bg: 'oklch(50% 0.18 15 / 0.08)',  border: 'oklch(50% 0.18 15 / 0.22)' },
  high:     { icon: '⚠️',  label: 'High',     color: 'oklch(58% 0.16 55)', bg: 'oklch(58% 0.16 55 / 0.08)',  border: 'oklch(58% 0.16 55 / 0.22)' },
  medium:   { icon: '📋',  label: 'Medium',   color: 'oklch(70% 0.10 55)', bg: 'oklch(70% 0.10 55 / 0.08)',  border: 'oklch(70% 0.10 55 / 0.22)' },
  low:      { icon: 'ℹ️',  label: 'Low',      color: 'oklch(60% 0.008 260)', bg: 'oklch(60% 0.008 260 / 0.06)', border: 'oklch(60% 0.008 260 / 0.14)' },
};

function urlSignalScore() {
  const path = (location.pathname + location.search).toLowerCase();
  let score = 0;
  if (TOS_URL_SIGNALS.some(s => path.includes(s)))  score += 3;
  if (REG_URL_SIGNALS.some(s => path.includes(s)))   score += 2;
  return score;
}

function linkSignalScore() {
  let score = 0;
  document.querySelectorAll('a').forEach(a => {
    const t = (a.textContent || '').toLowerCase();
    if (t.includes('terms') || t.includes('privacy policy') || t.includes('user agreement')) {
      score += 1;
    }
  });
  return Math.min(score, 3);
}

function hasCheckboxWithTosLink() {
  return Array.from(document.querySelectorAll('input[type="checkbox"]')).some(cb => {
    const parent = cb.closest('label,div,p,li') || cb.parentElement;
    if (!parent) return false;
    const text = parent.textContent.toLowerCase();
    return text.includes('terms') || text.includes('privacy') || text.includes('conditions');
  });
}

function shouldAutoAudit() {
  const score = urlSignalScore() + linkSignalScore() + (hasCheckboxWithTosLink() ? 4 : 0);
  return score >= 3;
}

function extractPolicyText() {
  for (const sel of CONTENT_SELECTORS) {
    const el = document.querySelector(sel);
    if (el && el.innerText && el.innerText.length > MIN_TEXT_LENGTH) {
      return el.innerText.trim().slice(0, 60_000);
    }
  }

  let best = null;
  let bestLen = 0;
  document.querySelectorAll('div, section, article').forEach(el => {
    const len = (el.innerText || '').length;
    if (len > bestLen && len > MIN_TEXT_LENGTH) {
      bestLen = len;
      best = el;
    }
  });
  if (best) return best.innerText.trim().slice(0, 60_000);

  return (document.body?.innerText || '').trim().slice(0, 60_000);
}

function riskMeterSVG(score) {
  const r     = 28;
  const cx    = 40;
  const cy    = 40;
  const circ  = Math.PI * r; // half-circle circumference
  const dash  = (score / 100) * circ;
  const color = score >= 70 ? 'oklch(50% 0.18 15)' : score >= 40 ? 'oklch(58% 0.16 55)' : score >= 20 ? 'oklch(70% 0.10 55)' : 'oklch(50% 0.14 145)';
  return `
    <svg width="80" height="48" viewBox="0 0 80 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M 12 40 A ${r} ${r} 0 0 1 68 40" stroke="rgba(120,120,190,0.15)" stroke-width="6" fill="none" stroke-linecap="round"/>
      <path d="M 12 40 A ${r} ${r} 0 0 1 68 40"
        stroke="${color}" stroke-width="6" fill="none" stroke-linecap="round"
        stroke-dasharray="${dash} ${circ}"
        style="transform-origin:40px 40px; transform: rotate(-180deg)"/>
      <text x="40" y="38" text-anchor="middle" font-size="13" font-weight="600" fill="${color}"
        font-family="ui-monospace,'Cascadia Code',monospace">${score}</text>
    </svg>`;
}

function flagHTML(flag, idx) {
  const sev = SEV_CONFIG[flag.severity] || SEV_CONFIG.low;
  const evidence = flag.evidence
    ? `<blockquote class="tos-evidence">"…${escHtml(flag.evidence.trim())}…"</blockquote>`
    : '';
  return `
    <details class="tos-flag" style="border-color:${sev.border};background:${sev.bg}" data-idx="${idx}">
      <summary class="tos-flag-sum">
        <span class="tos-sev-badge" style="color:${sev.color};border-color:${sev.border}">
          ${sev.icon} ${sev.label}
        </span>
        <span class="tos-flag-title">${escHtml(flag.title)}</span>
        <span class="tos-chevron">›</span>
      </summary>
      <div class="tos-flag-body">
        <p class="tos-explanation">${escHtml(flag.explanation)}</p>
        ${evidence}
        <span class="tos-category">${formatCategory(flag.category)}</span>
      </div>
    </details>`;
}

function formatCategory(cat) {
  const map = {
    data_sharing: '🔗 Data Sharing',
    ai_training: '🤖 AI Training',
    account_deletion: '🗑 Account Deletion',
    intellectual_property: '©️ IP Rights',
    arbitration_clause: '⚖️ Arbitration',
    data_retention: '🗄 Data Retention',
    third_party_tracking: '👁 Tracking',
    auto_renewal: '🔄 Auto-Renewal',
    other: '📌 Other',
  };
  return map[cat] || '📌 ' + cat;
}

function buildPanel(result) {
  const { flags, risk_score, summary, url, text_length } = result;
  const noFlags = flags.length === 0;
  const headerColor = risk_score >= 70 ? 'oklch(50% 0.18 15)' : risk_score >= 40 ? 'oklch(58% 0.16 55)' : risk_score >= 20 ? 'oklch(70% 0.10 55)' : 'oklch(50% 0.14 145)';
  const headerLabel = risk_score >= 70 ? 'High Risk' : risk_score >= 40 ? 'Moderate Risk' : risk_score >= 20 ? 'Low Risk' : 'Appears Safe';

  const flagsHTML = flags.length
    ? flags.map((f, i) => flagHTML(f, i)).join('')
    : '<p class="tos-no-flags">✓ No red-flag clauses detected. Review the full policy for context.</p>';

  const panel = document.createElement('div');
  panel.id = PANEL_ID;
  panel.setAttribute('role', 'complementary');
  panel.setAttribute('aria-label', 'Diatom ToS Risk Audit');
  panel.innerHTML = `
    <style>
      #${PANEL_ID} {
        all: initial;
        display: block;
        position: fixed;
        top: 0; right: 0;
        width: 380px;
        max-height: 88vh;
        overflow-y: auto;
        z-index: 2147483646;
        background: oklch(98.5% 0.003 260);
        border-left: 1px solid oklch(88% 0.005 260);
        border-bottom: 1px solid oklch(88% 0.005 260 / 0.7);
        border-bottom-left-radius: 10px;
        box-shadow: -4px 4px 24px oklch(0% 0 0 / 0.10);
        font-family: 'Switzer', 'Open Sans', ui-sans-serif, system-ui, sans-serif;
        font-size: 13px;
        color: oklch(28% 0.008 260);
        scrollbar-width: thin;
      }
      @media (prefers-color-scheme: dark) {
        #${PANEL_ID} {
          background: oklch(16% 0.004 260);
          color: oklch(88% 0.008 260);
          border-color: oklch(24% 0.005 260);
        }
      }
      .tos-header {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 14px 16px 12px;
        border-bottom: 1px solid oklch(88% 0.005 260 / 0.7);
        position: sticky;
        top: 0;
        background: inherit;
        z-index: 1;
      }
      .tos-header-text { flex: 1; min-width: 0; }
      .tos-eyebrow {
        font-family: ui-monospace, 'Cascadia Code', monospace;
        font-size: 9px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        opacity: 0.5;
        margin-bottom: 2px;
      }
      .tos-risk-label {
        font-size: 14px;
        font-weight: 600;
        color: ${headerColor};
        line-height: 1.2;
      }
      .tos-summary { font-size: 11.5px; opacity: 0.7; margin-top: 2px; line-height: 1.4; }
      .tos-close {
        background: none; border: none; cursor: pointer;
        font-size: 18px; color: inherit; opacity: 0.4;
        padding: 2px 4px; border-radius: 4px; flex-shrink: 0;
        transition: opacity 0.15s;
      }
      .tos-close:hover { opacity: 0.8; }
      .tos-flags { padding: 10px 14px 16px; display: flex; flex-direction: column; gap: 6px; }
      .tos-flag {
        border: 1px solid;
        border-radius: 6px;
        overflow: hidden;
        transition: box-shadow 0.15s;
      }
      .tos-flag[open] { box-shadow: 0 2px 8px rgba(0,0,0,0.07); }
      .tos-flag-sum {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 9px 11px;
        cursor: pointer;
        list-style: none;
        user-select: none;
      }
      .tos-flag-sum::-webkit-details-marker { display: none; }
      .tos-sev-badge {
        font-family: ui-monospace, 'Cascadia Code', monospace;
        font-size: 9.5px;
        letter-spacing: 0.05em;
        border: 1px solid;
        border-radius: 3px;
        padding: 1px 6px;
        white-space: nowrap;
        flex-shrink: 0;
      }
      .tos-flag-title { flex: 1; font-size: 12.5px; font-weight: 500; line-height: 1.3; }
      .tos-chevron { opacity: 0.4; transition: transform 0.15s; }
      .tos-flag[open] .tos-chevron { transform: rotate(90deg); }
      .tos-flag-body { padding: 0 11px 11px; display: flex; flex-direction: column; gap: 7px; }
      .tos-explanation { font-size: 12px; line-height: 1.55; opacity: 0.85; }
      .tos-evidence {
        font-family: ui-monospace, 'Cascadia Code', monospace;
        font-size: 10.5px;
        line-height: 1.5;
        opacity: 0.6;
        border-left: 2px solid currentColor;
        padding: 4px 8px;
        margin: 0;
        word-break: break-word;
      }
      .tos-category {
        font-family: ui-monospace, 'Cascadia Code', monospace;
        font-size: 9.5px;
        opacity: 0.5;
        letter-spacing: 0.05em;
      }
      .tos-no-flags {
        font-size: 12.5px;
        opacity: 0.7;
        padding: 8px 0;
        text-align: center;
      }
      .tos-footer {
        padding: 10px 16px 14px;
        border-top: 1px solid oklch(88% 0.005 260 / 0.6);
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .tos-meta {
        font-family: ui-monospace, 'Cascadia Code', monospace;
        font-size: 9.5px;
        opacity: 0.4;
      }
      .tos-full-link {
        font-size: 11px;
        opacity: 0.6;
        cursor: pointer;
        text-decoration: underline;
        background: none;
        border: none;
        color: inherit;
      }
      .tos-full-link:hover { opacity: 0.9; }
    </style>

    <div class="tos-header">
      ${riskMeterSVG(risk_score)}
      <div class="tos-header-text">
        <div class="tos-eyebrow">Diatom · ToS Audit</div>
        <div class="tos-risk-label">${headerLabel} · ${risk_score}/100</div>
        <div class="tos-summary">${flags.length} clause${flags.length !== 1 ? 's' : ''} flagged</div>
      </div>
      <button class="tos-close" aria-label="Close ToS audit panel">✕</button>
    </div>

    <div class="tos-flags">${flagsHTML}</div>

    <div class="tos-footer">
      <span class="tos-meta">${text_length.toLocaleString()} chars analysed · local only</span>
      <button class="tos-full-link" id="tos-full-btn">View full summary ›</button>
    </div>
  `;

  return panel;
}

function buildFullSummary(result) {
  const { flags, risk_score, summary, url } = result;
  const overlay = document.createElement('div');
  overlay.id = '__diatom_tos_full';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-label', 'Full ToS Audit Summary');
  overlay.style.cssText = `
    all: initial; display: flex; position: fixed; inset: 0;
    z-index: 2147483647; background: rgba(20,18,40,0.72);
    backdrop-filter: blur(6px); align-items: center; justify-content: center;
    font-family: 'Switzer', 'Open Sans', ui-sans-serif, system-ui, sans-serif;
  `;

  const rows = flags.map(f => {
    const sev = SEV_CONFIG[f.severity] || SEV_CONFIG.low;
    return `<tr>
      <td style="padding:7px 10px;white-space:nowrap">
        <span style="color:${sev.color};font-weight:500;font-size:11px">${sev.icon} ${sev.label}</span>
      </td>
      <td style="padding:7px 10px;font-weight:500;font-size:12px">${escHtml(f.title)}</td>
      <td style="padding:7px 10px;font-size:11.5px;opacity:0.75">${escHtml(f.explanation)}</td>
    </tr>`;
  }).join('');

  overlay.innerHTML = `
    <div style="background:oklch(98.5% 0.003 260);border-radius:12px;max-width:680px;width:90%;
      max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.3);padding:28px;">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px">
        ${riskMeterSVG(risk_score)}
        <div>
          <div style="font-family:ui-monospace,'Cascadia Code',monospace;font-size:10px;letter-spacing:0.1em;text-transform:uppercase;opacity:0.5;margin-bottom:4px">Diatom · ToS Red-Flag Audit</div>
          <div style="font-size:18px;font-weight:600;color:oklch(28% 0.008 260)">${summary}</div>
          <div style="font-size:11px;opacity:0.5;margin-top:3px">${escHtml(url)}</div>
        </div>
        <button onclick="this.closest('#__diatom_tos_full').remove()" aria-label="Close"
          style="margin-left:auto;background:none;border:none;cursor:pointer;font-size:20px;opacity:0.4">✕</button>
      </div>
      ${flags.length ? `
        <table style="width:100%;border-collapse:collapse;font-family:'Switzer','Open Sans',ui-sans-serif,system-ui">
          <thead>
            <tr style="border-bottom:1px solid oklch(88% 0.005 260 / 0.8)">
              <th style="text-align:left;padding:6px 10px;font-size:10px;letter-spacing:0.08em;opacity:0.5;font-weight:500">SEVERITY</th>
              <th style="text-align:left;padding:6px 10px;font-size:10px;letter-spacing:0.08em;opacity:0.5;font-weight:500">CLAUSE</th>
              <th style="text-align:left;padding:6px 10px;font-size:10px;letter-spacing:0.08em;opacity:0.5;font-weight:500">WHAT IT MEANS</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      ` : '<p style="opacity:0.6;text-align:center;padding:20px">No red-flag clauses detected.</p>'}
      <p style="font-size:11px;opacity:0.4;margin-top:18px;line-height:1.5">
        ⚙ Analysis is heuristic-based and runs entirely on-device. Always read the full policy for legal matters.
        Powered by Diatom ToS Auditor v1.0.
      </p>
    </div>`;

  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.remove();
  });
  return overlay;
}

let _panelActive = false;
let _lastResult  = null;

function showPanel(result) {
  const existing = document.getElementById(PANEL_ID);
  if (existing) existing.remove();

  _lastResult  = result;
  _panelActive = true;

  const panel = buildPanel(result);
  document.body.appendChild(panel);

  panel.querySelector('.tos-close').addEventListener('click', () => {
    panel.remove();
    _panelActive = false;
  });

  panel.querySelector('#tos-full-btn').addEventListener('click', () => {
    const existing = document.getElementById('__diatom_tos_full');
    if (existing) { existing.remove(); return; }
    document.body.appendChild(buildFullSummary(result));
  });

  const nav = new MutationObserver(() => {
    if (document.getElementById(PANEL_ID) === panel) {
    } else {
      nav.disconnect();
    }
  });
  nav.observe(document.documentElement, { childList: true, subtree: false });
}

let _auditInProgress = false;

async function runAudit(forceShow = false) {
  if (_auditInProgress) return;
  _auditInProgress = true;

  try {
    const text = extractPolicyText();
    if (text.length < MIN_TEXT_LENGTH) {
      if (forceShow) {
        console.info('[tos-auditor] Page has too little text to audit meaningfully.');
      }
      return;
    }

    let loadingEl = null;
    if (forceShow) {
      loadingEl = document.createElement('div');
      loadingEl.id = '__diatom_tos_loading';
      loadingEl.style.cssText = `
        all:initial; display:flex; position:fixed; top:12px; right:12px;
        z-index:2147483646; background:oklch(20% 0.02 260 / 0.88); color:oklch(90% 0.03 220);
        font-family:ui-monospace,'Cascadia Code',monospace; font-size:11px; padding:7px 14px;
        border-radius:6px; gap:8px; align-items:center;
        box-shadow: 0 4px 16px rgba(0,0,0,0.2);
      `;
      loadingEl.innerHTML = '<span style="animation:spin 1s linear infinite;display:inline-block">⚙</span> Auditing policy…';
      loadingEl.style.cssText += `@keyframes spin{to{transform:rotate(360deg)}}`;
      document.body.appendChild(loadingEl);
    }

    const result = await invoke('cmd_tos_audit', {
      url: location.href,
      text,
    });

    if (loadingEl) loadingEl.remove();

    if (!forceShow && result.flags.length === 0) return;

    showPanel(result);

  } catch (err) {
    console.warn('[tos-auditor] audit failed:', err);
  } finally {
    _auditInProgress = false;
  }
}

let _currentUrl  = location.href;
let _navTimer    = null;   // [BUG-5 FIX] single settle-timer slot

function onNavigate(url) {
  _currentUrl  = url;
  _panelActive = false;

  clearTimeout(_navTimer);

  _navTimer = setTimeout(() => {
    _navTimer = null;
    if (_currentUrl !== url) return;   // superseded by a later navigation
    if (!shouldAutoAudit()) return;
    if (window.__DIATOM_INIT__?.labs?.tos_auditor === false) return;
    runAudit(false);
  }, 1500);
}

document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === TRIGGER_KEY) {
    e.preventDefault();
    if (_panelActive && document.getElementById(PANEL_ID)) {
      document.getElementById(PANEL_ID).remove();
      _panelActive = false;
    } else {
      runAudit(true);
    }
  }
}, { capture: false });

export const tosAuditor = {
  audit: () => runAudit(true),
  onNavigate,
  lastResult: () => _lastResult,
};

window.__diatom_tos_auditor = tosAuditor;
