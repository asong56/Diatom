/**
 * diatom/src/features/zen.js  — v7
 *
 * Zen Mode frontend.
 *
 * Activation: /zen address-bar command or keyboard shortcut (Ctrl+Shift+Z).
 * Deactivation: user types ≥ 50-character "intent declaration" in the interstitial.
 *
 * When active:
 *   - All Notification API calls are suppressed (handled in sw.js via BroadcastChannel)
 *   - Navigations to blocked-category domains show the Zen interstitial instead of loading
 *   - The address bar receives a faint teal left border
 */

'use strict';

import { invoke } from '../browser/ipc.js';
import { el, qs } from '../browser/utils.js';

let _zenActive = false;
let _aphorism  = 'Now will always have been.';

// ── Init ──────────────────────────────────────────────────────────────────────

export async function initZen() {
  try {
    const cfg = await invoke('cmd_zen_state');
    _zenActive = cfg.state === 'Active';
    _aphorism  = cfg.aphorism || _aphorism;
    if (_zenActive) applyZenUi(true);
  } catch (err) {
    console.warn('[Zen] init failed:', err);
  }

  // Keyboard shortcut: Ctrl+Shift+Z
  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.shiftKey && e.key === 'Z') {
      e.preventDefault();
      _zenActive ? deactivate() : activate();
    }
  });

  // Notify Service Worker of current state
  broadcastToSW();
}

// ── Activate / Deactivate ────────────────────────────────────────────────────

export async function activate() {
  await invoke('cmd_zen_activate');
  _zenActive = true;
  applyZenUi(true);
  broadcastToSW();
}

export async function deactivate() {
  await invoke('cmd_zen_deactivate');
  _zenActive = false;
  applyZenUi(false);
  broadcastToSW();
}

export function isActive() { return _zenActive; }

// ── Interstitial ─────────────────────────────────────────────────────────────

/**
 * Show the Zen interstitial when a blocked domain is navigated to.
 * Returns a Promise that resolves when the user unlocks Zen (or refuses).
 */
export function showInterstitial(domain, category) {
  return new Promise(resolve => {
    // Remove any existing interstitial
    qs('#zen-interstitial')?.remove();

    // P4 fix: inject Zen stylesheet once — Lumière dark tokens + reduced-motion
    if (!qs('#zen-interstitial-style')) {
      const style = document.createElement('style');
      style.id = 'zen-interstitial-style';
      style.textContent = `
        #zen-interstitial {
          position: fixed; inset: 0; z-index: 99999;
          background:
            radial-gradient(ellipse 70% 56% at 50% 46%,
              rgba(64,56,102,0.38) 0%, rgba(64,56,102,0.08) 55%, transparent 72%),
            #171620;
          display: flex; flex-direction: column;
          align-items: center; justify-content: center;
          font-family: var(--f-sans, 'DM Sans', system-ui, sans-serif);
          color: #F2EFF8;
        }
        .zen-aphorism {
          font-family: var(--f-serif, 'Playfair Display', Georgia, serif);
          font-size: clamp(1.1rem,3.8vw,2rem); font-weight: 700;
          text-align: center; max-width: 580px; line-height: 1.55;
          color: #C49248;
          filter: drop-shadow(0 2px 14px rgba(196,146,72,0.26));
          margin: 0 0 2.8rem;
          animation: zen-breathe 4s ease-in-out infinite;
        }
        @keyframes zen-breathe {
          0%,100% { transform:scale(1); opacity:.92; }
          50%      { transform:scale(1.018); opacity:1; }
        }
        @media (prefers-reduced-motion: reduce) {
          .zen-aphorism { animation: none !important; }
        }
        .zen-domain-info {
          color: #4C4860; font-size: .82rem;
          margin: 0 0 2rem; text-align: center;
          font-family: var(--f-mono, 'DM Mono', monospace);
          letter-spacing: 0.04em;
        }
        .zen-unlock-wrap { width: 100%; max-width: 480px; }
        .zen-label { display:block; color:#8A8698; font-size:.78rem; margin-bottom:.5rem; }
        .zen-textarea {
          width:100%; height:4rem;
          background: rgba(160,150,225,0.06);
          border: 0.5px solid rgba(130,120,200,0.24);
          border-radius: 6px; color: #F2EFF8;
          font-family: var(--f-sans, 'DM Sans', system-ui, sans-serif);
          font-size: .84rem; padding:.5rem .75rem; resize:none;
          box-sizing:border-box; outline:none; transition:border-color .12s;
        }
        .zen-textarea:focus {
          border-color: rgba(196,146,72,0.50);
          box-shadow: 0 0 0 2px rgba(196,146,72,0.14);
        }
        .zen-counter {
          color:#4C4860; font-size:.73rem;
          margin:.25rem 0 1rem; text-align:right;
          font-family: var(--f-mono, 'DM Mono', monospace);
          transition: color .12s;
        }
        .zen-counter.ready { color:#C49248; }
        .zen-buttons { display:flex; gap:.75rem; }
        .zen-btn-unlock {
          flex:1; padding:.65rem; border:none; border-radius:6px;
          background: linear-gradient(140deg,#D4A85E 0%,#C49248 55%,#A07030 100%);
          color:rgba(255,252,236,.97); font-size:.84rem; cursor:pointer;
          box-shadow: 0 2px 10px rgba(196,146,72,0.22);
          opacity:.40; transition:opacity .15s, box-shadow .15s;
        }
        .zen-btn-unlock:not(:disabled) { opacity:1; }
        .zen-btn-unlock:not(:disabled):hover { box-shadow:0 2px 18px rgba(196,146,72,0.38); }
        .zen-btn-stay {
          flex:1; padding:.65rem;
          border:0.5px solid rgba(130,120,200,0.24); border-radius:6px;
          background:rgba(160,150,225,0.06); color:#8A8698;
          font-size:.84rem; cursor:pointer; transition:background .12s,color .12s;
        }
        .zen-btn-stay:hover { background:rgba(160,150,225,0.12); color:#CAC6D8; }
      `;
      document.head.appendChild(style);
    }

    const overlay = el('div', '');
    overlay.id = 'zen-interstitial';

    const quote = el('p');
    quote.className = 'zen-aphorism';
    quote.textContent = _aphorism;
    overlay.appendChild(quote);

    const info = el('p');
    info.className = 'zen-domain-info';
    info.textContent = `${domain} · ${category === 'social' ? 'Social media' : 'Entertainment'} · blocked by Zen Mode`;
    overlay.appendChild(info);

    const unlockWrap = el('div');
    unlockWrap.className = 'zen-unlock-wrap';

    const label = el('label');
    label.className = 'zen-label';
    label.textContent = 'Enter your focus declaration (at least 50 characters) to temporarily lift Zen Mode:';
    unlockWrap.appendChild(label);

    const textarea = el('textarea');
    textarea.className = 'zen-textarea';
    textarea.placeholder = 'I need to briefly visit this site because…';
    unlockWrap.appendChild(textarea);

    const counter = el('p');
    counter.className = 'zen-counter';
    counter.textContent = '0 / 50';
    unlockWrap.appendChild(counter);

    const unlockBtn = el('button');
    unlockBtn.disabled = true;
    unlockBtn.textContent = 'Leave focus temporarily';
    unlockBtn.className = 'zen-btn-unlock';

    textarea.addEventListener('input', () => {
      const len = textarea.value.length;
      counter.textContent = `${len} / 50`;
      counter.classList.toggle('ready', len >= 50);
      unlockBtn.disabled = len < 50;
    });

    unlockBtn.addEventListener('click', async () => {
      await deactivate();
      overlay.remove();
      resolve('unlocked');
    });

    const stayBtn = el('button');
    stayBtn.textContent = 'Stay focused';
    stayBtn.className = 'zen-btn-stay';
    stayBtn.addEventListener('click', () => {
      overlay.remove();
      resolve('stayed');
      history.back();
    });

    const buttons = el('div');
    buttons.className = 'zen-buttons';
    buttons.appendChild(stayBtn);
    buttons.appendChild(unlockBtn);
    unlockWrap.appendChild(buttons);
    overlay.appendChild(unlockWrap);

    document.body.appendChild(overlay);
  });
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function applyZenUi(active) {
  const omni = qs('#omnibox');
  if (!omni) return;
  omni.style.borderLeft = active ? '2px solid #0d9488' : '';
  omni.title = active ? 'Zen Mode active · Ctrl+Shift+Z to toggle' : '';
}

function broadcastToSW() {
  const bc = new BroadcastChannel('diatom:sw');
  bc.postMessage({ type: 'ZEN', active: _zenActive });
  bc.close();
}
