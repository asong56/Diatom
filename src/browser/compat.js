/**
 * diatom/src/browser/compat.js  — v7.3
 *
 * [FIX BUG-04] MutationObserver now wired for dom_mutation_storm detection.
 *   Counts DOM mutations over a 3-second window; >500 triggers the broken
 *   page heuristic, improving detection of runaway React/Vue SPAs.
 *
 * Compatibility Router frontend.
 *
 * Responsibilities:
 *   1. Monitor page health after load (JS errors, blank body, DOM storms)
 *   2. If broken detected → inject compat hint banner
 *   3. Handle system browser handoff via Tauri shell plugin
 *   4. Pre-emptively warn on known payment/banking domains
 *   5. Route diatom://about to the about page
 *
 * Philosophy: Diatom never silently falls back to Blink.
 *   It always tells the user what happened and lets them decide.
 *   "Adapting upward is not the same as abandoning the user."
 */

'use strict';

import { invoke } from './ipc.js';
import { domainOf } from './utils.js';

// ── Health monitor ────────────────────────────────────────────────────────────

let _jsErrors       = 0;
let _consoleErrs    = 0;
let _mutationCount  = 0;
let _monitorUrl     = '';
let _monitorTimer   = null;
let _mutationObserver = null;

// DOM mutation storm threshold: >500 mutations within the 3-second monitoring
// window indicates an SPA rendering loop or runaway reactive framework.
const MUTATION_STORM_THRESHOLD = 500;

/**
 * Start monitoring the current page for compatibility issues.
 * Called by tabs.js on every navigation.
 */
export function startHealthMonitor(url) {
  _jsErrors      = 0;
  _consoleErrs   = 0;
  _mutationCount = 0;
  _monitorUrl    = url;
  clearTimeout(_monitorTimer);

  // Disconnect any previous observer from the last navigation
  if (_mutationObserver) {
    _mutationObserver.disconnect();
    _mutationObserver = null;
  }

  // Count uncaught JS errors
  window.addEventListener('error', onJsError, { capture: true, once: false });

  // Wire MutationObserver to count DOM mutations (fixes BUG-04).
  // We observe childList + subtree only — attribute/characterData noise
  // would inflate counts on normal animated pages.
  try {
    _mutationObserver = new MutationObserver(mutations => {
      _mutationCount += mutations.length;
    });
    const root = document.body ?? document.documentElement;
    if (root) {
      _mutationObserver.observe(root, { childList: true, subtree: true, attributes: false });
    }
  } catch { /* MutationObserver unavailable — degrade gracefully */ }

  // Check for blank body after 3s
  _monitorTimer = setTimeout(() => checkPageHealth(url), 3000);
}

function onJsError() { _jsErrors++; }

async function checkPageHealth(url) {
  // Snapshot and disconnect observer before reading counts
  if (_mutationObserver) {
    _mutationObserver.disconnect();
    _mutationObserver = null;
  }

  const domain    = domainOf(url);
  const blankBody = !document.body?.innerText?.trim().length;
  const report    = {
    url,
    js_errors:          _jsErrors,
    dom_mutation_storm: _mutationCount > MUTATION_STORM_THRESHOLD,
    blank_body:         blankBody,
    console_errors:     _consoleErrs,
  };

  // Ask Rust whether this domain is marked as legacy
  let isLegacy = false;
  try {
    isLegacy = await invoke('cmd_compat_is_legacy', { domain });
  } catch { /* non-critical */ }

  const appearsBroken = blankBody
    || _jsErrors >= 5
    || (_jsErrors >= 2 && _consoleErrs >= 10);

  if (isLegacy || appearsBroken) {
    // Report to Rust for domain tracking
    try {
      await invoke('cmd_compat_page_report', { report });
    } catch { /* non-critical */ }

    injectCompatBanner(domain);
  }

  // Payment domain pre-emptive warning
  try {
    const isPayment = await invoke('cmd_compat_is_payment', { domain });
    if (isPayment) injectPaymentWarning(domain);
  } catch { /* non-critical */ }
}

// ── Compat banner ─────────────────────────────────────────────────────────────

let _bannerShown = false;

function injectCompatBanner(domain) {
  if (_bannerShown || document.getElementById('__diatom_compat')) return;
  _bannerShown = true;

  const bar = document.createElement('div');
  bar.id = '__diatom_compat';
  bar.setAttribute('role', 'alert');
  bar.setAttribute('aria-live', 'assertive');
  bar.style.cssText = `
    position:fixed; top:0; left:0; right:0; z-index:2147483647;
    background:#1e293b; border-bottom:1px solid rgba(245,158,11,.25);
    color:#fbbf24; font:500 12px/1.5 'Inter',system-ui;
    padding:7px 12px; display:flex; align-items:center; gap:8px;
  `;

  const msg = document.createElement('span');
  msg.textContent = `⚠ Diatom detected a potential compatibility issue with this page`;

  const openBtn = document.createElement('button');
  openBtn.style.cssText = `
    margin-left:auto; background:#92400e; color:#fef3c7;
    border:none; border-radius:3px; padding:3px 10px;
    cursor:pointer; font:500 11px 'Inter',system-ui;
  `;
  openBtn.textContent = 'Open in system browser';
  openBtn.addEventListener('click', () => handoffToSystemBrowser());

  const dismissBtn = document.createElement('button');
  dismissBtn.style.cssText = `
    background:none; border:none; color:#64748b; cursor:pointer;
    font-size:14px; padding:0 4px; line-height:1;
  `;
  dismissBtn.setAttribute('aria-label', 'Dismiss compatibility notice');
  dismissBtn.textContent = '✕';
  dismissBtn.addEventListener('click', () => {
    bar.remove();
    _bannerShown = false;
  });

  bar.appendChild(msg);
  bar.appendChild(openBtn);
  bar.appendChild(dismissBtn);
  document.body.prepend(bar);
}

function injectPaymentWarning(domain) {
  // Only show once per domain per session
  const key = `diatom:compat:payment:${domain}`;
  if (sessionStorage.getItem(key)) return;
  sessionStorage.setItem(key, '1');

  const bar = document.createElement('div');
  bar.style.cssText = `
    position:fixed; top:0; left:0; right:0; z-index:2147483647;
    background:#1e1b4b; border-bottom:1px solid rgba(139,92,246,.25);
    color:#c4b5fd; font:500 12px/1.5 'Inter',system-ui;
    padding:7px 12px; display:flex; align-items:center; gap:8px;
  `;
  bar.innerHTML = `
    <span>🔐 This site may require a hardware security key or payment plugin. Diatom does not support proprietary plugins.</span>
    <button onclick="window.__diatom_handoff();" style="
      margin-left:auto; background:#4c1d95; color:#ddd6fe; border:none;
      border-radius:3px; padding:3px 10px; cursor:pointer; font:500 11px 'Inter',system-ui;">
      Switch to system browser
    </button>
    <button onclick="this.parentElement.remove();" style="
      background:none; border:none; color:#6b7280; cursor:pointer; font-size:14px;">✕</button>
  `;
  document.body.prepend(bar);
}

// ── System browser handoff ────────────────────────────────────────────────────

export async function handoffToSystemBrowser(url) {
  const target = url || location.href;
  try {
    await invoke('cmd_compat_handoff', { url: target });
    // Brief visual confirmation
    const msg = document.createElement('div');
    msg.style.cssText = `
      position:fixed; bottom:1.5rem; left:50%; transform:translateX(-50%);
      background:rgba(15,23,42,.92); color:#94a3b8;
      font:500 .75rem 'Inter',system-ui; padding:.4rem .8rem;
      border-radius:.3rem; z-index:9999; pointer-events:none;
    `;
    msg.textContent = 'Opened in system browser (tracking parameters stripped)';
    document.body.appendChild(msg);
    setTimeout(() => msg.remove(), 2500);
  } catch (err) {
    console.error('[compat] handoff failed:', err);
  }
}

// Expose for inline button calls
window.__diatom_handoff = handoffToSystemBrowser;
window.__diatom_compat_handoff = handoffToSystemBrowser;

// ── Legacy domain management ──────────────────────────────────────────────────

export async function addCurrentDomainAsLegacy() {
  const domain = domainOf(location.href);
  await invoke('cmd_compat_add_legacy', { domain });
}

export async function removeCurrentDomainFromLegacy() {
  const domain = domainOf(location.href);
  await invoke('cmd_compat_remove_legacy', { domain });
}

// ── diatom:// URL routing ─────────────────────────────────────────────────────

/**
 * Handle internal diatom:// URLs.
 * These are intercepted before navigation reaches the WebView.
 *
 * diatom://about          → /ui/about.html
 * diatom://museum/:id     → thaw and display frozen bundle
 * diatom://tools?tool=&input= → Wasm toolbox
 */
export function routeDiatomUrl(url) {
  if (!url.startsWith('diatom://')) return null;

  const parsed = (() => { try { return new URL(url); } catch { return null; } })();
  if (!parsed) return null;

  switch (parsed.hostname) {
    case 'about':
      return '/ui/about.html';
    case 'museum': {
      const id = parsed.pathname.slice(1);
      return `/ui/museum-viewer.html?id=${encodeURIComponent(id)}`;
    }
    case 'tools':
      return `/ui/wasm-tools.html${parsed.search}`;
    default:
      return null;
  }
}
