
'use strict';

import { invoke } from './ipc.js';
import { domainOf } from './utils.js';

let _jsErrors       = 0;
let _consoleErrs    = 0;
let _mutationCount  = 0;
let _monitorTimer   = null;
let _mutationObserver = null;

const MUTATION_STORM_THRESHOLD = 500;

export function startHealthMonitor(url) {
  _jsErrors      = 0;
  _consoleErrs   = 0;
  _mutationCount = 0;
  clearTimeout(_monitorTimer);

  if (_mutationObserver) {
    _mutationObserver.disconnect();
    _mutationObserver = null;
  }

  window.addEventListener('error', onJsError, { capture: true, once: false });

  try {
    _mutationObserver = new MutationObserver(mutations => {
      _mutationCount += mutations.length;
    });
    const root = document.body ?? document.documentElement;
    if (root) {
      _mutationObserver.observe(root, { childList: true, subtree: true, attributes: false });
    }
  } catch { /* observation unavailable */ }

  _monitorTimer = setTimeout(() => checkPageHealth(url), 3000);
}

function onJsError() { _jsErrors++; }

async function checkPageHealth(url) {
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

  try {
    const isLegacy = await invoke('cmd_compat_is_legacy', { domain });

    const appearsBroken = blankBody
      || _jsErrors >= 5
      || (_jsErrors >= 2 && _consoleErrs >= 10);

    if (isLegacy || appearsBroken) {
      try {
        await invoke('cmd_compat_page_report', { report });
      } catch { /* non-critical */ }
      injectCompatBanner(domain);
    }
  } catch { /* non-critical */ }

  try {
    const isPayment = await invoke('cmd_compat_is_payment', { domain });
    if (isPayment) injectPaymentWarning(domain);
  } catch { /* non-critical */ }
}

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

export async function handoffToSystemBrowser(url) {
  const target = url || location.href;
  try {
    await invoke('cmd_compat_handoff', { url: target });
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

window.__diatom_handoff = handoffToSystemBrowser;

export async function addCurrentDomainAsLegacy() {
  const domain = domainOf(location.href);
  await invoke('cmd_compat_add_legacy', { domain });
}

export async function removeCurrentDomainFromLegacy() {
  const domain = domainOf(location.href);
  await invoke('cmd_compat_remove_legacy', { domain });
}

export function routeDiatomUrl(url) {
  if (!url.startsWith('diatom://')) return null;

  const parsed = (() => { try { return new URL(url); } catch { return null; } })();
  if (!parsed) return null;

  switch (parsed.hostname) {
    case 'about':
      return '/ui/about.html';
    case 'json-viewer':
      return `/ui/json-viewer.html${parsed.search}`;
    default:
      return null;
  }
}
