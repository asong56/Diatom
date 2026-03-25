/**
 * diatom/src/browser/tabs.js  — v7
 *
 * Tab UI + lifecycle management.
 *
 * v7 additions:
 *   • Reading event recording on tab blur / navigation
 *   • Freeze (E-WBN) integration: Cmd/Ctrl+S → cmd_freeze_page
 *   • DOM Crusher rules loaded for each domain on navigation
 *   • Zen mode navigation intercept
 *   • Threat check on navigation
 */

'use strict';

import { invoke, listen, emit } from './ipc.js';
import { domainOf, resolveUrl, escHtml, el, qs, timeAgo, uid } from './utils.js';
import { applyCrusherRules } from '../features/dom-crusher.js';
import { showInterstitial as zenInterstitial, isActive as zenIsActive } from '../features/zen.js';

// ── State ─────────────────────────────────────────────────────────────────────

let _tabs      = [];           // Array<Tab> from Rust
let _activeId  = null;

// Reading telemetry for the active tab
let _dwellStart   = Date.now();
let _scrollVelocity = 0;       // running average px/s
let _lastScrollY  = 0;
let _lastScrollTs = Date.now();
let _tabSwitches  = 0;
let _readingMode  = false;

// Worker reference (set from main.js)
let _worker = null;

// ── Init ──────────────────────────────────────────────────────────────────────

export async function initTabs(worker) {
  _worker = worker;

  // Load initial state from Rust
  const state = await invoke('cmd_tabs_state');
  _tabs     = state.tabs;
  _activeId = state.active_id;
  render();

  // Listen for Rust-side events
  await listen('diatom:tab_created',  t   => { _tabs.push(t); render(); });
  await listen('diatom:tab_closed',   id  => { _tabs = _tabs.filter(t => t.id !== id); render(); });
  await listen('diatom:tabs_updated', st  => { _tabs = st.tabs; _activeId = st.active_id; render(); });

  // Keyboard: Cmd/Ctrl+T (new tab), Cmd/Ctrl+W (close), Cmd/Ctrl+S (freeze)
  document.addEventListener('keydown', onGlobalKey);

  // Track scroll velocity for reading telemetry
  document.addEventListener('scroll', onScroll, { passive: true });

  // Visibility: record dwell when page goes background
  document.addEventListener('visibilitychange', onVisibilityChange);

  // Load Museum index into worker for Ghost Redirect
  loadMuseumIndex();
}

// ── Navigation ────────────────────────────────────────────────────────────────

/**
 * Navigate the active tab to a URL.
 * Runs the full v7 pre-process pipeline:
 *   1. Rust cmd_preprocess_url (block check, param strip, HTTPS upgrade, Zen check)
 *   2. Threat check (async, non-blocking for known-clean domains)
 *   3. Load in WebView
 */
export async function navigate(rawUrl) {
  const url = resolveUrl(rawUrl);

  // 1. Rust pre-process
  const nav = await invoke('cmd_preprocess_url', { url });

  if (nav.blocked) {
    // Tracker domain — show brief ambient indicator, don't navigate
    flashBlockIndicator(nav.clean_url);
    return;
  }

  if (nav.zen_blocked) {
    // Zen interstitial — wait for user decision
    const decision = await zenInterstitial(domainOf(nav.clean_url), nav.zen_category);
    if (decision !== 'unlocked') return;
  }

  // 2. Record dwell for previous page before navigating away
  flushReadingEvent();

  // 3. Load
  loadUrl(nav.clean_url);

  // 4. Load DOM Crusher rules for new domain (non-blocking)
  loadCrusherRulesForDomain(domainOf(nav.clean_url));

  // 5. Async threat check (shows warning tint if threat found — doesn't block)
  checkThreatAsync(domainOf(nav.clean_url));
}

function loadUrl(url) {
  // In Tauri, we navigate the WebView via Rust eval or a dedicated command.
  // In the shell WebView (chrome), we use location.href.
  emit('diatom:navigate', { url });
  // Reset dwell tracking
  _dwellStart    = Date.now();
  _scrollVelocity = 0;
  _lastScrollY   = window.scrollY;
  _lastScrollTs  = Date.now();
  _tabSwitches   = 0;
  _readingMode   = false;
}

// ── Tab CRUD ──────────────────────────────────────────────────────────────────

export async function createTab(url = 'about:blank') {
  const tab = await invoke('cmd_tab_create', { url });
  _tabs.push(tab);
  _activeId = tab.id;
  render();
  if (url !== 'about:blank') navigate(url);
}

export async function closeTab(tabId) {
  // Record dwell before closing
  if (tabId === _activeId) flushReadingEvent();
  await invoke('cmd_tab_close', { tab_id: tabId });
  _tabs = _tabs.filter(t => t.id !== tabId);
  if (_activeId === tabId) {
    _activeId = _tabs[_tabs.length - 1]?.id ?? null;
    if (_activeId) await invoke('cmd_tab_activate', { tab_id: _activeId });
  }
  render();
}

export async function activateTab(tabId) {
  if (tabId === _activeId) return;
  flushReadingEvent();    // record dwell for current tab
  _tabSwitches++;
  _activeId = tabId;
  await invoke('cmd_tab_activate', { tab_id: tabId });
  _dwellStart = Date.now();
  render();
}

// ── Freeze (E-WBN) ───────────────────────────────────────────────────────────

export async function freezeCurrentPage() {
  const tab = _tabs.find(t => t.id === _activeId);
  if (!tab) return;

  // Film-grain convergence animation (100ms)
  triggerFreezeAnimation();

  // Capture current page HTML via injected API
  let rawHtml;
  try {
    rawHtml = await invoke('cmd_fetch', { url: tab.url }).then(r => r.body);
  } catch {
    // Fallback: use document.documentElement.outerHTML via eval
    rawHtml = document.documentElement?.outerHTML ?? '<html></html>';
  }

  // Compute TF-IDF tags in worker
  const tags = await workerRpc('TFIDF_TAGS_FOR', { text: rawHtml, n: 8 });

  // Send to Rust for stripping + encryption + storage
  try {
    const bundle = await invoke('cmd_freeze_page', {
      raw_html:   rawHtml,
      url:        tab.url,
      title:      tab.title,
      tfidf_tags: tags ?? [],
    });

    // Index in worker for Ghost Redirect + Museum search
    if (_worker && bundle) {
      _worker.postMessage({
        id: uid(), type: 'INDEX_BUNDLE',
        payload: { bundleId: bundle.id, text: rawHtml, url: bundle.url, title: bundle.title },
      });
    }

    // Play freeze sound (mechanical shutter)
    playFreezeSound();

    showFreezeConfirmation(tab.title);
  } catch (err) {
    console.error('[Freeze] failed:', err);
  }
}

function triggerFreezeAnimation() {
  const canvas = qs('#noise-canvas');
  if (!canvas) return;
  canvas.classList.add('freeze-converge');
  setTimeout(() => canvas.classList.remove('freeze-converge'), 120);
}

function playFreezeSound() {
  // Minimal mechanical click via Web Audio API (< 50ms burst)
  try {
    const ctx   = new AudioContext();
    const buf   = ctx.createBuffer(1, ctx.sampleRate * 0.04, ctx.sampleRate);
    const data  = buf.getChannelData(0);
    for (let i = 0; i < data.length; i++) {
      // Exponentially decaying white noise burst
      data[i] = (Math.random() * 2 - 1) * Math.exp(-i / (ctx.sampleRate * 0.008));
    }
    const src = ctx.createBufferSource();
    src.buffer = buf;
    const gain = ctx.createGain();
    gain.gain.value = 0.12;
    src.connect(gain);
    gain.connect(ctx.destination);
    src.start();
    src.onended = () => ctx.close();
  } catch { /* audio not critical */ }
}

function showFreezeConfirmation(title) {
  const msg = document.createElement('div');
  msg.style.cssText = `
    position:fixed; bottom:1.5rem; left:50%; transform:translateX(-50%);
    background:rgba(10,10,16,.92); border:1px solid rgba(96,165,250,.2);
    color:#94a3b8; font:500 .75rem/1 'Inter',system-ui,sans-serif;
    padding:.5rem .9rem; border-radius:.35rem; z-index:9999;
    pointer-events:none; white-space:nowrap;
  `;
  msg.textContent = `🧊 Frozen · ${title.slice(0, 48)}`;
  document.body.appendChild(msg);
  // Fade out after 2s
  setTimeout(() => {
    msg.style.transition = 'opacity .4s';
    msg.style.opacity = '0';
    setTimeout(() => msg.remove(), 420);
  }, 2000);
}

// ── Reading telemetry ─────────────────────────────────────────────────────────

function onScroll() {
  const now   = Date.now();
  const dy    = Math.abs(window.scrollY - _lastScrollY);
  const dt    = (now - _lastScrollTs) / 1000;
  if (dt > 0) {
    // Exponential moving average
    _scrollVelocity = _scrollVelocity * 0.7 + (dy / dt) * 0.3;
  }
  _lastScrollY  = window.scrollY;
  _lastScrollTs = now;
}

function onVisibilityChange() {
  if (document.hidden) {
    flushReadingEvent();
    _tabSwitches++;
  } else {
    _dwellStart = Date.now();
  }
}

/**
 * Record and flush the current reading event to the worker buffer.
 * Worker auto-forwards to Rust every 10 events or 30 s.
 */
function flushReadingEvent() {
  const tab = _tabs.find(t => t.id === _activeId);
  if (!tab || tab.url === 'about:blank') return;

  const dwellMs = Date.now() - _dwellStart;
  if (dwellMs < 500) return;   // ignore flickers

  const event = {
    url:          tab.url,
    dwell_ms:     dwellMs,
    scroll_px_s:  Math.round(_scrollVelocity * 10) / 10,
    reading_mode: _readingMode,
    tab_switches: _tabSwitches,
  };

  // Post to worker buffer
  if (_worker) {
    _worker.postMessage({ id: uid(), type: 'READING_EVENT', payload: event });
  }

  // Reset
  _dwellStart   = Date.now();
  _tabSwitches  = 0;
}

export function setReadingMode(active) {
  _readingMode = active;
}

// ── DOM Crusher ───────────────────────────────────────────────────────────────

async function loadCrusherRulesForDomain(domain) {
  try {
    const rules = await invoke('cmd_dom_blocks_for', { domain });
    if (rules?.length) {
      // Apply immediately to the current document
      applyCrusherRules(rules);
      // Also push to SW for future navigations to this domain
      const bc = new BroadcastChannel('diatom:sw');
      bc.postMessage({
        type:      'CRUSHER_RULES',
        domain,
        selectors: rules.map(r => r.selector),
      });
      bc.close();
    }
  } catch { /* non-critical */ }
}

// ── Threat check ─────────────────────────────────────────────────────────────

async function checkThreatAsync(domain) {
  try {
    const result = await invoke('cmd_threat_check', { domain });
    if (result.level === 'Malicious') {
      showThreatBanner(result.reason);
    } else if (result.level === 'Suspicious') {
      showThreatHint(result.reason);
    }
  } catch { /* non-critical */ }
}

function showThreatBanner(reason) {
  const bar = document.createElement('div');
  bar.style.cssText = `
    position:fixed; top:0; left:0; right:0; z-index:99998;
    background:#7f1d1d; color:#fca5a5;
    font:500 .78rem/1 'Inter',system-ui,sans-serif;
    padding:.4rem 1rem; text-align:center;
    border-bottom:1px solid rgba(239,68,68,.3);
  `;
  bar.textContent = `⚠ ${reason}`;
  const dismiss = document.createElement('button');
  dismiss.style.cssText = 'margin-left:.75rem;background:none;border:none;color:#fca5a5;cursor:pointer;';
  dismiss.textContent = 'Continue anyway';
  dismiss.addEventListener('click', () => bar.remove());
  bar.appendChild(dismiss);
  document.body.prepend(bar);
}

function showThreatHint(reason) {
  // Subtle tint on address bar
  const omni = qs('#omnibox');
  if (omni) {
    omni.style.borderColor = '#d97706';
    omni.title = reason;
    setTimeout(() => {
      omni.style.borderColor = '';
      omni.title = '';
    }, 8000);
  }
}

function flashBlockIndicator(url) {
  const domain = domainOf(url);
  const indicator = document.createElement('div');
  indicator.style.cssText = `
    position:fixed; top:.75rem; right:.75rem; z-index:99997;
    background:rgba(15,23,42,.9); border:1px solid rgba(100,116,139,.2);
    color:#64748b; font:500 .72rem/1 'Inter',system-ui,sans-serif;
    padding:.3rem .6rem; border-radius:.25rem; pointer-events:none;
  `;
  indicator.textContent = `🚫 ${domain}`;
  document.body.appendChild(indicator);
  setTimeout(() => {
    indicator.style.transition = 'opacity .3s';
    indicator.style.opacity = '0';
    setTimeout(() => indicator.remove(), 320);
  }, 1200);
}

// ── Museum index ──────────────────────────────────────────────────────────────

async function loadMuseumIndex() {
  if (!_worker) return;
  try {
    const bundles = await invoke('cmd_museum_list', { limit: 500 });
    if (bundles?.length) {
      _worker.postMessage({
        id: uid(), type: 'MUSEUM_LOAD',
        payload: { entries: bundles },
      });
    }
  } catch { /* non-critical */ }
}

// ── Worker RPC helper ─────────────────────────────────────────────────────────

function workerRpc(type, payload) {
  if (!_worker) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const id = uid();
    const handler = ({ data }) => {
      if (data.id !== id) return;
      _worker.removeEventListener('message', handler);
      if (data.error) reject(new Error(data.error));
      else resolve(data.result);
    };
    _worker.addEventListener('message', handler);
    _worker.postMessage({ id, type, payload });
  });
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────

function onGlobalKey(e) {
  const mod = e.metaKey || e.ctrlKey;
  if (!mod) return;

  switch (e.key) {
    case 't':
      e.preventDefault();
      createTab();
      break;
    case 'w':
      e.preventDefault();
      if (_activeId) closeTab(_activeId);
      break;
    case 's':
      e.preventDefault();
      freezeCurrentPage();
      break;
  }
}

// ── Render ────────────────────────────────────────────────────────────────────

function render() {
  const bar = qs('#tab-bar');
  if (!bar) return;

  bar.innerHTML = '';
  for (const tab of _tabs) {
    const btn = el('button', `tab-btn${tab.id === _activeId ? ' active' : ''}`);
    btn.dataset.tabId = tab.id;
    btn.title = tab.url;
    btn.innerHTML = `
      <span class="tab-title">${escHtml(tab.title.slice(0, 40) || domainOf(tab.url))}</span>
      <span class="tab-sleep">${sleepIcon(tab.sleep)}</span>
      <button class="tab-close" data-tab-id="${tab.id}" aria-label="Close tab">×</button>
    `;

    btn.addEventListener('click', e => {
      if (e.target.classList.contains('tab-close')) return;
      activateTab(tab.id);
    });

    bar.appendChild(btn);
  }

  // Close buttons
  bar.querySelectorAll('.tab-close').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      closeTab(btn.dataset.tabId);
    });
  });
}

function sleepIcon(sleep) {
  return { Awake: '', Shallow: '·', Deep: '💤', Evicted: '·' }[sleep] ?? '';
}
