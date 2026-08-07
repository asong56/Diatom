'use strict';

import { invoke, listen, emit } from './ipc.js';
import { domainOf, resolveUrl, escHtml, el, qs, timeAgo, uid } from './utils.js';
import { applyCrusherRules } from '../features/dom-crusher.js';
import { startHealthMonitor, routeDiatomUrl } from './compat.js';

let _tabs         = [];       // Array<Tab> from Rust
let _activeId     = null;

let _dwellStart    = Date.now();
let _scrollVelocity = 0;     // exponential moving average, px/s
let _lastScrollY   = 0;
let _lastScrollTs  = Date.now();
let _tabSwitches   = 0;
let _readingMode   = false;

let _worker = null;

export async function initTabs(worker) {
  _worker = worker;

  const state = await invoke('cmd_tabs_state');
  _tabs     = state.tabs;
  _activeId = state.active_id;
  render();

  await listen('diatom:tab_created',  t  => { _tabs.push(t); render(); });
  await listen('diatom:tab_closed',   id => { _tabs = _tabs.filter(t => t.id !== id); render(); });
  await listen('diatom:tabs_updated', st => { _tabs = st.tabs; _activeId = st.active_id; render(); });

  document.addEventListener('keydown',          onGlobalKey);
  document.addEventListener('scroll',           onScroll,           { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange);

  loadMuseumIndex();
}

export async function navigate(rawUrl) {
  const url = resolveUrl(rawUrl);

  // diatom:// URLs are Diatom's own internal pages (about, museum,
  // settings, the JSON viewer, …) — resolve directly to their real path
  // and load them without tracking-param stripping or threat checks,
  // neither of which make sense for content Diatom itself ships.
  const internalPath = routeDiatomUrl(url);
  if (internalPath) {
    flushReadingEvent();
    loadUrl(internalPath);
    return;
  }

  const nav = await invoke('cmd_preprocess_url', { url });

  if (nav.blocked) {
    flashBlockIndicator(nav.clean_url);
    return;
  }

  // Opening a .json file or URL directly renders it pretty-printed and
  // collapsible instead of a wall of raw text — no command needed. Checked
  // after block-listing so a blocked .json URL still gets blocked, not
  // silently loaded through the viewer.
  if (looksLikeJsonUrl(nav.clean_url)) {
    return navigate(`diatom://json-viewer?src=${encodeURIComponent(nav.clean_url)}`);
  }

  flushReadingEvent();
  loadUrl(nav.clean_url);
  loadCrusherRulesForDomain(domainOf(nav.clean_url));
  checkThreatAsync(domainOf(nav.clean_url));
}

/// True when the URL's path (ignoring query string and fragment) ends in
/// `.json` — covers `file:///…/data.json`, `https://api.example.com/x.json`,
/// and `https://…/x.json?query=1`. Deliberately does NOT try to sniff
/// content-type for extensionless URLs; that would need a network round
/// trip before every navigation just to check, which isn't worth it for
/// the rare API endpoint that serves JSON with no `.json` in the path —
/// those still render fine as plain text, same as any other browser.
function looksLikeJsonUrl(url) {
  try {
    const { pathname } = new URL(url);
    return /\.json$/i.test(pathname);
  } catch {
    return false;
  }
}

let _navAbort = new AbortController();
export function navSignal() { return _navAbort.signal; }

function loadUrl(url) {
  _navAbort.abort();
  _navAbort = new AbortController();
  emit('diatom:navigate', { url });

  try { startHealthMonitor(url); }             catch {}
  try { window.__diatom_tos_auditor?.onNavigate(url); } catch {}
  try { window.__diatom_shadow_index?.close?.(); }      catch {}

  _dwellStart     = Date.now();
  _scrollVelocity = 0;
  _lastScrollY    = window.scrollY;
  _lastScrollTs   = Date.now();
  _tabSwitches    = 0;
  _readingMode    = false;
}

export async function createTab(url = 'about:blank') {
  const tab = await invoke('cmd_tab_create', { url });
  _activeId = tab.id;
  render();
  if (url !== 'about:blank') navigate(url);
}

export async function closeTab(tabId) {
  if (tabId === _activeId) flushReadingEvent();
  await invoke('cmd_tab_close', { tab_id: tabId });
  _tabs = _tabs.filter(t => t.id !== tabId);
  if (_activeId === tabId) {
    const fallback = _tabs[_tabs.length - 1];
    if (!fallback) { await createTab(); return; }
    _activeId = fallback.id;
    if (_activeId) await invoke('cmd_tab_activate', { tab_id: _activeId });
  }
  render();
}

export async function activateTab(tabId) {
  if (tabId === _activeId) return;
  flushReadingEvent();
  _tabSwitches++;
  _activeId = tabId;
  await invoke('cmd_tab_activate', { tab_id: tabId });
  _dwellStart     = Date.now();
  _scrollVelocity = 0;
  _lastScrollY    = window.scrollY;
  _lastScrollTs   = Date.now();
  render();
}

export async function freezeCurrentPage() {
  const tab = _tabs.find(t => t.id === _activeId);
  if (!tab) return;

  triggerFreezeAnimation();

  let rawHtml;
  try {
    rawHtml = await invoke('cmd_fetch', { url: tab.url }).then(r => r.body);
  } catch {
    rawHtml = document.documentElement?.outerHTML ?? '<html></html>';
  }

  const tags = await workerRpc('TFIDF_TAGS_FOR', { text: rawHtml, n: 8 });

  try {
    const bundle = await invoke('cmd_freeze_page', {
      raw_html:   rawHtml,
      url:        tab.url,
      title:      tab.title,
      tfidf_tags: tags ?? [],
    });

    if (_worker && bundle) {
      _worker.postMessage({
        id: uid(), type: 'INDEX_BUNDLE',
        payload: { bundleId: bundle.id, text: rawHtml, url: bundle.url, title: bundle.title },
      });
    }

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
  try {
    const ctx  = new AudioContext();
    const buf  = ctx.createBuffer(1, ctx.sampleRate * 0.04, ctx.sampleRate);
    const data = buf.getChannelData(0);
    for (let i = 0; i < data.length; i++) {
      data[i] = (Math.random() * 2 - 1) * Math.exp(-i / (ctx.sampleRate * 0.008));
    }
    const src  = ctx.createBufferSource();
    src.buffer = buf;
    const gain = ctx.createGain();
    gain.gain.value = 0.12;
    src.connect(gain);
    gain.connect(ctx.destination);
    src.start();
    src.onended = () => ctx.close();
  } catch { /* AudioContext unavailable */ }
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
  msg.textContent = `🧊 Frozen · ${title.slice(0, 64)}`;
  document.body.appendChild(msg);
  setTimeout(() => {
    msg.style.transition = 'opacity .4s';
    msg.style.opacity    = '0';
    setTimeout(() => msg.remove(), 420);
  }, 2000);
}

function onScroll() {
  const now = Date.now();
  const dy  = Math.abs(window.scrollY - _lastScrollY);
  const dt  = (now - _lastScrollTs) / 1000;
  if (dt > 0) _scrollVelocity = _scrollVelocity * 0.7 + (dy / dt) * 0.3;
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

function flushReadingEvent() {
  const tab = _tabs.find(t => t.id === _activeId);
  if (!tab || tab.url === 'about:blank') return;

  const dwellMs = Date.now() - _dwellStart;
  if (dwellMs < 500) return;

  const event = {
    url:          tab.url,
    dwell_ms:     dwellMs,
    scroll_px_s:  Math.round(_scrollVelocity * 10) / 10,
    reading_mode: _readingMode,
    tab_switches: _tabSwitches,
  };

  _worker?.postMessage({ id: uid(), type: 'READING_EVENT', payload: event });

  _dwellStart  = Date.now();
  _tabSwitches = 0;
}

export function setReadingMode(active) {
  _readingMode = active;
}

async function loadCrusherRulesForDomain(domain) {
  try {
    const rules = await invoke('cmd_dom_blocks_for', { domain });
    if (rules?.length) {
      applyCrusherRules(rules);
      const bc = new BroadcastChannel('diatom:sw');
      bc.postMessage({ type: 'CRUSHER_RULES', domain, selectors: rules.map(r => r.selector) });
      bc.close();
    }
  } catch { /* non-critical */ }
}

async function checkThreatAsync(domain) {
  try {
    const result = await invoke('cmd_threat_check', { domain });
    if (result.flagged) showThreatBanner(domain);
  } catch { /* non-critical */ }
}

function showThreatBanner(domain) {
  const bar = document.createElement('div');
  bar.style.cssText = `
    position:fixed; top:0; left:0; right:0; z-index:99998;
    background:#7f1d1d; color:#fca5a5;
    font:500 .78rem/1 'Inter',system-ui,sans-serif;
    padding:.4rem 1rem; text-align:center;
    border-bottom:1px solid rgba(239,68,68,.3);
  `;
  bar.textContent = `⚠ Threat detected: ${domain}`;
  const dismiss = document.createElement('button');
  dismiss.style.cssText = 'margin-left:.75rem;background:none;border:none;color:#fca5a5;cursor:pointer;';
  dismiss.textContent   = 'Continue anyway';
  dismiss.addEventListener('click', () => bar.remove());
  bar.appendChild(dismiss);
  document.body.prepend(bar);
}

function flashBlockIndicator(url) {
  const domain    = domainOf(url);
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
    indicator.style.opacity    = '0';
    setTimeout(() => indicator.remove(), 320);
  }, 1200);
}

async function loadMuseumIndex() {
  if (!_worker) return;
  try {
    const resp    = await invoke('cmd_museum_list', { limit: 500 });
    const bundles = resp?.bundles ?? [];
    if (bundles.length) {
      _worker.postMessage({ id: uid(), type: 'MUSEUM_LOAD', payload: { entries: bundles } });
    }
  } catch { /* non-critical */ }
}

function workerRpc(type, payload) {
  if (!_worker) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const id = uid();
    const handler = ({ data }) => {
      if (data.id !== id) return;
      _worker.removeEventListener('message', handler);
      data.error ? reject(new Error(data.error)) : resolve(data.result);
    };
    _worker.addEventListener('message', handler);
    _worker.postMessage({ id, type, payload });
  });
}

function onGlobalKey(e) {
  const mod = e.metaKey || e.ctrlKey;
  if (!mod) return;
  switch (e.key) {
    case 't': e.preventDefault(); createTab();                              break;
    case 'w': e.preventDefault(); if (_activeId) closeTab(_activeId);      break;
    case 's': e.preventDefault(); freezeCurrentPage();                     break;
  }
}

function render() {
  const bar = qs('#tab-bar');
  if (!bar) return;

  bar.innerHTML = '';
  for (const tab of _tabs) {
    const btn = el('button', `tab-btn${tab.id === _activeId ? ' active' : ''}`);
    btn.dataset.tabId = tab.id;
    btn.title         = tab.url;
    btn.innerHTML = `
      <span class="tab-title">${escHtml(tab.title.slice(0, 60) || domainOf(tab.url))}</span>
      <span class="tab-sleep">${sleepIcon(tab.sleep)}</span>
      <button class="tab-close" data-tab-id="${tab.id}" aria-label="Close tab">×</button>
    `;
    btn.addEventListener('click', e => {
      if (e.target.classList.contains('tab-close')) return;
      activateTab(tab.id);
    });
    bar.appendChild(btn);
  }

  bar.querySelectorAll('.tab-close').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      closeTab(btn.dataset.tabId);
    });
  });
}

function sleepIcon(sleep) {
  return { Awake: '', ShallowSleep: '·', DeepSleep: '💤' }[sleep] ?? '';
}
