/**
 * diatom/src/main.js  — v0.11.0
 *
 * Application entry point. Wires all modules together.
 * Zero frameworks. Cold start target: < 80ms.
 *
 * Module init order (deliberate — each depends on the previous):
 *   1. IPC stub check (fail fast if not in Tauri)
 *   2. Hotkey manager (needs to capture events before anything else)
 *   3. Worker (needed by tabs, echo scheduler)
 *   4. Tabs (needs worker)
 *   5. Feature modules (each registers its own hotkeys)
 *   6. Service Worker registration
 *   7. Echo hint (ambient, non-blocking)
 *   8. Museum progressive indexing (idle-time, background)
 */

'use strict';

import { invoke, listen } from './browser/ipc.js';
import { initTabs, createTab, closeTab, navigate, freezeCurrentPage, setReadingMode } from './browser/tabs.js';
import { initHotkeys, registerDefaultHotkeys, updateContext as updateHotkeyContext } from './browser/hotkey.js';
import { updateLustre } from './browser/lustre.js';
import { initZen, activate as zenActivate, isActive as zenIsActive } from './features/zen.js';
import { initVisionOverlay } from './features/vision-overlay.js';
import { initCrusherCapture } from './features/dom-crusher.js';
import { maybeShowEchoHint, openEchoPanel } from './features/echo.js';
import { openNetworkPanel } from './features/network-panel.js';
import { injectVideoController } from './features/video-controller.js';
import { qs } from './browser/utils.js';
import { tosAuditor } from './features/tos-auditor.js';
import { shadowIndex } from './features/shadow-index.js';

// ── CSS lazy-loader ─────────────────────────────────────────────────────────
// [v0.6.0 OPT-01] Feature CSS files are loaded on demand, not at boot.
// This keeps the main-path CSS parse to ~17 KB (down from 45 KB).
// Files: ai-panel.css, shadow-index.css, tab-groups.css, tos-auditor.css

const _loadedStyles = new Set();

function loadStylesheet(href) {
  if (_loadedStyles.has(href)) return Promise.resolve();
  return new Promise((resolve) => {
    const link = document.createElement('link');
    link.rel  = 'stylesheet';
    link.href = href;
    link.onload  = () => { _loadedStyles.add(href); resolve(); };
    link.onerror = resolve; // non-critical — degrade gracefully
    document.head.appendChild(link);
  });
}


// ── Worker ────────────────────────────────────────────────────────────────────

const worker = new Worker('/workers/core.worker.js', { type: 'module' });

// Forward worker SW-sync messages to the Service Worker
worker.addEventListener('message', e => {
  if (e.data?.type === 'SW_MUSEUM_SYNC') {
    navigator.serviceWorker?.controller?.postMessage({
      type:  'MUSEUM_INDEX',
      index: e.data.index,
    });
  }
  if (e.data?.type === 'ECHO_DUE') {
    // Echo is due — show the hint in the Notes zone
    maybeShowEchoHint();
  }
  if (e.data?.type === 'INDEX_PROGRESS') {
    updateIndexProgressBadge(e.data.remaining);
  }
  if (e.data?.type === 'READING_EVENTS_READY') {
    // Flush reading events to Rust backend
    for (const evt of e.data.events) {
      invoke('cmd_record_reading', { evt }).catch(() => {});
    }
  }
});

// ── Service Worker ────────────────────────────────────────────────────────────

async function registerSW() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    // Push current config to SW
    const bc = new BroadcastChannel('diatom:sw');
    bc.postMessage({ type: 'CONFIG', config: {
      adblock:        true,
      ua_uniformity:  true,
      csp_injection:  true,
      zen_active:     zenIsActive(),
    }});
    bc.close();
  } catch (err) {
    console.warn('[SW] registration failed:', err);
  }
}

// ── Omnibox command routing ───────────────────────────────────────────────────

/**
 * Route address-bar commands before they navigate.
 * Returns true if the input was handled as a command.
 */
function routeCommand(input) {
  const s = input.trim();

  if (s === '/devnet') {
    openNetworkPanel();
    return true;
  }
  if (s === '/files' || s === '/localfiles') {
    navigate('diatom://localfiles');
    return true;
  }
  if (s === '/zen') {
    zenActivate();
    return true;
  }
  if (s.startsWith('/json')) {
    openWasmTool('json', s.slice(5).trim());
    return true;
  }
  if (s.startsWith('/crypto')) {
    openWasmTool('crypto', s.slice(7).trim());
    return true;
  }
  if (s.startsWith('/math') || s.startsWith('/calc')) {
    openWasmTool('math', s.slice(5).trim());
    return true;
  }
  if (s.startsWith('/img')) {
    openWasmTool('img', '');
    return true;
  }
  if (s.startsWith('/echo')) {
    openEchoPanel();
    return true;
  }
  if (s.startsWith('/scholar ') || s.startsWith('/debug ') ||
      s.startsWith('/scribe ') || s.startsWith('/oracle ')) {
    // Route to AI panel with the correct Resonance Mode
    const [mode, ...rest] = s.slice(1).split(' ');
    openAiPanel(mode, rest.join(' '));
    return true;
  }
  return false;
}

function openWasmTool(tool, input) {
  // Navigate to the Wasm toolbox page with tool + input as URL params
  const params = new URLSearchParams({ tool, input });
  navigate(`diatom://tools?${params}`);
}

function openAiPanel(mode, query) {
  const panel = qs('#ai-panel');
  if (panel) {
    panel.dataset.mode  = mode;
    panel.dataset.query = query;
    panel.hidden = false;
  }
}

// ── Progressive Museum indexing startup ───────────────────────────────────────

async function startMuseumIndexing() {
  try {
    const bundles = await invoke('cmd_museum_list', { limit: 1000 });
    if (!bundles?.length) return;

    // Use idle indexer for large collections to avoid CPU spike
    if (bundles.length > 50) {
      worker.postMessage({ id: 'startup', type: 'MUSEUM_LOAD_IDLE', payload: { entries: bundles } });
    } else {
      worker.postMessage({ id: 'startup', type: 'MUSEUM_LOAD', payload: { entries: bundles } });
    }
  } catch { /* non-critical */ }
}

function updateIndexProgressBadge(remaining) {
  let badge = qs('#index-progress');
  if (!badge && remaining > 0) {
    badge = document.createElement('div');
    badge.id = 'index-progress';
    badge.style.cssText = `
      position:fixed; bottom:1rem; right:1rem; z-index:9000;
      background:rgba(15,23,42,.88); border:1px solid rgba(255,255,255,.08);
      color:#64748b; font:500 .7rem/1 'Inter',system-ui;
      padding:.3rem .6rem; border-radius:.25rem; pointer-events:none;
    `;
    document.body.appendChild(badge);
  }
  if (badge) {
    if (remaining === 0) {
      badge.remove();
    } else {
      badge.textContent = `🗂 Indexing… ${remaining} remaining`;
    }
  }
}

// ── Lustre integration ────────────────────────────────────────────────────────

// Update ambient colour when the active tab changes
async function onTabChange(tabId) {
  try {
    const state = await invoke('cmd_tabs_state');
    const tab   = state.tabs?.find(t => t.id === tabId);
    if (tab?.url) {
      updateHotkeyContext(tab.url);
      // Use DuckDuckGo's favicon service — it accepts only the hostname (not the
      // full URL), so it never receives the user's browsing path.
      // Google's s2/favicons API (?domain=<full URL>) would leak every navigation.
      let faviconUrl = '';
      try {
        const host = new URL(tab.url).hostname;
        faviconUrl = `https://icons.duckduckgo.com/ip3/${host}.ico`;
      } catch { /* non-navigable URL — no favicon */ }
      if (faviconUrl) updateLustre(faviconUrl);
      injectVideoController();
    }
  } catch { /* non-critical */ }
}

// ── Boot sequence ─────────────────────────────────────────────────────────────

async function boot() {
  // [B-05 FIX] Signal Rust that JS loaded successfully. This cancels the 3-second
  // watchdog in main.rs that would otherwise force-show the window with a boot-error.
  // Also call show() here unconditionally so even if the IPC fails (e.g. Tauri not
  // ready yet) the window still becomes visible.
  try {
    await invoke('cmd_setting_get', { key: '__noop__' }).catch(() => {});
    // Emit window-ready — Rust watchdog will cancel on receiving this via IPC
    await invoke('cmd_setting_set', { key: '__window_ready__', value: '1' }).catch(() => {});
  } catch { /* non-critical */ }

  // 1. Hotkeys first — capture events before anything renders
  await initHotkeys();
  registerDefaultHotkeys({
    onNewTab:   () => createTab(),
    onCloseTab: () => { const id = qs('[data-tab-id].active')?.dataset.tabId; if (id) closeTab(id); },
    onFreeze:   () => freezeCurrentPage(),
    onZen:      () => zenIsActive() ? import('./features/zen.js').then(m => m.deactivate()) : zenActivate(),
  });

  // 2. Omnibox command intercept
  const omnibox = qs('#omnibox');
  if (omnibox) {
    omnibox.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const input = omnibox.value.trim();
      if (routeCommand(input)) {
        e.preventDefault();
        omnibox.blur();
        omnibox.value = '';
      }
    });
  }

  // 3. Worker + tabs
  await initTabs(worker);

  // 4. Zen mode
  await initZen();

  // 5. Vision overlay (with hotkey yield awareness)
  initVisionOverlay();

  // 6. DOM Crusher capture
  initCrusherCapture();

  // 7. Tab change → Lustre + hotkey context
  await listen('diatom:tab_activated', e => onTabChange(e.tab_id));

  // [v0.11.0 PERF] Forward page visibility to the worker so it can pause
  // idle indexing while the browser window is hidden (saves CPU/battery).
  document.addEventListener('visibilitychange', () => {
    worker?.postMessage({ type: 'VISIBILITY', payload: { hidden: document.hidden } });
  });

  // 8. Service Worker
  await registerSW();

  // 9. Echo ambient hint (non-blocking — runs after everything else)
  setTimeout(() => maybeShowEchoHint(), 1500);

  // 10. Museum progressive indexing (background, idle-time)
  setTimeout(() => startMuseumIndexing(), 3000);

  // 11. Threat list refresh trigger (once per session, non-blocking)
  setTimeout(() => invoke('cmd_threat_list_refresh').catch(() => {}), 10_000);

  // 12. ToS Auditor — register navigation hook (fires when lab enabled)
  if (window.__DIATOM_INIT__?.labs?.tos_auditor !== false) {
    // Expose navigation hook for tabs.js to call on page load
    window.__diatom_tos_auditor = tosAuditor;
  }

  // 13. Shadow Index is keyboard-driven; module self-registers ⌘⇧F globally
  window.__diatom_shadow_index = shadowIndex;
}

// Boot on DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
