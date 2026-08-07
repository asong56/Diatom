'use strict';

import { invoke, listen } from './browser/ipc.js';
import { initTabs, createTab, closeTab, navigate, freezeCurrentPage, setReadingMode } from './browser/tabs.js';
import { initHotkeys, registerDefaultHotkeys, updateContext as updateHotkeyContext } from './browser/hotkey.js';
import { updateLustre } from './browser/lustre.js';
import { initVisionOverlay } from './features/vision-overlay.js';
import { initCrusherCapture } from './features/dom-crusher.js';
import { injectVideoController } from './features/video-controller.js';
import { qs } from './browser/utils.js';
import { tosAuditor } from './features/tos-auditor.js';
import { shadowIndex } from './features/shadow-index.js';
import { initAgentBridge } from './features/agent.js';

// ── Background worker ─────────────────────────────────────────────────────────

const worker = new Worker('/workers/core.worker.js', { type: 'module' });

worker.addEventListener('message', e => {
    if (e.data?.type === 'SW_MUSEUM_SYNC') {
        navigator.serviceWorker?.controller?.postMessage({
            type:  'MUSEUM_INDEX',
            index: e.data.index,
        });
    }
    if (e.data?.type === 'INDEX_PROGRESS') {
        updateIndexProgressBadge(e.data.remaining);
    }
    if (e.data?.type === 'READING_EVENTS_READY') {
        for (const evt of e.data.events) {
            invoke('cmd_record_reading', { evt }).catch(() => {});
        }
    }
});

// ── Service Worker ────────────────────────────────────────────────────────────

async function registerSW() {
    if (!('serviceWorker' in navigator)) return;
    try {
        await navigator.serviceWorker.register('/sw.js', { scope: '/' });
        const bc = new BroadcastChannel('diatom:sw');
        bc.postMessage({ type: 'CONFIG', config: {
            adblock:       true,
            ua_uniformity: true,
            csp_injection: true,
        }});
        bc.close();
    } catch (err) {
        console.warn('[SW] registration failed:', err);
    }
}

// ── Address-bar commands ──────────────────────────────────────────────────────
//
//  /command   → system command (about, freeze)
//  ?query     → ask local AI about the current page or anything
//  (normal)   → search or navigate

function routeCommand(input) {
    const s = input.trim();

    // ? prefix → local AI conversation with page context
    if (s.startsWith('?')) {
        const query = s.slice(1).trim();
        if (query) openAiPanel(query);
        return true;
    }

    // / prefix → system commands
    if (s.startsWith('/')) {
        const [cmd] = s.slice(1).split(' ');

        switch (cmd) {
            case 'about':
                navigate('diatom://about');
                return true;
            case 'freeze':
                freezeCurrentPage();
                return true;
        }

        // fallback: show a brief "unknown command" tooltip on the omnibox
        return true;
    }

    return false;
}

function openAiPanel(query) {
    const panel = qs('#ai-panel');
    if (panel) {
        panel.dataset.query = query;
        panel.dataset.mode  = 'chat';
        panel.hidden = false;
        // Pass page context automatically so the AI can answer about what's on screen
        if (window.__diatom_shadow_index) {
            const ctx = window.__diatom_shadow_index.currentPageSummary?.() ?? '';
            panel.dataset.pageCtx = ctx;
        }
    }
}

// ── Museum indexing ───────────────────────────────────────────────────────────

async function startMuseumIndexing() {
    try {
        const resp    = await invoke('cmd_museum_list', { limit: 1000 });
        const bundles = resp?.bundles ?? [];
        if (!bundles.length) return;
        const type = bundles.length > 50 ? 'MUSEUM_LOAD_IDLE' : 'MUSEUM_LOAD';
        worker.postMessage({ id: 'startup', type, payload: { entries: bundles } });
    } catch (err) {
        console.warn('[museum] indexing startup failed:', err);
    }
}

function updateIndexProgressBadge(remaining) {
    let badge = qs('#index-progress');
    if (!badge && remaining > 0) {
        badge = Object.assign(document.createElement('div'), { id: 'index-progress' });
        badge.style.cssText = `
          position:fixed; bottom:1rem; right:1rem; z-index:9000;
          background:rgba(15,23,42,.88); border:1px solid rgba(255,255,255,.08);
          color:#64748b; font:500 .7rem/1 system-ui,sans-serif;
          padding:.3rem .6rem; border-radius:.25rem; pointer-events:none;
        `;
        document.body.appendChild(badge);
    }
    if (badge) {
        if (remaining === 0) badge.remove();
        else badge.textContent = `🗂 Indexing… ${remaining} remaining`;
    }
}

// ── Onion mirror suggestion banner ────────────────────────────────────────────

function showOnionSuggestionBanner(suggestion) {
    qs('#diatom-onion-banner')?.remove();

    const banner   = document.createElement('div');
    banner.id      = 'diatom-onion-banner';
    banner.style.cssText = `
      position:fixed; bottom:1.2rem; right:1.2rem; z-index:9500;
      background:rgba(15,23,42,.96); border:1px solid rgba(96,165,250,.25);
      border-radius:.5rem; padding:.8rem 1rem; max-width:320px;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
      font-size:.78rem; color:#94a3b8; line-height:1.5;
      box-shadow:0 4px 20px rgba(0,0,0,.4);
      display:flex; align-items:flex-start; gap:.7rem;
    `;

    const icon = Object.assign(document.createElement('span'), { textContent: '🧅' });
    icon.style.cssText = 'font-size:1.1rem;flex-shrink:0;margin-top:.05rem;';

    const body    = document.createElement('div');
    body.style.cssText = 'flex:1;min-width:0;';

    const titleEl = Object.assign(document.createElement('div'), { textContent: 'More private mirror available' });
    titleEl.style.cssText = 'color:#60a5fa;font-weight:500;margin-bottom:.2rem;';

    const desc = Object.assign(document.createElement('div'), { textContent: suggestion.label });

    const addr = Object.assign(document.createElement('div'), { textContent: suggestion.hidden_host });
    addr.style.cssText = 'font-family:SF Mono,Cascadia Code,monospace;font-size:.68rem;color:#475569;word-break:break-all;margin-top:.2rem;';

    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:.5rem;margin-top:.6rem;';

    const copyBtn = Object.assign(document.createElement('button'), { textContent: 'Copy address' });
    copyBtn.style.cssText = 'background:rgba(96,165,250,.14);border:1px solid rgba(96,165,250,.3);color:#60a5fa;border-radius:.3rem;padding:.25rem .6rem;font-size:.7rem;cursor:pointer;';
    copyBtn.addEventListener('click', () =>
        navigator.clipboard.writeText(suggestion.hidden_host).then(() => {
            copyBtn.textContent = 'Copied ✓';
            setTimeout(() => banner.remove(), 1500);
        })
    );

    const dismissBtn = Object.assign(document.createElement('button'), { textContent: 'Dismiss' });
    dismissBtn.style.cssText = 'background:none;border:1px solid rgba(255,255,255,.08);color:#475569;border-radius:.3rem;padding:.25rem .6rem;font-size:.7rem;cursor:pointer;';
    dismissBtn.addEventListener('click', () => banner.remove());

    btnRow.append(copyBtn, dismissBtn);
    body.append(titleEl, desc, addr, btnRow);
    banner.append(icon, body);
    document.body.appendChild(banner);

    setTimeout(() => banner.remove(), 15_000);
}

// ── Tab change hook ───────────────────────────────────────────────────────────

async function onTabChange(tabId) {
    try {
        const state = await invoke('cmd_tabs_state');
        const tab   = state.tabs?.find(t => t.id === tabId);
        if (!tab?.url) return;
        updateHotkeyContext(tab.url);
        try {
            const host = new URL(tab.url).hostname;
            updateLustre(`https://icons.duckduckgo.com/ip3/${host}.ico`);
        } catch { /* invalid URL */ }
        injectVideoController();
    } catch { /* non-critical */ }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

async function boot() {
    await invoke('cmd_signal_window_ready').catch(() => {});

    await initHotkeys();
    registerDefaultHotkeys({
        onNewTab:   () => createTab(),
        onCloseTab: () => { const id = qs('[data-tab-id].active')?.dataset.tabId; if (id) closeTab(id); },
        onFreeze:   () => freezeCurrentPage(),
    });

    const omnibox = qs('#omnibox');
    if (omnibox) {
        omnibox.addEventListener('keydown', e => {
            if (e.key !== 'Enter') return;
            if (routeCommand(omnibox.value)) {
                e.preventDefault();
                omnibox.blur();
                omnibox.value = '';
            }
        });

        // Hint text in the placeholder so users know about / and ? prefixes
        omnibox.placeholder = 'Search, navigate, /command, ?ask AI';
    }

    await initTabs(worker);
    initVisionOverlay();
    initCrusherCapture();
    initAgentBridge();

    await listen('diatom:tab_activated', e => onTabChange(e.tab_id));

    document.addEventListener('visibilitychange', () => {
        worker.postMessage({ type: 'VISIBILITY', payload: { hidden: document.hidden } });
    });

    await registerSW();

    setTimeout(() => startMuseumIndexing(),                                  3_000);
    setTimeout(() => invoke('cmd_threat_list_refresh').catch(() => {}),     10_000);

    if (window.__DIATOM_INIT__?.labs?.tos_auditor !== false) {
        window.__diatom_tos_auditor = tosAuditor;
    }
    window.__diatom_shadow_index = shadowIndex;

    window.addEventListener('diatom:onion_suggest', e => {
        if (e.detail) showOnionSuggestionBanner(e.detail);
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
} else {
    boot();
}
