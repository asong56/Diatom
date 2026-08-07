
'use strict';

import { invoke } from '../browser/ipc.js';
import { escHtml, domainOf } from '../browser/utils.js';

const PANEL_ID    = '__diatom_shadow_panel';
const OVERLAY_ID  = '__diatom_shadow_overlay';
const OPEN_KEY    = 'f';         // ⌘⇧F or Ctrl⇧F
const FREEZE_KEY  = 's';         // ⌘⇧S to freeze current page
const MAX_RESULTS = 20;
const DEBOUNCE_MS = 280;

const LEAN_DOMAINS = {
  left:        ['theguardian.com','huffpost.com','vox.com','msnbc.com','salon.com','thenation.com','democracynow.org'],
  centerleft:  ['nytimes.com','washingtonpost.com','theatlantic.com','slate.com'],
  center:      ['reuters.com','apnews.com','bbc.com','bbc.co.uk','npr.org','pbs.org','csmonitor.com'],
  centerright: ['wsj.com','ft.com','economist.com','businessinsider.com','bloomberg.com'],
  right:       ['foxnews.com','breitbart.com','dailywire.com','nypost.com','washingtontimes.com','nationalreview.com'],
};

function estimateLean(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    for (const [lean, domains] of Object.entries(LEAN_DOMAINS)) {
      if (domains.some(d => host === d || host.endsWith('.' + d))) return lean;
    }
  } catch {}
  return 'unknown';
}

const LEAN_CONFIG = {
  left:        { icon: '◀◀', label: 'Left',         color: '#5a85c8' },
  centerleft:  { icon: '◀',  label: 'Centre-Left',  color: '#7a9fd0' },
  center:      { icon: '●',  label: 'Centre',        color: '#747490' },
  centerright: { icon: '▶',  label: 'Centre-Right', color: '#c49868' },
  right:       { icon: '▶▶', label: 'Right',         color: '#c46848' },
  unknown:     { icon: '?',  label: 'Unknown',       color: '#747490' },
};

const QUALITY_CONFIG = {
  human_curated: { icon: '✦', label: 'Human Curated', color: '#c4a468' },
  ai_high_rated: { icon: '◈', label: 'AI Rated',      color: '#7a9fd0' },
  standard:      { icon: '○', label: 'Standard',       color: '#747490' },
};

function formatDate(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts * 1000);
    return d.toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' });
  } catch { return ''; }
}

function highlight(text, query) {
  if (!query || !text) return escHtml(text);
  const words = query.trim().split(/\s+/).filter(w => w.length > 2);
  if (!words.length) return escHtml(text);
  const pattern = new RegExp(`(${words.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
  return escHtml(text).replace(
    new RegExp(`(${words.map(w => escHtml(w)).join('|')})`, 'gi'),
    '<mark style="background:rgba(196,164,104,0.3);border-radius:2px;padding:0 1px">$1</mark>'
  );
}

function getSnippet(text, query, maxLen = 200) {
  if (!text) return '';
  const words = (query || '').split(/\s+/).filter(w => w.length > 2);
  if (words.length) {
    const pos = text.toLowerCase().indexOf(words[0].toLowerCase());
    if (pos > -1) {
      const start = Math.max(0, pos - 60);
      const end   = Math.min(text.length, pos + maxLen);
      return (start > 0 ? '…' : '') + text.slice(start, end) + (end < text.length ? '…' : '');
    }
  }
  return text.slice(0, maxLen) + (text.length > maxLen ? '…' : '');
}

let _open      = false;
let _query     = '';
let _results   = [];
let _selected  = -1;
let _debounce  = null;
let _searching = false;
let _biasMode  = false;
let _currentPageLean = 'unknown';

let _overlayEl = null;
let _panelEl   = null;
let _inputEl   = null;
let _resultsEl = null;

function createDOM() {
  const overlay = document.createElement('div');
  overlay.id = OVERLAY_ID;

  const panel = document.createElement('div');
  panel.id    = PANEL_ID;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Shadow Index Search');
  panel.setAttribute('aria-modal', 'true');

  panel.innerHTML = `
    <style>
      #${OVERLAY_ID} {
        all: initial;
        display: flex;
        position: fixed;
        inset: 0;
        z-index: 2147483646;
        background: oklch(20% 0.02 260 / 0.6);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        align-items: flex-start;
        justify-content: center;
        padding-top: clamp(40px, 8vh, 80px);
        font-family: 'Switzer', 'Open Sans', ui-sans-serif, 'Segoe UI', system-ui, sans-serif;
      }
      #${PANEL_ID} {
        all: initial;
        display: flex;
        flex-direction: column;
        width: min(660px, 94vw);
        max-height: min(580px, 82vh);
        background: oklch(98.5% 0.003 260);
        border: 1px solid oklch(88% 0.005 260);
        border-radius: 12px;
        box-shadow: 0 8px 32px oklch(0% 0 0 / 0.10), 0 2px 8px oklch(0% 0 0 / 0.05);
        overflow: hidden;
        font-family: 'Switzer', 'Open Sans', ui-sans-serif, 'Segoe UI', system-ui, sans-serif;
        color: oklch(28% 0.008 260);
      }
      @media (prefers-reduced-motion: no-preference) {
        #${PANEL_ID} { animation: si-in 180ms cubic-bezier(0.34, 1.56, 0.64, 1); }
      }
      @keyframes si-in {
        from { opacity: 0; transform: scale(0.97) translateY(-6px); }
        to   { opacity: 1; transform: scale(1) translateY(0); }
      }
      @media (prefers-color-scheme: dark) {
        #${PANEL_ID} {
          background: oklch(16% 0.004 260);
          color: oklch(88% 0.008 260);
          border-color: oklch(24% 0.005 260);
        }
      }
      .si-search-row {
        display: flex; align-items: center; gap: 12px;
        padding: 16px 18px 14px;
        border-bottom: 1px solid oklch(88% 0.005 260 / 0.6);
        flex-shrink: 0;
      }
      .si-icon { font-size: 18px; opacity: 0.5; flex-shrink: 0; }
      .si-input {
        all: initial; flex: 1;
        font-family: inherit; font-size: 16px; color: inherit;
        background: transparent; outline: none; border: none;
        caret-color: oklch(52% 0.18 220);
      }
      .si-input::placeholder { opacity: 0.4; font-size: 15px; }
      .si-shortcut {
        font-family: ui-monospace, 'Cascadia Code', monospace;
        font-size: 9.5px; opacity: 0.4;
        border: 1px solid currentColor; border-radius: 4px;
        padding: 2px 6px; letter-spacing: 0.04em; white-space: nowrap; flex-shrink: 0;
      }
      .si-toolbar {
        display: flex; align-items: center; gap: 8px;
        padding: 7px 18px 8px;
        border-bottom: 1px solid oklch(88% 0.005 260 / 0.5);
        flex-shrink: 0; overflow-x: auto;
      }
      .si-toolbar::-webkit-scrollbar { display: none; }
      .si-tb-label {
        font-family: ui-monospace, monospace; font-size: 9px;
        letter-spacing: 0.1em; text-transform: uppercase; opacity: 0.45; white-space: nowrap;
      }
      .si-tb-btn {
        font-family: ui-monospace, monospace; font-size: 10px;
        padding: 3px 9px; border-radius: 50px;
        border: 1px solid oklch(88% 0.005 260); background: transparent; color: inherit;
        cursor: pointer; white-space: nowrap; opacity: 0.65;
      }
      @media (prefers-reduced-motion: no-preference) {
        .si-tb-btn { transition: opacity 120ms ease, background 120ms ease, border-color 120ms ease, color 120ms ease; }
      }
      .si-tb-btn:hover, .si-tb-btn.active {
        opacity: 1;
        background: oklch(96% 0.04 220);
        border-color: oklch(52% 0.18 220 / 0.4);
        color: oklch(52% 0.18 220);
      }
      .si-results { flex: 1; overflow-y: auto; padding: 6px 0 10px; scrollbar-width: thin; }
      .si-results::-webkit-scrollbar { width: 4px; }
      .si-results::-webkit-scrollbar-thumb { background: oklch(88% 0.005 260); border-radius: 2px; }
      .si-empty {
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        gap: 12px; padding: 48px 20px; opacity: 0.45; text-align: center;
      }
      .si-empty-glyph { font-size: 36px; opacity: 0.5; }
      .si-empty-text { font-size: 13px; line-height: 1.5; }
      .si-loading {
        display: flex; align-items: center; justify-content: center; gap: 8px;
        padding: 40px; opacity: 0.45; font-size: 13px;
      }
      .si-spinner {
        width: 18px; height: 18px;
        border: 2px solid oklch(52% 0.18 220 / 0.3);
        border-top-color: oklch(52% 0.18 220);
        border-radius: 50%;
      }
      @media (prefers-reduced-motion: no-preference) {
        .si-spinner { animation: si-spin 0.7s linear infinite; }
      }
      @keyframes si-spin { to { transform: rotate(360deg); } }
      .si-result-item {
        display: flex; flex-direction: column; gap: 5px;
        padding: 11px 18px 10px; cursor: pointer;
        border-bottom: 1px solid oklch(88% 0.005 260 / 0.4);
        border-left: 3px solid transparent;
      }
      @media (prefers-reduced-motion: no-preference) {
        .si-result-item { transition: background 100ms ease, border-color 100ms ease; }
      }
      .si-result-item:hover, .si-result-item.selected {
        background: oklch(96% 0.04 220 / 0.5);
        border-left-color: oklch(52% 0.18 220);
      }
      .si-result-item:last-child { border-bottom: none; }
      .si-result-head { display: flex; align-items: flex-start; gap: 8px; }
      .si-result-favicon {
        width: 14px; height: 14px; border-radius: 2px; margin-top: 2px;
        flex-shrink: 0; object-fit: contain; opacity: 0.7;
      }
      .si-result-title { flex: 1; font-size: 13px; font-weight: 500; line-height: 1.35; color: inherit; }
      .si-result-badges { display: flex; gap: 5px; flex-shrink: 0; align-items: center; flex-wrap: wrap; }
      .si-badge {
        font-family: ui-monospace, monospace; font-size: 8.5px;
        padding: 1px 5px; border-radius: 4px; letter-spacing: 0.04em;
        border: 1px solid currentColor; white-space: nowrap;
      }
      .si-result-snippet { font-size: 11.5px; line-height: 1.55; opacity: 0.65; margin-left: 22px; }
      .si-result-meta { display: flex; gap: 10px; align-items: center; margin-left: 22px; }
      .si-result-domain, .si-result-date {
        font-family: ui-monospace, monospace; font-size: 10px; opacity: 0.45;
      }
      .si-result-score { font-family: ui-monospace, monospace; font-size: 9px; opacity: 0.3; margin-left: auto; }
      .si-section-header {
        padding: 10px 18px 5px; font-family: ui-monospace, monospace; font-size: 9px;
        letter-spacing: 0.12em; text-transform: uppercase; opacity: 0.4;
        display: flex; align-items: center; gap: 10px;
      }
      .si-section-line { flex: 1; height: 1px; background: oklch(88% 0.005 260); }
      .si-footer {
        padding: 8px 18px; border-top: 1px solid oklch(88% 0.005 260 / 0.5);
        display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;
      }
      .si-footer-info, .si-footer-hints {
        font-family: ui-monospace, monospace; font-size: 9.5px; opacity: 0.4;
      }
      .si-footer-hints { display: flex; gap: 12px; }
      .si-hint-key { border: 1px solid currentColor; border-radius: 4px; padding: 0 4px; margin-right: 3px; }
      .si-bias-block { padding: 12px 18px; border-top: 1px solid oklch(88% 0.005 260 / 0.6); flex-shrink: 0; }
      .si-bias-title {
        font-family: ui-monospace, monospace; font-size: 9px; letter-spacing: 0.12em;
        text-transform: uppercase; opacity: 0.45; margin-bottom: 10px;
      }
      .si-spectrum {
        display: flex; align-items: center; height: 28px; border-radius: 8px;
        overflow: hidden; border: 1px solid oklch(88% 0.005 260);
      }
      .si-spectrum-slot {
        flex: 1; height: 100%; display: flex; align-items: center; justify-content: center;
        font-family: ui-monospace, monospace; font-size: 9px; opacity: 0.3; cursor: pointer;
      }
      @media (prefers-reduced-motion: no-preference) {
        .si-spectrum-slot { transition: opacity 150ms ease, outline-color 150ms ease; }
      }
      .si-spectrum-slot.has-results { opacity: 0.8; }
      .si-spectrum-slot.current { outline: 2px solid oklch(52% 0.18 220 / 0.6); z-index: 1; }
    </style>

    <div class="si-search-row">
      <span class="si-icon">✦</span>
      <input class="si-input" id="__diatom_si_input" type="text"
        placeholder="Search your Museum archive…"
        autocomplete="off" spellcheck="false" autocorrect="off">
      <span class="si-shortcut">ESC to close</span>
    </div>
    <div class="si-toolbar">
      <span class="si-tb-label">Filter:</span>
      <button class="si-tb-btn active" data-filter="all">All</button>
      <button class="si-tb-btn" data-filter="article">Articles</button>
      <button class="si-tb-btn" data-filter="doc">Documents</button>
      <button class="si-tb-btn" data-filter="human_curated">Human Curated</button>
      <span style="margin-left:auto;flex-shrink:0">
        <button class="si-tb-btn" id="__diatom_si_bias_btn" title="Bias Contrast View — find opposing perspectives">
          ◀●▶ Bias View
        </button>
      </span>
    </div>
    <div class="si-results" id="__diatom_si_results" role="listbox" aria-label="Search results"></div>
    <div class="si-footer">
      <span class="si-footer-info" id="__diatom_si_count">Shadow Index · Local Museum</span>
      <span class="si-footer-hints">
        <span><span class="si-hint-key">↑↓</span> navigate</span>
        <span><span class="si-hint-key">↵</span> open</span>
        <span><span class="si-hint-key">⌘↵</span> open in new tab</span>
      </span>
    </div>
  `;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  _overlayEl = overlay;
  _panelEl   = panel;
  _inputEl   = panel.querySelector('#__diatom_si_input');
  _resultsEl = panel.querySelector('#__diatom_si_results');

  overlay.addEventListener('click', e => {
    if (e.target === overlay) close();
  });

  _inputEl.addEventListener('input', e => {
    _query = e.target.value.trim();
    _selected = -1;
    clearTimeout(_debounce);
    if (!_query) { renderEmpty(); return; }
    _debounce = setTimeout(doSearch, DEBOUNCE_MS);
  });

  _inputEl.addEventListener('keydown', handleKeyNav);

  panel.querySelectorAll('.si-tb-btn[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      panel.querySelectorAll('.si-tb-btn[data-filter]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _activeFilter = btn.dataset.filter;
      renderResults();
    });
  });

  panel.querySelector('#__diatom_si_bias_btn').addEventListener('click', () => {
    _biasMode = !_biasMode;
    panel.querySelector('#__diatom_si_bias_btn').classList.toggle('active', _biasMode);
    renderResults();
  });

  return overlay;
}

let _activeFilter = 'all';

async function doSearch() {
  if (!_open || !_query) return;
  _searching = true;
  _resultsEl.innerHTML = `
    <div class="si-loading">
      <div class="si-spinner"></div>
      Searching Museum…
    </div>`;

  try {
    const raw = await invoke('cmd_shadow_search', {
      query: _query,
      limit: MAX_RESULTS,
    });
    _results = raw || [];
    renderResults();
  } catch (err) {
    _results = [];
    _resultsEl.innerHTML = `
      <div class="si-empty">
        <span class="si-empty-glyph">⚠</span>
        <p class="si-empty-text">Search failed. Is your Museum populated?<br>
        <small style="opacity:0.6">Freeze some pages first with ⌘⇧S</small></p>
      </div>`;
    console.warn('[shadow-index] search error:', err);
  } finally {
    _searching = false;
    updateCount();
  }
}

function renderEmpty() {
  _resultsEl.innerHTML = `
    <div class="si-empty">
      <span class="si-empty-glyph">✦</span>
      <p class="si-empty-text">
        Search your personal Museum archive.<br>
        Every result comes from a page <em>you</em> chose to save.
      </p>
    </div>`;
  updateCount();
}

function filterResults(results) {
  if (_activeFilter === 'all') return results;
  if (_activeFilter === 'human_curated') {
    return results.filter(r => r.quality_tier === 'human_curated');
  }
  if (_activeFilter === 'article') {
    return results.filter(r => {
      const u = (r.url || '').toLowerCase();
      return u.includes('/article') || u.includes('/post') || u.includes('/blog') ||
             u.includes('/news') || u.includes('/story') || u.includes('/opinion');
    });
  }
  if (_activeFilter === 'doc') {
    return results.filter(r => (r.url || '').match(/\.(pdf|docx?|xlsx?|pptx?)(\?|#|$)/i));
  }
  return results;
}

function resultHTML(r, idx, query) {
  const selected = idx === _selected ? ' selected' : '';
  const lean  = estimateLean(r.url);
  const lCfg  = LEAN_CONFIG[lean];
  const qCfg  = QUALITY_CONFIG[r.quality_tier] || QUALITY_CONFIG.standard;
  const domain = domainOf(r.url);
  const date   = formatDate(r.frozen_at);
  const snippet = highlight(getSnippet(r.snippet || r.title, query, 180), query);
  const title   = highlight(r.title, query);

  const leanBadge = lean !== 'unknown'
    ? `<span class="si-badge" style="color:${lCfg.color};border-color:${lCfg.color}40">
        ${lCfg.icon} ${lCfg.label}
       </span>`
    : '';

  const qualityBadge = `
    <span class="si-badge" style="color:${qCfg.color};border-color:${qCfg.color}40">
      ${qCfg.icon} ${qCfg.label}
    </span>`;

  const faviconUrl = `https://icons.duckduckgo.com/ip3/${domain}.ico`;

  return `
    <div class="si-result-item${selected}"
         role="option"
         aria-selected="${idx === _selected}"
         data-idx="${idx}"
         data-url="${escHtml(r.url)}"
         data-id="${escHtml(r.museum_id)}">
      <div class="si-result-head">
        <img class="si-result-favicon" src="${faviconUrl}"
          onerror="this.style.display='none'" alt="" aria-hidden="true">
        <div class="si-result-title">${title || '(untitled)'}</div>
        <div class="si-result-badges">
          ${qualityBadge}
          ${leanBadge}
        </div>
      </div>
      ${snippet ? `<div class="si-result-snippet">${snippet}</div>` : ''}
      <div class="si-result-meta">
        <span class="si-result-domain">${domain}</span>
        ${date ? `<span class="si-result-date">${date}</span>` : ''}
        <span class="si-result-score">${r.score?.toFixed ? r.score.toFixed(2) : ''}</span>
      </div>
    </div>`;
}

function biasSpectrumHTML(results) {
  const leans = ['left','centerleft','center','centerright','right'];
  const counts = {};
  leans.forEach(l => counts[l] = 0);
  results.forEach(r => {
    const l = estimateLean(r.url);
    if (counts[l] !== undefined) counts[l]++;
  });

  const currentLean = _currentPageLean;

  const slots = leans.map(l => {
    const cfg = LEAN_CONFIG[l];
    const hasRes = counts[l] > 0;
    const isCurrent = l === currentLean;
    return `<div class="si-spectrum-slot ${hasRes ? 'has-results' : ''} ${isCurrent ? 'current' : ''}"
      style="background:${cfg.color}18;color:${cfg.color}"
      title="${cfg.label}: ${counts[l]} results"
      data-lean="${l}">
      ${cfg.icon} ${counts[l] > 0 ? `<sup style="font-size:7px">${counts[l]}</sup>` : ''}
    </div>`;
  }).join('');

  return `
    <div class="si-bias-block">
      <div class="si-bias-title">Bias Contrast View — Perspectives in your Museum</div>
      <div class="si-spectrum">${slots}</div>
    </div>`;
}

function renderResults() {
  const filtered = filterResults(_results);

  if (!_query) { renderEmpty(); return; }

  if (filtered.length === 0 && !_searching) {
    _resultsEl.innerHTML = `
      <div class="si-empty">
        <span class="si-empty-glyph">○</span>
        <p class="si-empty-text">
          Nothing in your Museum for <strong>"${escHtml(_query)}"</strong>.<br>
          <small style="opacity:0.6">Freeze pages while browsing to build your archive.</small>
        </p>
      </div>`;
    updateCount();
    return;
  }

  let html = '';

  if (_biasMode) {
    const leanOrder = ['left','centerleft','center','centerright','right','unknown'];
    const groups = {};
    leanOrder.forEach(l => groups[l] = []);
    filtered.forEach(r => {
      const l = estimateLean(r.url);
      (groups[l] || groups.unknown).push(r);
    });

    let globalIdx = 0;
    let anyGroup  = false;
    leanOrder.forEach(lean => {
      const items = groups[lean];
      if (!items.length) return;
      anyGroup = true;
      const lCfg = LEAN_CONFIG[lean];
      html += `
        <div class="si-section-header">
          <span style="color:${lCfg.color}">${lCfg.icon} ${lCfg.label}</span>
          <div class="si-section-line"></div>
          <span style="opacity:0.4;font-size:9px">${items.length}</span>
        </div>`;
      items.forEach(r => {
        html += resultHTML(r, globalIdx, _query);
        globalIdx++;
      });
    });
    if (!anyGroup) html = `<div class="si-empty"><span class="si-empty-glyph">○</span><p class="si-empty-text">No matching results.</p></div>`;
  } else {
    filtered.forEach((r, idx) => {
      html += resultHTML(r, idx, _query);
    });
  }

  _resultsEl.innerHTML = html;

  if (_biasMode && _results.length > 0) {
    const biasDom = document.createElement('div');
    biasDom.innerHTML = biasSpectrumHTML(_results);
    _panelEl.insertBefore(biasDom.firstElementChild, _panelEl.querySelector('.si-footer'));

    _panelEl.querySelectorAll('.si-spectrum-slot[data-lean]').forEach(slot => {
      slot.addEventListener('click', () => {
        const lean = slot.dataset.lean;
        const first = _resultsEl.querySelector(`[data-url]`);
        if (first) {
          const items = Array.from(_resultsEl.querySelectorAll('.si-result-item'));
          const target = items.find(el => estimateLean(el.dataset.url) === lean);
          if (target) target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      });
    });
  }

  _resultsEl.querySelectorAll('.si-result-item').forEach(item => {
    item.addEventListener('click', e => {
      const url = item.dataset.url;
      if (!url) return;
      if (e.metaKey || e.ctrlKey) {
        openResult(url, true);
      } else {
        openResult(url, false);
      }
    });
  });

  updateCount();
}

function updateCount() {
  const countEl = _panelEl?.querySelector('#__diatom_si_count');
  if (!countEl) return;
  if (!_query) {
    countEl.textContent = 'Shadow Index · Local Museum';
  } else if (_searching) {
    countEl.textContent = 'Searching…';
  } else {
    const n = filterResults(_results).length;
    countEl.textContent = `${n} result${n !== 1 ? 's' : ''} · local · ${_results.length > n ? `${_results.length} total` : 'all shown'}`;
  }
}

function handleKeyNav(e) {
  const items = _resultsEl ? Array.from(_resultsEl.querySelectorAll('.si-result-item')) : [];

  if (e.key === 'Escape') {
    e.preventDefault();
    close();
    return;
  }

  if (e.key === 'ArrowDown' || (e.key === 'Tab' && !e.shiftKey)) {
    e.preventDefault();
    _selected = Math.min(_selected + 1, items.length - 1);
    updateSelection(items);
    return;
  }

  if (e.key === 'ArrowUp' || (e.key === 'Tab' && e.shiftKey)) {
    e.preventDefault();
    _selected = Math.max(_selected - 1, -1);
    updateSelection(items);
    return;
  }

  if (e.key === 'Enter') {
    e.preventDefault();
    if (_selected >= 0 && items[_selected]) {
      const url = items[_selected].dataset.url;
      if (url) openResult(url, e.metaKey || e.ctrlKey);
    }
    return;
  }
}

function updateSelection(items) {
  items.forEach((el, idx) => {
    el.classList.toggle('selected', idx === _selected);
    el.setAttribute('aria-selected', idx === _selected);
  });
  if (_selected >= 0 && items[_selected]) {
    items[_selected].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

function openResult(url, newTab) {
  close();
  if (newTab) {
    invoke('cmd_tab_create', { url }).catch(() => window.open(url, '_blank'));
  } else {
    location.href = url;
  }
}

function open() {
  if (_open) { _inputEl?.focus(); return; }
  _open      = true;
  _query     = '';
  _results   = [];
  _selected  = -1;
  _biasMode  = false;
  _currentPageLean = estimateLean(location.href);

  createDOM();
  _inputEl.value = '';
  renderEmpty();

  requestAnimationFrame(() => {
    _inputEl?.focus();
  });

  document.addEventListener('keydown', trapEsc, true);
}

function close() {
  if (!_open) return;
  _open = false;
  clearTimeout(_debounce);

  const overlay = document.getElementById(OVERLAY_ID);
  _panelEl?.querySelector('.si-bias-block')?.remove();
  if (overlay) {
    overlay.style.animation = 'none';
    overlay.style.opacity   = '0';
    overlay.style.transition = 'opacity 0.12s';
    setTimeout(() => overlay.remove(), 130);
  }

  _overlayEl = null;
  _panelEl   = null;
  _inputEl   = null;
  _resultsEl = null;

  document.removeEventListener('keydown', trapEsc, true);
}

function trapEsc(e) {
  if (e.key === 'Escape') { e.preventDefault(); close(); }
}

async function freezeCurrentPage() {
  try {
    const html = document.documentElement.outerHTML;
    await invoke('cmd_freeze_page', {
      url:      location.href,
      title:    document.title || location.href,
      raw_html: html,
    });
    showFreezeToast('✦ Archived to Museum');
  } catch (err) {
    showFreezeToast('⚠ Freeze failed: ' + (err?.message || err));
    console.warn('[shadow-index] freeze error:', err);
  }
}

function showFreezeToast(msg) {
  const existing = document.getElementById('__diatom_si_toast');
  if (existing) existing.remove();
  const t = document.createElement('div');
  t.id = '__diatom_si_toast';
  t.style.cssText = `
    all: initial; position: fixed; bottom: 20px; right: 20px;
    z-index: 2147483647;
    background: oklch(20% 0.02 260 / 0.92);
    color: oklch(90% 0.03 220);
    font-family: ui-monospace, 'Cascadia Code', monospace;
    font-size: 11px;
    padding: 8px 16px;
    border-radius: 8px;
    box-shadow: 0 4px 16px oklch(0% 0 0 / 0.25);
  `;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2800);
}

document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === OPEN_KEY) {
    e.preventDefault();
    if (_open) close();
    else open();
    return;
  }

  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === FREEZE_KEY) {
    e.preventDefault();
    freezeCurrentPage();
    return;
  }
}, { capture: true });

export const shadowIndex = {
  open,
  close,
  search: (query) => {
    open();
    if (_inputEl) {
      _inputEl.value = query;
      _query = query;
      doSearch();
    }
  },
  freezePage: freezeCurrentPage,
  isOpen: () => _open,
};

window.__diatom_shadow_index = shadowIndex;
