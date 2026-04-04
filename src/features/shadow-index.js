/**
 * diatom/src/features/shadow-index.js  — v1.1.0
 *
 * Shadow Index — Human-Curated Search Panel
 *
 * Responsibilities:
 *   1. Keyboard shortcut (⌘⇧F / Ctrl⇧F) opens the search overlay
 *   2. Full-text TF-IDF search over the user's Museum via cmd_shadow_search
 *   3. Renders results with title, snippet, domain, date, quality badge
 *   4. Bias Contrast View: surfaces opposing perspectives for news pages
 *   5. "Freeze this page" shortcut to add the current page to Museum
 *
 * All search runs locally in Rust. No network requests unless P2P mode
 * is explicitly enabled in Labs.
 */

'use strict';

import { invoke } from '../browser/ipc.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const PANEL_ID    = '__diatom_shadow_panel';
const OVERLAY_ID  = '__diatom_shadow_overlay';
const OPEN_KEY    = 'f';         // ⌘⇧F or Ctrl⇧F
const FREEZE_KEY  = 's';         // ⌘⇧S to freeze current page
const MAX_RESULTS = 20;
const DEBOUNCE_MS = 280;

// Domain → estimated political lean for Bias Contrast View
// Political lean map — last reviewed 2025-Q1.
// NOTE: This is a HEURISTIC classifier, not an editorial judgment.
//   • Classifications cover publication-level editorial stance, NOT individual articles.
//   • Media stances drift over time; this list is versioned and reviewed quarterly.
//   • Any domain not listed → 'unknown' (the safe default).
//   • User-configurable overrides planned for v0.11.0.
// [BUG-2 FIX] Removed duplicate 'atlantic.com' entry (theatlantic.com is canonical).
const LEAN_DOMAINS_VERSION = '2025-Q1';
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

// ── Helpers ───────────────────────────────────────────────────────────────────

function escHtml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function formatDate(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts * 1000);
    return d.toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' });
  } catch { return ''; }
}

function domainOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return url; }
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

// ── State ─────────────────────────────────────────────────────────────────────

let _open      = false;
let _query     = '';
let _results   = [];
let _selected  = -1;
let _debounce  = null;
let _searching = false;
let _biasMode  = false;
let _currentPageLean = 'unknown';

// ── Styles ────────────────────────────────────────────────────────────────────

const STYLES = null; // [v0.6.0 OPT-01] Extracted to /shadow-index.css — loaded on first open

// ── DOM ───────────────────────────────────────────────────────────────────────

let _overlayEl = null;
let _panelEl   = null;
let _inputEl   = null;
let _resultsEl = null;

function createDOM() {
  // Inject styles once
  if (!document.getElementById('__diatom_si_styles')) {
    const style = document.createElement('style');
    style.id = '__diatom_si_styles';
    style.textContent = STYLES;
    document.head.appendChild(style);
  }

  const overlay = document.createElement('div');
  overlay.id = OVERLAY_ID;

  const panel = document.createElement('div');
  panel.id    = PANEL_ID;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Shadow Index Search');
  panel.setAttribute('aria-modal', 'true');

  panel.innerHTML = `
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
  // [v0.6.0 OPT-01] Load external shadow-index.css on first open
  if (typeof loadStylesheet === 'function') loadStylesheet('/shadow-index.css');
  document.body.appendChild(overlay);

  _overlayEl = overlay;
  _panelEl   = panel;
  _inputEl   = panel.querySelector('#__diatom_si_input');
  _resultsEl = panel.querySelector('#__diatom_si_results');

  // Close on overlay click
  overlay.addEventListener('click', e => {
    if (e.target === overlay) close();
  });

  // Input → search
  _inputEl.addEventListener('input', e => {
    _query = e.target.value.trim();
    _selected = -1;
    clearTimeout(_debounce);
    if (!_query) { renderEmpty(); return; }
    _debounce = setTimeout(doSearch, DEBOUNCE_MS);
  });

  // Keyboard navigation
  _inputEl.addEventListener('keydown', handleKeyNav);

  // Toolbar filters
  panel.querySelectorAll('.si-tb-btn[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      panel.querySelectorAll('.si-tb-btn[data-filter]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _activeFilter = btn.dataset.filter;
      renderResults();
    });
  });

  // Bias View toggle
  panel.querySelector('#__diatom_si_bias_btn').addEventListener('click', () => {
    _biasMode = !_biasMode;
    panel.querySelector('#__diatom_si_bias_btn').classList.toggle('active', _biasMode);
    renderResults();
  });

  return overlay;
}

let _activeFilter = 'all';

// ── Search ────────────────────────────────────────────────────────────────────

async function doSearch() {
  // [BUG-3 FIX] Guard against ghost IPC: panel may have closed during the 280ms debounce window.
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

// ── Render ────────────────────────────────────────────────────────────────────

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
  // Simple content-type heuristics based on URL/domain
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
    // Group by lean
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

  // Bias spectrum at bottom when in bias mode
  if (_biasMode && _results.length > 0) {
    const biasDom = document.createElement('div');
    biasDom.innerHTML = biasSpectrumHTML(_results);
    _panelEl.insertBefore(biasDom.firstElementChild, _panelEl.querySelector('.si-footer'));

    // Click lean slot → filter to that lean
    _panelEl.querySelectorAll('.si-spectrum-slot[data-lean]').forEach(slot => {
      slot.addEventListener('click', () => {
        const lean = slot.dataset.lean;
        // highlight results of that lean by scrolling to first
        const first = _resultsEl.querySelector(`[data-url]`);
        if (first) {
          const items = Array.from(_resultsEl.querySelectorAll('.si-result-item'));
          const target = items.find(el => estimateLean(el.dataset.url) === lean);
          if (target) target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      });
    });
  }

  // Wire click handlers
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

// ── Keyboard navigation ───────────────────────────────────────────────────────

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

// ── Navigation ────────────────────────────────────────────────────────────────

function openResult(url, newTab) {
  close();
  if (newTab) {
    invoke('cmd_tab_create', { url }).catch(() => window.open(url, '_blank'));
  } else {
    location.href = url;
  }
}

// ── Open / Close ──────────────────────────────────────────────────────────────

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

  // Trap focus
  document.addEventListener('keydown', trapEsc, true);
}

function close() {
  if (!_open) return;
  _open = false;
  clearTimeout(_debounce);

  const overlay = document.getElementById(OVERLAY_ID);
  // Remove bias block if present
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

// ── Freeze shortcut ───────────────────────────────────────────────────────────

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
  t.className = 'si-freeze-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2800);
}

// ── Global keyboard shortcuts ─────────────────────────────────────────────────

document.addEventListener('keydown', e => {
  // ⌘⇧F / Ctrl⇧F → open / close search panel
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === OPEN_KEY) {
    e.preventDefault();
    if (_open) close();
    else open();
    return;
  }

  // ⌘⇧S / Ctrl⇧S → freeze current page
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === FREEZE_KEY) {
    // Don't intercept normal Ctrl+S (page-save) — only when combined with Shift
    e.preventDefault();
    freezeCurrentPage();
    return;
  }
}, { capture: true });

// ── Public API ────────────────────────────────────────────────────────────────

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
