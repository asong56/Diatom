/**
 * diatom/src/features/peek.js  — v0.12.0  [F-06]
 *
 * Peek — Link Hover Preview — 悬停链接预览
 *
 * Hovering over a hyperlink for 600ms shows a compact preview card:
 *   - Page title
 *   - Domain
 *   - Open Graph description + image (if available and already cached)
 *   - Blocked badge if the domain is in the block list
 *
 * Privacy:
 *   - All fetches use current_ua() + GhostPipe if enabled.
 *   - Previously-visited URLs resolve from Museum cache (zero network).
 *   - Disabled when Zen mode is active.
 *
 * Lab ID: peek_preview
 */

'use strict';

import { invoke } from '../browser/ipc.js';
import { domainOf, escHtml } from '../browser/utils.js';

// ── Config ────────────────────────────────────────────────────────────────────

const HOVER_DELAY_MS = 600;
const CARD_MAX_W     = 340;
const CARD_Z         = 2147483640;

// ── State ─────────────────────────────────────────────────────────────────────

let _card        = null;    // Current preview card DOM node
let _hoverTimer  = null;    // setTimeout handle
let _currentUrl  = null;    // URL being previewed
let _enabled     = false;

// ── Init ──────────────────────────────────────────────────────────────────────

export function initPeek() {
    _enabled = true;
    document.addEventListener('mouseover',  onMouseOver,  { passive: true });
    document.addEventListener('mouseout',   onMouseOut,   { passive: true });
    document.addEventListener('scroll',     dismissCard,  { passive: true });
    document.addEventListener('keydown',    dismissCard,  { passive: true });
}

// ── Event handlers ────────────────────────────────────────────────────────────

function onMouseOver(e) {
    if (!_enabled) return;

    const anchor = e.target.closest('a[href]');
    if (!anchor) return;

    const href = anchor.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;

    // Resolve relative URLs
    let url;
    try { url = new URL(href, location.href).href; } catch { return; }
    if (!url.startsWith('http')) return;
    if (url === _currentUrl) return;

    clearTimeout(_hoverTimer);
    _hoverTimer = setTimeout(() => triggerPeek(url, anchor), HOVER_DELAY_MS);
}

function onMouseOut(e) {
    clearTimeout(_hoverTimer);
    // Only dismiss if we're leaving both the anchor and the card
    const to = e.relatedTarget;
    if (!_card || (!_card.contains(to) && to !== _card)) {
        dismissCard();
    }
}

// ── Peek fetch ────────────────────────────────────────────────────────────────

async function triggerPeek(url, anchor) {
    _currentUrl = url;
    showLoadingCard(url, anchor);

    try {
        const data = await invoke('cmd_peek_fetch', { url });
        if (url !== _currentUrl) return; // navigated away during fetch
        showCard(data, anchor);
    } catch (err) {
        if (url !== _currentUrl) return;
        // Show minimal card on fetch failure
        showCard({ url, title: domainOf(url), description: null, og_image: null, blocked: false }, anchor);
    }
}

// ── Card rendering ────────────────────────────────────────────────────────────

function showLoadingCard(url, anchor) {
    dismissCard();
    _card = createCard(`
        <div class="peek-loading">
            <span class="peek-domain">${escHtml(domainOf(url))}</span>
            <span class="peek-spinner">···</span>
        </div>
    `);
    positionCard(_card, anchor);
    document.body.appendChild(_card);
}

function showCard(data, anchor) {
    dismissCard();

    const blocked = data.blocked;
    const title   = data.title   || domainOf(data.url);
    const desc    = data.description;
    const img     = data.og_image;
    const domain  = domainOf(data.url);

    let inner = '';

    if (blocked) {
        inner = `
            <div class="peek-blocked">
                <span class="peek-blocked-icon">🚫</span>
                <div>
                    <div class="peek-domain">${escHtml(domain)}</div>
                    <div class="peek-blocked-label">Blocked by Diatom</div>
                </div>
            </div>
        `;
    } else {
        inner = `
            ${img ? `<img class="peek-og-img" src="${escHtml(img)}" alt="" loading="lazy">` : ''}
            <div class="peek-body">
                <div class="peek-title">${escHtml(title.slice(0, 80))}</div>
                <div class="peek-domain">${escHtml(domain)}</div>
                ${desc ? `<div class="peek-desc">${escHtml(desc.slice(0, 120))}</div>` : ''}
            </div>
        `;
    }

    _card = createCard(inner);
    if (blocked) _card.classList.add('peek-card--blocked');
    positionCard(_card, anchor);
    document.body.appendChild(_card);
}

function createCard(inner) {
    const card = document.createElement('div');
    card.className = 'peek-card';
    card.style.cssText = `
        position:fixed; z-index:${CARD_Z}; max-width:${CARD_MAX_W}px;
        background:rgba(10,10,18,.96); border:1px solid rgba(96,165,250,.15);
        border-radius:8px; box-shadow:0 8px 32px rgba(0,0,0,.5);
        font:13px/1.5 'Inter',system-ui; color:#e2e8f0;
        overflow:hidden; pointer-events:none;
        animation:peekIn .12s ease-out;
    `;
    card.innerHTML = inner;

    // Keep card alive when mouse enters it
    card.addEventListener('mouseenter', () => clearTimeout(_hoverTimer));
    card.addEventListener('mouseleave', () => dismissCard());

    return card;
}

function positionCard(card, anchor) {
    const rect = anchor.getBoundingClientRect();
    const vw   = window.innerWidth;
    const vh   = window.innerHeight;

    // Place below the link; flip if near bottom
    let top  = rect.bottom + 8;
    let left = rect.left;

    // Clamp horizontally
    if (left + CARD_MAX_W > vw - 12) {
        left = vw - CARD_MAX_W - 12;
    }
    // Flip above if near bottom
    if (top + 160 > vh) {
        top = rect.top - 160;
    }

    card.style.top  = `${Math.max(8, top)}px`;
    card.style.left = `${Math.max(8, left)}px`;
}

function dismissCard() {
    clearTimeout(_hoverTimer);
    if (_card) { _card.remove(); _card = null; }
    _currentUrl = null;
}

// ── Zen mode guard ────────────────────────────────────────────────────────────

export function setEnabled(active) {
    _enabled = active;
    if (!active) dismissCard();
}

// ── CSS injection (minimal, inlined) ─────────────────────────────────────────

const PEEK_CSS = `
@keyframes peekIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
.peek-card .peek-og-img { width:100%; max-height:120px; object-fit:cover; display:block; }
.peek-card .peek-body   { padding:10px 12px; }
.peek-card .peek-title  { font-weight:600; color:#f1f5f9; margin-bottom:2px; }
.peek-card .peek-domain { font-size:11px; color:#64748b; }
.peek-card .peek-desc   { font-size:12px; color:#94a3b8; margin-top:4px; }
.peek-card .peek-loading { padding:10px 14px; display:flex; align-items:center; gap:8px; }
.peek-card .peek-spinner { color:#334155; letter-spacing:2px; }
.peek-card--blocked .peek-blocked { padding:10px 14px; display:flex; gap:10px; align-items:center; }
.peek-blocked-icon  { font-size:20px; flex-shrink:0; }
.peek-blocked-label { font-size:11px; color:#ef4444; margin-top:2px; }
`;

if (!document.getElementById('__diatom_peek_css')) {
    const style = document.createElement('style');
    style.id = '__diatom_peek_css';
    style.textContent = PEEK_CSS;
    document.head.appendChild(style);
}
