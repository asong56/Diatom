// ─────────────────────────────────────────────────────────────────────────────
// diatom/src/browser/utils.js  — v0.9.0
//
// Shared pure functions. No side effects, no module-level state.
// Import selectively — avoid barrel imports that pull everything.
// ─────────────────────────────────────────────────────────────────────────────

// ── URL utilities ─────────────────────────────────────────────────────────────

/** Extract the eTLD+1 (registrable domain) from a URL string. */
export function domainOf(url) {
    try {
        return new URL(url).hostname.replace(/^www\./, '');
    } catch {
        return url;
    }
}

/** Return true if the URL is a Diatom internal page (diatom:// scheme). */
export function isDiatomPage(url) {
    return url.startsWith('diatom://') || url === 'about:blank' || url === '';
}

/** Upgrade HTTP to HTTPS (mirrors Rust blocker::upgrade_https). */
export function upgradeHttps(url) {
    if (url.startsWith('http://') && !url.startsWith('http://localhost')) {
        return 'https://' + url.slice(7);
    }
    return url;
}

/** Route a diatom:// URL to the corresponding HTML file. */
export function diatomPagePath(url) {
    const routes = {
        'diatom://labs':       '/src/ui/labs.html',
        'diatom://about':      '/src/ui/about.html',
        'diatom://newtab':     null,   // handled by #new-tab-page in index.html
        'diatom://settings':   '/src/ui/settings.html',
        'diatom://museum':     '/src/ui/museum.html',
        'diatom://echo':       '/src/ui/echo.html',
        'diatom://localfiles': '/src/ui/localfiles.html',
    };
    return routes[url.toLowerCase()] ?? null;
}

// ── String utilities ──────────────────────────────────────────────────────────

/** Truncate a string to `max` characters with an ellipsis. */
export function truncate(str, max = 60) {
    return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

/** Format a byte count as a human-readable string (KB / MB / GB). */
export function formatBytes(bytes) {
    if (bytes < 1024)           return `${bytes} B`;
    if (bytes < 1024 ** 2)      return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 ** 3)      return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
    return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

/** Format a Unix timestamp as a relative time string ("2 min ago", "3 days ago"). */
export function relativeTime(unixSec) {
    const diff = Math.floor(Date.now() / 1000) - unixSec;
    if (diff < 60)     return 'just now';
    if (diff < 3600)   return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400)  return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return new Date(unixSec * 1000).toLocaleDateString();
}

// ── DOM utilities ─────────────────────────────────────────────────────────────

/** Query selector with type narrowing + null guard. */
export function q(selector, root = document) {
    return root.querySelector(selector);
}

/** Query all with Array.from shorthand. */
export function qAll(selector, root = document) {
    return Array.from(root.querySelectorAll(selector));
}

/** Create an element with optional attributes and children. */
export function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') node.className = v;
        else if (k.startsWith('on') && typeof v === 'function') {
            node.addEventListener(k.slice(2), v);
        } else {
            node.setAttribute(k, v);
        }
    }
    for (const child of children.flat()) {
        if (typeof child === 'string') node.append(document.createTextNode(child));
        else if (child instanceof Node) node.append(child);
    }
    return node;
}

/** Announce a message to screen readers via the ARIA live region. */
export function announce(message) {
    const live = document.getElementById('aria-live');
    if (!live) return;
    live.textContent = '';
    requestAnimationFrame(() => { live.textContent = message; });
}

// ── Number / math utilities ───────────────────────────────────────────────────

/** Clamp a value between min and max. */
export function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}

/** Golden ratio. Used for Focus/Buffer zone split. */
export const PHI = 1.618033988749895;

/** Compute Focus zone tab count from a total budget. */
export function focusZoneCount(tMax) {
    return Math.max(1, Math.floor(tMax / PHI));
}

// ── Event utilities ───────────────────────────────────────────────────────────

/** One-shot event listener that auto-removes after first invocation. */
export function once(target, event, handler) {
    const wrapped = (...args) => {
        target.removeEventListener(event, wrapped);
        handler(...args);
    };
    target.addEventListener(event, wrapped);
}

/** Debounce: returns a function that delays calling fn until after `wait` ms. */
export function debounce(fn, wait = 200) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), wait);
    };
}

/** Throttle: returns a function that calls fn at most once per `interval` ms. */
export function throttle(fn, interval = 100) {
    let last = 0;
    return (...args) => {
        const now = Date.now();
        if (now - last >= interval) { last = now; fn(...args); }
    };
}

// ── Storage utilities ─────────────────────────────────────────────────────────

/**
 * Tiny sessionStorage wrapper.
 * Prefer Rust-side settings for persistence; use this only for ephemeral UI state.
 */
export const session = {
    get(key)       { try { return JSON.parse(sessionStorage.getItem(key)); } catch { return null; } },
    set(key, val)  { try { sessionStorage.setItem(key, JSON.stringify(val)); } catch {} },
    del(key)       { try { sessionStorage.removeItem(key); } catch {} },
};
