/**
 * diatom/src/sw.js  — v0.9.0
 *
 * Service Worker — last line of defence before bytes hit the renderer.
 *
 * v7 additions:
 *   • Ghost Redirect: offline navigation miss → semantic fallback from Museum
 *   • Zen Mode: block navigations to social/entertainment categories
 *   • Threat intercept: block known-malicious domains at fetch level
 *   • DOM Crusher rules injected into HTML responses via content rewriting
 */

'use strict';

const CACHE   = 'diatom-v7';
const SHELL   = ['/', '/index.html', '/diatom.css', '/main.js', '/sw.js', '/manifest.json'];

// ── Config (hot-updated via BroadcastChannel) ─────────────────────────────────
let CONFIG = {
  adblock:         true,
  ua_uniformity:   true,
  csp_injection:   true,
  degrade_images:  false,
  image_quality:   0.4,
  image_scale:     0.5,
  decoy_traffic:   false,
  zen_active:      false,
  zen_categories:  ['social', 'entertainment'],
};

// In-memory Museum index (populated by IPC from the app on SW init)
// Format: Array<{ id, url, title, tfidf_tags: string[] }>
let MUSEUM_INDEX = [];

// In-memory threat list (populated from DB on startup)
let THREAT_SET = new Set();

// DOM crusher rules per domain: Map<domain, selector[]>
let CRUSHER_RULES = new Map();

// [FIX-S4] DIATOM_UA is now dynamic — updated by main thread after Sentinel populates.
// Falls back to a reasonable static UA until the first CONFIG message arrives.
// The main thread sends { type: 'CONFIG', config: { synthesised_ua: '...' } }
// after boot() completes.
let DIATOM_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/619.1.26 (KHTML, like Gecko) Version/18.0 Safari/619.1.26';

const bc = new BroadcastChannel('diatom:sw');
const devnetBC = new BroadcastChannel('diatom:devnet');
let _reqSeq = 0;

bc.addEventListener('message', e => {
  const msg = e.data;
  if (!msg?.type) return;

  switch (msg.type) {
    case 'CONFIG':
      Object.assign(CONFIG, msg.config);
      // [FIX-S4] Update UA when Sentinel provides a fresh synthesised string
      if (msg.config?.synthesised_ua) {
        DIATOM_UA = msg.config.synthesised_ua;
      }
      break;
    case 'ZEN':
      CONFIG.zen_active = !!msg.active;
      break;
    case 'MUSEUM_INDEX':
      MUSEUM_INDEX = msg.index ?? [];
      break;
    case 'THREAT_LIST':
      THREAT_SET = new Set(msg.list ?? []);
      break;
    case 'CRUSHER_RULES':
      // { domain: string, selectors: string[] }
      CRUSHER_RULES.set(msg.domain, msg.selectors ?? []);
      break;
  }
});

// ── Blocklist ─────────────────────────────────────────────────────────────────

const BLOCKED = new Set([
  'doubleclick.net','googlesyndication.com','googletagmanager.com',
  'google-analytics.com','adservice.google.','connect.facebook.net',
  'pixel.facebook.com','hotjar.com','amplitude.com','api.segment.io',
  'cdn.segment.com','mixpanel.com','clarity.ms','fullstory.com',
  'chartbeat.com','parsely.com','quantserve.com','scorecardresearch.com',
  'bugsnag.com','ingest.sentry.io','js-agent.newrelic.com','nr-data.net',
  'adnxs.com','adroll.com','criteo.com','media.net','moatads.com',
  'outbrain.com','pubmatic.com','rubiconproject.com','taboola.com',
  'adsrvr.org','beacon.krxd.net','px.ads.linkedin.com','bat.bing.com',
  'munchkin.marketo.net','js.hs-scripts.com','cdn.heapanalytics.com',
]);

const STRIP_PARAMS = new Set([
  '_ga','_gac','_gl','dclid','fbclid','gad_source','gbraid','gclid',
  'gclsrc','igshid','li_fat_id','mc_eid','msclkid','s_kwcid','trk',
  'ttclid','twclid','utm_campaign','utm_content','utm_id','utm_medium',
  'utm_source','utm_term','wbraid','wickedid','yclid',
]);

const STUB_MAP = {
  'google-analytics.com': 'window.ga=function(){};window.gtag=function(){};',
  'googletagmanager.com': 'window.dataLayer=window.dataLayer||[];',
  'hotjar.com': '(function(h){h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)}})(window);',
  'connect.facebook.net': '!function(f){f.fbq=function(){};f.fbq.loaded=!0;}(window);',
};

// Zen mode category domains
const ZEN_CATEGORIES = {
  social: new Set([
    'twitter.com','x.com','instagram.com','facebook.com','tiktok.com',
    'weibo.com','douyin.com','threads.net','mastodon.social','bluesky.app',
    'reddit.com','discord.com','snapchat.com','linkedin.com','pinterest.com',
  ]),
  entertainment: new Set([
    'youtube.com','bilibili.com','netflix.com','twitch.tv','hulu.com',
    'disneyplus.com','primevideo.com','9gag.com','tumblr.com',
    'buzzfeed.com','dailymotion.com','vimeo.com',
  ]),
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function hostOf(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch { return ''; }
}

function isBlocked(url) {
  const h = hostOf(url);
  if (!h) return false;
  for (const p of BLOCKED) { if (h.includes(p)) return true; }
  return false;
}

function isThreat(url) {
  const h = hostOf(url);
  return THREAT_SET.has(h);
}

function zenCategory(url) {
  if (!CONFIG.zen_active) return null;
  const h = hostOf(url);
  for (const cat of CONFIG.zen_categories) {
    const set = ZEN_CATEGORIES[cat];
    if (set && (set.has(h) || [...set].some(d => h.endsWith(`.${d}`)))) return cat;
  }
  return null;
}

function stubFor(url) {
  const h = hostOf(url);
  for (const [pat, stub] of Object.entries(STUB_MAP)) {
    if (h.includes(pat)) return stub;
  }
  return null;
}

function stripParams(url) {
  try {
    const u = new URL(url);
    for (const key of [...u.searchParams.keys()]) {
      if (STRIP_PARAMS.has(key)) u.searchParams.delete(key);
    }
    return u.toString();
  } catch { return url; }
}

function upgradeHttps(url) {
  return url.startsWith('http://') ? url.replace('http://', 'https://') : url;
}

function cleanHeaders(req) {
  const headers = new Headers();
  headers.set('User-Agent', DIATOM_UA);
  headers.set('DNT', '1');
  headers.set('Sec-GPC', '1');
  // Preserve Accept / Accept-Language from original request
  const accept = req.headers.get('Accept');
  if (accept) headers.set('Accept', accept);
  return headers;
}

// ── Ghost Redirect ────────────────────────────────────────────────────────────

/**
 * Find semantically similar Museum entries for a failed URL.
 *
 * LEGAL NOTE (Safe Harbor):
 *   Ghost Redirect only surfaces content the USER personally froze
 *   on their own device. It never fetches, mirrors, or distributes
 *   third-party content. It is legally equivalent to macOS Spotlight
 *   searching the user's own local files.
 *
 *   - No content leaves the device.
 *   - No P2P sharing of frozen pages between users.
 *   - E-WBN bundles are user-initiated, device-local, and encrypted.
 *
 * Uses simple overlap of URL tokens against tfidf_tags.
 */
function ghostRedirect(failedUrl) {
  if (!MUSEUM_INDEX.length) return null;

  // Tokenise the failed URL path
  let parsedHost = '';
  let parsedPath = '';
  try {
    const u = new URL(failedUrl);
    parsedHost = u.hostname;
    parsedPath = u.pathname;
  } catch { return null; }

  const tokens = new Set(
    (parsedPath + ' ' + parsedHost)
      .toLowerCase()
      .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 2),
  );

  const now = Date.now() / 1000;  // unix seconds

  const scored = MUSEUM_INDEX.map(entry => {
    const tags  = Array.isArray(entry.tfidf_tags)
      ? entry.tfidf_tags
      : JSON.parse(entry.tfidf_tags ?? '[]');
    const score = tags.filter(t => tokens.has(t.toLowerCase())).length;
    // Age of the frozen content in days
    const ageDays = entry.frozen_at ? Math.floor((now - entry.frozen_at) / 86400) : 0;
    return { ...entry, score, ageDays };
  }).filter(e => e.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

  if (!scored.length) return null;

  return buildGhostPage(failedUrl, scored);
}

function buildGhostPage(failedUrl, matches) {
  const items = matches.map(m => {
    // Staleness warning: content frozen > 30 days ago gets a flag
    const staleWarning = m.ageDays > 30
      ? `<span style="color:#d97706;font-size:.72rem;margin-left:.4rem;" title="This archive is over 30 days old">⚠ Archived ${m.ageDays}d ago</span>`
      : (m.ageDays > 0 ? `<span style="color:#64748b;font-size:.72rem;margin-left:.4rem;">${m.ageDays}d ago</span>` : '');

    return `
    <li>
      <a href="diatom://museum/${m.id}" style="color:#60a5fa;text-decoration:none;">
        ${escHtml(m.title || m.url)}
      </a>${staleWarning}
      <span style="color:#334155;font-size:.72rem;display:block;margin-top:.15rem;">
        ${escHtml(m.url.slice(0, 80))}
      </span>
    </li>
  `}).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Content Not Yet Archived</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0a0a10; color: #94a3b8;
      font-family: 'Inter', system-ui, sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 2rem;
    }
    .card { max-width: 560px; width: 100%; }
    h1 {
      font-family: 'Lora', Georgia, serif;
      font-size: 1.4rem; font-weight: 500;
      color: #e2e8f0; margin-bottom: .75rem; line-height: 1.4;
    }
    p { font-size: .85rem; line-height: 1.6; margin-bottom: 1.25rem; }
    .url { color: #475569; font-size: .75rem; word-break: break-all;
           background: rgba(255,255,255,.04); padding: .4rem .6rem;
           border-radius: .3rem; margin-bottom: 1.5rem; }
    h2 { font-size: .7rem; letter-spacing: .1em; text-transform: uppercase;
         color: #334155; margin-bottom: .75rem; }
    ul { list-style: none; }
    ul li { padding: .6rem 0; border-bottom: 1px solid rgba(255,255,255,.05); }
    ul li:last-child { border: none; }
    .stale-note { color:#64748b; font-size:.75rem; margin-top:1rem; font-style:italic; }
  </style>
</head>
<body>
  <div class="card">
    <h1>This Path Has Not Been Archived</h1>
    <p>You navigated to an unarchived page while offline. Here is semantically related content from your <strong>local Museum</strong>.</p>
    <div class="url">${escHtml(failedUrl)}</div>
    <h2>Approximate matches in your Museum</h2>
    <ul>${items}</ul>
    <p class="stale-note">⚠ Flagged archives are over 30 days old. Content may differ from the current live page — treat the online version as authoritative.</p>
  </div>
</body>
</html>`;
}

// ── DOM Crusher injection ─────────────────────────────────────────────────────

/**
 * Inject a <style> tag with crusher rules into an HTML response.
 * This fires before the browser parses the DOM, so elements never paint.
 */
function injectCrusherStyles(html, domain) {
  const selectors = CRUSHER_RULES.get(domain) ?? [];
  if (!selectors.length) return html;

  const css = selectors
    .map(s => `${s}{display:none!important}`)
    .join('\n');

  const injected = `<style id="diatom-crusher">\n${css}\n</style>`;
  // Inject right after <head> or before </head>
  if (html.includes('<head>')) {
    return html.replace('<head>', `<head>${injected}`);
  }
  if (html.includes('</head>')) {
    return html.replace('</head>', `${injected}</head>`);
  }
  return injected + html;
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))),
    ).then(() => self.clients.claim()),
  );
});

// ── Fetch handler ─────────────────────────────────────────────────────────────

self.addEventListener('fetch', e => {
  const req  = e.request;
  const url  = req.url;
  const mode = req.mode;  // 'navigate' | 'no-cors' | 'cors' | 'same-origin'

  // 1. Shell assets: cache-first
  if (SHELL.some(s => url.endsWith(s))) {
    e.respondWith(caches.match(req).then(r => r ?? fetch(req)));
    return;
  }

  // 2. Threat intercept
  if (isThreat(url)) {
    devnetBC.postMessage({ type:'NET_ENTRY', entry:{ id:++_reqSeq, url, method:req.method, status:-1, durationMs:0, blockedBy:'threat:local_list', ts:Date.now() }});
    e.respondWith(threatInterstitial(url));
    return;
  }

  // 3. Ad/tracker block
  if (CONFIG.adblock && isBlocked(url)) {
    devnetBC.postMessage({ type:'NET_ENTRY', entry:{ id:++_reqSeq, url, method:req.method, status:-1, durationMs:0, blockedBy:'adblock:aho-corasick', ts:Date.now() }});
    const stub = stubFor(url);
    if (stub) {
      e.respondWith(new Response(stub, { headers: { 'Content-Type': 'application/javascript; charset=utf-8' } }));
    } else {
      e.respondWith(new Response('', { status: 204 }));
    }
    return;
  }

  // 4. Zen mode: block navigation to social/entertainment
  if (mode === 'navigate') {
    const cat = zenCategory(url);
    if (cat) {
      e.respondWith(zenInterstitialResponse(url, cat));
      return;
    }
  }

  // 5. Offline navigation: Ghost Redirect
  if (mode === 'navigate') {
    e.respondWith(handleNavigate(req, url));
    return;
  }

  // 6. Default: clean fetch with /devnet timing
  const clean = upgradeHttps(stripParams(url));
  const cleaned = new Request(clean, {
    method:  req.method,
    headers: CONFIG.ua_uniformity ? cleanHeaders(req) : req.headers,
    body:    req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
    mode:    req.mode,
    credentials: 'omit',
    redirect: 'follow',
  });

  const reqId = ++_reqSeq;
  const t0    = Date.now();
  devnetBC.postMessage({ type:'NET_ENTRY', entry:{ id:reqId, url:clean, method:req.method, status:0, durationMs:0, blockedBy:null, ts:t0 }});

  e.respondWith(
    fetch(cleaned).then(resp => {
      devnetBC.postMessage({ type:'NET_ENTRY', entry:{ id:reqId, url:clean, method:req.method, status:resp.status, durationMs:Date.now()-t0, blockedBy:null, ts:t0 }});
      return resp;
    }).catch(() => caches.match(req)),
  );
});

// ── Navigate handler ──────────────────────────────────────────────────────────

async function handleNavigate(req, url) {
  // Try network first
  try {
    const netResp = await fetch(new Request(upgradeHttps(stripParams(url)), {
      headers: CONFIG.ua_uniformity ? cleanHeaders(req) : req.headers,
      credentials: 'omit',
    }));

    if (netResp.ok) {
      const contentType = netResp.headers.get('Content-Type') ?? '';
      if (contentType.includes('text/html')) {
        // Inject DOM crusher styles if rules exist for this domain
        const domain = hostOf(url);
        const rules  = CRUSHER_RULES.get(domain);
        if (rules?.length) {
          const html    = await netResp.text();
          const patched = injectCrusherStyles(html, domain);
          return new Response(patched, {
            status:  netResp.status,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          });
        }
      }
      return netResp;
    }
  } catch {
    // Network failed — try Ghost Redirect
  }

  // Try cache
  const cached = await caches.match(req);
  if (cached) return cached;

  // Ghost Redirect: semantic fallback from Museum index
  const ghost = ghostRedirect(url);
  if (ghost) {
    return new Response(ghost, {
      status:  200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // Final fallback: offline page
  return offlinePage(url);
}

// ── Static response builders ──────────────────────────────────────────────────

function zenInterstitialResponse(url, category) {
  // The JS Zen module handles the full interstitial UI.
  // The SW simply returns a minimal page that triggers the JS module.
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Zen</title>
<script>
  // Signal the Zen module that a blocked navigation was attempted
  window.__DIATOM_ZEN_BLOCK__ = { url: ${JSON.stringify(url)}, category: ${JSON.stringify(category)} };
</script>
</head><body>
<script type="module" src="/main.js"></script>
</body></html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function threatInterstitial(url) {
  const domain = hostOf(url);
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Warning</title>
<style>
  body{background:#0a0a10;color:#f87171;font-family:'Inter',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}
  .card{max-width:460px;}
  h1{font-size:1.3rem;margin-bottom:.75rem;}
  p{font-size:.85rem;color:#94a3b8;line-height:1.6;margin-bottom:1rem;}
  code{background:rgba(239,68,68,.1);padding:.2rem .4rem;border-radius:.25rem;}
  a{color:#60a5fa;}
</style>
</head>
<body>
<div class="card">
  <h1>⚠ Threat Intelligence Block</h1>
  <p>Independent threat intelligence has flagged <code>${escHtml(domain)}</code> as a malicious domain.</p>
  <p>If you believe this is a false positive, you can allowlist this domain in Diatom's trust settings.</p>
  <p><a href="javascript:history.back()">← Go back</a></p>
</div>
</body></html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function offlinePage(failedUrl) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Offline</title>
<style>
  body{background:#0a0a10;color:#475569;font-family:'Lora',Georgia,serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}
  p{font-size:1rem;line-height:1.7;max-width:400px;}
  span{color:#334155;}
</style>
</head>
<body>
<p>
  This content has not been archived. Connect to the internet and use Freeze to save it.<br>
  <span style="font-size:.8rem;font-family:'Inter',system-ui;margin-top:.75rem;display:block;">${escHtml(failedUrl.slice(0, 80))}</span>
</p>
</body></html>`;
  return new Response(html, {
    status: 503,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function escHtml(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
