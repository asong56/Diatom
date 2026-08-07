
'use strict';

const CACHE = (typeof __DIATOM_VERSION__ !== 'undefined')
  ? 'diatom-' + __DIATOM_VERSION__
  : 'diatom-dev-' + Math.floor(Date.now() / 86400000);
const SHELL   = ['/', '/index.html', '/diatom.css', '/main.js', '/sw.js', '/manifest.json'];

let CONFIG = {
  adblock:         true,
  ua_uniformity:   true,
  csp_injection:   true,
  degrade_images:  false,
  image_quality:   0.4,
  image_scale:     0.5,
};

let MUSEUM_INDEX = [];

const IDB_NAME        = 'diatom-sw';
const IDB_VERSION     = 1;
const IDB_STORE       = 'kv';
const IDB_KEY_MUSEUM  = 'museum_index';
const IDB_KEY_CONFIG  = 'sw_config';    // { config: CONFIG, ua: DIATOM_UA }
const IDB_KEY_THREATS = 'threat_set';   // string[]
const IDB_KEY_CRUSHER = 'crusher_rules'; // [domain, selectors[]][]

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = e => { e.target.result.createObjectStore(IDB_STORE); };
    req.onsuccess  = e => resolve(e.target.result);
    req.onerror    = e => reject(e.target.error);
  });
}

async function idbGet(key) {
  try {
    const db = await idbOpen();
    return await new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(key);
      req.onsuccess = e => resolve(e.target.result ?? null);
      req.onerror   = e => reject(e.target.error);
    });
  } catch { return null; }
}

async function idbSet(key, value) {
  try {
    const db = await idbOpen();
    await new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readwrite');
      const req = tx.objectStore(IDB_STORE).put(value, key);
      req.onsuccess = () => resolve(true);
      req.onerror   = e  => reject(e.target.error);
      tx.onerror    = e  => reject(e.target.error);
      tx.onabort    = () => reject(new DOMException('Transaction aborted', 'AbortError'));
    });
    return true;
  } catch (err) {
    const isQuota = err?.name === 'QuotaExceededError' ||
                    err?.name === 'NS_ERROR_DOM_INDEXEDDB_QUOTA_ERR';
    if (isQuota && key === IDB_KEY_MUSEUM && Array.isArray(value) && value.length > 50) {
      console.warn('[diatom-sw] Quota exceeded — trimming Museum index to 50 entries');
      const trimmed = [...value].sort((a,b) => (b.frozen_at??0)-(a.frozen_at??0)).slice(0,50);
      try {
        const db2 = await idbOpen();
        await new Promise((res, rej) => {
          const tx2 = db2.transaction(IDB_STORE, 'readwrite');
          const r2  = tx2.objectStore(IDB_STORE).put(trimmed, key);
          r2.onsuccess = () => res(true);
          r2.onerror   = e  => rej(e.target.error);
        });
        return true;
      } catch { /* quota retry also failed — fall through to warn + false */ }
    }
    console.warn('[diatom-sw] idbSet failed', { key, errorName: err?.name, message: err?.message });
    return false;
  }
}

async function restoreAllState() {
  const [storedConfig, storedThreats, storedCrusher, storedMuseum] = await Promise.all([
    idbGet(IDB_KEY_CONFIG),
    idbGet(IDB_KEY_THREATS),
    idbGet(IDB_KEY_CRUSHER),
    idbGet(IDB_KEY_MUSEUM),
  ]);

  if (storedConfig && typeof storedConfig === 'object') {
    if (storedConfig.config) Object.assign(CONFIG, storedConfig.config);
    if (typeof storedConfig.ua === 'string') DIATOM_UA = storedConfig.ua;
  }
  if (Array.isArray(storedThreats) && storedThreats.length > 0) {
    THREAT_SET = new Set(storedThreats);
  }
  if (Array.isArray(storedCrusher) && storedCrusher.length > 0) {
    CRUSHER_RULES = new Map(storedCrusher);
  }
  if (Array.isArray(storedMuseum) && storedMuseum.length > 0) {
    MUSEUM_INDEX = storedMuseum;
  }
}

let THREAT_SET   = new Set();
let CRUSHER_RULES = new Map();
let DIATOM_UA    = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/619.1.26 (KHTML, like Gecko) Version/18.0 Safari/619.1.26';

const bc        = new BroadcastChannel('diatom:sw');
const devnetBC  = new BroadcastChannel('diatom:devnet');
let   _reqSeq   = 0;

bc.addEventListener('message', e => {
  const msg = e.data;
  if (!msg?.type) return;
  switch (msg.type) {
    case 'CONFIG':
      Object.assign(CONFIG, msg.config);
      if (msg.config?.synthesised_ua) DIATOM_UA = msg.config.synthesised_ua;
      // Persist CONFIG + UA together so SW restart recovers both atomically.
      idbSet(IDB_KEY_CONFIG, { config: CONFIG, ua: DIATOM_UA }).catch(() => {});
      break;
    case 'ZEN':
      // ZEN is a sub-key of CONFIG — persist the full CONFIG snapshot.
      idbSet(IDB_KEY_CONFIG, { config: CONFIG, ua: DIATOM_UA }).catch(() => {});
      break;
    case 'MUSEUM_INDEX':
      MUSEUM_INDEX = msg.index ?? [];
      idbSet(IDB_KEY_MUSEUM, MUSEUM_INDEX).catch(() => {});
      break;
    case 'THREAT_LIST':
      THREAT_SET = new Set(msg.list ?? []);
      // Store as plain array — Set is not IDB-serialisable.
      idbSet(IDB_KEY_THREATS, msg.list ?? []).catch(() => {});
      break;
    case 'CRUSHER_RULES':
      CRUSHER_RULES.set(msg.domain, msg.selectors ?? []);
      // Persist the full Map as entries so restoreAllState() can reconstruct it.
      idbSet(IDB_KEY_CRUSHER, [...CRUSHER_RULES.entries()]).catch(() => {});
      break;
  }
});

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

// Heatmap/session-replay script blocking is handled by HEATMAP_SCRIPT_SRC_RE
// in stripTrackingPixels() above. No runtime Set needed here.

// ── Local fingerprint stripper ────────────────────────────────────────────────
// Rule-based only. Adding a param here is the ONLY mechanism for stripping;
// AI never infers which params to remove (risk: accidental session ID deletion).
// Mirrors the PROTECTED_PARAMS / STRIP_PARAMS contract in url_stripper.rs.
// Safe params that must NEVER appear here: sid, session, session_id, auth,
// token, access_token, id_token, refresh_token, code, state, oauth_token,
// csrf, csrf_token, _token, xsrf_token, api_key, apikey, nonce, key.
const STRIP_PARAMS = new Set([
  // Google / GA
  '_ga','_gac','_gl','gclid','gclsrc','dclid','gbraid','wbraid',
  'gad_source','utm_source','utm_medium','utm_campaign','utm_term',
  'utm_content','utm_id','utm_source_platform','utm_creative_format',
  'utm_marketing_tactic',
  // Meta / Facebook
  'fbclid','fb_action_ids','fb_action_types','fb_source','fb_ref','fbid',
  // Microsoft / Bing
  'msclkid',
  // Twitter / X
  'twclid',
  // TikTok
  'ttclid',
  // Snapchat
  'ScCid',
  // LinkedIn
  'li_fat_id','li_source',
  // Pinterest
  'epik',
  // HubSpot
  '_hsenc','_hsmi','hsa_acc','hsa_ad','hsa_cam','hsa_grp','hsa_kw',
  'hsa_la','hsa_mt','hsa_net','hsa_src','hsa_tgt','hsa_ver',
  // Mailchimp / Klaviyo / Vero / Iterable / SendGrid
  'mc_eid','mc_cid','_kx','vero_id','vero_conv','mkt_tok',
  'iterableEmailCampaignId','iterableTemplateId','iterableMessageId',
  'sg_uid','sg_mid',
  // Adobe / Marketo / Outbrain / Taboola
  's_kwcid','icid','obOrigUrl','tblci',
  // Amazon affiliate
  'tag','psc',
  // Generic click IDs
  'click_id','clickid','cid','ncid','ocid','yclid','wickedid',
  'irclickid','smid',
  // Referrer leakage
  'referrer','ref_src','ref_url','sref',
  // Instagram
  'igshid',
  // Misc
  'trk','otc',
]);

const STUB_MAP = {
  'google-analytics.com': 'window.ga=function(){};window.gtag=function(){};',
  'googletagmanager.com': 'window.dataLayer=window.dataLayer||[];',
  'hotjar.com':           '(function(h){h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)}})(window);',
  'connect.facebook.net': '!function(f){f.fbq=function(){};f.fbq.loaded=!0;}(window);',
};

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

function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); }
  catch { return ''; }
}

function isBlocked(url) {
  const h = hostOf(url);
  if (!h) return false;
  for (const p of BLOCKED) { if (h.includes(p)) return true; }
  // Heatmap/session-replay host check — mirrors HEATMAP_SCRIPT_SRC_RE (static list).
  if (HEATMAP_SCRIPT_SRC_RE.test(h)) return true;
  return false;
}

function isThreat(url) { return THREAT_SET.has(hostOf(url)); }


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
  const accept = req.headers.get('Accept');
  if (accept) headers.set('Accept', accept);
  return headers;
}

function escHtml(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Rule-based pixel removal — static regex lists only, never AI heuristics.
// Matches <img> where either width OR height is explicitly 0 or 1 (1×1 beacon).
const TRACKING_PIXEL_RE =
  /<img\b[^>]*\s(?:width=["']?[01]["']?|height=["']?[01]["']?)[^>]*>/gi;

const HIDDEN_IMG_RE =
  /<img\b[^>]*\bstyle=["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>/gi;

// Known third-party pixel/beacon hostnames — static allowlist, never inferred.
const THIRD_PARTY_PIXEL_HOST_RE =
  /\b(?:pixel\.facebook\.com|bat\.bing\.com|px\.ads\.linkedin\.com|t\.co\/i\/adsct|analytics\.twitter\.com|ct\.pinterest\.com|snap\.licdn\.com|mc\.yandex\.ru\/watch|vk\.com\/rtrg|dmp\.adform\.net|cm\.g\.doubleclick\.net|idsync\.rlcdn\.com|sync\.1rx\.io|matching\.sharethrough\.com|pixel\.rubiconproject\.com|i\.6sc\.co|bcp\.crwdcntrl\.net|ib\.adnxs\.com\/getuid)\b/i;

// Known heatmap/session-replay <script> hostnames (static list, no inference).
const HEATMAP_SCRIPT_SRC_RE =
  /\b(?:static\.hotjar\.com|script\.hotjar\.com|vars\.hotjar\.com|mouseflow\.com|cdn\.mouseflow\.com|rec\.smartlook\.com|manager\.smartlook\.com|recordings\.lucky-orange\.com|lo\.lt\.lucky-orange\.com|cdn\.crazyegg\.com|heapanalytics\.com|cdn\.heapanalytics\.com|y\.clarity\.ms|cdn\.contentsquare\.net|cdn\.reamaze\.com)\b/i;

function stripTrackingPixels(html) {
  // 1. 1×1 dimension beacons
  let out = html
    .replace(TRACKING_PIXEL_RE, '<!-- [diatom] 1x1 pixel removed -->')
    .replace(HIDDEN_IMG_RE,     '<!-- [diatom] hidden img removed -->');

  // 2. <img> whose src matches a known third-party pixel hostname
  out = out.replace(/<img\b[^>]*>/gi, tag =>
    THIRD_PARTY_PIXEL_HOST_RE.test(tag) ? '<!-- [diatom] third-party pixel removed -->' : tag,
  );

  // 3. <script> tags loading known heatmap/session-replay scripts
  out = out.replace(/<script\b[^>]*src=["'][^"']*["'][^>]*>(\s*<\/script>)?/gi, tag =>
    HEATMAP_SCRIPT_SRC_RE.test(tag) ? '<!-- [diatom] heatmap script removed -->' : tag,
  );

  return out;
}

const CONSENT_REJECT_SCRIPT =`<script>
(function diatomConsentReject(){
  'use strict';
  try {
    if (typeof __tcfapi === 'function') {
      __tcfapi('setUserDecision', 2, function(){}, { decision: 2 });
    }

    if (typeof OneTrust !== 'undefined' && OneTrust.RejectAll) OneTrust.RejectAll();
    if (typeof OptanonWrapper === 'function') {
      document.cookie = 'OptanonAlertBoxClosed=' + new Date().toISOString();
      document.cookie = 'OptanonConsent=isGpcEnabled=0&datestamp=' + encodeURIComponent(new Date().toUTCString()) + '&version=6.38.0&consentId=diatom&isIABGlobal=false&hosts=&landingPath=NotLandingPage&groups=C0001%3A1&AwaitingReconsent=false';
    }

    if (typeof Cookiebot !== 'undefined') {
      Cookiebot.decline();
    }
    document.cookie = 'CookieConsent={stamp:%27reject%27%2C+necessary:true%2C+preferences:false%2C+statistics:false%2C+marketing:false%2C+method:%27explicit%27%2C+ver:1}; max-age=31536000; SameSite=Lax';

    document.cookie = 'cookieyes-consent=consentid:diatom,consent:no,action:no,necessary:yes,functional:no,analytics:no,performance:no,advertisement:no; max-age=31536000; SameSite=Lax';

    const style = document.createElement('style');
    style.textContent = [
      '#onetrust-consent-sdk','#onetrust-banner-sdk',
      '#cookie-law-info-bar','.cookieconsent','.cookie-consent',
      '#CybotCookiebotDialog','#cookiebot','.cc-banner','.cc-window',
      '#qc-cmp2-container','.qc-cmp2-container',
      '[id*="cookie-banner"],[id*="cookieBanner"],[class*="cookie-banner"]',
      '[id*="consent-banner"],[class*="consent-banner"]',
      '#didomi-notice','.didomi-notice-banner',
      '#axeptio_overlay','.axeptio_overlay',
      '.osano-cm-window','#osano-cm-window',
      '#sp_message_container','.sp_message_container',
    ].map(s => s + '{display:none!important;visibility:hidden!important;opacity:0!important;}').join('\\n');
    (document.head || document.documentElement).appendChild(style);
})();
</script>`;

function injectConsentReject(html) {
  if (html.includes('<head>')) return html.replace('<head>', '<head>' + CONSENT_REJECT_SCRIPT);
  if (html.includes('<body')) return html.replace('<body', CONSENT_REJECT_SCRIPT + '<body');
  return CONSENT_REJECT_SCRIPT + html;
}

const CLIPBOARD_STRIP_SCRIPT =`<script>
(function diatomClipboardStrip(){
  'use strict';
  document.addEventListener('copy', function(e){
    try {
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed) return;
      const raw = sel.toString();
      const clean = raw.replace(/[\u200B-\u200F\u2060\u2063\uFEFF\u00AD]/g, '');
      if (clean === raw) return; // nothing to strip
      e.preventDefault();
      e.clipboardData.setData('text/plain', clean);
  }, true);
})();
</script>`;

function injectClipboardStrip(html) {
  if (html.includes('</body>')) return html.replace('</body>', CLIPBOARD_STRIP_SCRIPT + '</body>');
  return html + CLIPBOARD_STRIP_SCRIPT;
}

const SENSOR_SPOOF_SCRIPT =`<script>
(function diatomSensorSpoof(){
  'use strict';
  if (window.__DIATOM_SENSOR_SPOOF__) return;
  window.__DIATOM_SENSOR_SPOOF__ = true;

  if (navigator.getBattery) {
    const fakeBattery = {
      level: 1.0,
      charging: true,
      chargingTime: 0,
      dischargingTime: Infinity,
      addEventListener: function(){},
      removeEventListener: function(){},
    };
    Object.defineProperty(navigator, 'getBattery', {
      value: function() { return Promise.resolve(fakeBattery); },
      writable: false, configurable: false,
    });
  }

  window.addEventListener('devicemotion', function(e) {
    e.stopImmediatePropagation();
  }, true);

  window.addEventListener('deviceorientation', function(e) {
    e.stopImmediatePropagation();
  }, true);

  if (typeof AmbientLightSensor !== 'undefined') {
    window.AmbientLightSensor = class FakeALS {
      get illuminance() { return 500; }
      start() {}
      stop()  {}
      addEventListener()    {}
      removeEventListener() {}
    };
  }
})();
</script>`;

function injectSensorSpoof(html) {
  if (html.includes('<head>')) return html.replace('<head>', '<head>' + SENSOR_SPOOF_SCRIPT);
  return SENSOR_SPOOF_SCRIPT + html;
}

function injectCrusherStyles(html, domain) {
  const selectors = CRUSHER_RULES.get(domain) ?? [];
  if (!selectors.length) return html;
  const css      = selectors.map(s =>`${s}{display:none!important}`).join('\n');
  const injected =`<style id="diatom-crusher">\n${css}\n</style>`;
  if (html.includes('<head>')) return html.replace('<head>',`<head>${injected}`);
  if (html.includes('</head>')) return html.replace('</head>',`${injected}</head>`);
  return injected + html;
}

function findArchiveMatches(failedUrl) {
  if (!MUSEUM_INDEX.length) return [];

  let parsedHost = '', parsedPath = '';
  try {
    const u   = new URL(failedUrl);
    parsedHost = u.hostname;
    parsedPath = u.pathname;
  } catch { return []; }

  const tokens = new Set(
    (parsedPath + ' ' + parsedHost)
      .toLowerCase()
      .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 2),
  );

  return MUSEUM_INDEX
    .map(entry => {
      const tags  = Array.isArray(entry.tfidf_tags)
        ? entry.tfidf_tags : JSON.parse(entry.tfidf_tags ?? '[]');
      const score = tags.filter(t => tokens.has(t.toLowerCase())).length;
      return { ...entry, score };
    })
    .filter(e => e.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
}

// Static suggestion — never auto-navigates.  The user reads the list and decides.
// Displayed inline in the offline page, not as a floating overlay.
function buildArchiveSuggestionBanner(failedUrl) {
  const matches = findArchiveMatches(failedUrl);
  if (!matches.length) return '';

  const n     = matches.length;
  const items = matches.map(m => {
    const ageDays = m.frozen_at
      ? Math.floor((Date.now() / 1000 - m.frozen_at) / 86400) : 0;
    const stale   = ageDays > 30;
    const ageStr  = ageDays > 0 ? ` · ${ageDays}d ago` : '';
    const staleWarn = stale
      ? ` <span style="color:#f59e0b;font-size:.7rem;">(archived ${ageDays}d ago)</span>`
      : '';
    return `<li style="margin:.3rem 0;">
      <a href="diatom://museum/${escHtml(m.id)}"
         style="color:#60a5fa;text-decoration:none;font-size:.82rem;">
        ${escHtml(m.title || m.url)}
      </a>${staleWarn}
      <span style="color:#475569;font-size:.7rem;">${ageStr}</span>
    </li>`;
  }).join('');

  // Inline section — no floating overlay, no auto-redirect.
  return `<section style="
    margin-top:1.4rem;
    background:#1e293b;border:1px solid rgba(96,165,250,.18);
    border-radius:.4rem;padding:.9rem 1rem;max-width:420px;text-align:left;
    font-size:.8rem;color:#94a3b8;line-height:1.6;
  ">
    <p style="margin:0 0 .5rem;color:#60a5fa;font-weight:500;">
      📚 In Museum: ${n} archived page${n > 1 ? 's' : ''}
    </p>
    <ul style="list-style:none;margin:0;padding:0;">${items}</ul>
  </section>`;
}

async function rewriteHtml(response, url) {
  let html = await response.text();

  html = stripTrackingPixels(html);

  html = injectSensorSpoof(html);

  html = injectConsentReject(html);

  html = injectClipboardStrip(html);

  const domain = hostOf(url);
  html = injectCrusherStyles(html, domain);

  return new Response(html, {
    status:  response.status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', e => {
  // Phase 1: evict stale caches then claim — fast path, no IDB.
  // clients.claim() is called here so pages do NOT wait on IDB reads.
  const claimPhase = caches.keys()
    .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim());

  // Phase 2: restore all persisted state from IDB in parallel.
  // waitUntil keeps the SW process alive until restore finishes, but claim has
  // already resolved so page loads are not delayed.  Requests arriving in the
  // brief window before restore completes use the hardcoded defaults — acceptable
  // because the client will immediately re-send CONFIG/THREAT_LIST etc. via
  // BroadcastChannel on startup, which overwrites the defaults.
  e.waitUntil(claimPhase.then(() => restoreAllState()));
});

self.addEventListener('fetch', e => {
  const req  = e.request;
  const url  = req.url;
  const mode = req.mode;

  if (SHELL.some(s => url.endsWith(s))) {
    e.respondWith(caches.match(req).then(r => r ?? fetch(req)));
    return;
  }

  if (isThreat(url)) {
    devnetBC.postMessage({ type:'NET_ENTRY', entry:{ id:++_reqSeq, url, method:req.method, status:-1, durationMs:0, blockedBy:'threat:local_list', ts:Date.now() }});
    e.respondWith(threatInterstitial(url));
    return;
  }

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

  if (mode === 'navigate') {
  }

  if (mode === 'navigate') {
    e.respondWith(handleNavigate(req, url));
    return;
  }

  const clean   = upgradeHttps(stripParams(url));
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

async function handleNavigate(req, url) {
  try {
    const netResp = await fetch(new Request(upgradeHttps(stripParams(url)), {
      headers: CONFIG.ua_uniformity ? cleanHeaders(req) : req.headers,
      credentials: 'omit',
    }));

    if (netResp.ok) {
      const ct = netResp.headers.get('Content-Type') ?? '';
      if (ct.includes('text/html')) {
        return await rewriteHtml(netResp, url);
      }
      return netResp;
    }
  } catch { /* network failure — fall through to cache/offline */ }

  const cached = await caches.match(req);
  if (cached) return cached;

  return offlinePage(url);
}


function threatInterstitial(url) {
  const domain = hostOf(url);
  const html =`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Warning</title>
<style>
  body{background:#0a0a10;color:#f87171;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}
  .card{max-width:460px;}h1{font-size:1.3rem;margin-bottom:.75rem;}
  p{font-size:.85rem;color:#94a3b8;line-height:1.6;margin-bottom:1rem;}
  code{background:rgba(239,68,68,.1);padding:.2rem .4rem;border-radius:.25rem;}a{color:#60a5fa;}
</style></head>
<body><div class="card">
  <h1>⚠ Threat Intelligence Block</h1>
  <p>Independent threat intelligence flagged <code>${escHtml(domain)}</code>.</p>
  <p><a href="javascript:history.back()">← Go back</a></p>
</div></body></html>`;
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function offlinePage(failedUrl) {
  const archiveSuggestion = buildArchiveSuggestionBanner(failedUrl);

  // "静态建议" — we display what we found in Museum; the user chooses what to open.
  // Diatom never auto-redirects.  The suggestion section is absent when Museum is empty.
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Offline</title>
<style>
  body{background:#0a0a10;color:#475569;
       font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
       display:flex;flex-direction:column;align-items:center;
       justify-content:center;min-height:100vh;
       text-align:center;padding:2rem;gap:.5rem;}
  p{font-size:1rem;line-height:1.7;max-width:420px;margin:0;}
  .url{color:#334155;font-size:.78rem;display:block;margin-top:.4rem;word-break:break-all;}
</style></head>
<body>
<p>
  This page is not available offline.
  <span class="url">${escHtml(failedUrl.slice(0, 120))}</span>
</p>
${archiveSuggestion}
</body></html>`;
  return new Response(html, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
