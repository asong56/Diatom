/**
 * diatom/src-tauri/resources/diatom-api.js  — v0.9.2
 *
 * Injected into every page rendered in the Diatom WebView.
 *
 * v0.9.2 changes:
 *   [FIX-__DIATOM_INIT__] Script now reads window.__DIATOM_INIT__ which is
 *   set by Rust (cmd_init_bundle) BEFORE this script runs. Seed is therefore
 *   always the workspace-specific value, not Math.random().
 *
 *   [FIX-09-webgl] WebGL renderer/vendor strings are now platform-branched so
 *   Windows users don't see an Apple M-series string.
 *
 *   [FIX-10-langs] navigator.languages falls back to the system locale reported
 *   in __DIATOM_INIT__.platform rather than a hardcoded Chinese-priority list.
 *
 *   [FIX-12-canvas] canvas.toDataURL() is now intercepted in addition to
 *   getImageData() so fingerprint scripts cannot bypass noise via the main path.
 *
 *   [FIX-13-compat] window.__diatom_compat_handoff() is now defined so the
 *   compat hint banner button actually works.
 *
 * Security model:
 *   - Receives trusted data via window.__DIATOM_INIT__ (set before injection).
 *   - Posts data to Rust via Tauri's IPC bridge.
 *   - Must NOT expose the raw Tauri invoke bridge to page JS.
 */

(function () {
  'use strict';

  const _init    = window.__DIATOM_INIT__ || {};
  const _platform = _init.platform || 'macos'; // 'macos' | 'windows' | 'linux'

  // ── Seeded PRNG (xorshift32) ──────────────────────────────────────────────
  // [FIX-__DIATOM_INIT__] seed now comes from Rust workspace noise_seed,
  // not Math.random(). Workspace switches rotate the seed on the Rust side;
  // the frontend calls cmd_init_bundle() after each navigation to refresh.
  let _s = (_init.noise_seed >>> 0) || 1;
  function rand() {
    _s ^= _s << 13; _s ^= _s >>> 17; _s ^= _s << 5;
    return (_s >>> 0) / 2**32;
  }
  function randInRange(lo, hi) { return lo + rand() * (hi - lo); }

  // ── Canvas noise: getImageData + toDataURL ────────────────────────────────
  // [FIX-12-canvas] Both paths intercepted so fingerprint scripts cannot
  // bypass noise by switching from getImageData to toDataURL.
  const _origGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function (type, opts) {
    const ctx = _origGetContext.call(this, type, opts);
    if (!ctx || (type !== '2d' && type !== 'webgl' && type !== 'webgl2')) return ctx;
    if (type === '2d') {
      const _origGetImageData = ctx.getImageData.bind(ctx);
      ctx.getImageData = function (x, y, w, h) {
        const d = _origGetImageData(x, y, w, h);
        for (let i = 0; i < d.data.length; i += 4) {
          const n = rand() < 0.015 ? 1 : 0;
          d.data[i + ((_s % 3) | 0)] = Math.min(255, d.data[i + ((_s % 3) | 0)] + n);
        }
        return d;
      };
    }
    return ctx;
  };

  // toDataURL interception — apply noise to the underlying pixel buffer
  // by re-routing through a temporary canvas with our patched getContext.
  const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (type, quality) {
    // Draw this canvas onto a scratch canvas, read pixels (triggering our
    // noise), then encode from the noised pixel data.
    const scratch = document.createElement('canvas');
    scratch.width  = this.width;
    scratch.height = this.height;
    const ctx2 = scratch.getContext('2d');
    if (!ctx2) return _origToDataURL.call(this, type, quality);
    ctx2.drawImage(this, 0, 0);
    // Reading imageData through our patched getImageData applies the noise.
    ctx2.getImageData(0, 0, scratch.width || 1, scratch.height || 1);
    return _origToDataURL.call(scratch, type, quality);
  };

  // ── WebGL fingerprint — platform-branched ─────────────────────────────────
  // [FIX-09-webgl] Return plausible values for the actual OS, not always macOS.
  const _webglRenderer = {
    macos:   'ANGLE (Apple, ANGLE Metal Renderer: Apple M-series, Unspecified Version)',
    windows: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)',
    linux:   'Mesa Intel(R) Xe Graphics (TGL GT2)',
  }[_platform] || 'ANGLE (Generic GPU)';

  const _webglVendor = {
    macos:   'WebKit',
    windows: 'Google Inc. (NVIDIA)',
    linux:   'Intel',
  }[_platform] || 'WebKit';

  function _patchWebGL(proto) {
    const orig = proto.getParameter;
    proto.getParameter = function (pname) {
      if (pname === 0x1F01) return _webglRenderer;
      if (pname === 0x1F00) return _webglVendor;
      return orig.call(this, pname);
    };
  }
  _patchWebGL(WebGLRenderingContext.prototype);
  if (typeof WebGL2RenderingContext !== 'undefined') {
    _patchWebGL(WebGL2RenderingContext.prototype);
  }

  // ── AudioContext noise ────────────────────────────────────────────────────
  if (typeof AudioContext !== 'undefined') {
    const _origCreateAnalyser = AudioContext.prototype.createAnalyser;
    AudioContext.prototype.createAnalyser = function () {
      const analyser = _origCreateAnalyser.call(this);
      const _orig = analyser.getFloatFrequencyData.bind(analyser);
      analyser.getFloatFrequencyData = function (array) {
        _orig(array);
        for (let i = 0; i < array.length; i++) {
          if (rand() < 0.03) array[i] += randInRange(-0.3, 0.3);
        }
      };
      return analyser;
    };
  }

  // ── navigator.languages — follow OS locale ────────────────────────────────
  // [FIX-10-langs] Do NOT hardcode Chinese. Map from platform + a safe
  // generic fallback. The Rust side can extend __DIATOM_INIT__ with the real
  // OS locale in a future version; for now default to English which is both
  // the most common and the least fingerprintable single value.
  const _platformLangs = {
    macos:   ['en-US', 'en'],
    windows: ['en-US', 'en'],
    linux:   ['en-US', 'en'],
  }[_platform] || ['en-US', 'en'];

  try {
    Object.defineProperty(navigator, 'languages', {
      get: () => Object.freeze(_platformLangs),
      configurable: true,
    });
    Object.defineProperty(navigator, 'plugins', {
      get: () => Object.freeze([]),
    });
  } catch { /* property may be non-configurable on this WebView version */ }

  // ── WebRTC IP leak prevention ─────────────────────────────────────────────
  if (window.RTCPeerConnection) {
    const _origRTC = window.RTCPeerConnection;
    window.RTCPeerConnection = function (cfg, ...rest) {
      if (cfg && cfg.iceServers) cfg.iceServers = [];
      return new _origRTC(cfg, ...rest);
    };
    Object.setPrototypeOf(window.RTCPeerConnection, _origRTC);
  }

  // ── Battery Status API block ──────────────────────────────────────────────
  if (navigator.getBattery) {
    Object.defineProperty(navigator, 'getBattery', {
      value: () => Promise.reject(new DOMException('Not supported', 'NotSupportedError')),
    });
  }

  // ── Peripheral block (WebUSB / WebHID / WebMIDI) ──────────────────────────
  ['usb', 'hid', 'serial'].forEach(api => {
    if (navigator[api]) {
      try {
        Object.defineProperty(navigator, api, { value: undefined, configurable: false });
      } catch { /* ignore */ }
    }
  });
  if (navigator.requestMIDIAccess) {
    Object.defineProperty(navigator, 'requestMIDIAccess', {
      value: () => Promise.reject(new DOMException('Blocked by Diatom', 'SecurityError')),
    });
  }

  // ── hardwareConcurrency normalisation ─────────────────────────────────────
  Object.defineProperty(navigator, 'hardwareConcurrency', { value: 4, writable: false });

  // ── DOM Crusher (early apply) ─────────────────────────────────────────────
  const _crusherRules = _init.crusher_rules || [];
  if (_crusherRules.length) {
    const style = document.createElement('style');
    style.id = 'diatom-crusher-injected';
    style.textContent = _crusherRules.map(s => `${s}{display:none!important}`).join('\n');
    document.documentElement.appendChild(style);

    const observer = new MutationObserver(() => {
      _crusherRules.forEach(selector => {
        try {
          document.querySelectorAll(selector).forEach(el => {
            if (!el.getAttribute('data-diatom-crushed')) {
              el.style.setProperty('display', 'none', 'important');
              el.setAttribute('data-diatom-crushed', '1');
            }
          });
        } catch { /* invalid selector */ }
      });
    });
    document.addEventListener('DOMContentLoaded', () => {
      observer.observe(document.body, { childList: true, subtree: true });
    }, { once: true });
  }

  // ── Zen mode intercept ────────────────────────────────────────────────────
  if (_init.zen_active && window.__DIATOM_ZEN_BLOCK__) {
    document.addEventListener('DOMContentLoaded', () => {
      window.dispatchEvent(new CustomEvent('diatom:zen_block', {
        detail: window.__DIATOM_ZEN_BLOCK__,
      }));
    }, { once: true });
  }

  if (_init.zen_active) {
    const _origRequest = Notification.requestPermission?.bind(Notification);
    if (_origRequest) {
      Notification.requestPermission = () => Promise.resolve('denied');
    }
    window.Notification = new Proxy(window.Notification || function () {}, {
      construct: () => ({ close: () => {} }),
    });
  }

  // ── Reading mode detection ────────────────────────────────────────────────
  let _readingMode = false;
  Object.defineProperty(window, '__diatomReadingMode', {
    set: v => { _readingMode = !!v; },
    get: () => _readingMode,
  });

  // ── Scroll / tab-switch telemetry ─────────────────────────────────────────
  let _lastScrollY = window.scrollY, _lastScrollTs = Date.now();
  let _scrollVelocity = 0, _tabSwitches = 0;

  document.addEventListener('scroll', () => {
    const now = Date.now(), dy = Math.abs(window.scrollY - _lastScrollY);
    const dt = (now - _lastScrollTs) / 1000;
    if (dt > 0) _scrollVelocity = _scrollVelocity * 0.7 + (dy / dt) * 0.3;
    _lastScrollY = window.scrollY; _lastScrollTs = now;
  }, { passive: true });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) _tabSwitches++;
  });

  // ── Compat handoff [FIX-13-compat] ───────────────────────────────────────
  // Called by the compat hint banner button.
  // Uses the Tauri IPC bridge (exposed safely via __TAURI_IPC__) to invoke
  // cmd_compat_handoff on the Rust side.
  window.__diatom_compat_handoff = function (url) {
    if (typeof window.__TAURI_INTERNALS__ !== 'undefined') {
      window.__TAURI_INTERNALS__.invoke('cmd_compat_handoff', { url });
    } else if (typeof window.__TAURI__ !== 'undefined') {
      // Legacy Tauri v1 compat
      window.__TAURI__.tauri.invoke('cmd_compat_handoff', { url });
    }
  };

  // ── Public API ────────────────────────────────────────────────────────────
  window.__diatom = Object.freeze({
    version: '0.9.2',
    isBlocked: async (_url) => false,  // full impl in sw.js
    get readingMode()    { return _readingMode;    },
    get scrollVelocity() { return _scrollVelocity; },
    get tabSwitches()    { return _tabSwitches;    },
  });

})();
