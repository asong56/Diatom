use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Inject noise into Canvas API outputs (toDataURL, getImageData).
    pub canvas_noise: bool,
    /// Clamp AudioContext precision to prevent timing fingerprinting.
    pub audio_noise: bool,
    /// Normalise font metric APIs (measureText) to generic values.
    pub font_noise: bool,
    /// Return a hardened navigator.hardwareConcurrency value.
    pub hw_concurrency_spoof: Option<u32>,
    /// Suppress WebRTC local IP leak via STUN.
    pub webrtc_block: bool,
    /// Override timezone to UTC in JS APIs.
    pub timezone_spoof: bool,
    /// Block access to battery status API.
    pub battery_block: bool,
    /// Limit screen resolution to common bucket values.
    pub screen_normalize: bool,
    /// Block access to USB/WebUSB/WebHID/WebMIDI.
    pub peripheral_block: bool,
    /// Suppress SharedArrayBuffer (timing oracle for Spectre).
    pub sab_block: bool,

    /// the field was missing from the struct, causing a compile error.
    /// When true, forces CandleWasm backend regardless of Ollama availability.
    #[serde(default)]
    pub extreme_mode: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        PrivacyConfig {
            canvas_noise: true,
            audio_noise: true,
            font_noise: true,
            hw_concurrency_spoof: Some(4),
            webrtc_block: true,
            timezone_spoof: false, // opt-in — breaks some apps
            battery_block: true,
            screen_normalize: true,
            peripheral_block: true,
            sab_block: false, // Needed by some WASM apps
            extreme_mode: false,
        }
    }
}

impl PrivacyConfig {
    /// Generate the JS snippet that enforces this config on every page load.
    pub fn injection_script(&self) -> String {
        let mut lines = vec![
            "// Diatom privacy hardening layer".to_owned(),
            "(function() { 'use strict';".to_owned(),
        ];

        if self.canvas_noise {
            lines.push(
                r#"
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(...a) {
    const d = origGetImageData.apply(this, a);
    for (let i = 0; i < d.data.length; i += 4) {
      const n = rand() < 0.5 ? 1 : 0;
      d.data[i]   ^= n;
      d.data[i+1] ^= (rand() < 0.5 ? 1 : 0);
    }
    return d;
  };
"#
                .to_owned(),
            );
        }

        if self.webrtc_block {
            lines.push(
                r#"
  if (window.RTCPeerConnection) {
    const orig = window.RTCPeerConnection;
    window.RTCPeerConnection = function(cfg, ...rest) {
      if (cfg && cfg.iceServers) { cfg.iceServers = []; }
      return new orig(cfg, ...rest);
    };
    Object.setPrototypeOf(window.RTCPeerConnection, orig);
  }
"#
                .to_owned(),
            );
        }

        if self.battery_block {
            lines.push(
                r#"
  if (navigator.getBattery) {
    Object.defineProperty(navigator, 'getBattery', {
      value: () => Promise.reject(new DOMException('Not supported', 'NotSupportedError'))
    });
  }
"#
                .to_owned(),
            );
        }

        if self.peripheral_block {
            lines.push(r#"
  ['usb','hid','serial'].forEach(api => {
    if (navigator[api]) Object.defineProperty(navigator, api, { value: undefined, configurable: false });
  });
  if (navigator.requestMIDIAccess) {
    Object.defineProperty(navigator, 'requestMIDIAccess', {
      value: () => Promise.reject(new DOMException('Blocked by Diatom', 'SecurityError'))
    });
  }
"#.to_owned());
        }

        if let Some(cores) = self.hw_concurrency_spoof {
            lines.push(format!(
                r#"
  Object.defineProperty(navigator, 'hardwareConcurrency', {{ value: {}, writable: false }});
"#,
                cores
            ));
        }

        lines.push("})();".to_owned());
        lines.join("\n")
    }
}

impl PrivacyConfig {
    /// Generate the JS snippet that installs the `diatom.debugPrivacy()` console API.
    /// Injected alongside the main privacy hardening script.
    pub fn debug_privacy_script() -> String {
        r#"
(function installDiatomDebugPrivacy() {
  if (window.__diatomPrivacyLog) return; // already installed

  const log = [];
  window.__diatomPrivacyLog = log;

  function record(api, requested, returned) {
    const entry = { api, requested: String(requested), returned: String(returned), ts: Date.now() };
    log.push(entry);
    if (window.__diatomPrivacyLive) {
      console.log(
        `%c[Diatom Privacy]%c ${api}`,
        'color:#60a5fa;font-weight:bold', 'color:inherit',
        `\n  requested: ${entry.requested}\n  returned:  ${entry.returned}`
      );
    }
  }

  const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    const real = _origToDataURL.apply(this, args);
    record('canvas.toDataURL', `${this.width}×${this.height} px`, 'noised (±1 LSB/channel)');
    return real;
  };

  const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(...args) {
    const real = _origGetImageData.apply(this, args);
    record('canvas.getImageData', `${args[2]}×${args[3]} px at (${args[0]},${args[1]})`, 'noised (±1 LSB)');
    return real;
  };

  const _origGetParam = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(pname) {
    const val = _origGetParam.call(this, pname);
    if (pname === 0x1F01 || pname === 0x1F00) {   // RENDERER / VENDOR
      record('WebGL.getParameter', `pname=0x${pname.toString(16)} → "${val}"`, 'spoofed (Generic GPU)');
    }
    return val;
  };

  if (window.AudioContext || window.webkitAudioContext) {
    const AC = window.AudioContext || window.webkitAudioContext;
    const _origCreateBuffer = AC.prototype.createBuffer;
    AC.prototype.createBuffer = function(...args) {
      record('AudioContext.createBuffer', `sampleRate=${args[2]}`, 'precision clamped to 100 Hz');
      return _origCreateBuffer.apply(this, args);
    };
  }

  ['hardwareConcurrency', 'deviceMemory', 'platform', 'userAgent'].forEach(prop => {
    const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop)
      || Object.getOwnPropertyDescriptor(navigator, prop);
    if (!desc) return;
    const origGet = desc.get;
    if (!origGet) return;
    Object.defineProperty(Navigator.prototype, prop, {
      get() {
        const val = origGet.call(this);
        record(`navigator.${prop}`, '(read)', String(val));
        return val;
      },
      configurable: true,
    });
  });

  if (!window.diatom) window.diatom = {};
  window.diatom.debugPrivacy = function(mode) {
    if (mode === 'clear') { log.length = 0; console.log('[Diatom] Privacy log cleared.'); return; }
    if (mode === 'live')  { window.__diatomPrivacyLive = true; console.log('[Diatom] Live intercept mode enabled.'); }

    if (!log.length) {
      console.log('%c[Diatom Privacy] No fingerprinting attempts recorded yet on this page.', 'color:#60a5fa');
      return;
    }
    console.group('%c[Diatom Privacy] Fingerprinting intercept log', 'color:#60a5fa;font-weight:bold');
    console.table(log.map(e => ({
      API: e.api,
      Requested: e.requested,
      'Returned (spoofed)': e.returned,
      'Time (ms ago)': Date.now() - e.ts,
    })));
    console.groupEnd();
    console.log(`Total: ${log.length} intercept(s). Run diatom.debugPrivacy('clear') to reset.`);
  };

  console.log('%c[Diatom] Privacy debug API ready. Run diatom.debugPrivacy() to inspect intercepts.', 'color:#60a5fa;font-style:italic;font-size:11px');
})();
"#.to_owned()
    }
}
