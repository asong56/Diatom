// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/privacy.rs
//
// Fingerprint resistance configuration. Controls which entropy sources
// Diatom modifies or suppresses to prevent cross-site tracking via
// browser fingerprinting.
// ─────────────────────────────────────────────────────────────────────────────

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
  // Canvas noise: add ±1 LSB per channel on getImageData
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(...a) {
    const d = origGetImageData.apply(this, a);
    for (let i = 0; i < d.data.length; i += 4) {
      // [FIX-08] Use the seeded xorshift PRNG from __DIATOM_INIT__, not
      // Math.random(). The seed is set by Rust before this script runs.
      // Note: diatom-api.js already handles canvas noise with rand(); this
      // injection_script() is retained for configurable enable/disable but
      // delegates the actual PRNG to the same rand() function.
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
  // Block WebRTC local IP leak
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
  // Block Battery Status API
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
  // Block WebUSB / WebHID / WebMIDI
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
