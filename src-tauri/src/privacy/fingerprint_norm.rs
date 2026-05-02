/// Normalised fingerprint constants.
/// All values match the statistical mode of desktop hardware in 2025.
pub struct FingerprintNorm {
    /// `navigator.hardwareConcurrency` — 8 is the p50 for modern desktop.
    pub hardware_concurrency: u32,
    /// `navigator.deviceMemory` — 8 GB.
    pub device_memory: u32,
    /// `screen.colorDepth` / `screen.pixelDepth`.
    pub color_depth: u32,
    /// WebGL VENDOR string.
    pub webgl_vendor: &'static str,
    /// WebGL RENDERER string.
    pub webgl_renderer: &'static str,
    /// `AudioContext.sampleRate`.
    pub audio_sample_rate: u32,
    /// `navigator.maxTouchPoints` — 0 for a desktop mouse.
    pub max_touch_points: u32,
}

impl Default for FingerprintNorm {
    fn default() -> Self {
        Self {
            hardware_concurrency: 8,
            device_memory: 8,
            color_depth: 24,
            webgl_vendor: "Google Inc. (Intel)",
            webgl_renderer: "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
            audio_sample_rate: 44100,
            max_touch_points: 0,
        }
    }
}

impl FingerprintNorm {
    /// Generate the JavaScript injection snippet.
    ///
    /// The snippet:
    ///   • Is idempotent (guarded by `__DIATOM_FP_NORM__`).
    ///   • Uses `Object.defineProperty` with `configurable: false` so site
    ///     scripts cannot re-read the original value through the prototype.
    ///   • Overrides Canvas `toDataURL` / `toBlob` with a pass-through that
    ///     applies a deterministic, imperceptible pixel shift — identical
    ///     output every call, unique per domain (keyed by a stable per-domain
    ///     salt derived from the hostname, not from randomness).
    ///   • Does NOT override `Date`, timezone, or language — changing those
    ///     breaks calendar applications and localisation.
    pub fn generate(&self) -> String {
        let hw = self.hardware_concurrency;
        let mem = self.device_memory;
        let cd = self.color_depth;
        let wv = self.webgl_vendor;
        let wr = self.webgl_renderer;
        let ar = self.audio_sample_rate;
        let tp = self.max_touch_points;

        format!(
            r#"
(function normaliseFingerprintAPIs() {{
  "use strict";
  if (window.__DIATOM_FP_NORM__) return;
  window.__DIATOM_FP_NORM__ = true;

  function def(obj, prop, value) {{
    try {{
      Object.defineProperty(obj, prop, {{
        get: () => value,
        configurable: false,
        enumerable: true,
      }});
    }} catch (_) {{
    }}
  }}

  def(Navigator.prototype, "hardwareConcurrency", {hw});
  def(Navigator.prototype, "deviceMemory",        {mem});
  def(Navigator.prototype, "maxTouchPoints",      {tp});

  def(Screen.prototype, "colorDepth",  {cd});
  def(Screen.prototype, "pixelDepth",  {cd});

  function patchWebGL(ctx) {{
    if (!ctx) return;
    const origGetParam = ctx.prototype.getParameter.bind(ctx.prototype);
    ctx.prototype.getParameter = function(param) {{
      if (param === this.VENDOR)   return "{wv}";
      if (param === this.RENDERER) return "{wr}";
      return origGetParam.call(this, param);
    }};
  }}
  patchWebGL(window.WebGLRenderingContext);
  patchWebGL(window.WebGL2RenderingContext);

  if (window.AudioContext) {{
    const OrigAudioContext = window.AudioContext;
    window.AudioContext = function(options) {{
      options = options || {{}};
      options.sampleRate = {ar};
      return new OrigAudioContext(options);
    }};
    Object.setPrototypeOf(window.AudioContext, OrigAudioContext);
    Object.setPrototypeOf(window.AudioContext.prototype, OrigAudioContext.prototype);
  }}

  (function patchCanvas() {{
    const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
    const _toBlob    = HTMLCanvasElement.prototype.toBlob;
    const host       = location.hostname;

    function hostSeed(h) {{
      let n = 0;
      for (let i = 0; i < h.length; i++) n = (n * 31 + h.charCodeAt(i)) | 0;
      return n;
    }}
    const seed = hostSeed(host);

    function perturb(canvas) {{
      const ctx2d = canvas.getContext && canvas.getContext("2d");
      if (!ctx2d || canvas.width < 2 || canvas.height < 2) return;
      const x = Math.abs(seed % (canvas.width  - 1)) + 1;
      const y = Math.abs(seed % (canvas.height - 1)) + 1;
      const px = ctx2d.getImageData(x, y, 1, 1);
      px.data[0] ^= 1;
      ctx2d.putImageData(px, x, y);
    }}

    HTMLCanvasElement.prototype.toDataURL = function(type, quality) {{
      perturb(this);
      const result = _toDataURL.call(this, type, quality);
      perturb(this); // restore
      return result;
    }};

    HTMLCanvasElement.prototype.toBlob = function(cb, type, quality) {{
      perturb(this);
      _toBlob.call(this, (blob) => {{ perturb(this); cb(blob); }}, type, quality);
    }};
  }})();

}})();
"#,
            hw = hw,
            mem = mem,
            cd = cd,
            wv = wv,
            wr = wr,
            ar = ar,
            tp = tp,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_is_non_empty() {
        let norm = FingerprintNorm::default();
        let script = norm.generate();
        assert!(script.contains("__DIATOM_FP_NORM__"));
        assert!(script.contains("hardwareConcurrency"));
        assert!(script.contains("WebGLRenderingContext"));
        assert!(script.contains("AudioContext"));
        assert!(script.contains("toDataURL"));
    }

    #[test]
    fn defaults_match_common_hardware() {
        let norm = FingerprintNorm::default();
        assert_eq!(norm.hardware_concurrency, 8);
        assert_eq!(norm.device_memory, 8);
        assert_eq!(norm.color_depth, 24);
        assert_eq!(norm.audio_sample_rate, 44100);
        assert_eq!(norm.max_touch_points, 0);
    }

    #[test]
    fn script_contains_no_randomness_calls() {
        let script = FingerprintNorm::default().generate();
        assert!(!script.contains("Math.random"));
        assert!(!script.contains("crypto.getRandomValues"));
    }
}
