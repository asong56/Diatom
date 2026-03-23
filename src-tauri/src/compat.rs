// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/compat.rs  — v7.2  RED-1
//
// Compatibility Router — "Adapting upward must not become self-exile"
//
// Problem: Sites using non-standard JS frameworks, enterprise intranet
//          systems, and government portals break on Servo/WebKit.
//
// Solution: Three-tier compatibility strategy, zero soul compromise.
//
//   Tier 0 — NATIVE (default):
//     Diatom's full stack. Privacy, blocking, noise all active.
//
//   Tier 1 — COMPAT_HINT:
//     Page failed to load correctly (detected via JS error event count
//     or user-triggered). Diatom adds a subtle ⚠ indicator and offers
//     to open in system browser. No automatic fallback — user decides.
//     Privacy stance: unchanged.
//
//   Tier 2 — SYSTEM_BROWSER_HANDOFF:
//     User explicitly requests opening the current URL in the system's
//     default browser (Chrome / Edge / Safari). Diatom strips tracking
//     params first, then hands off via shell::open.
//     This is the only path where Diatom yields rendering entirely.
//
// NEVER:
//   - Auto-silently fall back to Chromium/Blink
//   - Disable ad-blocking or noise injection for "compat" reasons
//   - Load a bundled Blink instance (would push binary past 15MB)
//
// Known-incompatible domain list:
//   User-maintained in diatom.json `compat.legacy_domains[]`.
//   Diatom does NOT ship a default list — we don't presuppose which
//   sites are broken for each user's environment.
// ─────────────────────────────────────────────────────────────────────────────

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ── Compat tier ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatTier {
    Native,              // default — full Diatom stack
    CompatHint,          // degraded detected — show indicator, offer handoff
    SystemBrowserQueued, // user accepted handoff, pending open()
}

impl Default for CompatTier {
    fn default() -> Self {
        CompatTier::Native
    }
}

// ── Page health signals from frontend ────────────────────────────────────────

/// Reported by the injected diatom-api.js after page load.
#[derive(Debug, Clone, Deserialize)]
pub struct PageHealthReport {
    pub url: String,
    pub js_errors: u32,           // uncaught errors in first 3s
    pub dom_mutation_storm: bool, // > 500 DOM mutations/s (React/Angular churn)
    pub blank_body: bool,         // <body> has no rendered text after 3s
    pub console_errors: u32,      // console.error calls
}

impl PageHealthReport {
    /// Returns true if the page shows signs of rendering incompatibility.
    pub fn appears_broken(&self) -> bool {
        // [FIX-12-compat] dom_mutation_storm is now included in the heuristic.
        self.blank_body
            || self.js_errors >= 5
            || self.dom_mutation_storm
            || (self.js_errors >= 2 && self.console_errors >= 10)
    }
}

// ── User legacy domain list ───────────────────────────────────────────────────

#[derive(Default)]
pub struct CompatStore {
    /// Domains the user has marked as "always open in system browser".
    legacy_domains: HashSet<String>,
    /// Domains that triggered auto-detection this session.
    auto_detected: HashSet<String>,
}

impl CompatStore {
    pub fn add_legacy(&mut self, domain: &str) {
        self.legacy_domains.insert(domain.to_lowercase());
    }

    pub fn remove_legacy(&mut self, domain: &str) {
        self.legacy_domains.remove(&domain.to_lowercase());
    }

    pub fn is_legacy(&self, domain: &str) -> bool {
        self.legacy_domains.contains(&domain.to_lowercase())
    }

    pub fn mark_auto_detected(&mut self, domain: &str) {
        self.auto_detected.insert(domain.to_lowercase());
    }

    pub fn is_auto_detected(&self, domain: &str) -> bool {
        self.auto_detected.contains(&domain.to_lowercase())
    }

    pub fn all_legacy(&self) -> Vec<String> {
        let mut v: Vec<_> = self.legacy_domains.iter().cloned().collect();
        v.sort();
        v
    }
}

// ── Handoff: open URL in system browser ──────────────────────────────────────

/// Strip tracking params, then hand off to the OS default browser.
/// This is the ONLY path where Diatom yields the render entirely.
/// Called from cmd_compat_handoff.
pub fn system_browser_open(url: &str) -> Result<()> {
    // Strip tracking params before handing off (privacy maintained even in handoff)
    let clean = crate::blocker::strip_params(&crate::blocker::upgrade_https_owned(url));
    tracing::info!("compat handoff → system browser: {}", clean);
    // Use Tauri's shell plugin for cross-platform open
    // Actual invocation happens in commands.rs via tauri_plugin_shell
    Ok(())
}

/// Build the compat hint HTML banner injected into degraded pages.
/// The "Open in system browser" button calls window.__diatom_compat_handoff()
/// which is defined by diatom-api.js and invokes cmd_compat_handoff via IPC.
/// [FIX-13-compat] Previously this called an undefined function; now it works.
pub fn compat_hint_banner(domain: &str) -> String {
    format!(
        r#"<div id="__diatom_compat" style="
          position:fixed;top:0;left:0;right:0;z-index:2147483647;
          background:#1e293b;border-bottom:1px solid rgba(245,158,11,.3);
          color:#fbbf24;font:500 12px/1.5 'Inter',system-ui;
          padding:6px 12px;display:flex;align-items:center;gap:8px;">
          <span>⚠ Diatom detected a compatibility issue with this page</span>
          <button onclick="window.__diatom_compat_handoff(location.href);"
            style="margin-left:auto;background:#b45309;color:#fff;border:none;
                   border-radius:3px;padding:3px 8px;cursor:pointer;font-size:11px;">
            Open in system browser
          </button>
          <button onclick="document.getElementById('__diatom_compat').remove();"
            style="background:none;border:none;color:#94a3b8;cursor:pointer;font-size:14px;">
            ✕
          </button>
        </div>"#,
    )
    // Note: domain parameter reserved for future per-domain hint text
    // crate::utils::escape_html(domain) — suppress unused warning
    .replace("__DOMAIN__", &crate::utils::escape_html(domain))
}

// ── Payment / U-Shield compatibility note ────────────────────────────────────

/// Known payment/banking domains that require system browser handoff.
/// These sites use proprietary NPAPI-era ActiveX/plugin-based verification
/// that no standards-compliant browser can support.
/// We auto-prompt on these rather than waiting for user report.
pub const PAYMENT_DOMAINS: &[&str] = &[
    // Chinese banking U-Shield domains (representative list — users add others)
    "ebssec.boc.cn",      // Bank of China security
    "perbank.ccb.com",    // CCB personal banking
    "mybank.icbc.com.cn", // ICBC
    "online.95599.cn",    // ABC
    "pcenter.bank.ecitic.com",
    // Generic WebUSB/plugin payment indicators
    "unionpay.com",
    "95516.com",
];

/// Check if a domain is a known payment/banking system requiring plugin support.
pub fn is_payment_domain(domain: &str) -> bool {
    let d = domain.to_lowercase();
    PAYMENT_DOMAINS.iter().any(|p| d.contains(p))
        || d.ends_with(".bank")
        || (d.contains("bank") && d.ends_with(".com.cn"))
        || (d.contains("pay") && d.contains("secure"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_report_detects_blank_page() {
        let r = PageHealthReport {
            url: "https://broken.example.com".into(),
            js_errors: 0,
            dom_mutation_storm: false,
            blank_body: true,
            console_errors: 0,
        };
        assert!(r.appears_broken());
    }

    #[test]
    fn health_report_threshold_js_errors() {
        let ok = PageHealthReport {
            url: "https://ok.example.com".into(),
            js_errors: 1,
            dom_mutation_storm: false,
            blank_body: false,
            console_errors: 2,
        };
        assert!(!ok.appears_broken());

        let broken = PageHealthReport {
            url: "https://broken.example.com".into(),
            js_errors: 5,
            dom_mutation_storm: false,
            blank_body: false,
            console_errors: 0,
        };
        assert!(broken.appears_broken());
    }

    #[test]
    fn legacy_store_add_remove() {
        let mut store = CompatStore::default();
        store.add_legacy("old-intranet.example.com");
        assert!(store.is_legacy("old-intranet.example.com"));
        store.remove_legacy("old-intranet.example.com");
        assert!(!store.is_legacy("old-intranet.example.com"));
    }
}
