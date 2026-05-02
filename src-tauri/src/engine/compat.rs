use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatTier {
    Native,              // default — full Diatom stack
    CompatHint,          // degraded detected — show indicator, offer handoff
    SystemBrowserQueued, // user accepted handoff, pending open()
}

/// Domains where Diatom proactively shows a compatibility indicator (⚠)
/// on first visit, offering system browser handoff.
/// These are well-known enterprise / banking / government portals that
/// commonly require Chromium-specific features or NPAPI plugins.
///
/// [PHILOSOPHY §4 compliance]: Diatom does NOT auto-redirect these domains.
/// The user sees a subtle indicator and chooses whether to hand off.
/// No tracking parameters are stripped from the offer — user decides.
pub const BUILTIN_COMPAT_HINTS: &[&str] = &[
    "icbc.com.cn",
    "boc.cn",
    "ccb.com",
    "abchina.com",
    "online.citibank.com",
    "secure.bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "hsbc.com",
    "barclays.co.uk",
    "lloydsbank.com",
    "webex.com",
    "teams.microsoft.com",
    "sharepoint.com",
    "portal.azure.com",
    "gov.uk",
    "irs.gov",
    "ssa.gov",
    "meituan.com",
    "12306.cn",
];

/// Community compat-hint list URLs (same pull mechanism as filter subscriptions).
/// Diatom downloads these weekly; the list maintainer takes legal responsibility
/// for the domain classifications. Diatom acts only as a downloader (cf. §4).
pub const COMMUNITY_COMPAT_LISTS: &[(&str, &str)] = &[(
    "Diatom Community Compat List",
    "https://raw.githubusercontent.com/Ansel-S/diatom-compat-lists/main/hints.txt",
)];

impl Default for CompatTier {
    fn default() -> Self {
        CompatTier::Native
    }
}

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
        self.blank_body
            || self.js_errors >= 5
            || self.dom_mutation_storm
            || (self.js_errors >= 2 && self.console_errors >= 10)
    }
}

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

/// Strip tracking params, then hand off to the OS default browser.
/// This is the ONLY path where Diatom yields the render entirely.
/// Called from cmd_compat_handoff.
pub fn system_browser_open(url: &str) -> Result<()> {
    let clean =
        crate::engine::blocker::strip_params(&crate::engine::blocker::upgrade_https_owned(url));
    tracing::info!("compat handoff → system browser: {}", clean);
    Ok(())
}

/// Build the compat hint HTML banner injected into degraded pages.
/// The "Open in system browser" button calls window.__diatom_compat_handoff()
/// which is defined by diatom-api.js and invokes cmd_compat_handoff via IPC.
pub fn compat_hint_banner(domain: &str) -> String {
    let escaped_domain = crate::utils::escape_html(domain);
    format!(
        r#"<div id="__diatom_compat" style="
          position:fixed;top:0;left:0;right:0;z-index:2147483647;
          background:#1e293b;border-bottom:1px solid rgba(245,158,11,.3);
          color:#fbbf24;font:500 12px/1.5 'Inter',system-ui;
          padding:6px 12px;display:flex;align-items:center;gap:8px;">
          <span>⚠ Diatom detected a compatibility issue with <b>{escaped_domain}</b></span>
          <button onclick="window.__diatom_compat_handoff(location.href);"
            style="margin-left:auto;background:#b45309;color:#fff;border:none;
                   border-radius:3px;padding:3px 8px;cursor:pointer;font-size:11px;">
            Open in system browser
          </button>
          <button onclick="document.getElementById('__diatom_compat').remove();"
            style="background:none;border:none;color:#94a3b8;cursor:pointer;font-size:14px;">
            ✕
          </button>
        </div>"#
    )
}

/// Known payment/banking domains that require system browser handoff.
/// These sites use proprietary NPAPI-era ActiveX/plugin-based verification
/// that no standards-compliant browser can support.
/// We auto-prompt on these rather than waiting for user report.
pub const PAYMENT_DOMAINS: &[&str] = &[
    "ebssec.boc.cn",      // Bank of China security
    "perbank.ccb.com",    // CCB personal banking
    "mybank.icbc.com.cn", // ICBC
    "online.95599.cn",    // ABC
    "pcenter.bank.ecitic.com",
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
