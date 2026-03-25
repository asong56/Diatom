// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/blocker.rs  — v0.9.1
//
// URL filtering pipeline:
//   1. HTTPS upgrade  — force-upgrade HTTP origins
//   2. Tracker param strip — remove UTM / fbclid / gclid etc.
//   3. Aho-Corasick domain blocklist — cosmetic + analytics + fingerprint nets
//
// v0.9.1 changes:
//   • Replaced `once_cell::sync::Lazy` with `std::sync::LazyLock` (stable ≥ 1.80).
//     Eliminates the `once_cell` direct dependency for this module.
//   • Added `dynamic_ua(cache)` — synthesises a platform-correct User-Agent
//     string from the Sentinel cache when the `sentinel_ua` lab is active.
//   • DIATOM_UA is now the *fallback* constant only; hot paths use the synthesised
//     string. The generic UA is still used for Sentinel's own poll requests to
//     avoid fingerprinting the polling origin.
// ─────────────────────────────────────────────────────────────────────────────

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, DNT, HeaderMap, HeaderValue};
use std::sync::LazyLock;
use url::Url;

// ── User-Agent ────────────────────────────────────────────────────────────────

/// Diatom's static fallback UA. Used when Sentinel is inactive or not yet
/// populated, and always used for Sentinel's own polling requests so that the
/// version-check traffic itself does not leak engine information.
///
/// Shape: macOS + Safari 17.x — the most common non-Windows desktop UA and the
/// one that causes least suspicion on modern web services.
pub const DIATOM_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15";

/// Synthesise a live UA string from the Sentinel cache.
///
/// Platform selection:
///   `prefer_safari` = true  → macOS Safari UA (best for Apple-ecosystem sites)
///   `prefer_safari` = false → Windows Chrome UA (universal compatibility)
///
/// Both strings will exactly match a freshly-updated device running the
/// current stable browser, making Diatom indistinguishable from a normal user.
///
/// Returns `None` if the cache is empty or stale (callers fall back to DIATOM_UA).
pub fn dynamic_ua(
    cache: &crate::sentinel::SentinelCache,
    prefer_safari: bool,
) -> Option<String> {
    if !cache.is_fresh() {
        return None;
    }
    if prefer_safari {
        if cache.safari.is_some() {
            return Some(cache.safari_ua_macos());
        }
    } else if cache.chrome_win().is_some() {
        return Some(cache.chrome_ua_windows());
    }
    None
}

// ── Built-in minimal blocklist ────────────────────────────────────────────────

// [FIX — 建议四] Expanded built-in blocklist: ~50 high-frequency patterns
// derived from EasyList's most commonly matched rules. This ensures ad blocking
// is effective on first launch before the user subscribes to EasyList.
// Included as "universal pattern library" — not platform-specific per PHILOSOPHY §4.
const BUILTIN_PATTERNS: &[&str] = &[
    // ── Analytics & telemetry ─────────────────────────────────────────────
    "/analytics/",
    "/telemetry/",
    "/collect?",
    "/beacon?",
    "/pixel.gif",
    "/pixel.png",
    "/1x1.gif",
    "analytics.",
    "telemetry.",
    "tracking.",
    "pixel.",
    "beacon.",
    "analytics.js",
    "tracking.js",
    "gtag/js",
    "gtm.js",
    // ── Ad networks ──────────────────────────────────────────────────────
    "/ads/",
    "/ad/",
    "/advert/",
    "/advertisement/",
    "/adserver/",
    "/adsystem/",
    "/adservice/",
    "/pagead/",
    "/doubleclick/",
    "googlesyndication.com",
    "googleadservices.com",
    "adnxs.com",
    "advertising.com",
    "adsrvr.org",
    "casalemedia.com",
    "rubiconproject.com",
    "openx.net",
    "pubmatic.com",
    "criteo.com",
    "outbrain.com",
    "taboola.com",
    "moatads.com",
    "adsafeprotected.com",
    // ── Fingerprinting / tracking pixels ─────────────────────────────────
    "scorecardresearch.com",
    "quantserve.com",
    "chartbeat.com",
    "newrelic.com/pageview",
    "bat.bing.com",
    "connect.facebook.net",
    "static.ads-twitter.com",
    "ads.linkedin.com",
    "/impression?",
    "/impression.gif",
    "/click?",
    "/clicktrack/",
    "/trackclick/",
    "/ad_click/",
    "/ad_impression/",
    // ── Crypto miners ────────────────────────────────────────────────────
    "coinhive.com",
    "coin-hive.com",
    "minero.cc",
    "cryptoloot.pro",
    "webminepool.com",
    "jsecoin.com",
    // ── Phishing infra ────────────────────────────────────────────────────
    "secure-paypa1.com",
    "paypa1-secure.com",
    "amazon-security-alert.com",
    "appleid-verify-account.com",
    "microsoft-login-secure.com",
    // ── Malware C2 (representative) ───────────────────────────────────────
    "emotet-c2.example.com",
    "trickbot-cdn.example.net",
];

// `std::sync::LazyLock` is stable since Rust 1.80 (Rust 2024 edition requires ≥ 1.85).
// This eliminates the `once_cell` crate dependency for this module.
static BLOCKER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostFirst)
        .ascii_case_insensitive(true)
        .build(BUILTIN_PATTERNS)
        .expect("blocker AC build failed")
});

// ── Tracking query parameters to strip ───────────────────────────────────────

const STRIP_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_source_platform",
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "tclid",
    "twclid",
    "ttclid",
    "mc_eid",
    "mc_cid",
    "_ga",
    "_gl",
    "_hsenc",
    "_hsmi",
    "igshid",
    "s_kwcid",
    "ref",
    "referrer",
    "source",
    "__twitter_impression",
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Returns true if the URL matches a tracking/analytics pattern.
#[inline]
pub fn is_blocked(url: &str) -> bool {
    BLOCKER.is_match(url)
}

/// Returns a JS stub string for the blocked URL (cosmetic replacement).
pub fn stub_for(url: &str) -> Option<&'static str> {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_owned()))
        .unwrap_or_default();

    const STUBS: &[(&str, &str)] = &[
        (
            "google-analytics.com",
            "window.ga=function(){};window.gtag=function(){};",
        ),
        (
            "googletagmanager.com",
            "window.dataLayer=window.dataLayer||[];",
        ),
        (
            "hotjar.com",
            "(function(h){h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)}})(window);",
        ),
        (
            "connect.facebook.net",
            "!function(f){f.fbq=function(){};f.fbq.loaded=!0;}(window);",
        ),
        (
            "amplitude.com",
            "window.amplitude={getInstance:function(){return{logEvent:function(){}}}};",
        ),
        (
            "api.segment.io",
            "window.analytics={track:function(){},page:function(){},identify:function(){}};",
        ),
        (
            "cdn.segment.com",
            "window.analytics={track:function(){},page:function(){},identify:function(){}};",
        ),
        (
            "mixpanel.com",
            "window.mixpanel={track:function(){},identify:function(){},init:function(){}};",
        ),
    ];

    for (pattern, stub) in STUBS {
        if host.contains(pattern) {
            return Some(stub);
        }
    }
    None
}

/// Upgrade HTTP → HTTPS for non-localhost origins.
pub fn upgrade_https(url: &str) -> String {
    // [FIX-27] HTTP scheme is case-insensitive (RFC 7230 §2.7.3).
    // Lowercase before comparison so HTTP:// and Http:// are both upgraded.
    let url_lc = url.to_lowercase();
    if url_lc.starts_with("http://") && !url_lc.starts_with("http://localhost") {
        // Preserve original casing after the scheme
        format!("https://{}", &url[7..])
    } else {
        url.to_owned()
    }
}

/// Owned version of upgrade_https (used in commands and compat).
#[inline]
pub fn upgrade_https_owned(url: &str) -> String {
    upgrade_https(url)
}

/// Strip tracking query parameters from a URL.
pub fn strip_params(url: &str) -> String {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return url.to_owned(),
    };

    let clean_pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| {
            let key = k.to_lowercase();
            !STRIP_PARAMS
                .iter()
                .any(|p| key == *p || key.starts_with(&format!("{}_", p)))
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let mut out = parsed.clone();
    if clean_pairs.is_empty() {
        out.set_query(None);
    } else {
        out.set_query(Some(
            &clean_pairs
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&"),
        ));
    }
    out.to_string()
}

/// Build clean request headers (no Referer, sanitised Accept-Language).
/// When `extra_ua` is provided it overrides DIATOM_UA — callers pass the
/// Sentinel-synthesised string here when the lab is active.
pub fn clean_headers(url: &str, extra_ua: Option<&str>) -> HeaderMap {
    let _ = url; // reserved for future per-domain header tuning
    let mut headers = HeaderMap::new();
    let ua = extra_ua.unwrap_or(DIATOM_UA);
    headers.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_str(ua).unwrap_or_else(|_| HeaderValue::from_static(DIATOM_UA)),
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
    );
    // Generic language — not locale-fingerprintable
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(DNT, HeaderValue::from_static("1"));
    headers.insert(
        reqwest::header::HeaderName::from_static("sec-gpc"),
        HeaderValue::from_static("1"),
    );
    headers
}

/// Extract the registrable domain from a URL.
pub fn domain_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_owned()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_utm_params() {
        let url = "https://example.com/page?utm_source=newsletter&id=42";
        let clean = strip_params(url);
        assert!(clean.contains("id=42"), "non-tracking params must survive");
        assert!(!clean.contains("utm_source"), "utm params must be stripped");
    }

    #[test]
    fn upgrades_http() {
        assert_eq!(upgrade_https("http://example.com/"), "https://example.com/");
        assert_eq!(
            upgrade_https("http://localhost:3000/"),
            "http://localhost:3000/"
        );
    }

    #[test]
    fn blocks_analytics_endpoint() {
        assert!(is_blocked("https://example.com/analytics/collect"));
        assert!(!is_blocked("https://example.com/about"));
    }

    #[test]
    fn dynamic_ua_returns_none_for_empty_cache() {
        let cache = crate::sentinel::SentinelCache::default();
        assert!(dynamic_ua(&cache, false).is_none());
        assert!(dynamic_ua(&cache, true).is_none());
    }
}
