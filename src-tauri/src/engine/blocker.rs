/// Generic Chrome UA used for filter list update requests.

pub const FILTER_FETCH_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/124.0.0.0 Safari/537.36";

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, DNT, HeaderMap, HeaderValue};
use std::collections::HashMap;
use std::sync::LazyLock;
use url::Url;

pub const DIATOM_UA_MACOS: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15";

pub const DIATOM_UA_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";

pub const DIATOM_UA_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";

pub fn platform_fallback_ua() -> &'static str {
    match std::env::consts::OS {
        "windows" => DIATOM_UA_WINDOWS,
        "linux" => DIATOM_UA_LINUX,
        _ => DIATOM_UA_MACOS,
    }
}

pub fn dynamic_ua(
    cache: &crate::features::sentinel::SentinelCache,
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

static BUILTIN_PATTERNS_RAW: &str = include_str!("../../resources/builtin_patterns.txt");

fn builtin_patterns() -> Vec<&'static str> {
    BUILTIN_PATTERNS_RAW
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect()
}

static BLOCKER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostFirst)
        .ascii_case_insensitive(true)
        .build(builtin_patterns())
        .expect("blocker AC build failed")
});

pub fn build_dynamic_blocker(patterns: &[String]) -> AhoCorasick {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostFirst)
        .ascii_case_insensitive(true)
        .build(patterns)
        .expect("dynamic blocker AC build failed")
}

const BUILTIN_FILTER_LISTS: &[(&str, &str)] = &[
    ("EasyList", "https://easylist.to/easylist/easylist.txt"),
    (
        "EasyPrivacy",
        "https://easylist.to/easylist/easyprivacy.txt",
    ),
    (
        "uBlock Filters",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    ),
    (
        "uBlock Badware",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    ),
    (
        "uBlock Privacy",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    ),
    (
        "Peter Lowe List",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext",
    ),
    (
        "AdGuard Base",
        "https://filters.adtidy.org/extension/ublock/filters/2.txt",
    ),
    (
        "AdGuard Tracking Protection",
        "https://filters.adtidy.org/extension/ublock/filters/3.txt",
    ),
    (
        "AdGuard Mobile Ads",
        "https://filters.adtidy.org/extension/ublock/filters/11.txt",
    ),
    (
        "Fanboy Annoyance",
        "https://easylist.to/easylist/fanboy-annoyance.txt",
    ),
    (
        "Fanboy Social",
        "https://easylist.to/easylist/fanboy-social.txt",
    ),
    (
        "Steven Black Hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "Dan Pollock Hosts",
        "https://someonewhocares.org/hosts/zero/hosts",
    ),
];

/// Parse an ABP/uBlock filter-list text into a flat list of URL patterns.
///
/// Drops:
/// - Comment lines prefixed with `!` or `#`.
/// - Exception rules prefixed with `@@`.
/// - Cosmetic-filter rules (`##`, `#@#`, `#?#`, `#$#`).
///
/// Keeps and normalises:
/// - `||domain.com^` → `domain.com`
/// - Hosts-file entries (`0.0.0.0 domain`) → `domain`
pub fn parse_filter_list(text: &str) -> Vec<String> {
    let mut patterns = Vec::with_capacity(4096);
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty()
            || l.starts_with('!')
            || l.starts_with('#')
            || l.starts_with("@@")
            || l.contains("##")
            || l.contains("#@#")
            || l.contains("#?#")
            || l.contains("#$#")
        {
            continue;
        }
        let l = if let Some(rest) = l
            .strip_prefix("0.0.0.0 ")
            .or_else(|| l.strip_prefix("127.0.0.1 "))
        {
            rest.split('#').next().unwrap_or("").trim().to_lowercase()
        } else if let Some(stripped) = l.strip_prefix("||") {
            stripped
                .trim_end_matches('^')
                .trim_end_matches('/')
                .to_lowercase()
        } else if l.starts_with('|') {
            let s = l.trim_start_matches('|');
            let s = s
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            s.trim_end_matches('^').to_lowercase()
        } else {
            l.to_lowercase()
        };

        if l.len() < 5 {
            continue;
        }

        if l.chars().all(|c| matches!(c, '*' | '^' | '|' | ' ')) {
            continue;
        }

        let l = l.split('$').next().unwrap_or(&l).trim_end_matches('^');
        if l.len() >= 5 {
            patterns.push(l.to_owned());
        }
    }
    patterns.dedup();
    patterns
}

/// Fetch all built-in filter lists over HTTPS and build the live automaton.
pub async fn boot_fetch_builtin_lists(
    live_blocker: std::sync::Arc<std::sync::RwLock<Option<AhoCorasick>>>,
) {
    use std::time::Duration;

    tracing::info!(
        "blocker: starting boot-time filter list fetch ({} lists)",
        BUILTIN_FILTER_LISTS.len()
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(FILTER_FETCH_UA)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "blocker: could not build HTTP client for filter fetch: {}",
                e
            );
            return;
        }
    };

    let base = builtin_patterns();
    let base_count = base.len();
    let mut all_patterns: Vec<String> = base.into_iter().map(|s| s.to_string()).collect();

    for (name, url) in BUILTIN_FILTER_LISTS {
        match client.get(*url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(text) => {
                    let parsed = parse_filter_list(&text);
                    tracing::info!("blocker: {} → {} patterns", name, parsed.len());
                    all_patterns.extend(parsed);
                }
                Err(e) => tracing::warn!("blocker: {} body read error: {}", name, e),
            },
            Ok(resp) => tracing::warn!("blocker: {} HTTP {}", name, resp.status()),
            Err(e) => tracing::warn!("blocker: {} fetch failed: {}", name, e),
        }
    }

    all_patterns.sort_unstable();
    all_patterns.dedup();

    let total = all_patterns.len();
    tracing::info!(
        "blocker: building merged automaton — {} patterns ({} builtin + {} from lists; target 60k+)",
        total,
        base_count,
        total - base_count
    );

    match AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostFirst)
        .ascii_case_insensitive(true)
        .build(&all_patterns)
    {
        Ok(ac) => {
            *live_blocker.write().unwrap() = Some(ac);
            tracing::info!("blocker: live automaton ready — {} patterns total", total);
        }
        Err(e) => tracing::error!("blocker: automaton build failed: {}", e),
    }
}

pub fn merge_with_builtins(extra: Vec<String>) -> Vec<String> {
    let mut all: Vec<String> = builtin_patterns()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    all.extend(extra);
    all.sort_unstable();
    all.dedup();
    all
}

/// Check `url` against the live dynamic automaton, with a fallback to the
/// static built-in automaton when the live one is not yet ready.
pub fn is_blocked_live(url: &str, live: &std::sync::RwLock<Option<AhoCorasick>>) -> bool {
    if let Ok(guard) = live.try_read() {
        if let Some(ac) = guard.as_ref() {
            return ac.is_match(url);
        }
    }
    is_blocked(url)
}

/// A compiled cosmetic filter set.
pub struct CosmeticEngine {
    pub global: Vec<String>,

    pub domain_map: HashMap<String, Vec<String>>,

    pub exception_map: HashMap<String, Vec<String>>,
}

impl CosmeticEngine {
    pub fn new() -> Self {
        let mut engine = CosmeticEngine {
            global: Vec::new(),
            domain_map: HashMap::new(),
            exception_map: HashMap::new(),
        };
        for rule in builtin_cosmetic_rules() {
            engine.add_raw(rule);
        }
        engine
    }

    pub fn add_raw(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            return;
        }
        if let Some(pos) = line.find("#@#") {
            let domains_str = &line[..pos];
            let selector = line[pos + 3..].trim().to_owned();
            for d in domains_str.split(',') {
                let d = d.trim().to_lowercase();
                if !d.is_empty() {
                    self.exception_map
                        .entry(d)
                        .or_default()
                        .push(selector.clone());
                }
            }
            return;
        }
        if let Some(pos) = line.find("##") {
            let domains_str = &line[..pos];
            let selector = line[pos + 2..].trim().to_owned();
            if selector.is_empty() {
                return;
            }
            if domains_str.is_empty() {
                self.global.push(selector);
            } else {
                for d in domains_str.split(',') {
                    let d = d.trim().to_lowercase();
                    if !d.is_empty() {
                        self.domain_map.entry(d).or_default().push(selector.clone());
                    }
                }
            }
        }
    }

    pub fn build_style_for_domain(&self, domain: &str) -> String {
        let domain = domain.to_lowercase();
        let domain = domain.trim_start_matches("www.");

        let exceptions: std::collections::HashSet<&str> = self
            .exception_map
            .get(domain)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();

        let mut selectors: Vec<&str> = Vec::new();
        for sel in &self.global {
            if !exceptions.contains(sel.as_str()) {
                selectors.push(sel);
            }
        }
        if let Some(rules) = self.domain_map.get(domain) {
            for sel in rules {
                if !exceptions.contains(sel.as_str()) {
                    selectors.push(sel);
                }
            }
        }
        if selectors.is_empty() {
            return String::new();
        }
        format!("{} {{ display:none !important; }}", selectors.join(",\n"))
    }

    pub fn injection_script_for_domain(&self, domain: &str) -> Option<String> {
        let css = self.build_style_for_domain(domain);
        if css.is_empty() {
            return None;
        }
        let escaped = css.replace('\\', "\\\\").replace('`', "\\`");
        Some(format!(
            r#"(function(){{var s=document.createElement('style');s.id='diatom-cosmetic';\
s.textContent=`{escaped}`;(document.head||document.documentElement).appendChild(s);}})();"#
        ))
    }
}

impl Default for CosmeticEngine {
    fn default() -> Self {
        Self::new()
    }
}

static BUILTIN_COSMETIC_RULES_RAW: &str = include_str!("../../resources/builtin_cosmetic.txt");

fn builtin_cosmetic_rules() -> Vec<&'static str> {
    BUILTIN_COSMETIC_RULES_RAW
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect()
}

static COSMETIC_ENGINE: LazyLock<CosmeticEngine> = LazyLock::new(CosmeticEngine::new);

pub fn cosmetic_engine() -> &'static CosmeticEngine {
    &COSMETIC_ENGINE
}

#[inline]
pub fn is_blocked(url: &str) -> bool {
    BLOCKER.is_match(url)
}

#[inline]
pub fn is_blocked_dynamic(url: &str, dyn_blocker: &Option<AhoCorasick>) -> bool {
    dyn_blocker.as_ref().map_or(false, |ac| ac.is_match(url))
}

pub fn stub_for(url: &str) -> Option<&'static str> {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_owned()))
        .unwrap_or_default();
    const STUBS: &[(&str, &str)] = &[
        (
            "google-analytics.com",
            "window.ga=function(){};window.gtag=function(){};window.dataLayer=window.dataLayer||[];",
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
            "window.amplitude={getInstance:function(){return{logEvent:function(){},setUserId:function(){}}}};",
        ),
        (
            "api.segment.io",
            "window.analytics={track:function(){},page:function(){},identify:function(){},group:function(){}};",
        ),
        (
            "cdn.segment.com",
            "window.analytics={track:function(){},page:function(){},identify:function(){}};",
        ),
        (
            "mixpanel.com",
            "window.mixpanel={track:function(){},identify:function(){},init:function(){},people:{set:function(){}}};",
        ),
        (
            "heap.io",
            "window.heap={track:function(){},identify:function(){},init:function(){}};",
        ),
        (
            "newrelic.com",
            "window.NREUM=window.NREUM||{};window.newrelic=window.newrelic||{noticeError:function(){},addPageAction:function(){}};",
        ),
        ("nr-data.net", "window.NREUM=window.NREUM||{};"),
    ];
    for (pattern, stub) in STUBS {
        if host.contains(pattern) {
            return Some(stub);
        }
    }
    None
}

pub fn upgrade_https(url: &str) -> String {
    let url_lc = url.to_lowercase();
    if url_lc.starts_with("http://") && !url_lc.starts_with("http://localhost") {
        format!("https://{}", &url[7..])
    } else {
        url.to_owned()
    }
}

/// Upgrade an http:// URL to https://, except localhost. Returns a new String.
pub fn upgrade_https_owned(url: &str) -> String {
    upgrade_https(url).to_owned()
}

/// Strip known tracking parameters from a URL.
/// Delegates to the canonical implementation in `url_stripper`.
pub fn strip_params(url: &str) -> String {
    crate::engine::url_stripper::strip(url).into_owned()
}

pub fn clean_headers(_url: &str, extra_ua: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let platform_ua = platform_fallback_ua();
    let ua = extra_ua.unwrap_or(platform_ua);
    headers.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_str(ua).unwrap_or_else(|_| HeaderValue::from_static(DIATOM_UA_MACOS)),
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(DNT, HeaderValue::from_static("1"));
    headers.insert(
        reqwest::header::HeaderName::from_static("sec-gpc"),
        HeaderValue::from_static("1"),
    );
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_utm_params() {
        let url = "https://example.com/page?utm_source=newsletter&id=42";
        let clean = strip_params(url);
        assert!(clean.contains("id=42"));
        assert!(!clean.contains("utm_source"));
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
    fn blocks_known_ad_domains() {
        assert!(is_blocked("https://doubleclick.net/pagead/show_ads"));
        assert!(is_blocked("https://adnxs.com/getuid"));
        assert!(is_blocked("https://criteo.com/delivery/r/ajs.php"));
        assert!(is_blocked("https://amplitude.com/collect"));
        assert!(is_blocked("https://hotjar.com/static/script.js"));
    }
    #[test]
    fn cosmetic_engine_global_rules() {
        let engine = CosmeticEngine::new();
        let css = engine.build_style_for_domain("example.com");
        assert!(css.contains(".ad-banner"));
    }
    #[test]
    fn cosmetic_engine_exception_rules() {
        let mut engine = CosmeticEngine::new();
        engine.add_raw("example.com#@#.ad-banner");
        let css = engine.build_style_for_domain("example.com");
        assert!(!css.contains(".ad-banner"));
    }
    #[test]
    fn cosmetic_injection_script_has_id() {
        let engine = CosmeticEngine::new();
        let script = engine.injection_script_for_domain("example.com");
        assert!(script.is_some());
        assert!(script.unwrap().contains("diatom-cosmetic"));
    }
    #[test]
    fn builtin_pattern_count_substantial() {
        let count = builtin_patterns().len();
        assert!(count >= 600, "built-in count fell below minimum: {}", count);
    }
    #[test]
    fn parse_filter_list_extracts_patterns() {
        let sample =
            "! Comment\n@@exception\n||example-ads.com^\n/tracking/pixel.gif\n##.ad-banner\n";
        let patterns = super::parse_filter_list(sample);
        assert!(
            patterns.contains(&"example-ads.com".to_string()),
            "should extract ||domain^ pattern"
        );
        assert!(
            patterns.contains(&"/tracking/pixel.gif".to_string()),
            "should extract path pattern"
        );
        assert!(
            !patterns.iter().any(|p| p.contains(".ad-banner")),
            "should skip cosmetic rules"
        );
        assert!(
            !patterns.iter().any(|p| p.starts_with("@@")),
            "should skip exception rules"
        );
    }
    #[test]
    fn merge_with_builtins_deduplicates() {
        let extra = vec![
            "coinhive.com".to_string(),
            "new-tracker.example.com".to_string(),
        ];
        let merged = super::merge_with_builtins(extra);
        let coinhive_count = merged
            .iter()
            .filter(|p| p.as_str() == "coinhive.com")
            .count();
        assert_eq!(coinhive_count, 1, "duplicate should be removed");
        assert!(merged.contains(&"new-tracker.example.com".to_string()));
    }
    #[test]
    fn dynamic_ua_returns_none_for_empty_cache() {
        let cache = crate::features::sentinel::SentinelCache::default();
        assert!(dynamic_ua(&cache, false).is_none());
        assert!(dynamic_ua(&cache, true).is_none());
    }
}
