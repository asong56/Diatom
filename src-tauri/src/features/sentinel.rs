use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Mutex, OnceLock},
    time::Duration,
};

// Sentinel makes 3 scheduled HTTPS calls (Chrome version history, Apple/Chrome
// RSS) to keep UA strings current — no user data leaves the device on any of
// them. 1h interval balances freshness vs. background activity; extended to
// 3h on battery (see power_budget_current). Toggle: Settings > UA Normalisation.
const CHROME_PLATFORMS: &[(&str, &str)] = &[
    ("win64", "windows"),
    ("mac_arm64", "mac"),
    ("linux", "linux"),
];

pub const POLL_INTERVAL_S: u64 = 3_600;

// Used when the Sentinel cache is cold (fresh install, or fetch failing).
const SAFARI_WEBKIT_BUILDS: &[(u32, u32, u32, u32)] = &[
    (18, 5, 619, 5), // projected
    (18, 4, 619, 4),
    (18, 3, 619, 3),
    (18, 2, 619, 2),
    (18, 1, 619, 1),
    (18, 0, 619, 1),
    (17, 6, 605, 1),
    (17, 5, 605, 1),
    (17, 4, 605, 1),
    (17, 3, 605, 1),
    (17, 2, 605, 1),
    (17, 1, 605, 1),
    (17, 0, 605, 1),
    (16, 6, 615, 3),
    (16, 5, 615, 3),
    (16, 4, 615, 3),
    (16, 3, 615, 3),
    (16, 2, 614, 4),
    (16, 1, 614, 3),
    (16, 0, 614, 3),
    (15, 6, 612, 3),
    (15, 5, 612, 2),
];

// Populated by run_sentinel_loop, read by webkit_build_for — avoids locking
// AppState on every UA synthesis call.
static SENTINEL_CACHE: OnceLock<Mutex<SentinelCache>> = OnceLock::new();

pub fn set_global_cache(cache: SentinelCache) {
    let m = SENTINEL_CACHE.get_or_init(|| Mutex::new(SentinelCache::default()));
    if let Ok(mut guard) = m.lock() {
        *guard = cache;
    }
}

// Falls back to a SENTINEL_STALE marker for unknown Safari majors so the
// static table's staleness is visible in logs rather than silently wrong.
pub fn webkit_build_for(safari_major: u32, safari_minor: u32) -> String {
    if let Some(cache) = SENTINEL_CACHE.get().and_then(|m| m.lock().ok()) {
        if let Some(ref safari) = cache.safari {
            if safari.major > safari_major
                || (safari.major == safari_major && safari.minor >= safari_minor)
            {
                let wk_major = webkit_major_for_safari_major(safari.major);
                let wk_sub = safari_minor;
                return format!("{}.{}.15", wk_major, wk_sub);
            }
        }
    }

    if let Some(row) = SAFARI_WEBKIT_BUILDS
        .iter()
        .find(|&&(mj, mn, _, _)| mj == safari_major && mn == safari_minor)
    {
        return format!("{}.{}.15", row.2, row.3);
    }
    if let Some(row) = SAFARI_WEBKIT_BUILDS
        .iter()
        .filter(|&&(mj, _, _, _)| mj == safari_major)
        .max_by_key(|&&(_, mn, _, _)| mn)
    {
        return format!("{}.{}.15", row.2, row.3);
    }
    tracing::warn!(
        "sentinel: webkit_build_for({}, {}) — unknown Safari major; \
         SENTINEL_STALE: update SAFARI_WEBKIT_BUILDS table",
        safari_major,
        safari_minor
    );
    let wk_major = webkit_major_for_safari_major(safari_major);
    format!("{}.{}.15 /* SENTINEL_STALE */", wk_major, safari_minor)
}

fn webkit_major_for_safari_major(safari_major: u32) -> u32 {
    match safari_major {
        19 => {
            tracing::warn!(
                "sentinel: Safari 19 detected — webkit_major_for_safari_major \
                           needs updating. Returning provisional estimate."
            );
            625 // provisional — update when Apple ships Safari 19
        }
        18 => 619,
        17 => 605,
        16 => 615,
        15 => 612,
        _ => {
            tracing::warn!(
                "sentinel: completely unknown Safari major {}; returning 619 as \
                 placeholder. SENTINEL_STALE: table update required.",
                safari_major
            );
            619
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChromeVersionInfo {
    pub version: String,
    pub major: u32,
    pub platform: String,
    pub channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SafariVersionInfo {
    pub version: String,
    pub major: u32,
    pub minor: u32,
    pub webkit_build: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentinelCache {
    pub chrome: Vec<ChromeVersionInfo>,
    pub chrome_extended: Option<ChromeVersionInfo>,
    pub safari: Option<SafariVersionInfo>,
    pub last_refresh: u64,
    pub refresh_ok: bool,
    pub fail_streak: u32,
    pub cve_critical: bool,
    /// Capped at 20 — see fetch_chrome_cves.
    pub recent_cves: Vec<String>,
    pub prev_chrome_major: u32,
}

impl SentinelCache {
    pub fn chrome_win(&self) -> Option<&ChromeVersionInfo> {
        self.chrome.iter().find(|v| v.platform == "windows")
    }

    pub fn chrome_mac(&self) -> Option<&ChromeVersionInfo> {
        self.chrome.iter().find(|v| v.platform == "mac")
    }

    pub fn is_fresh(&self) -> bool {
        let now = unix_now();
        now.saturating_sub(self.last_refresh) < POLL_INTERVAL_S * 2
    }

    // Gate used by current_ua(): presence matters more than freshness on the
    // very first poll cycle, before any refresh has completed.
    pub fn has_data(&self) -> bool {
        !self.chrome.is_empty() || self.safari.is_some()
    }

    pub fn chrome_ua_windows(&self) -> String {
        let ver = self
            .chrome_win()
            .map(|v| v.version.as_str())
            .unwrap_or("124.0.6367.207");
        format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/{ver} Safari/537.36"
        )
    }

    pub fn safari_ua_macos(&self) -> String {
        match &self.safari {
            Some(s) => {
                let wb = &s.webkit_build;
                let v = &s.version;
                format!(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                     AppleWebKit/{wb} (KHTML, like Gecko) \
                     Version/{v} Safari/{wb}"
                )
            }
            None => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                 AppleWebKit/619.1.26 (KHTML, like Gecko) \
                 Version/18.0 Safari/619.1.26"
                .to_owned(),
        }
    }
}

fn make_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(crate::engine::blocker::platform_fallback_ua())
        .build()?)
}

fn unix_now() -> u64 {
    crate::storage::db::unix_now() as u64
}

#[derive(Deserialize)]
struct VersionHistoryResponse {
    versions: Vec<VersionEntry>,
}

#[derive(Deserialize)]
struct VersionEntry {
    version: String,
}

async fn fetch_chrome_stable(
    client: &reqwest::Client,
    platform: &str,
    display_name: &str,
) -> Result<ChromeVersionInfo> {
    let url = format!(
        "https://versionhistory.googleapis.com/v1/chrome/platforms/{platform}/\
         channels/stable/versions?filter=endtime%3Dnone&order_by=version+desc&pageSize=1"
    );
    let resp = client.get(&url).send().await?;
    let body: VersionHistoryResponse = resp.json().await?;
    let version = body
        .versions
        .into_iter()
        .next()
        .map(|v| v.version)
        .unwrap_or_else(|| "124.0.6367.207".to_owned());
    let major = version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(124);
    Ok(ChromeVersionInfo {
        version,
        major,
        platform: display_name.to_owned(),
        channel: "stable".to_owned(),
    })
}

async fn fetch_chrome_extended(client: &reqwest::Client) -> Result<ChromeVersionInfo> {
    let url = "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/\
               channels/extended/versions?filter=endtime%3Dnone&order_by=version+desc&pageSize=1";
    let resp = client.get(url).send().await?;
    let body: VersionHistoryResponse = resp.json().await?;
    let version = body
        .versions
        .into_iter()
        .next()
        .map(|v| v.version)
        .unwrap_or_else(|| "124.0.6367.150".to_owned());
    let major = version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(124);
    Ok(ChromeVersionInfo {
        version,
        major,
        platform: "windows".to_owned(),
        channel: "extended".to_owned(),
    })
}

// Title format: "Safari 17.6 Release Notes" or "macOS 14.6 – Safari 17.6"
fn parse_safari_version(rss_text: &str) -> Option<(u32, u32)> {
    for line in rss_text.lines() {
        let line = line.trim();
        if !line.contains("Safari") {
            continue;
        }
        if let Some(pos) = line.find("Safari ") {
            let after = &line[pos + 7..];
            let version_str: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let parts: Vec<&str> = version_str.splitn(3, '.').collect();
            if parts.len() >= 2 {
                if let (Ok(mj), Ok(mn)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    if mj >= 16 {
                        return Some((mj, mn));
                    }
                }
            }
        }
    }
    None
}

async fn fetch_safari_version(client: &reqwest::Client) -> Result<SafariVersionInfo> {
    let rss_text = client
        .get("https://developer.apple.com/news/releases/rss/releases.rss")
        .send()
        .await?
        .text()
        .await?;

    let (major, minor) = parse_safari_version(&rss_text).unwrap_or((18, 0));
    let webkit_build = webkit_build_for(major, minor);
    Ok(SafariVersionInfo {
        version: format!("{}.{}", major, minor),
        major,
        minor,
        webkit_build,
    })
}

async fn fetch_chrome_cves(client: &reqwest::Client) -> (bool, Vec<String>) {
    let Ok(resp) = client
        .get("https://chromereleases.googleblog.com/feeds/posts/default?max-results=3")
        .send()
        .await
    else {
        return (false, vec![]);
    };
    let Ok(text) = resp.text().await else {
        return (false, vec![]);
    };

    let mut cves: Vec<String> = Vec::new();
    let mut is_critical = false;

    for word in text.split_ascii_whitespace() {
        let clean: String = word
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect();
        if clean.starts_with("CVE-") && clean.len() >= 13 {
            if !cves.contains(&clean) {
                cves.push(clean);
            }
        }
    }
    if text.contains("Critical") {
        is_critical = true;
    }
    cves.truncate(20);
    (is_critical, cves)
}

pub async fn refresh(prev_cache: &SentinelCache) -> SentinelCache {
    let client = match make_client() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!("sentinel: failed to build HTTP client: {}", err);
            let mut c = prev_cache.clone();
            c.fail_streak += 1;
            c.refresh_ok = false;
            return c;
        }
    };

    let mut new_cache = prev_cache.clone();
    let mut ok = true;

    let mut chrome_versions = Vec::new();
    for &(platform_key, display_name) in CHROME_PLATFORMS {
        match fetch_chrome_stable(&client, platform_key, display_name).await {
            Ok(info) => {
                tracing::info!(
                    "sentinel: Chrome {} stable → {}",
                    display_name,
                    info.version
                );
                chrome_versions.push(info);
            }
            Err(err) => {
                tracing::warn!("sentinel: Chrome {} fetch failed: {}", display_name, err);
                ok = false;
                if let Some(prev) = prev_cache
                    .chrome
                    .iter()
                    .find(|v| v.platform == display_name)
                {
                    chrome_versions.push(prev.clone());
                }
            }
        }
    }

    match fetch_chrome_extended(&client).await {
        Ok(ext) => {
            tracing::info!("sentinel: Chrome Extended Stable → {}", ext.version);
            new_cache.chrome_extended = Some(ext);
        }
        Err(err) => {
            tracing::warn!("sentinel: Chrome Extended fetch failed: {}", err);
            ok = false;
        }
    }

    match fetch_safari_version(&client).await {
        Ok(safari) => {
            tracing::info!(
                "sentinel: Safari → {} (WebKit {})",
                safari.version,
                safari.webkit_build
            );
            new_cache.safari = Some(safari);
        }
        Err(err) => {
            tracing::warn!("sentinel: Safari fetch failed: {}", err);
            ok = false;
        }
    }

    let (cve_critical, cves) = fetch_chrome_cves(&client).await;
    if !cves.is_empty() {
        tracing::info!(
            "sentinel: CVE sweep → {} entries, critical={}",
            cves.len(),
            cve_critical
        );
    }

    let prev_major = prev_cache.prev_chrome_major;
    let new_major = chrome_versions
        .iter()
        .find(|v| v.platform == "windows")
        .map(|v| v.major)
        .unwrap_or(prev_major);

    if !chrome_versions.is_empty() {
        new_cache.chrome = chrome_versions;
    }
    new_cache.prev_chrome_major = new_major;
    new_cache.cve_critical = cve_critical;
    new_cache.recent_cves = cves;
    new_cache.last_refresh = unix_now();
    new_cache.refresh_ok = ok;
    new_cache.fail_streak = if ok { 0 } else { prev_cache.fail_streak + 1 };

    if prev_major > 0 && new_major > prev_major {
        tracing::info!(
            "sentinel: Chrome major version upgrade detected: {} → {}",
            prev_major,
            new_major
        );
    }

    new_cache
}

// token comes from AppState::shutdown_token; cancelling it (main window
// destroyed) exits the loop promptly instead of waiting out the poll sleep.
pub async fn run_sentinel_loop(
    app_handle: tauri::AppHandle,
    initial_delay_s: u64,
    token: tokio_util::sync::CancellationToken,
) {
    if initial_delay_s > 0 {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay_s)) => {},
            _ = token.cancelled() => { return; },
        }
    }

    loop {
        let new_cache = {
            let prev = app_handle
                .try_state::<crate::state::AppState>()
                .map(|st| st.sentinel.lock().unwrap().clone())
                .unwrap_or_default();
            refresh(&prev).await
        };

        let prev_major = {
            app_handle
                .try_state::<crate::state::AppState>()
                .map(|st| st.sentinel.lock().unwrap().prev_chrome_major)
                .unwrap_or(0)
        };
        let new_major = new_cache
            .chrome
            .iter()
            .find(|v| v.platform == "windows")
            .map(|v| v.major)
            .unwrap_or(0);

        if let Some(st) = app_handle.try_state::<crate::state::AppState>() {
            *st.sentinel.lock().unwrap() = new_cache.clone();

            set_global_cache(new_cache.clone());

            if let Ok(json) = serde_json::to_string(&new_cache) {
                let _ = st.db.set_setting("sentinel_cache", &json);
            }
        }

        if prev_major > 0 && new_major > prev_major {
            let _ = app_handle.emit(
                "diatom:engine-upgrade",
                serde_json::json!({
                    "prev_major": prev_major,
                    "new_major": new_major,
                    "chrome_version": new_cache.chrome_win().map(|v| v.version.as_str()).unwrap_or("")
                }),
            );
        }
        if new_cache.cve_critical {
            let _ = app_handle.emit(
                "diatom:cve-critical",
                serde_json::json!({
                    "cves": new_cache.recent_cves,
                    "chrome_version": new_cache.chrome_win().map(|v| v.version.as_str()).unwrap_or("")
                }),
            );
        }

        // Piggybacks on this cycle so no extra background task is needed.
        // AXIOMS.md §Permanent Black Zone: no auto-update, but a critical
        // WebView CVE must still surface prominently to the user (P2 §9.2).
        check_diatom_update(&app_handle, &new_cache).await;

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_S)) => {},
            _ = token.cancelled() => {
                tracing::info!("sentinel: shutdown signal received — exiting loop");
                return;
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SentinelStatus {
    pub cache: SentinelCache,
    pub ua_chrome_win: String,
    pub ua_safari_mac: String,
    pub lab_active: bool,
    pub next_refresh_in_s: u64,
}

impl SentinelStatus {
    pub fn from_cache(cache: &SentinelCache, lab_active: bool) -> Self {
        let ua_chrome_win = cache.chrome_ua_windows();
        let ua_safari_mac = cache.safari_ua_macos();
        let elapsed = unix_now().saturating_sub(cache.last_refresh);
        let next_refresh_in_s = POLL_INTERVAL_S.saturating_sub(elapsed);
        SentinelStatus {
            cache: cache.clone(),
            ua_chrome_win,
            ua_safari_mac,
            lab_active,
            next_refresh_in_s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webkit_build_known_version() {
        assert_eq!(webkit_build_for(18, 0), "619.1.15");
        assert_eq!(webkit_build_for(17, 6), "605.1.15");
    }

    #[test]
    fn webkit_build_unknown_minor_falls_back_to_same_major() {
        let build = webkit_build_for(18, 9);
        assert!(build.starts_with("619."), "expected 619.x.15, got: {build}");
    }

    #[test]
    fn webkit_build_unknown_major_returns_stale_marker() {
        let build = webkit_build_for(99, 0);
        assert!(
            build.contains("SENTINEL_STALE"),
            "unknown major must produce SENTINEL_STALE marker, got: {build}"
        );
    }

    #[test]
    fn parse_safari_rss_standard_title() {
        let rss = r#"<title>Safari 18.2 Release Notes</title>"#;
        assert_eq!(parse_safari_version(rss), Some((18, 2)));
    }

    #[test]
    fn parse_safari_rss_combined_title() {
        let rss = r#"<title>macOS Sequoia 15.2 – Safari 18.2</title>"#;
        assert_eq!(parse_safari_version(rss), Some((18, 2)));
    }

    #[test]
    fn chrome_ua_synthesis() {
        let mut cache = SentinelCache::default();
        cache.chrome.push(ChromeVersionInfo {
            version: "124.0.6367.207".to_owned(),
            major: 124,
            platform: "windows".to_owned(),
            channel: "stable".to_owned(),
        });
        let ua = cache.chrome_ua_windows();
        assert!(
            ua.contains("Chrome/124.0.6367.207"),
            "UA should use full version: {ua}"
        );
        assert!(ua.contains("Windows NT 10.0"));
    }

    #[test]
    fn safari_ua_synthesis_from_cache() {
        let mut cache = SentinelCache::default();
        cache.safari = Some(SafariVersionInfo {
            version: "17.6".to_owned(),
            major: 17,
            minor: 6,
            webkit_build: "605.1.15".to_owned(),
        });
        let ua = cache.safari_ua_macos();
        assert!(ua.contains("Version/17.6"));
        assert!(ua.contains("AppleWebKit/605.1.15"));
    }

    #[test]
    fn cache_freshness() {
        let mut cache = SentinelCache::default();
        assert!(!cache.is_fresh());
        cache.last_refresh = unix_now();
        assert!(cache.is_fresh());
    }
}

// Diatom never auto-updates (no consent, no background download) — but a
// critical WebView CVE with a <48h exploit window means the user needs to
// know loudly. This checks GitHub for a newer tag and emits an event the JS
// layer turns into a banner (or, if critical and overdue, a nav block); the
// user still initiates the download themselves. Request sends only Accept —
// no Diatom UA, no tokens.

const DIATOM_RELEASES_URL: &str =
    "https://api.github.com/repos/diatom-browser/diatom/releases/latest";

/// Days before a critical-CVE update prompt escalates to a navigation block.
pub const CRITICAL_UPDATE_BLOCK_DAYS: u64 = 3;

/// How many hours between self-update checks (independent of POLL_INTERVAL_S).
const UPDATE_CHECK_INTERVAL_H: u64 = 6;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateCheckState {
    pub latest_version: String,
    pub update_available: bool,
    /// 0 = never checked.
    pub last_check: u64,
    pub critical: bool,
    pub critical_since: u64,
}

impl UpdateCheckState {
    pub fn is_stale(&self) -> bool {
        unix_now().saturating_sub(self.last_check) >= UPDATE_CHECK_INTERVAL_H * 3_600
    }

    pub fn should_block_navigation(&self) -> bool {
        self.critical
            && self.critical_since > 0
            && unix_now().saturating_sub(self.critical_since) >= CRITICAL_UPDATE_BLOCK_DAYS * 86_400
    }
}

// Called every sentinel poll cycle; rate-limits itself via UpdateCheckState::is_stale.
pub async fn check_diatom_update(app_handle: &tauri::AppHandle, sentinel_cache: &SentinelCache) {
    let mut state = app_handle
        .try_state::<crate::state::AppState>()
        .and_then(|st| {
            st.db
                .get_setting("sentinel_update_check")
                .and_then(|s| serde_json::from_str::<UpdateCheckState>(&s).ok())
        })
        .unwrap_or_default();

    if !state.is_stale() {
        if state.update_available {
            emit_update_event(app_handle, &state, sentinel_cache.cve_critical);
        }
        return;
    }

    let running = env!("CARGO_PKG_VERSION");

    let client = match make_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("sentinel update-check: could not build client: {e}");
            return;
        }
    };

    // Generic Accept header only — no Diatom UA or identifier sent.
    let resp = match client
        .get(DIATOM_RELEASES_URL)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("sentinel update-check: request failed: {e}");
            return;
        }
    };

    #[derive(serde::Deserialize)]
    struct GhRelease {
        tag_name: String,
    }

    let tag = match resp.json::<GhRelease>().await {
        Ok(r) => r.tag_name,
        Err(e) => {
            tracing::debug!("sentinel update-check: parse failed: {e}");
            return;
        }
    };

    let latest = tag.trim_start_matches('v').to_owned(); // GitHub tags are "v0.16.0"
    let newer = semver_gt(&latest, running);

    let now = unix_now();
    state.last_check = now;
    state.latest_version = latest.clone();
    state.update_available = newer;

    if newer && sentinel_cache.cve_critical {
        if !state.critical {
            state.critical = true;
            state.critical_since = now; // starts the block-countdown from here
        }
    } else {
        state.critical = false;
        state.critical_since = 0;
    }

    if let Some(st) = app_handle.try_state::<crate::state::AppState>() {
        if let Ok(json) = serde_json::to_string(&state) {
            let _ = st.db.set_setting("sentinel_update_check", &json);
        }

        // commands.rs reads this flag to gate navigation.
        if state.should_block_navigation() {
            let _ = st.db.set_setting("update_block_navigation", "1");
        } else {
            let _ = st.db.set_setting("update_block_navigation", "0");
        }
    }

    if newer {
        emit_update_event(app_handle, &state, sentinel_cache.cve_critical);
    }
}

fn emit_update_event(app_handle: &tauri::AppHandle, state: &UpdateCheckState, cve: bool) {
    let _ = app_handle.emit(
        "diatom:update-available",
        serde_json::json!({
            "version":            state.latest_version,
            "critical":           cve && state.critical,
            "critical_since":     state.critical_since,
            "block_after_days":   CRITICAL_UPDATE_BLOCK_DAYS,
            "should_block_now":   state.should_block_navigation(),
        }),
    );
}

// MAJOR.MINOR.PATCH only; pre-release suffixes are ignored (treated as equal).
fn semver_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> [u32; 3] {
        let mut parts = s.split('-').next().unwrap_or(s).splitn(4, '.');
        [
            parts.next().and_then(|p| p.parse().ok()).unwrap_or(0),
            parts.next().and_then(|p| p.parse().ok()).unwrap_or(0),
            parts.next().and_then(|p| p.parse().ok()).unwrap_or(0),
        ]
    };
    parse(a) > parse(b)
}

#[cfg(test)]
mod update_tests {
    use super::*;

    #[test]
    fn semver_gt_basic() {
        assert!(semver_gt("0.16.0", "0.15.1"));
        assert!(semver_gt("1.0.0", "0.99.9"));
        assert!(!semver_gt("0.15.1", "0.16.0"));
        assert!(!semver_gt("0.15.0", "0.15.0"));
    }

    #[test]
    fn semver_gt_ignores_prerelease() {
        assert!(!semver_gt("0.16.0-beta.1", "0.16.0"));
    }

    #[test]
    fn update_state_stale_when_never_checked() {
        let s = UpdateCheckState::default();
        assert!(s.is_stale());
    }

    #[test]
    fn update_state_not_stale_after_recent_check() {
        let mut s = UpdateCheckState::default();
        s.last_check = unix_now();
        assert!(!s.is_stale());
    }

    #[test]
    fn block_navigation_after_critical_threshold() {
        let mut s = UpdateCheckState::default();
        s.critical = true;
        s.critical_since = unix_now() - (CRITICAL_UPDATE_BLOCK_DAYS + 1) * 86_400;
        assert!(s.should_block_navigation());
    }

    #[test]
    fn no_block_if_not_critical() {
        let s = UpdateCheckState {
            critical: false,
            ..Default::default()
        };
        assert!(!s.should_block_navigation());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    #[default]
    Plugged,
    Battery,
    BatteryCritical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerBudget {
    pub state: PowerState,
    pub battery_pct: Option<u8>,
    pub sentinel_interval_secs: u64,
    pub tab_budget_interval_secs: u64,
    pub pir_enabled: bool,
    pub decoy_enabled: bool,
}

impl Default for PowerBudget {
    fn default() -> Self {
        PowerBudget {
            state: PowerState::Plugged,
            battery_pct: None,
            sentinel_interval_secs: POLL_INTERVAL_S,
            tab_budget_interval_secs: 600,
            pir_enabled: true,
            decoy_enabled: false,
        }
    }
}

pub fn power_budget_current() -> PowerBudget {
    // Any failure (desktop, no battery, permission denied) falls back to Plugged.
    let (state, pct) = read_battery_state();

    let (sentinel_secs, tab_secs, pir, decoy) = match state {
        PowerState::Plugged => (POLL_INTERVAL_S, 600, true, false),
        PowerState::Battery => (POLL_INTERVAL_S * 3, 1200, true, false),
        PowerState::BatteryCritical => (POLL_INTERVAL_S * 12, 3600, false, false),
    };

    PowerBudget {
        state,
        battery_pct: pct,
        sentinel_interval_secs: sentinel_secs,
        tab_budget_interval_secs: tab_secs,
        pir_enabled: pir,
        decoy_enabled: decoy,
    }
}

// All errors collapse to (Plugged, None) — conservative default, not a real read.
fn read_battery_state() -> (PowerState, Option<u8>) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") {
            for entry in entries.flatten() {
                let base = entry.path();
                let status_path = base.join("status");
                let capacity_path = base.join("capacity");
                let Ok(status) = std::fs::read_to_string(&status_path) else {
                    continue;
                };
                let status = status.trim().to_lowercase();
                if status == "discharging" || status == "not charging" {
                    let pct = std::fs::read_to_string(&capacity_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u8>().ok());
                    let power_state = match pct {
                        Some(p) if p < 10 => PowerState::BatteryCritical,
                        _ => PowerState::Battery,
                    };
                    return (power_state, pct);
                }
            }
        }
    }

    // No macOS/Windows battery probe implemented yet — falls through to Plugged.
    (PowerState::Plugged, None)
}
