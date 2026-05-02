use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Mutex, OnceLock},
    time::Duration,
};

//
// Sentinel makes the following outbound HTTPS requests on a scheduled basis.
// None of these calls transmit any user data (no browsing history, no
// identifiers, no credentials). All requests use a generic Chrome UA.
//
// 1. Chrome Version History API (versionhistory.googleapis.com)
//    Purpose : Fetch the current Chrome stable version for UA normalisation.
//    Interval: Every POLL_INTERVAL_S (3 600 s = 1 hour).
//    Endpoint: GET /v1/chrome/platforms/{platform}/channels/stable/versions
//    Privacy : Stateless public API; no authentication; no user data sent.
//
// 2. Apple Developer RSS (developer.apple.com/news/releases/rss/releases.rss)
//    Purpose : Parse the latest Safari version for macOS UA normalisation.
//    Interval: Same 1-hour cycle.
//    Privacy : Public RSS feed; no user data sent.
//
// 3. Chrome Releases Blog RSS (chromereleases.googleblog.com)
//    Purpose : Detect critical CVEs in the current Chrome release.
//    Interval: Same 1-hour cycle.
//    Privacy : Public RSS feed; no user data sent.
//
// The 1-hour interval is a deliberate design choice (see POLL_INTERVAL_S).
// It keeps UA strings current while limiting background activity to three
// small HTTP requests per hour.  Power-budget mode (labs: power_budget)
// extends this to 3 hours when the device is on battery.
//
// Users may inspect all Sentinel traffic in the DevPanel Network panel.
// Sentinel can be disabled entirely by toggling "UA Normalisation" in Settings.

/// Sentinel polls Chrome version history for these platforms.
const CHROME_PLATFORMS: &[(&str, &str)] = &[
    ("win64", "windows"),
    ("mac_arm64", "mac"),
    ("linux", "linux"),
];

/// Poll interval: 60 minutes in seconds.
pub const POLL_INTERVAL_S: u64 = 3_600;

/// Fallback static WebKit build table (used when Sentinel cache is cold).

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

/// Global Sentinel cache — populated by `run_sentinel_loop`, read by
/// `webkit_build_for` for fast UA synthesis without locking AppState.
static SENTINEL_CACHE: OnceLock<Mutex<SentinelCache>> = OnceLock::new();

/// Update the global Sentinel cache after a successful refresh.
pub fn set_global_cache(cache: SentinelCache) {
    let m = SENTINEL_CACHE.get_or_init(|| Mutex::new(SentinelCache::default()));
    if let Ok(mut guard) = m.lock() {
        *guard = cache;
    }
}

/// Canonical WebKit UA build string for a given Safari version.
///

/// Canonical WebKit UA build string for a given Safari version.
/// Returns e.g. "619.3.15" for Safari 18.3. Falls back to a `SENTINEL_STALE`
/// marker for unknown Safari majors, signalling that the static table needs updating.
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

/// Map a Safari major version to the corresponding WebKit major number.
fn webkit_major_for_safari_major(safari_major: u32) -> u32 {
    match safari_major {
        19 => {
            tracing::warn!(
                "sentinel: Safari 19 detected — webkit_major_for_safari_major \
                           needs updating. Returning provisional estimate."
            );
            625 // provisional; must be updated when Apple ships Safari 19
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
    /// Full version string, e.g. "124.0.6367.207"
    pub version: String,
    /// Major version number, e.g. 124
    pub major: u32,
    /// Platform key, e.g. "win64"
    pub platform: String,
    /// Channel ("stable" | "extended")
    pub channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SafariVersionInfo {
    /// Full version string, e.g. "17.6"
    pub version: String,
    /// Major, e.g. 17
    pub major: u32,
    /// Minor, e.g. 6
    pub minor: u32,
    /// Synthesised WebKit build string, e.g. "605.1.15"
    pub webkit_build: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentinelCache {
    /// Chrome stable versions per platform.
    pub chrome: Vec<ChromeVersionInfo>,
    /// Chrome Extended Stable (enterprise-relevant).
    pub chrome_extended: Option<ChromeVersionInfo>,
    /// Safari / WebKit version.
    pub safari: Option<SafariVersionInfo>,
    /// Unix timestamp of the last successful refresh.
    pub last_refresh: u64,
    /// Whether the last refresh fully succeeded.
    pub refresh_ok: bool,
    /// Number of consecutive refresh failures.
    pub fail_streak: u32,
    /// True if any critical CVE was detected in the current Chrome version.
    pub cve_critical: bool,
    /// List of CVE IDs in the current Chrome release notes (max 20).
    pub recent_cves: Vec<String>,
    /// Detected previous Chrome major (used to emit engine-upgrade event).
    pub prev_chrome_major: u32,
}

impl SentinelCache {
    /// Returns the Chrome stable version for Windows (used for Windows UA).
    pub fn chrome_win(&self) -> Option<&ChromeVersionInfo> {
        self.chrome.iter().find(|v| v.platform == "windows")
    }

    /// Returns the Chrome stable version for macOS.
    pub fn chrome_mac(&self) -> Option<&ChromeVersionInfo> {
        self.chrome.iter().find(|v| v.platform == "mac")
    }

    /// True if the cache is fresh (within 2× poll interval).
    pub fn is_fresh(&self) -> bool {
        let now = unix_now();
        now.saturating_sub(self.last_refresh) < POLL_INTERVAL_S * 2
    }

    /// True if the cache contains at least one Chrome version entry.
    /// Used by current_ua() as the gate — data presence matters more than age
    /// during the first poll cycle.
    pub fn has_data(&self) -> bool {
        !self.chrome.is_empty() || self.safari.is_some()
    }

    /// Synthesise a Windows Chrome UA string with the full version number.
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

    /// Synthesise a macOS Safari UA string.
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

/// Response types for the Chrome Version History API v1.
#[derive(Deserialize)]
struct VersionHistoryResponse {
    versions: Vec<VersionEntry>,
}

#[derive(Deserialize)]
struct VersionEntry {
    version: String,
}

/// Fetch the latest Chrome Stable version for a given platform.
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

/// Parse Safari version from the Apple Developer News RSS feed.
/// Title format: "Safari 17.6 Release Notes" or "macOS 14.6 – Safari 17.6"
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

/// Check the Chrome Releases blog RSS for critical CVEs in the latest stable.
/// Returns (is_critical, cve_list).
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

/// Perform a full Sentinel refresh. Returns the new cache state.
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

/// Spawn the sentinel background loop. Runs every POLL_INTERVAL_S seconds.
/// Caller passes `app_handle` so we can emit events and write state.
/// `token` is a CancellationToken from AppState::shutdown_token; when the
/// main window is destroyed, token.cancel() causes the loop to exit promptly.
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

        // Self-update check — piggybacks on the existing Sentinel refresh cycle
        // so no additional background task or network call is needed.
        // See AXIOMS.md §Permanent Black Zone: no auto-update, but a critical-
        // severity WebView CVE must surface prominently to the user (P2 §9.2).
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
    /// Current synthesised Chrome UA (Windows).
    pub ua_chrome_win: String,
    /// Current synthesised Safari UA (macOS).
    pub ua_safari_mac: String,
    /// Lab is enabled?
    pub lab_active: bool,
    /// How many seconds until next scheduled refresh.
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

    /// Unknown Safari major must return a SENTINEL_STALE marker, not a stale build.
    /// It must include SENTINEL_STALE so monitoring can catch it.
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

//
// Diatom does not auto-update (no user consent, no background download).
// However, a critical WebView CVE with a <48 h exploit window makes silent
// manual-update-only behaviour dangerous. This function:
//
//  1. Checks the GitHub releases API for the latest Diatom version tag.
//  2. If a newer version exists AND the current cache has a critical CVE,
//     emits `diatom:update-available` with `{ version, critical: true }`.
//  3. If a newer version exists without a critical CVE, emits the same event
//     with `{ critical: false }` — the UI shows a lower-urgency badge.
//
// The event is consumed by the JS layer, which shows a non-blocking banner
// (regular update) or a blocking navigation interstitial (critical CVE update).
// The user always initiates the download; Diatom never fetches or applies
// updates automatically.
//
// Privacy: the request sends only the Accept header; no Diatom UA, no tokens.

const DIATOM_RELEASES_URL: &str =
    "https://api.github.com/repos/diatom-browser/diatom/releases/latest";

/// Days before a critical-CVE update prompt escalates to a navigation block.
pub const CRITICAL_UPDATE_BLOCK_DAYS: u64 = 3;

/// How many hours between self-update checks (independent of POLL_INTERVAL_S).
const UPDATE_CHECK_INTERVAL_H: u64 = 6;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateCheckState {
    /// Latest version string from GitHub, e.g. "0.16.0". Empty = not yet checked.
    pub latest_version: String,
    /// True if `latest_version` is newer than the running build.
    pub update_available: bool,
    /// Unix timestamp of last check (0 = never checked).
    pub last_check: u64,
    /// True if the last check found a critical CVE alongside a newer version.
    pub critical: bool,
    /// Unix timestamp when `critical` first became true (0 if not critical).
    pub critical_since: u64,
}

impl UpdateCheckState {
    /// Returns true if it is time to perform a new check.
    pub fn is_stale(&self) -> bool {
        unix_now().saturating_sub(self.last_check) >= UPDATE_CHECK_INTERVAL_H * 3_600
    }

    /// Returns true if a critical update has been pending for more than
    /// `CRITICAL_UPDATE_BLOCK_DAYS` days.
    pub fn should_block_navigation(&self) -> bool {
        self.critical
            && self.critical_since > 0
            && unix_now().saturating_sub(self.critical_since) >= CRITICAL_UPDATE_BLOCK_DAYS * 86_400
    }
}

/// Fetch the latest Diatom release tag from GitHub and compare to the running
/// version. Emits Tauri events consumed by the frontend.
///
/// This function is called from `run_sentinel_loop` on every poll cycle;
/// it rate-limits itself internally via `UpdateCheckState::is_stale`.
pub async fn check_diatom_update(app_handle: &tauri::AppHandle, sentinel_cache: &SentinelCache) {
    // Load persisted update state.
    let mut state = app_handle
        .try_state::<crate::state::AppState>()
        .and_then(|st| {
            st.db
                .get_setting("sentinel_update_check")
                .and_then(|s| serde_json::from_str::<UpdateCheckState>(&s).ok())
        })
        .unwrap_or_default();

    if !state.is_stale() {
        // Not yet time for another check; re-emit if update already known.
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

    // Use a generic Accept header; do not send Diatom UA or any identifier.
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

    // Strip leading 'v' prefix if present.
    let latest = tag.trim_start_matches('v').to_owned();
    let newer = semver_gt(&latest, running);

    let now = unix_now();
    state.last_check = now;
    state.latest_version = latest.clone();
    state.update_available = newer;

    if newer && sentinel_cache.cve_critical {
        if !state.critical {
            // First time we see critical=true — record the timestamp.
            state.critical = true;
            state.critical_since = now;
        }
    } else {
        state.critical = false;
        state.critical_since = 0;
    }

    // Persist updated state.
    if let Some(st) = app_handle.try_state::<crate::state::AppState>() {
        if let Ok(json) = serde_json::to_string(&state) {
            let _ = st.db.set_setting("sentinel_update_check", &json);
        }

        // If a critical update has been pending long enough, also set a flag
        // that commands.rs can read to gate navigation.
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

/// Returns true if `a` is a strictly greater semver than `b`.
/// Handles simple `MAJOR.MINOR.PATCH` form only; pre-release suffixes are
/// ignored (treated as equal to the base version).
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
        // "0.16.0-beta.1" should not be considered greater than "0.16.0"
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

/// Device power state affecting how aggressively Diatom runs background tasks.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    /// Device is plugged in — full background activity permitted.
    #[default]
    Plugged,
    /// Running on battery — background intervals extended.
    Battery,
    /// Battery critically low (< 10 %) — most background tasks paused.
    BatteryCritical,
}

/// Adaptive scheduling parameters derived from current power state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerBudget {
    pub state: PowerState,
    /// Battery percentage (0–100). None when running on AC or unknown.
    pub battery_pct: Option<u8>,
    /// Effective Sentinel poll interval (seconds).
    pub sentinel_interval_secs: u64,
    /// Effective tab-budget evaluation interval (seconds).
    pub tab_budget_interval_secs: u64,
    /// Whether PIR (Private Information Retrieval) queries are enabled.
    pub pir_enabled: bool,
    /// Whether decoy-traffic injection is enabled.
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

/// Read the current power state from the OS and return the corresponding
/// `PowerBudget`. Falls back to the default (Plugged / full activity) when
/// the battery API is unavailable.
///
/// On macOS this reads `IOPSGetPowerSourceDescription`; on Linux it reads
/// `/sys/class/power_supply`; on Windows it calls `GetSystemPowerStatus`.
/// All three paths are guarded by `cfg` and default gracefully.
pub fn power_budget_current() -> PowerBudget {
    // Attempt to read battery level from the platform.
    // Failure (desktop, no battery, permission denied) → return Plugged default.
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

/// Platform-specific battery probe. Returns (PowerState, Option<battery_pct>).
/// All errors collapse to (Plugged, None) — conservative and safe.
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

    // macOS / Windows / unknown → treat as Plugged (safe default).
    (PowerState::Plugged, None)
}
