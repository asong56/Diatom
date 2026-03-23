// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/commands.rs  — v0.9.0
// All Tauri IPC commands. Thin wrappers only; business logic lives in modules.
// ─────────────────────────────────────────────────────────────────────────────

use crate::{
    blocker,
    db::{BundleRow, DomBlock, HistoryRow, KnowledgePack, new_id, unix_now, week_start},
    dom_crusher,
    echo::{self, EchoOutput, PrevSpectrum},
    freeze, labs, slm,
    state::AppState,
    tab_budget::{self, TabBudget, TabBudgetConfig},
    tabs::{SleepState, TabsState},
    threat,
    totp::TotpCode,
    trust::TrustProfile,
    war_report::{self, WarReport},
    zen::ZenConfig,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::AtomicBool};
use tauri::{AppHandle, Emitter, State};

type R<T> = Result<T, String>;
fn e(err: impl std::fmt::Display) -> String {
    err.to_string()
}

// ── Navigation ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct NavResult {
    pub clean_url: String,
    pub blocked: bool,
    pub stub: Option<&'static str>,
    pub zen_blocked: bool,
    pub zen_category: Option<&'static str>,
}

#[tauri::command]
pub fn cmd_preprocess_url(url: String, s: State<'_, AppState>) -> NavResult {
    let upgraded = blocker::upgrade_https_owned(&url);
    let clean = blocker::strip_params(&upgraded);
    let blocked = blocker::is_blocked(&clean);
    let stub = if blocked {
        blocker::stub_for(&clean)
    } else {
        None
    };
    let domain = crate::utils::domain_of(&clean);
    let zen = s.zen.lock().unwrap();
    let zen_cat = zen.blocks_domain(&domain);
    if blocked {
        let ws = week_start(unix_now());
        let _ = s.db.increment_block_count(ws);
        // [FIX-11-warreport] Record estimated time saved per blocked request.
        // Conservative heuristic: 0.9 s per blocked tracker (matches war_report constant).
        let _ = s.db.add_time_saved(ws, 0.9 / 60.0);
    }
    NavResult {
        clean_url: clean,
        blocked,
        stub,
        zen_blocked: zen_cat.is_some(),
        zen_category: zen_cat,
    }
}

#[derive(Serialize)]
pub struct FetchResult {
    pub url: String,
    pub status: u16,
    pub body: String,
}

#[tauri::command]
pub async fn cmd_fetch(url: String, method: Option<String>) -> R<FetchResult> {
    // [FIX-03] Block SSRF: reject requests to private/loopback addresses
    if is_private_url(&url) {
        return Err(format!("blocked: private address not permitted: {url}"));
    }
    if blocker::is_blocked(&url) {
        return Err(format!("blocked: {url}"));
    }
    let clean = blocker::strip_params(&blocker::upgrade_https_owned(&url));
    let client = reqwest::Client::builder()
        .default_headers(blocker::clean_headers(&clean, None))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(e)?;
    let req = match method.as_deref().unwrap_or("GET") {
        "POST" => client.post(&clean),
        _ => client.get(&clean),
    };
    let resp = req.send().await.map_err(e)?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(e)?;
    Ok(FetchResult { url: clean, status, body })
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_tab_create(url: String, s: State<'_, AppState>) -> R<crate::tabs::Tab> {
    let id = new_id();
    let ws = s.workspace_id();
    let tab = s.tabs.lock().unwrap().create(&id, &ws, &url).clone();
    Ok(tab)
}

#[tauri::command]
pub fn cmd_tab_close(tab_id: String, s: State<'_, AppState>) {
    s.tabs.lock().unwrap().close(&tab_id);
}

#[tauri::command]
pub fn cmd_tab_activate(tab_id: String, s: State<'_, AppState>) {
    s.tabs.lock().unwrap().activate(&tab_id);
}

#[tauri::command]
pub fn cmd_tab_update(
    tab_id: String,
    url: Option<String>,
    title: Option<String>,
    dwell_ms: Option<u64>,
    s: State<'_, AppState>,
) -> R<()> {
    let ws = s.workspace_id();
    let url_c = url.clone();
    {
        let mut tabs = s.tabs.lock().unwrap();
        if let Some(t) = tabs.get_mut(&tab_id) {
            if let Some(u) = &url {
                t.url = u.clone();
            }
            if let Some(ti) = &title {
                t.title = ti.clone();
            }
        }
    }
    if let (Some(u), Some(ti)) = (url_c, title) {
        s.db.upsert_history(&ws, &u, &ti, dwell_ms.unwrap_or(0))
            .map_err(e)?;
    }
    Ok(())
}

#[tauri::command]
pub fn cmd_tab_sleep(tab_id: String, deep: bool, snapshot: Option<String>, s: State<'_, AppState>) {
    let mut tabs = s.tabs.lock().unwrap();
    if deep {
        let pre = snapshot.as_ref().map(|s| s.len()).unwrap_or(0);
        tabs.deep_sleep(&tab_id, snapshot.as_deref().unwrap_or("{}"));
        let post = tabs
            .get(&tab_id)
            .and_then(|t| t.zram.as_ref())
            .map(|z| z.len())
            .unwrap_or(0);
        let saved = (pre.saturating_sub(post)) as f64 / 1_048_576.0;
        if saved > 0.0 {
            let _ = s.db.add_ram_saved(week_start(unix_now()), saved);
        }
    } else {
        tabs.shallow_sleep(&tab_id);
    }
}

#[tauri::command]
pub fn cmd_tab_wake(tab_id: String, s: State<'_, AppState>) -> R<Option<String>> {
    let mut tabs = s.tabs.lock().unwrap();
    let snap = tabs.get(&tab_id).and_then(|t| t.decompress());
    if let Some(t) = tabs.get_mut(&tab_id) {
        t.sleep = SleepState::Awake;
        t.zram = None;
    }
    Ok(snap)
}

#[tauri::command]
pub fn cmd_tabs_state(s: State<'_, AppState>) -> TabsState {
    TabsState::from(&*s.tabs.lock().unwrap())
}

// ── Tab budget — v0.9.0 ───────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_tab_budget(screen_width: Option<u32>, s: State<'_, AppState>) -> R<TabBudget> {
    if let Some(w) = screen_width {
        *s.screen_width_px.lock().unwrap() = w;
    }
    let cfg = s.tab_budget_cfg.lock().unwrap().clone();
    let omega = s.tabs.lock().unwrap().avg_mem_weight();
    let count = s.tabs.lock().unwrap().count() as u32;
    let sw = *s.screen_width_px.lock().unwrap();
    Ok(tab_budget::compute_budget(&cfg, sw, omega, count))
}

#[tauri::command]
pub fn cmd_tab_budget_config_set(
    memory_ratio: Option<f64>,
    min_tabs: Option<u32>,
    max_tabs_hard: Option<u32>,
    screen_gravity: Option<bool>,
    golden_ratio: Option<bool>,
    s: State<'_, AppState>,
) -> R<()> {
    let mut cfg = s.tab_budget_cfg.lock().unwrap();
    if let Some(v) = memory_ratio {
        cfg.memory_ratio = v.clamp(0.05, 0.9);
    }
    if let Some(v) = min_tabs {
        cfg.min_tabs = v.max(1);
    }
    if let Some(v) = max_tabs_hard {
        cfg.max_tabs_hard = v.clamp(1, 50);
    }
    if let Some(v) = screen_gravity {
        cfg.screen_gravity = v;
    }
    if let Some(v) = golden_ratio {
        cfg.golden_ratio = v;
    }
    s.db.set_setting(
        "tab_budget_config",
        &serde_json::to_string(&*cfg).unwrap_or_default(),
    )
    .map_err(e)
}

// ── Workspaces ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub color: String,
    pub is_private: bool,
}

#[tauri::command]
pub fn cmd_workspaces_list(s: State<'_, AppState>) -> R<Vec<Workspace>> {
    let conn = s.db.0.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id,name,color,is_private FROM workspaces ORDER BY rowid")
        .map_err(e)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Workspace {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
                is_private: r.get::<_, i32>(3)? != 0,
            })
        })
        .map_err(e)?;
    rows.collect::<Result<_, _>>().map_err(e)
}

#[tauri::command]
pub fn cmd_workspace_create(
    name: String,
    color: String,
    is_private: bool,
    s: State<'_, AppState>,
) -> R<Workspace> {
    let id = new_id();
    s.db.0
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO workspaces(id,name,color,is_private,created_at) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![id, name, color, is_private as i32, unix_now()],
        )
        .map_err(e)?;
    Ok(Workspace {
        id,
        name,
        color,
        is_private,
    })
}

#[tauri::command]
pub fn cmd_workspace_switch(workspace_id: String, s: State<'_, AppState>) -> R<u64> {
    s.switch_workspace(&workspace_id).map_err(e)?;
    Ok(*s.noise_seed.lock().unwrap())
}

#[tauri::command]
pub fn cmd_workspace_fire(workspace_id: String, s: State<'_, AppState>) -> R<()> {
    s.fire_workspace(&workspace_id).map_err(e)
}

// ── History & bookmarks ───────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_history_search(
    query: String,
    limit: Option<u32>,
    s: State<'_, AppState>,
) -> R<Vec<HistoryRow>> {
    s.db.search_history(&s.workspace_id(), &query, limit.unwrap_or(20))
        .map_err(e)
}

#[tauri::command]
pub fn cmd_history_clear(s: State<'_, AppState>) -> R<()> {
    s.db.clear_history(&s.workspace_id()).map_err(e)
}

#[derive(Serialize, Deserialize)]
pub struct Bookmark {
    pub id: String,
    pub url: String,
    pub title: String,
    pub tags: Vec<String>,
    pub ephemeral: bool,
    pub expires_at: Option<i64>,
}

#[tauri::command]
pub fn cmd_bookmark_add(
    url: String,
    title: String,
    tags: Vec<String>,
    ephemeral: bool,
    s: State<'_, AppState>,
) -> R<Bookmark> {
    let id = new_id();
    let ws = s.workspace_id();
    let exp = if ephemeral {
        Some(unix_now() + 86_400)
    } else {
        None
    };
    let tj = serde_json::to_string(&tags).unwrap_or_default();
    s.db.0.lock().unwrap().execute(
        "INSERT INTO bookmarks(id,workspace_id,url,title,tags,ephemeral,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![id, ws, url, title, tj, ephemeral as i32, exp, unix_now()],
    ).map_err(e)?;
    Ok(Bookmark {
        id,
        url,
        title,
        tags,
        ephemeral,
        expires_at: exp,
    })
}

#[tauri::command]
pub fn cmd_bookmark_list(s: State<'_, AppState>) -> R<Vec<Bookmark>> {
    let ws = s.workspace_id();
    let conn = s.db.0.lock().unwrap();
    let now = unix_now();
    let mut stmt = conn.prepare(
        "SELECT id,url,title,tags,ephemeral,expires_at FROM bookmarks WHERE workspace_id=?1 AND (expires_at IS NULL OR expires_at>?2) ORDER BY created_at DESC"
    ).map_err(e)?;
    let rows = stmt
        .query_map(rusqlite::params![ws, now], |r| {
            let tags: Vec<String> =
                serde_json::from_str(&r.get::<_, String>(3).unwrap_or_default())
                    .unwrap_or_default();
            Ok(Bookmark {
                id: r.get(0)?,
                url: r.get(1)?,
                title: r.get(2)?,
                tags,
                ephemeral: r.get::<_, i32>(4)? != 0,
                expires_at: r.get(5)?,
            })
        })
        .map_err(e)?;
    rows.collect::<Result<_, _>>().map_err(e)
}

#[tauri::command]
pub fn cmd_bookmark_remove(id: String, s: State<'_, AppState>) -> R<()> {
    s.db.0
        .lock()
        .unwrap()
        .execute("DELETE FROM bookmarks WHERE id=?1", [id])
        .map(|_| ())
        .map_err(e)
}

// ── Settings ──────────────────────────────────────────────────────────────────

/// Keys that page JS is allowed to read via cmd_setting_get.
const SETTING_READ_ALLOWLIST: &[&str] = &[
    "quad9_enabled", "age_heuristic_enabled", "active_workspace_id",
    "slm_active_model", "tab_budget_config", "storage_budget",
];

/// Keys that page JS is allowed to write via cmd_setting_set.
/// Security-sensitive keys (master_key_hex, sentinel_cache, consent:*, lab_*)
/// must NOT appear here — they are managed exclusively by Rust command handlers.
const SETTING_WRITE_ALLOWLIST: &[&str] = &[
    "quad9_enabled", "age_heuristic_enabled",
    "slm_active_model", "tab_budget_config",
    "storage_budget",
];

#[tauri::command]
pub fn cmd_setting_get(key: String, s: State<'_, AppState>) -> Option<String> {
    // Allow prefixed keys for safe per-domain settings
    let safe = SETTING_READ_ALLOWLIST.contains(&key.as_str())
        || key.starts_with("compat_")
        || key.starts_with("prev_echo_");
    if safe { s.db.get_setting(&key) } else { None }
}

#[tauri::command]
pub fn cmd_setting_set(key: String, value: String, s: State<'_, AppState>) -> R<()> {
    // [FIX-06] Whitelist: page JS cannot overwrite sensitive meta keys
    if !SETTING_WRITE_ALLOWLIST.contains(&key.as_str()) {
        return Err(format!("setting key '{}' is not writable via IPC", key));
    }
    s.db.set_setting(&key, &value).map_err(e)
}

// ── Privacy ───────────────────────────────────────────────────────────────────

/// Returns true if the URL targets a private/loopback/link-local address.
/// Used to block SSRF via cmd_fetch. [FIX-03]
fn is_private_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else { return false };
    let host = parsed.host_str().unwrap_or("").to_lowercase();
    // Loopback / localhost
    if host == "localhost" || host == "127.0.0.1" || host == "::1" { return true; }
    if host.starts_with("127.") { return true; }
    // RFC-1918 private ranges
    if host.starts_with("10.")  { return true; }
    if host.starts_with("192.168.") { return true; }
    if let Some(rest) = host.strip_prefix("172.") {
        if let Some(octet) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            if (16..=31).contains(&octet) { return true; }
        }
    }
    // Link-local
    if host.starts_with("169.254.") { return true; }
    // file:// scheme
    if parsed.scheme() == "file" { return true; }
    false
}

#[tauri::command]
pub fn cmd_is_blocked(url: String) -> bool {
    blocker::is_blocked(&url)
}

#[tauri::command]
pub fn cmd_clean_url(url: String) -> String {
    blocker::strip_params(&blocker::upgrade_https_owned(&url))
}

/// [FIX-08-noise] cmd_noise_seed no longer returns the raw seed value.
/// It only triggers the noise-count increment and signals the frontend
/// to re-request the __DIATOM_INIT__ bundle via cmd_init_bundle.
#[tauri::command]
pub fn cmd_noise_seed(s: State<'_, AppState>) -> u64 {
    let _ = s.db.increment_noise_count(week_start(unix_now()), 1);
    // Return an opaque counter rather than the raw seed so page JS cannot
    // reconstruct the PRNG state.
    unix_now() as u64
}

// ── TOTP ──────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_totp_list(s: State<'_, AppState>) -> Vec<crate::totp::TotpEntry> {
    s.totp.lock().unwrap().list()
}
#[tauri::command]
pub fn cmd_totp_add(
    issuer: String,
    account: String,
    secret: String,
    domains: Vec<String>,
    s: State<'_, AppState>,
) -> R<crate::totp::TotpEntry> {
    s.totp
        .lock()
        .unwrap()
        .add(&issuer, &account, &secret, domains, &s.db, &s.master_key())
        .map_err(e)
}
#[tauri::command]
pub fn cmd_totp_generate(entry_id: String, s: State<'_, AppState>) -> R<TotpCode> {
    s.totp.lock().unwrap().generate(&entry_id).map_err(e)
}
#[tauri::command]
pub fn cmd_totp_match(domain: String, s: State<'_, AppState>) -> Vec<TotpCode> {
    s.totp.lock().unwrap().match_domain(&domain)
}
#[tauri::command]
pub fn cmd_totp_remove(entry_id: String, s: State<'_, AppState>) {
    s.totp.lock().unwrap().remove(&entry_id, &s.db);
}

// ── Trust ─────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_trust_get(domain: String, s: State<'_, AppState>) -> TrustProfile {
    s.trust.lock().unwrap().get(&domain)
}
#[tauri::command]
pub fn cmd_trust_set(domain: String, level: String, s: State<'_, AppState>) {
    s.trust.lock().unwrap().set(&domain, &level, "user", &s.db);
}
#[tauri::command]
pub fn cmd_trust_list(s: State<'_, AppState>) -> Vec<TrustProfile> {
    s.trust.lock().unwrap().all()
}

// ── RSS ───────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_rss_feeds(s: State<'_, AppState>) -> Vec<crate::rss::Feed> {
    s.rss.lock().unwrap().feeds()
}
#[tauri::command]
pub fn cmd_rss_add(
    url: String,
    category: Option<String>,
    s: State<'_, AppState>,
) -> crate::rss::Feed {
    s.rss.lock().unwrap().add(&url, category, &s.db)
}
#[tauri::command]
pub async fn cmd_rss_fetch(feed_id: String, s: State<'_, AppState>) -> R<u32> {
    let url = s
        .rss
        .lock()
        .unwrap()
        .feed_url(&feed_id)
        .ok_or("feed not found")?;
    let xml = cmd_fetch(url, None).await?.body;
    Ok(s.rss.lock().unwrap().ingest(&feed_id, &xml, &s.db))
}
#[tauri::command]
pub fn cmd_rss_items(
    feed_id: Option<String>,
    unread_only: bool,
    limit: usize,
    s: State<'_, AppState>,
) -> Vec<crate::rss::Item> {
    s.rss
        .lock()
        .unwrap()
        .items(feed_id.as_deref(), unread_only, limit)
}
#[tauri::command]
pub fn cmd_rss_mark_read(item_id: String, s: State<'_, AppState>) {
    s.rss.lock().unwrap().mark_read(&item_id, &s.db);
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_snapshot_save(tab_id: String, text: String, s: State<'_, AppState>) -> R<bool> {
    let h = blake3::hash(text.as_bytes()).to_hex().to_string();
    let conn = s.db.0.lock().unwrap();
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*)>0 FROM snapshots WHERE tab_id=?1 AND hash=?2",
            rusqlite::params![tab_id, h],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if !exists {
        conn.execute(
            "INSERT OR IGNORE INTO snapshots(tab_id,hash,text_body,saved_at) VALUES(?1,?2,?3,?4)",
            rusqlite::params![tab_id, h, text, unix_now()],
        )
        .map_err(e)?;
        return Ok(true);
    }
    Ok(false)
}

// ── System ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub version: String,
    pub ua: &'static str,
}

#[tauri::command]
pub fn cmd_system_info() -> SystemInfo {
    SystemInfo {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        ua: blocker::DIATOM_UA,
    }
}

#[tauri::command]
pub fn cmd_devtools_open(app: AppHandle) -> R<()> {
    #[cfg(debug_assertions)]
    if let Some(win) = app.get_webview_window("main") {
        win.open_devtools();
    }
    #[cfg(not(debug_assertions))]
    if std::env::var("DIATOM_DEVTOOLS").as_deref() == Ok("1") {
        if let Some(win) = app.get_webview_window("main") {
            win.open_devtools();
        }
    }
    Ok(())
}

// ── Echo ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ReadingEventPayload {
    pub url: String,
    pub dwell_ms: i64,
    pub scroll_px_s: f64,
    pub reading_mode: bool,
    pub tab_switches: i64,
}

#[tauri::command]
pub fn cmd_record_reading(evt: ReadingEventPayload, s: State<'_, AppState>) -> R<()> {
    let domain = crate::utils::domain_of(&evt.url);
    let ev = crate::db::ReadingEvent {
        id: new_id(),
        url: evt.url,
        domain,
        dwell_ms: evt.dwell_ms,
        scroll_px_s: evt.scroll_px_s,
        reading_mode: evt.reading_mode,
        tab_switches: evt.tab_switches,
        recorded_at: unix_now(),
    };
    s.db.insert_reading_event(&ev).map_err(e)
}

#[tauri::command]
pub fn cmd_echo_compute(s: State<'_, AppState>) -> R<EchoOutput> {
    // [FIX-07] Check consent before running persona analysis
    crate::compliance::check_consent("echo_analysis", &s.db)
        .map_err(|t| format!("consent_required:{t}"))?;

    let now = unix_now();
    let week_ago = now - 7 * 86_400;
    let week_iso = echo::iso_week(now);
    let events = s.db.reading_events_since(week_ago).map_err(e)?;
    let prev: PrevSpectrum =
        s.db.get_setting("prev_echo_spectrum")
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();
    let input = echo::aggregate(&events);
    let output = echo::compute(input, &prev, &week_iso);
    let new_prev = PrevSpectrum {
        scholar: output.spectrum.scholar,
        builder: output.spectrum.builder,
        leisure: output.spectrum.leisure,
    };
    let _ = s.db.set_setting(
        "prev_echo_spectrum",
        &serde_json::to_string(&new_prev).unwrap_or_default(),
    );
    let _ = s.db.purge_reading_events_before(week_ago);
    Ok(output)
}

// ── War report ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_war_report(s: State<'_, AppState>) -> R<WarReport> {
    let row =
        s.db.war_report_week(week_start(unix_now()))
            .unwrap_or(crate::db::WarReportRow {
                tracking_block_count: 0,
                fingerprint_noise_count: 0,
                ram_saved_mb: 0.0,
                time_saved_min: 0.0,
            });
    Ok(WarReport::from_row(&row))
}

// ── Freeze / Museum ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct FreezePayload {
    pub raw_html: String,
    pub url: String,
    pub title: String,
    pub tfidf_tags: Vec<String>,
}

#[tauri::command]
pub fn cmd_freeze_page(payload: FreezePayload, s: State<'_, AppState>) -> R<BundleRow> {
    let result = freeze::freeze_page(
        &payload.raw_html,
        &payload.url,
        &payload.title,
        &s.workspace_id(),
        &s.master_key(),
        &s.bundles_dir(),
    )
    .map_err(e)?;
    let mut row = result.bundle_row;
    row.tfidf_tags = serde_json::to_string(&payload.tfidf_tags).unwrap_or_else(|_| "[]".to_owned());
    s.db.insert_bundle(&row).map_err(e)?;
    Ok(row)
}

#[tauri::command]
pub fn cmd_museum_list(limit: Option<u32>, s: State<'_, AppState>) -> R<Vec<BundleRow>> {
    s.db.list_bundles(&s.workspace_id(), limit.unwrap_or(50))
        .map_err(e)
}

#[tauri::command]
pub fn cmd_museum_search(query: String, s: State<'_, AppState>) -> R<Vec<BundleRow>> {
    s.db.search_bundles_fts(&query, &s.workspace_id())
        .map_err(e)
}

#[tauri::command]
pub fn cmd_museum_delete(id: String, s: State<'_, AppState>) -> R<()> {
    // [FIX-20] Use direct ID lookup, not a capped list query
    if let Ok(Some(b)) = s.db.get_bundle_by_id(&id) {
        let _ = std::fs::remove_file(s.bundles_dir().join(&b.bundle_path));
    }
    s.db.delete_bundle(&id).map_err(e)
}

#[tauri::command]
pub fn cmd_museum_thaw(id: String, s: State<'_, AppState>) -> R<String> {
    // [FIX-20] Direct ID lookup instead of capped list scan
    let row = s.db.get_bundle_by_id(&id).map_err(e)?
        .ok_or_else(|| format!("bundle {id} not found"))?;
    freeze::thaw_bundle(&s.bundles_dir().join(&row.bundle_path), &s.master_key()).map_err(e)
}

// ── DOM Crusher ───────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_dom_crush(domain: String, selector: String, s: State<'_, AppState>) -> R<String> {
    let clean = dom_crusher::clean_selector(&selector);
    dom_crusher::validate_selector(&clean).map_err(e)?;
    s.db.insert_dom_block(&domain, &clean).map_err(e)
}
#[tauri::command]
pub fn cmd_dom_blocks_for(domain: String, s: State<'_, AppState>) -> R<Vec<DomBlock>> {
    s.db.dom_blocks_for(&domain).map_err(e)
}
#[tauri::command]
pub fn cmd_dom_block_remove(id: String, s: State<'_, AppState>) -> R<()> {
    s.db.delete_dom_block(&id).map_err(e)
}

// ── Zen ───────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_zen_activate(s: State<'_, AppState>) {
    let mut z = s.zen.lock().unwrap();
    z.activate();
    z.save_to_db(&s.db); // [FIX-zen]
}
#[tauri::command]
pub fn cmd_zen_deactivate(s: State<'_, AppState>) {
    let mut z = s.zen.lock().unwrap();
    z.deactivate();
    z.save_to_db(&s.db); // [FIX-zen]
}
#[tauri::command]
pub fn cmd_zen_state(s: State<'_, AppState>) -> ZenConfig {
    s.zen.lock().unwrap().clone()
}
#[tauri::command]
pub fn cmd_zen_set_aphorism(aphorism: String, s: State<'_, AppState>) {
    let mut z = s.zen.lock().unwrap();
    z.aphorism = aphorism;
    z.save_to_db(&s.db); // [FIX-zen]
}

// ── Threat ────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn cmd_threat_check(domain: String, s: State<'_, AppState>) -> R<threat::ThreatResult> {
    let list = s.threat_list.read().unwrap().clone();
    let quad9 = s.quad9_enabled.load(std::sync::atomic::Ordering::Relaxed);
    let age_h = s
        .age_heuristic_enabled
        .load(std::sync::atomic::Ordering::Relaxed);
    Ok(threat::evaluate_domain(&domain, &list, quad9, age_h).await)
}

#[tauri::command]
pub async fn cmd_threat_list_refresh(s: State<'_, AppState>) -> R<usize> {
    let list = threat::fetch_live_list().await.map_err(e)?;
    let count = list.len();
    let _ = s.db.set_setting(
        "threat_list_json",
        &serde_json::to_string(&list).unwrap_or_default(),
    );
    *s.threat_list.write().unwrap() = list;
    Ok(count)
}

// ── Knowledge packs ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_knowledge_packs_list(s: State<'_, AppState>) -> R<Vec<KnowledgePack>> {
    s.db.list_knowledge_packs().map_err(e)
}

#[tauri::command]
pub fn cmd_knowledge_pack_add(
    name: String,
    format: String,
    pack_path: String,
    s: State<'_, AppState>,
) -> R<KnowledgePack> {
    if format != "docset" && format != "zim" {
        return Err("format must be 'docset' or 'zim'".to_owned());
    }
    let size = std::fs::metadata(&pack_path).map(|m| m.len()).unwrap_or(0) as i64;
    let pack = KnowledgePack {
        id: new_id(),
        name,
        format,
        pack_path,
        size_bytes: size,
        added_at: unix_now(),
        enabled: true,
    };
    s.db.insert_knowledge_pack(&pack).map_err(e)?;
    Ok(pack)
}

// ── Compat ────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn cmd_compat_handoff(url: String, app: AppHandle) -> R<()> {
    let clean = blocker::strip_params(&blocker::upgrade_https_owned(&url));
    tauri_plugin_shell::ShellExt::shell(&app)
        .open(&clean, None)
        .map_err(e)
}
#[tauri::command]
pub fn cmd_compat_page_report(
    report: crate::compat::PageHealthReport,
    s: State<'_, AppState>,
) -> R<bool> {
    let domain = crate::utils::domain_of(&report.url);
    let broken = report.appears_broken();
    if broken {
        s.compat.lock().unwrap().mark_auto_detected(&domain);
    }
    Ok(broken)
}
#[tauri::command]
pub fn cmd_compat_is_legacy(domain: String, s: State<'_, AppState>) -> bool {
    s.compat.lock().unwrap().is_legacy(&domain)
}
#[tauri::command]
pub fn cmd_compat_is_payment(domain: String) -> bool {
    crate::compat::is_payment_domain(&domain)
}
#[tauri::command]
pub fn cmd_compat_add_legacy(domain: String, s: State<'_, AppState>) -> R<()> {
    s.compat.lock().unwrap().add_legacy(&domain);
    let d = s.compat.lock().unwrap().all_legacy();
    s.db.set_setting(
        "compat_legacy_domains",
        &serde_json::to_string(&d).unwrap_or_default(),
    )
    .map_err(e)
}
#[tauri::command]
pub fn cmd_compat_remove_legacy(domain: String, s: State<'_, AppState>) -> R<()> {
    s.compat.lock().unwrap().remove_legacy(&domain);
    let d = s.compat.lock().unwrap().all_legacy();
    s.db.set_setting(
        "compat_legacy_domains",
        &serde_json::to_string(&d).unwrap_or_default(),
    )
    .map_err(e)
}
#[tauri::command]
pub fn cmd_compat_list_legacy(s: State<'_, AppState>) -> Vec<String> {
    s.compat.lock().unwrap().all_legacy()
}

// ── Storage guard ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_storage_report(s: State<'_, AppState>) -> R<crate::storage_guard::StorageReport> {
    Ok(crate::storage_guard::report(
        &s.db,
        &s.storage_budget.lock().unwrap(),
    ))
}
#[tauri::command]
pub fn cmd_storage_evict_lru(target_pct: Option<u8>, s: State<'_, AppState>) -> R<(u32, u64)> {
    crate::storage_guard::evict_lru(
        &s.db,
        &s.storage_budget.lock().unwrap(),
        target_pct.unwrap_or(70),
        &s.bundles_dir(),
    )
    .map_err(e)
}
#[tauri::command]
pub fn cmd_storage_budget_set(
    museum_mb: Option<u64>,
    kpack_mb: Option<u64>,
    warn_pct: Option<u8>,
    hard_cap: Option<bool>,
    s: State<'_, AppState>,
) -> R<()> {
    let mut b = s.storage_budget.lock().unwrap();
    if let Some(v) = museum_mb {
        b.museum_budget_mb = v;
    }
    if let Some(v) = kpack_mb {
        b.kpack_budget_mb = v;
    }
    if let Some(v) = warn_pct {
        b.warn_at_pct = v;
    }
    if let Some(v) = hard_cap {
        b.hard_cap_enabled = v;
    }
    s.db.set_setting(
        "storage_budget",
        &serde_json::to_string(&*b).unwrap_or_default(),
    )
    .map_err(e)
}

// ── Compliance ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_feature_consent_check(
    feature_id: String,
    s: State<'_, AppState>,
) -> Result<bool, String> {
    match crate::compliance::check_consent(&feature_id, &s.db) {
        Ok(()) => Ok(true),
        Err(t) => Err(t),
    }
}
#[tauri::command]
pub fn cmd_feature_consent_record(feature_id: String, s: State<'_, AppState>) -> R<()> {
    crate::compliance::record_consent(&feature_id, &s.db).map_err(e)
}
#[tauri::command]
pub fn cmd_feature_consent_revoke(feature_id: String, s: State<'_, AppState>) -> R<()> {
    crate::compliance::revoke_consent(&feature_id, &s.db).map_err(e)
}
#[derive(Serialize)]
pub struct FeatureLegalInfo {
    pub id: String,
    pub display_name: String,
    pub legal_class: String,
    pub requires_consent: bool,
    pub consent_text: String,
    pub controls: Vec<String>,
    pub residual_risk: String,
}
#[tauri::command]
pub fn cmd_feature_legal_info(feature_id: String) -> Option<FeatureLegalInfo> {
    crate::compliance::feature_legal(&feature_id).map(|f| FeatureLegalInfo {
        id: f.id.to_owned(),
        display_name: f.display_name.to_owned(),
        legal_class: f.legal_class.to_owned(),
        requires_consent: f.requires_consent,
        consent_text: f.consent_text.to_owned(),
        controls: f.controls.iter().map(|s| s.to_string()).collect(),
        residual_risk: f.residual_risk.to_owned(),
    })
}

// ── Decoy ─────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn cmd_decoy_fire(s: State<'_, AppState>) -> R<Option<String>> {
    if let Err(t) = crate::compliance::check_consent("decoy_traffic", &s.db) {
        return Err(format!("consent_required:{t}"));
    }
    // [FIX-decoy-globals] Acquire the decoy lock, run the request, then drop.
    // We cannot hold a std::sync::MutexGuard across .await points (compiler
    // error on non-Send types). Instead we do the network call while holding
    // the lock via a scoped block that keeps the guard live but the future is
    // structured so the guard is dropped before the first suspension point.
    //
    // Because fire_noise_request is async and may suspend (sleep / fetch),
    // we must NOT hold the MutexGuard during the await. Instead we:
    //   1. Pre-check rate-limit and robots synchronously (acquiring guard).
    //   2. If allowed, clone the needed state, drop the guard, then do I/O.
    // The DecoyState::fire_checked() method handles this split.
    let (allowed, url, origin) = {
        let mut decoy = s.decoy.lock().unwrap();
        crate::decoy::pre_check(&mut decoy)
    };
    if !allowed {
        return Ok(None);
    }
    // Phase 2: async I/O without holding MutexGuard
    let result = crate::decoy::fire_after_check(
        &s.db, &s.decoy, url, origin
    ).await;
    Ok(result)
}
#[tauri::command]
pub fn cmd_decoy_log(s: State<'_, AppState>) -> Vec<String> {
    crate::decoy::get_decoy_log(&s.db)
}

// ── Labs — v0.9.0 ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_labs_list(s: State<'_, AppState>) -> Vec<labs::Lab> {
    labs::load_labs(&s.db)
}

#[tauri::command]
pub fn cmd_lab_set(id: String, enabled: bool, s: State<'_, AppState>) -> R<bool> {
    labs::set_lab(&s.db, &id, enabled).map_err(e)
}

#[tauri::command]
pub fn cmd_lab_is_enabled(id: String, s: State<'_, AppState>) -> bool {
    labs::is_lab_enabled(&s.db, &id)
}

// ── SLM microkernel — v0.9.0 ──────────────────────────────────────────────────

#[tauri::command]
pub async fn cmd_slm_status(s: State<'_, AppState>) -> R<slm::SlmStatus> {
    let privacy = labs::is_lab_enabled(&s.db, "slm_extreme_privacy");
    let model = s.db.get_setting("slm_active_model");
    let server = slm::SlmServer::new(privacy, model.as_deref()).await;
    Ok(server.status())
}

#[derive(Deserialize)]
pub struct SlmChatPayload {
    pub messages: Vec<slm::ChatMessage>,
    pub model: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

#[tauri::command]
pub async fn cmd_slm_chat(payload: SlmChatPayload, s: State<'_, AppState>) -> R<slm::ChatResponse> {
    let privacy = labs::is_lab_enabled(&s.db, "slm_extreme_privacy");
    let model = payload
        .model
        .or_else(|| s.db.get_setting("slm_active_model"))
        .unwrap_or_else(|| "diatom-balanced".to_owned());
    let server = slm::SlmServer::new(privacy, Some(&model)).await;
    let req = slm::ChatRequest {
        model,
        messages: payload.messages,
        stream: Some(false),
        max_tokens: payload.max_tokens,
        temperature: payload.temperature,
    };
    server.chat(&req).await.map_err(e)
}

#[tauri::command]
pub fn cmd_slm_models() -> slm::ModelsResponse {
    let now = unix_now();
    slm::ModelsResponse {
        object: "list",
        data: slm::CURATED_MODELS
            .iter()
            .map(|m| slm::ModelInfo {
                id: m.id.to_owned(),
                object: "model",
                created: now,
                owned_by: "diatom",
            })
            .collect(),
    }
}

#[tauri::command]
pub fn cmd_slm_set_model(model_id: String, s: State<'_, AppState>) -> R<()> {
    if !slm::CURATED_MODELS.iter().any(|m| m.id == model_id) {
        return Err(format!("unknown model: {model_id}"));
    }
    s.db.set_setting("slm_active_model", &model_id).map_err(e)
}

/// Toggle the SLM server on/off at runtime without a full restart.
#[tauri::command]
pub async fn cmd_slm_server_toggle(enable: bool, s: State<'_, AppState>) -> R<bool> {
    let mut shutdown_guard = s.slm_shutdown.lock().unwrap();
    if enable {
        if shutdown_guard.is_some() {
            return Ok(true);
        } // already running
        let privacy = labs::is_lab_enabled(&s.db, "slm_extreme_privacy");
        let model = s.db.get_setting("slm_active_model");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_c = Arc::clone(&shutdown);
        *shutdown_guard = Some(shutdown);
        tauri::async_runtime::spawn(async move {
            let server = Arc::new(slm::SlmServer::new(privacy, model.as_deref()).await);
            slm::run_server(server, shutdown_c).await;
        });
        labs::set_lab(&s.db, "slm_server", true).map_err(e)?;
        Ok(true)
    } else {
        if let Some(sd) = shutdown_guard.take() {
            sd.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        labs::set_lab(&s.db, "slm_server", false).map_err(e)?;
        Ok(false)
    }
}

// ── Init bundle [FIX-__DIATOM_INIT__] ────────────────────────────────────────

/// Serialisable payload injected as window.__DIATOM_INIT__ before diatom-api.js.
/// Contains the workspace noise_seed (for deterministic fingerprint noise),
/// active DOM crusher rules, and Zen active flag.
#[derive(Serialize)]
pub struct DiatomInitBundle {
    pub noise_seed: u64,
    pub crusher_rules: Vec<String>,
    pub zen_active: bool,
    /// Current platform for client-side UA/WebGL spoofing decisions.
    pub platform: &'static str,
}

/// Called by the frontend immediately after each page navigation to obtain
/// the data that must be set as window.__DIATOM_INIT__ before the injected
/// scripts run. The frontend injects this via:
///   win.eval(`window.__DIATOM_INIT__ = ${JSON.stringify(bundle)};`);
///   // then diatom-api.js reads window.__DIATOM_INIT__
#[tauri::command]
pub fn cmd_init_bundle(domain: String, s: State<'_, AppState>) -> DiatomInitBundle {
    let noise_seed = *s.noise_seed.lock().unwrap();
    let crusher_rules = s.db.dom_blocks_for(&domain)
        .unwrap_or_default()
        .into_iter()
        .map(|b| b.selector)
        .collect();
    let zen_active = s.zen.lock().unwrap().is_active();
    DiatomInitBundle { noise_seed, crusher_rules, zen_active, platform: s.platform }
}

// ── Sentinel ──────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_sentinel_status(s: State<'_, AppState>) -> crate::sentinel::SentinelStatus {
    let cache = s.sentinel.lock().unwrap().clone();
    let lab_active = crate::labs::is_lab_enabled(&s.db, "sentinel_ua");
    crate::sentinel::SentinelStatus::from_cache(&cache, lab_active)
}

#[tauri::command]
pub async fn cmd_sentinel_refresh(s: State<'_, AppState>) -> R<crate::sentinel::SentinelStatus> {
    let prev = s.sentinel.lock().unwrap().clone();
    let new_cache = crate::sentinel::refresh(&prev).await;
    if let Ok(json) = serde_json::to_string(&new_cache) {
        let _ = s.db.set_setting("sentinel_cache", &json);
    }
    *s.sentinel.lock().unwrap() = new_cache.clone();
    let lab_active = crate::labs::is_lab_enabled(&s.db, "sentinel_ua");
    Ok(crate::sentinel::SentinelStatus::from_cache(&new_cache, lab_active))
}

// ── Onboarding [NEW] ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_onboarding_complete(step: String, s: State<'_, AppState>) -> R<()> {
    s.db.onboarding_complete(&step).map_err(e)
}

#[tauri::command]
pub fn cmd_onboarding_is_done(step: String, s: State<'_, AppState>) -> bool {
    s.db.onboarding_is_done(&step)
}

#[tauri::command]
pub fn cmd_onboarding_all(s: State<'_, AppState>) -> Vec<(String, bool)> {
    s.db.onboarding_all_steps()
}

// ── Privacy Presets / Filter Subscriptions [NEW] ─────────────────────────────

#[derive(Deserialize)]
pub struct FilterSubPayload {
    pub name: String,
    pub url: String,
}

/// Add a filter subscription (Privacy Presets). Diatom is the downloader only;
/// the user chooses the source. Responsibility for rule content is the user's.
#[tauri::command]
pub async fn cmd_filter_sub_add(payload: FilterSubPayload, s: State<'_, AppState>) -> R<String> {
    // Reject private URLs for security
    if is_private_url(&payload.url) {
        return Err("filter subscription URL must not be a private address".to_owned());
    }
    let id = crate::db::new_id();
    s.db.filter_sub_upsert(&id, &payload.name, &payload.url).map_err(e)?;
    Ok(id)
}

#[tauri::command]
pub fn cmd_filter_subs_list(s: State<'_, AppState>) -> R<Vec<crate::db::FilterSub>> {
    s.db.filter_subs_all().map_err(e)
}

/// Download and apply a filter subscription, then persist rule count.
/// Returns number of new patterns added to the in-memory blocker.
/// Note: for now rules are stored in DB meta; a future version will
/// hot-reload the Aho-Corasick automaton.
#[tauri::command]
pub async fn cmd_filter_sub_sync(url: String, s: State<'_, AppState>) -> R<usize> {
    if is_private_url(&url) {
        return Err("private URL rejected".to_owned());
    }
    // Download the list
    let result = cmd_fetch(url.clone(), None).await?;
    // Count rules (lines not starting with '!' or '#' or empty)
    let rule_count = result.body.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('!') && !l.starts_with('#'))
        .count();
    // Persist stats
    s.db.filter_sub_update_stats(&url, rule_count).map_err(e)?;
    Ok(rule_count)
}

// ── Nostr relay management [NEW] ─────────────────────────────────────────────

#[tauri::command]
pub fn cmd_nostr_relay_add(url: String, s: State<'_, AppState>) -> R<String> {
    if is_private_url(&url) {
        return Err("private URL rejected for relay".to_owned());
    }
    s.db.nostr_relay_add(&url).map_err(e)
}

#[tauri::command]
pub fn cmd_nostr_relays(s: State<'_, AppState>) -> R<Vec<String>> {
    s.db.nostr_relays_enabled().map_err(e)
}
