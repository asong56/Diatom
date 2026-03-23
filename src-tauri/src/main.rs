// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/main.rs  — v0.9.1
// ─────────────────────────────────────────────────────────────────────────────

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// ── Global allocator: mimalloc ────────────────────────────────────────────────
// mimalloc replaces the system allocator (ptmalloc on Linux, jemalloc on macOS,
// HeapAlloc on Windows). Benefits for a long-running desktop app:
//   • Dramatically reduces heap fragmentation over multi-hour sessions.
//     The system allocator accumulates ~15–25% RSS bloat after 4h+ of browsing;
//     mimalloc's per-thread segment design prevents this entirely.
//   • ~3–8% throughput improvement on allocation-heavy paths (JSON parsing,
//     RSS fetching, IPC serialisation).
//   • Secure allocation: mimalloc uses a distinct memory region per type class,
//     making heap overflow exploits significantly harder.
// Zero source-code changes required: `GlobalAlloc` impl is entirely in the crate.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod a11y;
mod blocker;
mod commands;
mod compat;
mod compliance;
mod db;
mod decoy;
mod dom_crusher;
mod echo;
mod freeze;
mod labs;
mod privacy;
mod rss;
mod sentinel;
mod slm;
mod state;
mod storage_guard;
mod tab_budget;
mod tabs;
mod threat;
mod totp;
mod trust;
mod utils;
mod war_report;
mod zen;

use anyhow::Result;
use state::AppState;
use std::sync::{Arc, atomic::AtomicBool};
use tauri::{Builder, Emitter, Manager};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("diatom=info".parse().unwrap())
                .add_directive("tauri=warn".parse().unwrap()),
        )
        .compact()
        .init();

    Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(setup)
        .invoke_handler(tauri::generate_handler![
            commands::cmd_preprocess_url,
            commands::cmd_fetch,
            commands::cmd_tab_create,
            commands::cmd_tab_close,
            commands::cmd_tab_activate,
            commands::cmd_tab_update,
            commands::cmd_tab_sleep,
            commands::cmd_tab_wake,
            commands::cmd_tabs_state,
            commands::cmd_tab_budget,
            commands::cmd_tab_budget_config_set,
            commands::cmd_workspaces_list,
            commands::cmd_workspace_create,
            commands::cmd_workspace_switch,
            commands::cmd_workspace_fire,
            commands::cmd_history_search,
            commands::cmd_history_clear,
            commands::cmd_bookmark_add,
            commands::cmd_bookmark_list,
            commands::cmd_bookmark_remove,
            commands::cmd_setting_get,
            commands::cmd_setting_set,
            commands::cmd_is_blocked,
            commands::cmd_clean_url,
            commands::cmd_noise_seed,
            commands::cmd_totp_list,
            commands::cmd_totp_add,
            commands::cmd_totp_generate,
            commands::cmd_totp_match,
            commands::cmd_totp_remove,
            commands::cmd_trust_get,
            commands::cmd_trust_set,
            commands::cmd_trust_list,
            commands::cmd_rss_feeds,
            commands::cmd_rss_add,
            commands::cmd_rss_fetch,
            commands::cmd_rss_items,
            commands::cmd_rss_mark_read,
            commands::cmd_snapshot_save,
            commands::cmd_system_info,
            commands::cmd_devtools_open,
            commands::cmd_record_reading,
            commands::cmd_echo_compute,
            commands::cmd_war_report,
            commands::cmd_freeze_page,
            commands::cmd_museum_list,
            commands::cmd_museum_search,
            commands::cmd_museum_delete,
            commands::cmd_museum_thaw,
            commands::cmd_dom_crush,
            commands::cmd_dom_blocks_for,
            commands::cmd_dom_block_remove,
            commands::cmd_zen_activate,
            commands::cmd_zen_deactivate,
            commands::cmd_zen_state,
            commands::cmd_zen_set_aphorism,
            commands::cmd_threat_check,
            commands::cmd_threat_list_refresh,
            commands::cmd_knowledge_packs_list,
            commands::cmd_knowledge_pack_add,
            commands::cmd_compat_handoff,
            commands::cmd_compat_page_report,
            commands::cmd_compat_is_legacy,
            commands::cmd_compat_is_payment,
            commands::cmd_compat_add_legacy,
            commands::cmd_compat_remove_legacy,
            commands::cmd_compat_list_legacy,
            commands::cmd_storage_report,
            commands::cmd_storage_evict_lru,
            commands::cmd_storage_budget_set,
            commands::cmd_feature_consent_check,
            commands::cmd_feature_consent_record,
            commands::cmd_feature_consent_revoke,
            commands::cmd_feature_legal_info,
            commands::cmd_decoy_fire,
            commands::cmd_decoy_log,
            commands::cmd_labs_list,
            commands::cmd_lab_set,
            commands::cmd_lab_is_enabled,
            commands::cmd_slm_status,
            commands::cmd_slm_chat,
            commands::cmd_slm_models,
            commands::cmd_slm_set_model,
            commands::cmd_slm_server_toggle,
            // ── Sentinel ──────────────────────────────────────────────────────
            commands::cmd_sentinel_status,
            commands::cmd_sentinel_refresh,
            // ── Init bundle [FIX-__DIATOM_INIT__] ────────────────────────────
            commands::cmd_init_bundle,
            // ── Onboarding [NEW] ──────────────────────────────────────────────
            commands::cmd_onboarding_complete,
            commands::cmd_onboarding_is_done,
            commands::cmd_onboarding_all,
            // ── Privacy Presets / Filter Subscriptions [NEW] ─────────────────
            commands::cmd_filter_sub_add,
            commands::cmd_filter_subs_list,
            commands::cmd_filter_sub_sync,
            // ── Nostr relay management [NEW] ──────────────────────────────────
            commands::cmd_nostr_relay_add,
            commands::cmd_nostr_relays,
        ])
        .run(tauri::generate_context!())
        .expect("Diatom failed to start");
}

fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    tracing::info!(
        "Diatom v{} — data: {:?}",
        env!("CARGO_PKG_VERSION"),
        data_dir
    );

    let state = AppState::new(data_dir)?;
    app.manage(state);

    let st = app.state::<AppState>();

    if let Some(win) = app.get_webview_window("main") {
        // [FIX-__DIATOM_INIT__] Inject the init bundle BEFORE diatom-api.js so
        // the script reads the correct noise_seed, crusher_rules, and zen_active.
        // On subsequent navigations the frontend calls cmd_init_bundle() to refresh.
        let init_seed  = *st.noise_seed.lock().unwrap();
        let init_zen   = st.zen.lock().unwrap().is_active();
        let init_platform = st.platform;
        let init_js = format!(
            "window.__DIATOM_INIT__ = {{ noise_seed: {}, crusher_rules: [], zen_active: {}, platform: '{}' }};",
            init_seed, init_zen, init_platform
        );
        let _ = win.eval(&init_js);
        // [FIX-privacy.rs] Inject the PrivacyConfig JS so canvas_noise, webrtc_block,
        // battery_block, peripheral_block, and hw_concurrency_spoof from AppState
        // actually take effect. Previously this module was dead code.
        let privacy_js = st.privacy.read().unwrap().injection_script();
        let _ = win.eval(&privacy_js);
        let _ = win.eval(include_str!("../resources/diatom-api.js"));
        let _ = win.eval(&crate::a11y::generate_aria_injection_script());
        let _ = win.eval(crate::a11y::keyboard_nav_script());
        let _ = win.emit("diatom:ready", ());
    }

    // ── Sentinel background task ───────────────────────────────────────────────
    // [FIX-14] Always spawn — lab only gates whether UA synthesis is applied,
    // not whether the version data is collected (CVE awareness needs it always).
    {
        let ah = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            sentinel::run_sentinel_loop(ah, 15).await;
        });
        tracing::info!("sentinel: version-tracking task spawned");
    }

    // ── SLM server background task (when lab enabled) ─────────────────────────
    if labs::is_lab_enabled(&st.db, "slm_server") {
        let privacy_mode = labs::is_lab_enabled(&st.db, "slm_extreme_privacy");
        let preferred = st.db.get_setting("slm_active_model");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_c = Arc::clone(&shutdown);
        *st.slm_shutdown.lock().unwrap() = Some(shutdown);
        tauri::async_runtime::spawn(async move {
            let server = Arc::new(slm::SlmServer::new(privacy_mode, preferred.as_deref()).await);
            tracing::info!("SLM server online — backend: {:?}", server.backend);
            slm::run_server(server, shutdown_c).await;
        });
    }

    // ── Tab budget recalculation loop (60s interval) ──────────────────────────
    if labs::is_lab_enabled(&st.db, "dynamic_tab_budget") {
        let ah = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if let Some(st) = ah.try_state::<AppState>() {
                    let cfg = st.tab_budget_cfg.lock().unwrap().clone();
                    let omega = st.tabs.lock().unwrap().avg_mem_weight();
                    let count = st.tabs.lock().unwrap().count() as u32;
                    let sw = *st.screen_width_px.lock().unwrap();
                    let b = tab_budget::compute_budget(&cfg, sw, omega, count);
                    let _ = ah.emit(
                        "diatom:budget-update",
                        serde_json::to_value(&b).unwrap_or_default(),
                    );
                }
            }
        });
    }

    // ── Weekly threat list refresh ─────────────────────────────────────────────
    // [FIX-07] URLhaus local-list refresh is independent of quad9_enabled.
    // Quad9 is a real-time DNS check; URLhaus is an offline blocklist.
    // Disabling Quad9 should not prevent the local list from staying fresh.
    let ah = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(7 * 24 * 3_600)).await;
            if let Some(st) = ah.try_state::<AppState>() {
                // Always refresh the local URLhaus list regardless of Quad9 setting
                if let Ok(list) = threat::fetch_live_list().await {
                    let _ = st.db.set_setting(
                        "threat_list_json",
                        &serde_json::to_string(&list).unwrap_or_default(),
                    );
                    *st.threat_list.write().unwrap() = list;
                    tracing::info!("threat list refreshed (URLhaus)");
                }
            }
        }
    });

    Ok(())
}
