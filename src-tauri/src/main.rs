//! Diatom backend process.
//!
//! Manages all browser state: tabs, storage, privacy engine, ad blocker,
//! local AI, and sync.  Does not render UI — the visible browser chrome is
//! rendered by the `diatom-shell` GPUI process, communicating via the
//! [`diatom_bridge`] Unix-domain-socket protocol.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod agent_commands;
pub mod ai;
pub mod auth;
pub mod browser;
pub mod commands;
pub mod engine;
pub mod features;
pub mod privacy;
pub mod research;
pub mod state;
pub mod storage;
pub mod sync;
pub mod utils;

use state::AppState;
use tauri::Manager;

fn main() {
    if let Err(e) = run() {
        eprintln!("Diatom startup error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let initial_power = features::sentinel::power_budget_current();

    let app_data = tauri::path::app_data_dir(&tauri::Config::default())
        .map_err(|e| anyhow::anyhow!("Failed to get app data dir: {}", e))?;

    let state = AppState::new(app_data, initial_power)
        .map_err(|e| anyhow::anyhow!("AppState initialisation failed: {e:#}"))?;

    tauri::Builder::default()
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(state)
        .manage(agent_commands::ActiveAgent::new())
        .invoke_handler(tauri::generate_handler![
            agent_commands::cmd_agent_start,
            agent_commands::cmd_agent_abort,
            agent_commands::cmd_agent_tool_result,
            commands::cmd_history_search,
            commands::cmd_history_clear,
            commands::cmd_bookmark_add,
            commands::cmd_bookmark_list,
            commands::cmd_bookmark_remove,
            commands::cmd_setting_get,
            commands::cmd_setting_set,
            commands::cmd_net_monitor_log,
            commands::cmd_net_monitor_clear,
            commands::cmd_bandwidth_set_global,
            commands::cmd_bandwidth_rule_upsert,
            commands::cmd_bandwidth_rule_remove,
            commands::cmd_bandwidth_status,
            commands::cmd_plugin_list,
            commands::cmd_plugin_install,
            commands::cmd_plugin_remove,
            commands::cmd_privacy_config_get,
            commands::cmd_privacy_config_set,
            commands::cmd_fp_norm_script,
            commands::cmd_ohttp_status,
            commands::cmd_onion_suggest,
            commands::cmd_threat_check,
            commands::cmd_threat_list_refresh,
            commands::cmd_wifi_scan,
            commands::cmd_wifi_trust_network,
            commands::cmd_wifi_distrust_network,
            commands::cmd_wifi_trusted_networks,
            commands::cmd_freeze_page,
            commands::cmd_museum_search,
            commands::cmd_museum_list,
            commands::cmd_museum_get,
            commands::cmd_museum_delete,
            commands::cmd_museum_touch_access,
            commands::cmd_museum_thaw,
            commands::cmd_museum_deep_dig,
            commands::cmd_storage_report,
            commands::cmd_storage_evict_lru,
            commands::cmd_storage_budget_set,
            commands::cmd_storage_degrade_cold,
            commands::cmd_vault_list,
            commands::cmd_vault_add,
            commands::cmd_vault_update,
            commands::cmd_vault_delete,
            commands::cmd_vault_autofill,
            commands::cmd_slm_status,
            commands::cmd_slm_complete,
            commands::cmd_slm_reset,
            commands::cmd_slm_set_model,
            commands::cmd_slm_server_toggle,
            commands::cmd_ai_rename_suggest,
            commands::cmd_shadow_search,
            commands::cmd_mcp_status,
            commands::cmd_mcp_session_token,
            commands::cmd_tabs_list,
            commands::cmd_tabs_state,
            commands::cmd_tab_create,
            commands::cmd_tab_close,
            commands::cmd_tab_activate,
            commands::cmd_tab_update,
            commands::cmd_tab_sleep,
            commands::cmd_tab_wake,
            commands::cmd_tab_budget_config_set,
            commands::cmd_tab_limit_get,
            commands::cmd_tab_limit_set,
            commands::cmd_tab_proxy_set,
            commands::cmd_tab_proxy_get,
            commands::cmd_tab_proxy_remove,
            commands::cmd_tab_screenshot,
            commands::cmd_dom_crush,
            commands::cmd_dom_blocks_for,
            commands::cmd_dom_block_remove,
            commands::cmd_boosts_for_domain,
            commands::cmd_boosts_list,
            commands::cmd_boost_upsert,
            commands::cmd_boost_delete,
            commands::cmd_totp_list,
            commands::cmd_totp_add,
            commands::cmd_totp_code,
            commands::cmd_totp_delete,
            commands::cmd_totp_import,
            commands::cmd_biometric_verify,
            commands::cmd_trust_get,
            commands::cmd_trust_set,
            commands::cmd_noise_fingerprint,
            commands::cmd_nostr_publish,
            commands::cmd_nostr_fetch,
            commands::cmd_zen_status,
            commands::cmd_zen_activate,
            commands::cmd_zen_deactivate,
            commands::cmd_zen_set_aphorism,
            commands::cmd_rss_feeds_list,
            commands::cmd_rss_feed_add,
            commands::cmd_rss_feed_remove,
            commands::cmd_rss_items,
            commands::cmd_rss_mark_read,
            commands::cmd_panic_toggle,
            commands::cmd_panic_config_get,
            commands::cmd_panic_config_set,
            commands::cmd_breach_check_password,
            commands::cmd_breach_check_email,
            commands::cmd_search_engines_list,
            commands::cmd_search_engine_get_default,
            commands::cmd_search_engine_set_default,
            commands::cmd_searxng_set_endpoint,
            commands::cmd_tos_audit,
            commands::cmd_war_report,
            commands::cmd_labs_list,
            commands::cmd_lab_set,
            commands::cmd_power_budget_status,
            commands::cmd_signal_window_ready,
            commands::cmd_home_base_data,
            commands::cmd_peek_fetch,
            commands::cmd_compliance_registry,
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            let state: tauri::State<AppState> = app.state();

            // Fetch built-in filter lists; exits cleanly on window close.
            let blocker = state.live_blocker.clone();
            let shutdown = state.shutdown_token.clone();
            tauri::async_runtime::spawn(async move {
                tokio::select! {
                    _ = engine::blocker::boot_fetch_builtin_lists(blocker) => {},
                    _ = shutdown.cancelled() => {
                        tracing::info!("blocker: boot fetch cancelled by shutdown");
                    },
                }
            });

            // Start the local AI server if the lab is enabled.
            if features::labs::is_lab_enabled(&state.db, "slm_server") {
                let privacy_mode = state
                    .privacy
                    .read()
                    .map(|p| p.extreme_mode)
                    .unwrap_or(false);
                let slm_cache = state.slm_cache.clone();
                let slm_tok_ref = state.slm_shutdown_token.clone();
                let slm_shutdown = tokio_util::sync::CancellationToken::new();
                *slm_tok_ref.lock().unwrap() = Some(slm_shutdown.clone());
                let preferred = state
                    .db
                    .get_setting("slm_preferred_model")
                    .unwrap_or_else(|| "diatom-balanced".to_owned());

                tauri::async_runtime::spawn(async move {
                    let server = std::sync::Arc::new(
                        ai::slm::SlmServer::new(privacy_mode, Some(&preferred)).await,
                    );
                    *slm_cache.lock().await = Some(server.clone());
                    ai::slm::run_server(server, slm_shutdown).await;
                    tracing::info!("SLM server exited");
                });
            }

            // Sentinel UA-normalisation loop — delayed 10 s so startup paint
            // is not blocked by network requests.
            {
                let handle = app_handle.clone();
                let shutdown = state.shutdown_token.clone();
                tauri::async_runtime::spawn(async move {
                    features::sentinel::run_sentinel_loop(handle, 10, shutdown).await;
                });
            }

            // Show the window once the shell signals readiness, or after 3 s.
            let token = state.window_ready_token.clone();
            let handle = app_handle.clone();
            let shutdown = state.shutdown_token.clone();
            tauri::async_runtime::spawn(async move {
                tokio::select! {
                    _ = token.cancelled()   => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                    _ = shutdown.cancelled() => { return; }
                }
                if let Some(w) = handle.get_webview_window("main") {
                    let _ = w.show();
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Cancel all background tasks on close or process teardown.
            match event {
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed => {
                    if let Some(state) = window.try_state::<AppState>() {
                        state.shutdown_token.cancel();
                        if let Ok(mut tok) = state.slm_shutdown_token.lock() {
                            if let Some(t) = tok.take() {
                                t.cancel();
                            }
                        }
                    }
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("Diatom backend failed: {e:#}"))
}
