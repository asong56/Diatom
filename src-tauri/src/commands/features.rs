use super::{St, es};

#[tauri::command]
pub async fn cmd_zen_status(state: St<'_>) -> Result<crate::features::zen::ZenConfig, String> {
    Ok(state.zen.lock().unwrap().clone())
}

#[tauri::command]
pub async fn cmd_zen_activate(state: St<'_>) -> Result<(), String> {
    state.zen.lock().unwrap().activate(&state.db);
    Ok(())
}

/// Deactivate Zen mode.
///
/// When `require_intent_gate` is `true` (the default, Axiom 2), the caller
/// must supply a non-empty `unlock_phrase` of at least 50 characters — the
/// typed declaration that makes disengaging focus a conscious act.
///
/// Users who have deliberately opted out of the gate via
/// `Settings → Focus → Require intent declaration` may pass any string;
/// the length check is skipped.  This is a user-initiated opt-out, never
/// a silent bypass.
#[tauri::command]
pub async fn cmd_zen_deactivate(unlock_phrase: String, state: St<'_>) -> Result<bool, String> {
    let zen = state.zen.lock().unwrap();
    if zen.require_intent_gate && unlock_phrase.trim().chars().count() < 50 {
        return Err("Intent declaration must be at least 50 characters (Axiom 2).".into());
    }
    drop(zen);
    state.zen.lock().unwrap().deactivate(&state.db);
    Ok(true)
}

#[tauri::command]
pub async fn cmd_rss_feeds_list(state: St<'_>) -> Result<serde_json::Value, String> {
    let feeds = state.rss.lock().unwrap().list_feeds();
    Ok(serde_json::json!({ "feeds": feeds }))
}

#[tauri::command]
pub async fn cmd_rss_feed_add(url: String, state: St<'_>) -> Result<String, String> {
    state
        .rss
        .lock()
        .unwrap()
        .add_feed(url, &state.db)
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_rss_feed_remove(id: String, state: St<'_>) -> Result<(), String> {
    state
        .rss
        .lock()
        .unwrap()
        .remove_feed(&id, &state.db)
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_rss_items(
    feed_id: Option<String>,
    state: St<'_>,
) -> Result<serde_json::Value, String> {
    let items = state.rss.lock().unwrap().items(feed_id.as_deref(), 50);
    Ok(serde_json::json!({ "items": items }))
}

#[tauri::command]
pub async fn cmd_rss_mark_read(item_id: String, state: St<'_>) -> Result<(), String> {
    state
        .rss
        .lock()
        .unwrap()
        .mark_read(&item_id, &state.db)
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_panic_toggle(app_handle: tauri::AppHandle, state: St<'_>) -> Result<(), String> {
    let cfg = crate::features::panic::load_config(&state.db);
    crate::features::panic::toggle(&app_handle, &cfg);
    Ok(())
}

#[tauri::command]
pub async fn cmd_panic_config_get(
    state: St<'_>,
) -> Result<crate::features::panic::PanicConfig, String> {
    Ok(crate::features::panic::load_config(&state.db))
}

#[tauri::command]
pub async fn cmd_panic_config_set(
    config: crate::features::panic::PanicConfig,
    state: St<'_>,
) -> Result<(), String> {
    crate::features::panic::save_config(&state.db, &config).map_err(es)
}

/// Check a password against HIBP k-anonymity API with DB caching.
///
/// This command is for ad-hoc password checks (e.g. from the Vault UI).
/// Background scans that tie results back to a specific login record should
/// use `scan_login_and_persist` directly from the scan task.
#[tauri::command]
pub async fn cmd_breach_check_password(
    password: String,
    state: St<'_>,
) -> Result<crate::features::breach::PasswordBreachResult, String> {
    crate::features::breach::check_password_cached(&reqwest::Client::new(), &state.db, &password)
        .await
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_breach_check_email(
    email: String,
    state: St<'_>,
) -> Result<crate::features::breach::EmailBreachResult, String> {
    if state
        .db
        .get_setting("breach_monitor_email_optin")
        .as_deref()
        != Some("true")
    {
        return Err("Email breach check requires explicit opt-in".into());
    }
    let api_key = state.db.get_setting("hibp_api_key").unwrap_or_default();
    crate::features::breach::check_email(&reqwest::Client::new(), &email, &api_key)
        .await
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_search_engines_list() -> Result<Vec<crate::features::search::SearchEngine>, String>
{
    Ok(crate::features::search::builtin_engines())
}

#[tauri::command]
pub async fn cmd_search_engine_get_default(state: St<'_>) -> Result<String, String> {
    Ok(crate::features::search::get_default(&state.db))
}

#[tauri::command]
pub async fn cmd_search_engine_set_default(engine_id: String, state: St<'_>) -> Result<(), String> {
    crate::features::search::set_default(&state.db, &engine_id).map_err(es)
}

#[tauri::command]
pub async fn cmd_searxng_set_endpoint(endpoint: String, state: St<'_>) -> Result<(), String> {
    crate::features::search::set_searxng_endpoint(&state.db, &endpoint).map_err(es)
}

#[tauri::command]
pub async fn cmd_tos_audit(url: String, text: String) -> Result<serde_json::Value, String> {
    let flags = crate::features::tos::audit_text(&url, &text);
    Ok(serde_json::json!({ "flags": flags }))
}

#[tauri::command]
pub async fn cmd_war_report(state: St<'_>) -> Result<crate::features::report::WarReport, String> {
    let ws = state.workspace_id();
    crate::features::report::build(&state.db, &ws).map_err(es)
}

#[tauri::command]
pub async fn cmd_labs_list(state: St<'_>) -> Result<Vec<crate::features::labs::Lab>, String> {
    Ok(crate::features::labs::load_labs(&state.db))
}

#[tauri::command]
pub async fn cmd_lab_set(id: String, enabled: bool, state: St<'_>) -> Result<(), String> {
    crate::features::labs::set_lab(&state.db, &id, enabled).map_err(es)?;
    Ok(())
}

#[tauri::command]
pub async fn cmd_compliance_registry() -> Result<serde_json::Value, String> {
    let registry = crate::features::compliance::feature_registry();
    Ok(serde_json::json!({ "features": registry }))
}
