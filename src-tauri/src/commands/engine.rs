use super::{St, es};

#[tauri::command]
pub async fn cmd_net_monitor_log(state: St<'_>) -> Result<serde_json::Value, String> {
    let entries = state.net_monitor.recent(500);
    Ok(serde_json::json!({ "entries": entries }))
}

#[tauri::command]
pub async fn cmd_net_monitor_clear(state: St<'_>) -> Result<(), String> {
    state.net_monitor.clear();
    Ok(())
}

#[tauri::command]
pub async fn cmd_bandwidth_set_global(kbps: u32, state: St<'_>) -> Result<(), String> {
    state.bandwidth_limiter.set_global_limit(kbps);
    state.bandwidth_limiter.save_to_db(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_bandwidth_rule_upsert(
    rule: crate::engine::bandwidth::BandwidthRule,
    state: St<'_>,
) -> Result<(), String> {
    state.bandwidth_limiter.upsert_rule(rule);
    state.bandwidth_limiter.save_to_db(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_bandwidth_rule_remove(
    domain_pattern: String,
    state: St<'_>,
) -> Result<(), String> {
    state.bandwidth_limiter.remove_rule(&domain_pattern);
    state.bandwidth_limiter.save_to_db(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_bandwidth_status(state: St<'_>) -> Result<serde_json::Value, String> {
    let global = state
        .db
        .get_setting("bandwidth_global_kbps")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let rules = state
        .db
        .get_setting("bandwidth_rules")
        .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
        .unwrap_or(serde_json::json!([]));
    Ok(serde_json::json!({ "global_kbps": global, "rules": rules }))
}

#[tauri::command]
pub async fn cmd_plugin_list(
    state: St<'_>,
) -> Result<Vec<crate::engine::plugins::PluginManifest>, String> {
    Ok(state.plugin_registry.list_manifests())
}

#[tauri::command]
pub async fn cmd_plugin_install(path: String, state: St<'_>) -> Result<String, String> {
    let plugin = crate::engine::plugins::WasmPlugin::load(path.into(), None).map_err(es)?;
    let id = state.plugin_registry.install(plugin);
    Ok(id.to_string())
}

#[tauri::command]
pub async fn cmd_plugin_remove(id: String, state: St<'_>) -> Result<bool, String> {
    let uuid = uuid::Uuid::parse_str(&id).map_err(es)?;
    Ok(state.plugin_registry.remove(uuid))
}
