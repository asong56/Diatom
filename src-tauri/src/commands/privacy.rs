use super::{St, es};

#[tauri::command]
pub async fn cmd_privacy_config_get(
    state: St<'_>,
) -> Result<crate::privacy::config::PrivacyConfig, String> {
    Ok(state.privacy.read().unwrap().clone())
}

#[tauri::command]
pub async fn cmd_privacy_config_set(
    config: crate::privacy::config::PrivacyConfig,
    state: St<'_>,
) -> Result<(), String> {
    *state.privacy.write().unwrap() = config;
    Ok(())
}

#[tauri::command]
pub async fn cmd_ohttp_status(state: St<'_>) -> Result<serde_json::Value, String> {
    let relay = state
        .db
        .get_setting("ohttp_relay")
        .unwrap_or_else(|| crate::privacy::ohttp::OHTTP_RELAYS[0].to_owned());
    let has_key = state.db.get_setting("ohttp_key_config").is_some();
    Ok(serde_json::json!({
        "relay":          relay,
        "has_key_config": has_key,
        "relays":         crate::privacy::ohttp::OHTTP_RELAYS,
    }))
}

#[tauri::command]
pub async fn cmd_onion_suggest(
    host: String,
) -> Result<Option<crate::privacy::onion::OnionSuggestion>, String> {
    Ok(crate::privacy::onion::lookup(&host))
}

#[tauri::command]
pub async fn cmd_threat_check(url: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let domain = crate::utils::domain_of(&url);
    let flagged = crate::privacy::threat::check_local(&state.threat_list.read().unwrap(), &domain);
    Ok(serde_json::json!({ "domain": domain, "flagged": flagged }))
}

/// Return the count of loaded threat-list entries (used by JS `threatRefresh()`).
#[tauri::command]
pub async fn cmd_threat_list_refresh(state: St<'_>) -> Result<serde_json::Value, String> {
    let count = state.threat_list.read().map(|l| l.len()).unwrap_or(0);
    Ok(serde_json::json!({ "domains": count }))
}

#[tauri::command]
pub async fn cmd_wifi_scan() -> Result<Option<crate::privacy::wifi::WifiInfo>, String> {
    Ok(crate::privacy::wifi::detect_current_network())
}

#[tauri::command]
pub async fn cmd_wifi_trust_network(
    ssid: String,
    bssid: String,
    state: St<'_>,
) -> Result<(), String> {
    crate::privacy::wifi::trust_network(&state.db, &ssid, &bssid).map_err(es)
}

#[tauri::command]
pub async fn cmd_wifi_distrust_network(
    ssid: String,
    bssid: String,
    state: St<'_>,
) -> Result<(), String> {
    crate::privacy::wifi::distrust_network(&state.db, &ssid, &bssid).map_err(es)
}

#[tauri::command]
pub async fn cmd_wifi_trusted_networks(state: St<'_>) -> Result<serde_json::Value, String> {
    let info = crate::privacy::wifi::detect_current_network();
    let trusted = info
        .as_ref()
        .map(|w| crate::privacy::wifi::is_trusted(&state.db, &w.ssid, &w.bssid))
        .unwrap_or(false);
    Ok(serde_json::json!({ "current": info, "current_trusted": trusted }))
}

/// Return the JS injection script that normalises the browser fingerprint.
/// Called once during the frontend init sequence.
#[tauri::command]
pub async fn cmd_fp_norm_script(state: St<'_>) -> Result<String, String> {
    Ok(state.fp_norm_script())
}
