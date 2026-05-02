use super::{St, es};

/// Read the user-configured Nostr relay URL from the database,
/// falling back to the built-in default if none is set.
fn nostr_relay(state: &crate::state::AppState) -> String {
    state
        .db
        .get_setting("nostr_relay")
        .unwrap_or_else(|| crate::sync::nostr::DEFAULT_RELAY.to_owned())
}

#[tauri::command]
pub async fn cmd_nostr_publish(
    kind: u64,
    content: String,
    state: St<'_>,
) -> Result<String, String> {
    let key = *state.master_key.lock().unwrap();
    let relay = nostr_relay(&state);
    crate::sync::nostr::publish(&relay, kind, &content, &key)
        .await
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_nostr_fetch(kind: u64, state: St<'_>) -> Result<serde_json::Value, String> {
    let key = *state.master_key.lock().unwrap();
    let relay = nostr_relay(&state);
    let events = crate::sync::nostr::fetch(&relay, kind, &key)
        .await
        .map_err(es)?;
    Ok(serde_json::json!({ "events": events }))
}
