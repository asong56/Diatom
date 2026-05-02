use super::{St, es};

#[tauri::command]
pub async fn cmd_freeze_page(
    url: String,
    title: String,
    raw_html: String,
    state: St<'_>,
) -> Result<String, String> {
    let master_key = *state.master_key.lock().unwrap();
    let ws = state.workspace_id();
    let bundle = crate::storage::freeze::freeze_page(
        &raw_html,
        &url,
        &title,
        &ws,
        &master_key,
        &state.bundles_dir(),
    )
    .map_err(es)?;
    let id = bundle.bundle_row.id.clone();
    state.db.insert_bundle(&bundle.bundle_row).map_err(es)?;
    Ok(id)
}

#[tauri::command]
pub async fn cmd_museum_search(query: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.search_bundles_fts(&query, &ws))
        .await
        .map_err(es)?;
    Ok(serde_json::json!({ "results": rows.unwrap_or_default() }))
}

#[tauri::command]
pub async fn cmd_museum_list(state: St<'_>) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();
    let rows = state.db.list_bundles(&ws, 100).unwrap_or_default();
    Ok(serde_json::json!({ "bundles": rows }))
}

#[tauri::command]
pub async fn cmd_museum_get(id: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let bundle = state
        .db
        .get_bundle_by_id(&id)
        .map_err(es)?
        .ok_or_else(|| format!("bundle {} not found", id))?;
    Ok(serde_json::json!({ "bundle": bundle }))
}

#[tauri::command]
pub async fn cmd_museum_delete(id: String, state: St<'_>) -> Result<(), String> {
    if let Ok(Some(b)) = state.db.get_bundle_by_id(&id) {
        let _ = std::fs::remove_file(state.bundles_dir().join(&b.bundle_path));
    }
    state.db.delete_bundle(&id).map_err(es)
}

/// Promote a Museum snapshot back to the hot (full-text) tier when opened.
#[tauri::command]
pub async fn cmd_museum_touch_access(id: String, state: St<'_>) -> Result<(), String> {
    state.db.touch_bundle_access(&id).map_err(es)
}

/// Decompress and return the HTML for a saved Museum bundle.
#[tauri::command]
pub async fn cmd_museum_thaw(id: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let meta = state
        .db
        .get_bundle_by_id(&id)
        .map_err(es)?
        .ok_or_else(|| format!("museum bundle not found: {id}"))?;
    let path = state.bundles_dir().join(&meta.bundle_path);
    let html = state
        .with_master_key(|key| crate::storage::freeze::thaw_bundle(&path, &id, key))
        .map_err(es)?;
    Ok(serde_json::json!({
        "id":        id,
        "url":       meta.url,
        "title":     meta.title,
        "html":      html,
        "frozen_at": meta.frozen_at,
    }))
}

/// Keyword search across cold-tier bundles (no FTS5 index required).
/// Triggered only after a hot-tier search returns no results.
#[tauri::command]
pub async fn cmd_museum_deep_dig(
    query: String,
    state: St<'_>,
) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();
    let db = state.db.clone();
    let results = tokio::task::spawn_blocking(move || db.search_cold_keyword(&query, &ws))
        .await
        .map_err(es)?
        .map_err(es)?;
    Ok(serde_json::json!({ "bundles": results }))
}

#[tauri::command]
pub async fn cmd_vault_list(state: St<'_>) -> Result<serde_json::Value, String> {
    let entries = state.vault.lock().unwrap().list_titles();
    Ok(serde_json::json!({ "entries": entries }))
}

#[tauri::command]
pub async fn cmd_vault_add(
    entry: crate::storage::vault::VaultEntry,
    state: St<'_>,
) -> Result<String, String> {
    state.with_master_key(|key| {
        state
            .vault
            .lock()
            .unwrap()
            .add(entry, &state.db, key)
            .map_err(es)
    })
}

#[tauri::command]
pub async fn cmd_vault_update(
    id: String,
    entry: crate::storage::vault::VaultEntry,
    state: St<'_>,
) -> Result<(), String> {
    state.with_master_key(|key| {
        state
            .vault
            .lock()
            .unwrap()
            .update(&id, entry, &state.db, key)
            .map_err(es)
    })
}

#[tauri::command]
pub async fn cmd_vault_delete(id: String, state: St<'_>) -> Result<(), String> {
    state
        .vault
        .lock()
        .unwrap()
        .delete(&id, &state.db)
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_vault_autofill(url: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let domain = crate::utils::domain_of(&url);
    let result = state.with_master_key(|key| {
        state
            .vault
            .lock()
            .unwrap()
            .autofill_for_domain(&domain, key)
            .map_err(es)
    })?;
    Ok(serde_json::json!({ "matches": result }))
}

#[tauri::command]
pub async fn cmd_storage_report(
    state: St<'_>,
) -> Result<crate::storage::guard::StorageReport, String> {
    let budget = crate::storage::guard::StorageBudget::load_from_db(&state.db);
    Ok(crate::storage::guard::report(&state.db, &budget))
}

#[tauri::command]
pub async fn cmd_storage_evict_lru(
    target_pct: u8,
    state: St<'_>,
) -> Result<serde_json::Value, String> {
    let budget = crate::storage::guard::StorageBudget::load_from_db(&state.db);
    let (deleted, freed) =
        crate::storage::guard::evict_lru(&state.db, &budget, target_pct, &state.bundles_dir())
            .map_err(es)?;
    Ok(serde_json::json!({ "deleted": deleted, "freed_bytes": freed }))
}

#[tauri::command]
pub async fn cmd_storage_budget_set(
    museum_mb: Option<u64>,
    index_mb: Option<u64>,
    state: St<'_>,
) -> Result<(), String> {
    if let Some(mb) = museum_mb {
        state
            .db
            .set_setting("museum_budget_mb", &mb.to_string())
            .map_err(es)?;
    }
    if let Some(mb) = index_mb {
        state
            .db
            .set_setting("index_budget_mb", &mb.max(10).to_string())
            .map_err(es)?;
    }
    Ok(())
}

#[tauri::command]
pub async fn cmd_storage_degrade_cold(state: St<'_>) -> Result<u32, String> {
    let budget = crate::storage::guard::StorageBudget::load_from_db(&state.db);
    crate::storage::guard::degrade_cold_indexes(&state.db, &budget).map_err(es)
}
