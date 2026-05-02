use super::{St, es};
use serde::{Deserialize, Serialize};

#[tauri::command]
pub async fn cmd_history_search(
    query: String,
    limit: Option<u32>,
    state: St<'_>,
) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();
    let limit = limit.unwrap_or(50).min(200);
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.search_history(&ws, &query, limit))
        .await
        .map_err(es)?
        .map_err(es)?;
    Ok(serde_json::json!({ "results": rows }))
}

#[tauri::command]
pub async fn cmd_history_clear(state: St<'_>) -> Result<(), String> {
    let ws = state.workspace_id();
    state.db.clear_history(&ws).map_err(es)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BookmarkPayload {
    pub id: String,
    pub url: String,
    pub title: String,
    pub tags: Vec<String>,
    pub ephemeral: bool,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[tauri::command]
pub async fn cmd_bookmark_add(
    url: String,
    title: String,
    tags: Option<Vec<String>>,
    ephemeral: Option<bool>,
    state: St<'_>,
) -> Result<String, String> {
    let ws = state.workspace_id();
    let tags_json = serde_json::to_string(&tags.unwrap_or_default()).map_err(es)?;
    let id = crate::storage::db::new_id();
    let now = crate::storage::db::unix_now();
    let ephem = ephemeral.unwrap_or(false);

    state
        .db
        .0
        .lock()
        .unwrap()
        .execute(
            "INSERT OR IGNORE INTO bookmarks(id,workspace_id,url,title,tags,ephemeral,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![id, ws, url, title, tags_json, ephem as i32, now],
        )
        .map_err(es)?;
    Ok(id)
}

#[tauri::command]
pub async fn cmd_bookmark_list(state: St<'_>) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();
    let conn = state.db.0.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id,url,title,tags,ephemeral,expires_at,created_at
         FROM bookmarks WHERE workspace_id=?1 ORDER BY created_at DESC",
        )
        .map_err(es)?;
    let rows: Vec<BookmarkPayload> = stmt
        .query_map(rusqlite::params![ws], |r| {
            let tags_json: String = r.get(3)?;
            Ok(BookmarkPayload {
                id: r.get(0)?,
                url: r.get(1)?,
                title: r.get(2)?,
                tags: serde_json::from_str(&tags_json).unwrap_or_default(),
                ephemeral: r.get::<_, i32>(4)? != 0,
                expires_at: r.get(5)?,
                created_at: r.get(6)?,
            })
        })
        .map_err(es)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(serde_json::json!({ "bookmarks": rows }))
}

#[tauri::command]
pub async fn cmd_bookmark_remove(id: String, state: St<'_>) -> Result<(), String> {
    state
        .db
        .0
        .lock()
        .unwrap()
        .execute("DELETE FROM bookmarks WHERE id=?1", rusqlite::params![id])
        .map_err(es)?;
    Ok(())
}

#[tauri::command]
pub async fn cmd_setting_get(key: String, state: St<'_>) -> Result<Option<String>, String> {
    Ok(state.db.get_setting(&key))
}

#[tauri::command]
pub async fn cmd_setting_set(key: String, value: String, state: St<'_>) -> Result<(), String> {
    state.db.set_setting(&key, &value).map_err(es)
}

#[tauri::command]
pub async fn cmd_dom_block_remove(id: String, state: St<'_>) -> Result<(), String> {
    state
        .db
        .0
        .lock()
        .unwrap()
        .execute("DELETE FROM dom_blocks WHERE id=?1", rusqlite::params![id])
        .map_err(es)?;
    Ok(())
}

#[tauri::command]
pub async fn cmd_zen_set_aphorism(aphorism: String, state: St<'_>) -> Result<(), String> {
    let mut zen = state.zen.lock().unwrap();
    zen.aphorism = aphorism;
    zen.save_to_db(&state.db);
    Ok(())
}
