use super::{St, es};

#[tauri::command]
pub async fn cmd_slm_status(state: St<'_>) -> Result<serde_json::Value, String> {
    let online = crate::features::labs::is_lab_enabled(&state.db, "slm_server");
    Ok(serde_json::json!({ "enabled": online }))
}

#[tauri::command]
pub async fn cmd_slm_complete(prompt: String, state: St<'_>) -> Result<String, String> {
    use crate::ai::slm::{ChatMessage, ChatRequest, SlmServer};

    let mut cache = state.slm_cache.lock().await;
    let server = match cache.as_ref() {
        Some(srv) => srv.clone(),
        None => {
            let privacy_mode = state
                .privacy
                .read()
                .map(|p| p.extreme_mode)
                .unwrap_or(false);
            let srv = std::sync::Arc::new(SlmServer::new(privacy_mode, None).await);
            *cache = Some(srv.clone());
            srv
        }
    };
    drop(cache);

    let req = ChatRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: prompt,
        }],
        model: server.active_model.clone(),
        stream: false,
        max_tokens: None,
    };
    let resp = server.chat(&req).await.map_err(es)?;
    Ok(resp
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default())
}

/// Cancel the running SLM server and release its TCP port.
#[tauri::command]
pub async fn cmd_slm_reset(state: St<'_>) -> Result<(), String> {
    if let Ok(mut tok) = state.slm_shutdown_token.lock() {
        if let Some(t) = tok.take() {
            t.cancel();
        }
    }
    *state.slm_cache.lock().await = None;
    Ok(())
}

/// Persist the preferred model id and hot-swap it in the running server.
#[tauri::command]
pub async fn cmd_slm_set_model(model_id: String, state: St<'_>) -> Result<(), String> {
    state
        .db
        .set_setting("slm_preferred_model", &model_id)
        .map_err(es)?;
    let mut cache = state.slm_cache.lock().await;
    if let Some(old) = cache.as_ref() {
        let mut updated = (**old).clone();
        updated.active_model = model_id;
        *cache = Some(std::sync::Arc::new(updated));
        tracing::info!("slm: active_model hot-swapped");
    }
    Ok(())
}

/// Enable or disable the SLM server lab; cancels the server when disabling.
#[tauri::command]
pub async fn cmd_slm_server_toggle(enable: bool, state: St<'_>) -> Result<(), String> {
    crate::features::labs::set_lab(&state.db, "slm_server", enable).map_err(es)?;
    if !enable {
        if let Ok(mut tok) = state.slm_shutdown_token.lock() {
            if let Some(t) = tok.take() {
                t.cancel();
            }
        }
        *state.slm_cache.lock().await = None;
    }
    Ok(())
}

#[tauri::command]
pub async fn cmd_ai_rename_suggest(
    ctx: crate::ai::renamer::DownloadContext,
    state: St<'_>,
) -> Result<crate::ai::renamer::RenameResult, String> {
    if crate::features::labs::is_lab_enabled(&state.db, "slm_server") {
        match crate::ai::renamer::suggest_via_slm(&ctx).await {
            Ok(result) => return Ok(result),
            Err(e) => tracing::debug!("ai_rename: SLM failed ({}), using slug fallback", e),
        }
    }
    Ok(crate::ai::renamer::suggest_from_title(&ctx))
}

#[tauri::command]
pub async fn cmd_shadow_search(query: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();
    let results = crate::ai::shadow_index::search_local(&state.db, &ws, &query).map_err(es)?;
    Ok(serde_json::json!({ "results": results }))
}

#[tauri::command]
pub async fn cmd_mcp_status(state: St<'_>) -> Result<serde_json::Value, String> {
    let token_present = std::path::Path::new(&state.data_dir)
        .join("mcp.token")
        .exists();
    Ok(serde_json::json!({
        "port":          crate::ai::mcp::MCP_PORT,
        "token_present": token_present,
    }))
}

/// Return the DevPanel auth token, which also serves as the local MCP bearer.
#[tauri::command]
pub async fn cmd_mcp_session_token(state: St<'_>) -> Result<String, String> {
    Ok(state.devpanel_auth_token.clone())
}
