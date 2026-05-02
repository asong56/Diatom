use super::{St, es};

/// Called by the frontend once the initial render is complete.
/// Cancels the 3-second fallback timer and shows the window immediately.
#[tauri::command]
pub async fn cmd_signal_window_ready(state: St<'_>) -> Result<(), String> {
    state.window_ready_token.cancel();
    Ok(())
}

#[tauri::command]
pub async fn cmd_power_budget_status() -> Result<serde_json::Value, String> {
    let b = crate::features::sentinel::power_budget_current();
    Ok(serde_json::json!({
        "state":                    format!("{:?}", b.state),
        "battery_pct":              b.battery_pct,
        "sentinel_interval_secs":   b.sentinel_interval_secs,
        "tab_budget_interval_secs": b.tab_budget_interval_secs,
        "pir_enabled":              b.pir_enabled,
        "decoy_enabled":            b.decoy_enabled,
    }))
}

#[tauri::command]
pub async fn cmd_home_base_data(state: St<'_>) -> Result<serde_json::Value, String> {
    let ws = state.workspace_id();

    // All three DB queries run on a blocking thread to avoid stalling the
    // async executor.  They share the same workspace id but are independent
    // and safe to run sequentially.
    let (top_domains, pinned, recent_museum) = {
        let db = state.db.clone();
        let ws1 = ws.clone();
        let ws2 = ws.clone();
        let ws3 = ws.clone();

        let top = tokio::task::spawn_blocking(move || db.top_domains(&ws1, 8))
            .await
            .map_err(es)?
            .unwrap_or_default();

        let db = state.db.clone();
        let pin = tokio::task::spawn_blocking(move || db.pinned_bookmarks(&ws2, 8))
            .await
            .map_err(es)?
            .unwrap_or_default();

        let db = state.db.clone();
        let mus = tokio::task::spawn_blocking(move || db.list_bundles(&ws3, 3))
            .await
            .map_err(es)?
            .unwrap_or_default();

        (top, pin, mus)
    };

    let rss_unread = state.rss.lock().unwrap().unread_count();
    let slm_online = state
        .db
        .get_setting("lab_slm_server")
        .map(|v| v == "true")
        .unwrap_or(false);

    Ok(serde_json::json!({
        "top_domains":   top_domains,
        "pinned":        pinned,
        "recent_museum": recent_museum,
        "rss_unread":    rss_unread,
        "slm_status":    { "online": slm_online },
    }))
}

#[tauri::command]
pub async fn cmd_peek_fetch(url: String, state: St<'_>) -> Result<serde_json::Value, String> {
    let domain = crate::utils::domain_of(&url);

    if crate::engine::blocker::is_blocked(&domain) {
        return Ok(serde_json::json!({
            "url": url, "title": domain,
            "description": null, "og_image": null, "blocked": true,
        }));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .user_agent(state.current_ua(false))
        .build()
        .map_err(es)?;

    let html = client
        .get(&url)
        .send()
        .await
        .map_err(es)?
        .text()
        .await
        .unwrap_or_default();

    let title = extract_meta(&html, "og:title")
        .or_else(|| extract_tag(&html, "title"))
        .unwrap_or_else(|| domain.clone());
    let description =
        extract_meta(&html, "og:description").or_else(|| extract_meta(&html, "description"));
    let og_image = extract_meta(&html, "og:image");

    Ok(serde_json::json!({
        "url": url, "title": title,
        "description": description, "og_image": og_image, "blocked": false,
    }))
}

/// Extract a `<meta property="…" content="…">` or `<meta name="…" content="…">` value.
fn extract_meta(html: &str, name: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let needle = format!("property=\"{}\"", name.to_lowercase());
    let needle2 = format!("name=\"{}\"", name.to_lowercase());
    let pos = lower.find(&needle).or_else(|| lower.find(&needle2))?;
    let after = &html[pos..];
    let content_pos = after.to_lowercase().find("content=\"")? + "content=\"".len();
    let end = after[content_pos..].find('"')?;
    Some(after[content_pos..content_pos + end].to_owned())
}

/// Extract the text content of `<tag>…</tag>`.
fn extract_tag(html: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = html.to_lowercase().find(&open)? + open.len();
    let end = html[start..].to_lowercase().find(&close)?;
    Some(html[start..start + end].trim().to_owned())
}
