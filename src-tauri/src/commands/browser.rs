use super::{St, es};

#[tauri::command]
pub async fn cmd_tabs_list(state: St<'_>) -> Result<serde_json::Value, String> {
    let tabs = state.tabs.lock().unwrap().list();
    Ok(serde_json::json!({ "tabs": tabs }))
}

// JS always calls this variant rather than cmd_tabs_list.
#[tauri::command]
pub async fn cmd_tabs_state(state: St<'_>) -> Result<serde_json::Value, String> {
    let store = state.tabs.lock().unwrap();
    Ok(serde_json::json!({
        "tabs":      store.list(),
        "active_id": store.active_id(),
        "count":     store.count(),
    }))
}


#[tauri::command]
pub async fn cmd_tab_create(url: String, state: St<'_>) -> Result<String, String> {
    Ok(state.tabs.lock().unwrap().open(url))
}

#[tauri::command]
pub async fn cmd_tab_close(tab_id: String, state: St<'_>) -> Result<(), String> {
    state.tabs.lock().unwrap().close(&tab_id);
    Ok(())
}

#[tauri::command]
pub async fn cmd_tab_activate(tab_id: String, state: St<'_>) -> Result<(), String> {
    state.tabs.lock().unwrap().activate(&tab_id);
    Ok(())
}

#[tauri::command]
pub async fn cmd_tab_update(
    tab_id: String,
    url: String,
    title: String,
    dwell_ms: Option<u64>,
    state: St<'_>,
) -> Result<(), String> {
    state
        .tabs
        .lock()
        .unwrap()
        .update(&tab_id, &url, &title, dwell_ms);
    Ok(())
}

#[tauri::command]
pub async fn cmd_tab_sleep(
    tab_id: String,
    deep: bool,
    snapshot: Option<String>,
    state: St<'_>,
) -> Result<(), String> {
    let mut tabs = state.tabs.lock().unwrap();
    if deep {
        let snap = snapshot.unwrap_or_default();
        if !snap.is_empty() {
            tabs.deep_sleep(&tab_id, &snap);
        } else {
            tabs.shallow_sleep(&tab_id);
        }
    } else {
        tabs.shallow_sleep(&tab_id);
    }
    Ok(())
}

#[tauri::command]
pub async fn cmd_tab_wake(tab_id: String, state: St<'_>) -> Result<(), String> {
    state.tabs.lock().unwrap().wake(&tab_id);
    Ok(())
}

#[tauri::command]
pub async fn cmd_tab_budget_config_set(max_tabs: u32, state: St<'_>) -> Result<(), String> {
    let cfg = crate::browser::budget::TabBudgetConfig {
        max_tabs: max_tabs.clamp(1, 50),
    };
    *state.tab_budget_cfg.lock().unwrap() = cfg.clone();
    cfg.save(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_tab_limit_get(state: St<'_>) -> Result<u32, String> {
    Ok(crate::browser::budget::TabBudgetConfig::load(&state.db).max_tabs)
}

#[tauri::command]
pub async fn cmd_tab_limit_set(limit: u32, state: St<'_>) -> Result<(), String> {
    let cfg = crate::browser::budget::TabBudgetConfig {
        max_tabs: limit.clamp(1, 50),
    };
    cfg.save(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_tab_proxy_set(
    tab_id: String,
    proxy: Option<crate::browser::proxy::ProxyConfig>,
    state: St<'_>,
) -> Result<(), String> {
    state.tab_proxy.set(&tab_id, proxy.clone()).map_err(es)?;
    if let Some(ref p) = proxy {
        crate::browser::proxy::save_proxy(&state.db, &tab_id, p).map_err(es)?;
    }
    Ok(())
}

#[tauri::command]
pub async fn cmd_tab_proxy_get(
    tab_id: String,
    state: St<'_>,
) -> Result<Option<crate::browser::proxy::ProxyConfig>, String> {
    Ok(state
        .tab_proxy
        .get(&tab_id)
        .or_else(|| crate::browser::proxy::load_proxy(&state.db, &tab_id)))
}

#[tauri::command]
pub async fn cmd_tab_proxy_remove(tab_id: String, state: St<'_>) -> Result<(), String> {
    state.tab_proxy.remove(&tab_id);
    Ok(())
}

// Tauri's capture_image() returns raw RGBA; PNG-encoded here so the JS
// OffscreenCanvas consumer gets a valid image.
#[tauri::command]
pub async fn cmd_tab_screenshot(app: tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager;
    let win = app
        .get_webview_window("main")
        .ok_or("main window not found")?;

    let img = tokio::time::timeout(std::time::Duration::from_secs(3), win.capture_image())
        .await
        .map_err(|_| "screenshot timed out")?
        .map_err(es)?;

    let (w, h) = (img.width(), img.height());
    let rgba = img.rgba().to_vec();
    let png = tokio::task::spawn_blocking(move || {
        use image::{ImageBuffer, Rgba};
        let buf: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_raw(w, h, rgba).ok_or("invalid image dimensions")?;
        let mut cursor = std::io::Cursor::new(Vec::new());
        buf.write_to(&mut cursor, image::ImageFormat::Png)
            .map_err(es)?;
        Ok::<Vec<u8>, String>(cursor.into_inner())
    })
    .await
    .map_err(es)??;

    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    Ok(B64.encode(&png))
}

#[tauri::command]
pub async fn cmd_dom_crush(domain: String, selector: String, state: St<'_>) -> Result<(), String> {
    crate::browser::dom_crusher::add_rule(&state.db, &domain, &selector).map_err(es)
}

#[tauri::command]
pub async fn cmd_dom_blocks_for(domain: String, state: St<'_>) -> Result<Vec<String>, String> {
    crate::browser::dom_crusher::rules_for_domain(&state.db, &domain).map_err(es)
}

#[tauri::command]
pub async fn cmd_reshuffle_rule_add(
    domain_pattern: String,
    selector: String,
    replacement: serde_json::Value,
    state: St<'_>,
) -> Result<String, String> {
    use crate::browser::dom_crusher::{ReplacementContent, validate_selector, clean_selector};
    let clean = clean_selector(&selector);
    validate_selector(&clean).map_err(es)?;
    // Validate the replacement JSON deserialises into a known variant.
    let _: ReplacementContent = serde_json::from_value(replacement.clone())
        .map_err(|e| format!("invalid replacement: {e}"))?;
    let json = serde_json::to_string(&replacement).map_err(es)?;
    state.db.insert_reshuffle_rule(&domain_pattern, &clean, &json).map_err(es)
}

#[tauri::command]
pub async fn cmd_reshuffle_rules_list(
    state: St<'_>,
) -> Result<Vec<crate::browser::dom_crusher::ReshuffleRule>, String> {
    crate::browser::dom_crusher::list_rules(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_reshuffle_rule_toggle(
    id: String,
    enabled: bool,
    state: St<'_>,
) -> Result<(), String> {
    state.db.set_reshuffle_rule_enabled(&id, enabled).map_err(es)
}

#[tauri::command]
pub async fn cmd_reshuffle_rule_delete(id: String, state: St<'_>) -> Result<(), String> {
    state.db.delete_reshuffle_rule(&id).map_err(es)
}

#[tauri::command]
pub async fn cmd_museum_random_card(
    state: St<'_>,
) -> Result<Option<serde_json::Value>, String> {
    match state.db.random_museum_card().map_err(es)? {
        Some((title, url, snippet)) => Ok(Some(serde_json::json!({
            "title":   title,
            "url":     url,
            "snippet": snippet,
        }))),
        None => Ok(None),
    }
}

// Called by the JS navigation hook with the current page's hostname.
// Returns a ready-to-eval script string (empty string = no rules for this domain).
#[tauri::command]
pub async fn cmd_reshuffle_script_for(
    domain: String,
    state: St<'_>,
) -> Result<String, String> {
    let all = crate::browser::dom_crusher::list_rules(&state.db).map_err(es)?;
    let matching: Vec<_> = all
        .into_iter()
        .filter(|r| r.enabled && {
            let p = &r.domain_pattern;
            if p == "*" { true }
            else if let Some(suffix) = p.strip_prefix("*.") {
                domain.ends_with(suffix)
            } else {
                domain == *p || domain.ends_with(&format!(".{p}"))
            }
        })
        .collect();
    Ok(crate::browser::dom_crusher::reshuffle_script(&matching))
}

#[tauri::command]
pub async fn cmd_boosts_for_domain(
    domain: String,
    state: St<'_>,
) -> Result<Vec<crate::browser::boosts::BoostRule>, String> {
    crate::browser::boosts::boosts_for_domain(&state.db, &domain).map_err(es)
}

#[tauri::command]
pub async fn cmd_boosts_list(
    state: St<'_>,
) -> Result<Vec<crate::browser::boosts::BoostRule>, String> {
    crate::browser::boosts::all_boosts(&state.db).map_err(es)
}

#[tauri::command]
pub async fn cmd_boost_upsert(
    rule: crate::browser::boosts::BoostRule,
    state: St<'_>,
) -> Result<(), String> {
    if rule.builtin {
        return Err("built-in Boosts cannot be modified via this command".into());
    }
    crate::browser::boosts::upsert(&state.db, &rule).map_err(es)
}

#[tauri::command]
pub async fn cmd_boost_delete(id: String, state: St<'_>) -> Result<(), String> {
    crate::browser::boosts::delete(&state.db, &id).map_err(es)
}
