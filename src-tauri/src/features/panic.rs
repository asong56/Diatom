use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Emitter, Manager};

/// Global panic state — shared between the hotkey handler and the restore path.
pub static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanicConfig {
    /// Hotkey string in Tauri format, e.g. "CmdOrCtrl+Shift+Period".
    pub hotkey: String,
    /// URL to navigate to during panic (blank tab substitute).
    pub decoy_url: String,
    /// Fake page title shown while in panic state.
    pub decoy_title: String,
    /// If true, fire_workspace() is called on panic (destructive — wipes tabs).
    pub wipe_mode: bool,
}

impl Default for PanicConfig {
    fn default() -> Self {
        Self {
            hotkey: "CmdOrCtrl+Shift+Period".to_owned(),
            decoy_url: "https://calendar.google.com".to_owned(),
            decoy_title: "Google Calendar".to_owned(),
            wipe_mode: false,
        }
    }
}

/// Activate panic mode: minimize all windows and emit the overlay event.
///
/// The frontend receives `diatom:panic-activate` and injects a full-viewport
/// decoy DOM node over the WebView so the underlying page is not visible even
/// in the window thumbnail. No network requests are made.
pub fn activate(app: &AppHandle, config: &PanicConfig) {
    if PANIC_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tracing::info!("panic_button: activating — decoy: {}", config.decoy_url);

    for (label, win) in app.webview_windows() {
        if let Err(e) = win.minimize() {
            tracing::warn!("panic_button: could not minimize window {label}: {e}");
        }
    }

    let _ = app.emit(
        "diatom:panic-activate",
        serde_json::json!({
            "decoy_url":   config.decoy_url,
            "decoy_title": config.decoy_title,
            "wipe_mode":   config.wipe_mode,
        }),
    );
}

/// Restore from panic mode: un-minimize windows and remove the decoy overlay.
pub fn restore(app: &AppHandle) {
    if !PANIC_ACTIVE.swap(false, Ordering::SeqCst) {
        return; // Not in panic — nothing to restore
    }

    tracing::info!("panic_button: restoring workspace");

    for (label, win) in app.webview_windows() {
        if let Err(e) = win.unminimize() {
            tracing::warn!("panic_button: could not unminimize window {label}: {e}");
        }
        let _ = win.set_focus();
    }

    let _ = app.emit("diatom:panic-restore", serde_json::json!({}));
}

/// Toggle panic state — called by the global hotkey handler.
pub fn toggle(app: &AppHandle, config: &PanicConfig) {
    if PANIC_ACTIVE.load(Ordering::SeqCst) {
        restore(app);
    } else {
        activate(app, config);
    }
}

/// Load PanicConfig from the DB settings table.
pub fn load_config(db: &crate::storage::db::Db) -> PanicConfig {
    db.get_setting("panic_button_config")
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

/// Persist PanicConfig to the DB settings table.
pub fn save_config(db: &crate::storage::db::Db, cfg: &PanicConfig) -> anyhow::Result<()> {
    db.set_setting("panic_button_config", &serde_json::to_string(cfg)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_reasonable() {
        let cfg = PanicConfig::default();
        assert!(cfg.hotkey.contains("Shift"));
        assert!(!cfg.wipe_mode); // wipe mode must default OFF — destructive
    }
}
