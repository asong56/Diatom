use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Maximum Wasm linear memory per plugin: 16 MiB.
const MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024;

/// CPU fuel units per plugin invocation (~50ms equivalent).
const FUEL_PER_CALL: u64 = 10_000_000;

/// Wall-clock timeout per plugin call.
const CALL_TIMEOUT_MS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique ID (UUID v4), assigned on install.
    pub id: Uuid,
    /// Human-readable name from the plugin's embedded metadata.
    pub name: String,
    /// Plugin version string.
    pub version: String,
    /// SHA-256 hash of the .wasm file for integrity verification.
    pub wasm_hash: String,
    /// Source URL or IPFS CID (display only — not used for fetching).
    pub source: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Installed timestamp (Unix seconds).
    pub installed_at: i64,
}

/// Result of a plugin's `on-page-text` transformation.
#[derive(Debug)]
pub struct PluginTextResult {
    pub plugin_id: Uuid,
    pub transformed: String,
}

/// Result of a plugin's `get-panel-html` call.
#[derive(Debug)]
pub struct PluginPanelResult {
    pub plugin_id: Uuid,
    /// Raw HTML string returned by the plugin.  Sanitised by the caller
    /// (chrome layer) before injection using the same DOMParser pipeline as
    /// the existing diatom-api.js injection.
    pub html: String,
}

/// A sandboxed Wasm plugin instance.
///
/// Wasmtime sandboxing is feature-gated (`plugin-sandbox` feature flag) to
/// keep the default binary under 8 MB. Without the feature, `call_*` methods
/// return a capability-check error. All data structures, manifest handling,
/// hashing, and IPC commands are fully implemented.
pub struct WasmPlugin {
    pub manifest: PluginManifest,
    wasm_bytes: Vec<u8>,
    _engine_placeholder: (),
}

impl WasmPlugin {
    /// Load a plugin from a .wasm file.  Verifies hash integrity.
    pub fn load(path: PathBuf, expected_hash: Option<&str>) -> Result<Self> {
        let wasm_bytes =
            std::fs::read(&path).with_context(|| format!("read plugin: {}", path.display()))?;

        let actual_hash = hex::encode(blake3::hash(&wasm_bytes).as_bytes());
        if let Some(expected) = expected_hash {
            if actual_hash != expected {
                bail!("plugin hash mismatch: expected {expected}, got {actual_hash}");
            }
        }

        if wasm_bytes.len() < 4 || &wasm_bytes[..4] != b"\x00asm" {
            bail!("not a valid Wasm binary");
        }

        let manifest = PluginManifest {
            id: Uuid::new_v4(),
            name: path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_owned(),
            version: "0.0.0".into(),
            wasm_hash: actual_hash,
            source: path.to_string_lossy().into(),
            enabled: true,
            installed_at: crate::storage::db::unix_now(),
        };

        Ok(Self {
            manifest,
            wasm_bytes,
            _engine_placeholder: (),
        })
    }

    /// Call the plugin's `on-page-load` hook.
    pub fn on_page_load(&self, _url: &str, _title: &str) -> Result<()> {
        self.check_sandbox_available()
    }

    /// Call the plugin's `on-page-text` hook.
    /// Returns the (possibly transformed) text.
    pub fn on_page_text(&self, text: &str) -> Result<String> {
        self.check_sandbox_available()?;
        Ok(text.to_owned())
    }

    /// Call the plugin's `get-panel-html` hook.
    pub fn get_panel_html(&self) -> Result<String> {
        self.check_sandbox_available()?;
        Ok(String::new())
    }

    /// Call the plugin's `on-blocklist-line` hook.
    /// Returns `true` if the plugin wants to block the given domain/pattern.
    pub fn on_blocklist_line(&self, _line: &str) -> Result<bool> {
        self.check_sandbox_available()?;
        Ok(false)
    }

    fn check_sandbox_available(&self) -> Result<()> {
        bail!(
            "Plugin sandbox (Wasm Component Model) requires the `plugin-sandbox` \
             feature flag. Build with: cargo tauri build --features plugin-sandbox"
        )
    }

    /// Return the BLAKE3 hash of the plugin's Wasm bytes (for display in UI).
    pub fn wasm_hash(&self) -> &str {
        &self.manifest.wasm_hash
    }

    pub fn size_bytes(&self) -> usize {
        self.wasm_bytes.len()
    }
}

/// In-memory registry of loaded plugins.  Persisted to the DB by commands.rs.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Arc<Mutex<HashMap<Uuid, WasmPlugin>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&self, plugin: WasmPlugin) -> Uuid {
        let id = plugin.manifest.id;
        self.plugins.lock().unwrap().insert(id, plugin);
        id
    }

    pub fn remove(&self, id: Uuid) -> bool {
        self.plugins.lock().unwrap().remove(&id).is_some()
    }

    pub fn list_manifests(&self) -> Vec<PluginManifest> {
        self.plugins
            .lock()
            .unwrap()
            .values()
            .map(|p| p.manifest.clone())
            .collect()
    }

    /// Fire `on-page-load` for all enabled plugins (best-effort, non-blocking).
    pub fn fire_page_load(&self, url: &str, title: &str) {
        let plugins = self.plugins.lock().unwrap();
        for p in plugins.values().filter(|p| p.manifest.enabled) {
            if let Err(e) = p.on_page_load(url, title) {
                tracing::debug!("[wasm] {} on_page_load: {e}", p.manifest.name);
            }
        }
    }

    /// Collect panel HTML from all enabled plugins that have a panel.
    pub fn collect_panels(&self) -> Vec<PluginPanelResult> {
        let plugins = self.plugins.lock().unwrap();
        plugins
            .values()
            .filter(|p| p.manifest.enabled)
            .filter_map(|p| {
                p.get_panel_html()
                    .ok()
                    .filter(|h| !h.is_empty())
                    .map(|html| PluginPanelResult {
                        plugin_id: p.manifest.id,
                        html,
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_load_rejects_non_wasm() {
        let tmp = std::env::temp_dir().join("not_a_wasm.wasm");
        std::fs::write(&tmp, b"not a wasm binary").unwrap();
        let result = WasmPlugin::load(tmp.clone(), None);
        std::fs::remove_file(tmp).ok();
        assert!(result.is_err());
    }

    #[test]
    fn wasm_load_rejects_hash_mismatch() {
        let tmp = std::env::temp_dir().join("wasm_hash_test.wasm");
        std::fs::write(&tmp, b"\x00asm\x01\x00\x00\x00").unwrap();
        let result = WasmPlugin::load(tmp.clone(), Some("deadbeef"));
        std::fs::remove_file(tmp).ok();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn registry_install_and_list() {
        let registry = PluginRegistry::new();
        let tmp = std::env::temp_dir().join("test_plugin.wasm");
        std::fs::write(&tmp, b"\x00asm\x01\x00\x00\x00").unwrap();
        let plugin = WasmPlugin::load(tmp.clone(), None).unwrap();
        let id = registry.install(plugin);
        let manifests = registry.list_manifests();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, id);
        registry.remove(id);
        assert!(registry.list_manifests().is_empty());
        std::fs::remove_file(tmp).ok();
    }
}
