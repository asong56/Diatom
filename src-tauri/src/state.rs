use crate::{
    auth::totp::TotpStore, auth::trust::TrustStore, browser::budget::TabBudgetConfig,
    browser::proxy::TabProxyRegistry, browser::tabs::TabStore, engine::bandwidth::BandwidthLimiter,
    engine::compat::CompatStore, engine::ghostpipe::GhostPipeConfig, engine::monitor::NetMonitor,
    engine::plugins::PluginRegistry, features::rss::RssStore, features::sentinel::SentinelCache,
    features::zen::ZenConfig, privacy::config::PrivacyConfig,
    privacy::fingerprint_norm::FingerprintNorm, storage::db::Db, storage::vault::VaultStore,
};
use anyhow::Result;
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock, atomic::AtomicBool},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

pub struct AppState {
    pub db: Db,
    pub vault: Mutex<VaultStore>,

    pub ws_id: Mutex<String>,
    pub data_dir: PathBuf,

    pub privacy: RwLock<PrivacyConfig>,
    pub fp_norm: FingerprintNorm,
    pub ghostpipe: RwLock<GhostPipeConfig>,
    pub threat_list: RwLock<HashSet<String>>,
    pub quad9_enabled: AtomicBool,
    pub age_heuristic_enabled: AtomicBool,

    pub master_key: Mutex<[u8; 32]>,
    pub noise_seed: Mutex<u64>,

    pub tabs: Mutex<TabStore>,
    pub tab_budget_cfg: Mutex<TabBudgetConfig>,
    pub tab_proxy: TabProxyRegistry,
    pub compat: Mutex<CompatStore>,

    pub trust: Mutex<TrustStore>,
    pub totp: Mutex<TotpStore>,

    pub rss: Mutex<RssStore>,
    pub zen: Mutex<ZenConfig>,

    pub net_monitor: Arc<NetMonitor>,
    pub bandwidth_limiter: BandwidthLimiter,

    pub live_blocker: Arc<RwLock<Option<aho_corasick::AhoCorasick>>>,

    pub slm_cache: AsyncMutex<Option<Arc<crate::ai::slm::SlmServer>>>,
    pub slm_shutdown_token: Mutex<Option<CancellationToken>>,

    pub plugin_registry: PluginRegistry,

    pub sentinel: Mutex<SentinelCache>,

    pub storage_budget: Mutex<crate::storage::guard::StorageBudget>,

    pub power_budget: Mutex<crate::features::sentinel::PowerBudget>,

    pub shutdown_token: CancellationToken,
    pub window_ready_token: CancellationToken,

    /// Bearer token for the local MCP server (`crate::ai::mcp`). Generated
    /// once at startup; returned to the frontend via `cmd_mcp_session_token`.
    /// (Previously also handed to the DevPanel process for its bridge
    /// handshake — that consumer was removed along with `dev_panel.rs` and
    /// `diatom_bridge`'s protocol/client/server modules. This token now
    /// serves MCP auth only.)
    pub mcp_session_token: String,

    pub platform: &'static str,
}

impl AppState {
    pub fn new(
        data_dir: PathBuf,
        initial_power: crate::features::sentinel::PowerBudget,
    ) -> Result<Self> {
        let db = Db::open(&data_dir.join("diatom.db"))?;
        std::fs::create_dir_all(data_dir.join("bundles"))?;

        let master_key = crate::storage::freeze::get_or_init_master_key(&db)?;

        let quad9 = db
            .get_setting("quad9_enabled")
            .map(|v| v == "true")
            .unwrap_or(true);
        let age_h = db
            .get_setting("age_heuristic_enabled")
            .map(|v| v == "true")
            .unwrap_or(true);

        let threat_list: HashSet<String> = db
            .get_setting("threat_list_json")
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();

        let ws_id = db
            .get_setting("active_workspace_id")
            .unwrap_or_else(|| "default".to_owned());

        let totp = TotpStore::load_from_db(&db, &master_key);
        let trust = TrustStore::load_from_db(&db);
        let rss = RssStore::load_from_db(&db);
        let vault = VaultStore::load_from_db(&db, &master_key);
        let zen = db
            .zen_load()
            .map(|raw| ZenConfig::from_raw(&raw))
            .unwrap_or_default();

        let mut compat_store = CompatStore::default();
        if let Some(json) = db.get_setting("compat_legacy_domains") {
            if let Ok(domains) = serde_json::from_str::<Vec<String>>(&json) {
                for d in domains {
                    compat_store.add_legacy(&d);
                }
            }
        }

        let storage_budget = crate::storage::guard::StorageBudget::load_from_db(&db);

        let tab_budget_cfg = db
            .get_setting("tab_budget_config")
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();

        let sentinel: SentinelCache = db
            .get_setting("sentinel_cache")
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();

        let platform: &'static str = match std::env::consts::OS {
            "macos" => "macos",
            "windows" => "windows",
            _ => "linux",
        };

        let bandwidth_limiter = BandwidthLimiter::new();
        bandwidth_limiter.load_from_db(&db);

        Ok(AppState {
            db,
            vault: Mutex::new(vault),
            ws_id: Mutex::new(ws_id),
            data_dir,
            privacy: RwLock::new(PrivacyConfig::default()),
            fp_norm: FingerprintNorm::default(),
            ghostpipe: RwLock::new(crate::engine::ghostpipe::GhostPipeConfig::default()),
            threat_list: RwLock::new(threat_list),
            quad9_enabled: AtomicBool::new(quad9),
            age_heuristic_enabled: AtomicBool::new(age_h),
            master_key: Mutex::new(master_key),
            noise_seed: Mutex::new(rand::random()),
            tabs: Mutex::new(TabStore::default()),
            tab_budget_cfg: Mutex::new(tab_budget_cfg),
            tab_proxy: TabProxyRegistry::new(),
            compat: Mutex::new(compat_store),
            trust: Mutex::new(trust),
            totp: Mutex::new(totp),
            rss: Mutex::new(rss),
            zen: Mutex::new(zen),
            net_monitor: Arc::new(NetMonitor::default()),
            bandwidth_limiter,
            live_blocker: Arc::new(RwLock::new(None)),
            slm_cache: AsyncMutex::new(None),
            slm_shutdown_token: Mutex::new(None),
            plugin_registry: PluginRegistry::default(),
            sentinel: Mutex::new(sentinel),
            storage_budget: Mutex::new(storage_budget),
            power_budget: Mutex::new(initial_power),
            shutdown_token: CancellationToken::new(),
            window_ready_token: CancellationToken::new(),
            mcp_session_token: generate_mcp_session_token(),
            platform,
        })
    }

    pub fn workspace_id(&self) -> String {
        self.ws_id.lock().unwrap().clone()
    }

    pub fn switch_workspace(&self, ws_id: &str) -> anyhow::Result<()> {
        *self.ws_id.lock().unwrap() = ws_id.to_owned();
        self.db.set_setting("active_workspace_id", ws_id)?;
        *self.noise_seed.lock().unwrap() = rand::random();
        Ok(())
    }

    pub fn fire_workspace(&self, ws_id: &str) -> anyhow::Result<()> {
        self.tabs.lock().unwrap().close_workspace(ws_id);
        self.db.clear_history(ws_id)?;
        self.db
            .0
            .lock()
            .unwrap()
            .execute("DELETE FROM bookmarks WHERE workspace_id=?1", [ws_id])?;
        let bundle_paths = self.db.delete_bundles_for_workspace(ws_id)?;
        let bundles_dir = self.bundles_dir();
        for path in bundle_paths {
            let _ = std::fs::remove_file(bundles_dir.join(&path));
        }
        self.db
            .0
            .lock()
            .unwrap()
            .execute("DELETE FROM workspaces WHERE id=?1", [ws_id])?;
        Ok(())
    }

    pub fn bundles_dir(&self) -> PathBuf {
        self.data_dir.join("bundles")
    }

    /// Execute `f` with the master key. The Mutex is released before `f` runs,
    /// so slow crypto operations (AES, gzip) don't block other threads.
    pub fn with_master_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        let key = zeroize::Zeroizing::new(*self.master_key.lock().unwrap());
        f(&*key)
    }

    // Returns a live dynamic UA when Sentinel has data; falls back to the
    // compiled-in platform constant otherwise. Gates on has_data() rather
    // than last_refresh > 0, since last_refresh is 0 on a freshly loaded
    // DB row even though real cached data is present.
    pub fn current_ua(&self, prefer_safari: bool) -> String {
        let cache = self.sentinel.lock().unwrap();
        if cache.has_data() {
            if let Some(ua) = crate::engine::blocker::dynamic_ua(
                &cache,
                prefer_safari || self.platform == "macos",
            ) {
                return ua;
            }
        }
        crate::engine::blocker::platform_fallback_ua().to_owned()
    }

    // Called once at startup; passed to Tauri's initialization_script.
    pub fn fp_norm_script(&self) -> String {
        self.fp_norm.generate()
    }
}

/// 64-character hex CSPRNG token for local MCP bearer auth.
/// (Previously lived in `diatom_bridge::protocol::generate_auth_token` —
/// inlined here since that module was removed along with the DevPanel
/// bridge, and this is now its only caller.)
fn generate_mcp_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
