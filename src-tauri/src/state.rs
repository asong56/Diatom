// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/state.rs  — v0.9.2
//
// [FIX-persistence-totp]  TotpStore loaded from DB with encrypted secrets.
// [FIX-persistence-trust] TrustStore loaded from DB.
// [FIX-persistence-rss]   RssStore loaded from DB.
// [FIX-zen]  ZenConfig loaded from and saved to DB.
// [FIX-08-ua] current_ua() now calls dynamic_ua() when sentinel cache is fresh.
// ─────────────────────────────────────────────────────────────────────────────

use crate::{
    db::Db, decoy::DecoyState, privacy::PrivacyConfig, rss::RssStore, sentinel::SentinelCache,
    tab_budget::TabBudgetConfig, tabs::TabStore, totp::TotpStore,
    trust::TrustStore, zen::ZenConfig,
};
use anyhow::Result;
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock, atomic::AtomicBool},
};

pub struct AppState {
    pub db: Db,
    pub ws_id: Mutex<String>,
    pub tabs: Mutex<TabStore>,
    pub privacy: RwLock<PrivacyConfig>,
    pub trust: Mutex<TrustStore>,
    pub totp: Mutex<TotpStore>,
    pub rss: Mutex<RssStore>,
    pub data_dir: PathBuf,

    pub noise_seed: Mutex<u64>,
    pub zen: Mutex<ZenConfig>,
    pub threat_list: RwLock<HashSet<String>>,
    pub master_key: Mutex<[u8; 32]>,
    pub quad9_enabled: AtomicBool,
    pub age_heuristic_enabled: AtomicBool,

    pub compat: Mutex<crate::compat::CompatStore>,
    pub storage_budget: Mutex<crate::storage_guard::StorageBudget>,

    pub tab_budget_cfg: Mutex<TabBudgetConfig>,
    pub screen_width_px: Mutex<u32>,
    pub slm_shutdown: Mutex<Option<Arc<AtomicBool>>>,

    pub sentinel: Mutex<SentinelCache>,

    /// Cached platform string for WebGL/UA spoofing ("macos" | "windows" | "linux")
    pub platform: &'static str,

    /// [FIX-decoy-globals] Workspace-isolated decoy noise state.
    pub decoy: Mutex<DecoyState>,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let db = Db::open(&data_dir.join("diatom.db"))?;
        std::fs::create_dir_all(data_dir.join("bundles"))?;

        let master_key = crate::freeze::get_or_init_master_key(&db)?;

        let quad9 = db.get_setting("quad9_enabled").map(|v| v == "true").unwrap_or(true);
        let age_h = db.get_setting("age_heuristic_enabled").map(|v| v == "true").unwrap_or(true);

        let threat_list: HashSet<String> = db.get_setting("threat_list_json")
            .and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();

        let ws_id = db.get_setting("active_workspace_id").unwrap_or_else(|| "default".to_owned());

        // [FIX-persistence-*] Load from DB
        let totp = TotpStore::load_from_db(&db, &master_key);
        let trust = TrustStore::load_from_db(&db);
        let rss = RssStore::load_from_db(&db);

        // [FIX-zen] Load Zen config from DB
        let zen = db.zen_load().map(|raw| ZenConfig::from_raw(&raw)).unwrap_or_default();

        let mut compat_store = crate::compat::CompatStore::default();
        if let Some(json) = db.get_setting("compat_legacy_domains") {
            if let Ok(domains) = serde_json::from_str::<Vec<String>>(&json) {
                for d in domains { compat_store.add_legacy(&d); }
            }
        }

        let storage_budget = db.get_setting("storage_budget")
            .and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();

        let tab_budget_cfg = db.get_setting("tab_budget_config")
            .and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();

        let sentinel: SentinelCache = db.get_setting("sentinel_cache")
            .and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();

        let platform: &'static str = match std::env::consts::OS {
            "macos"   => "macos",
            "windows" => "windows",
            _         => "linux",
        };

        Ok(AppState {
            db,
            ws_id: Mutex::new(ws_id),
            tabs: Mutex::new(TabStore::default()),
            privacy: RwLock::new(PrivacyConfig::default()),
            trust: Mutex::new(trust),
            totp: Mutex::new(totp),
            rss: Mutex::new(rss),
            data_dir,
            noise_seed: Mutex::new(rand::random()),
            zen: Mutex::new(zen),
            threat_list: RwLock::new(threat_list),
            master_key: Mutex::new(master_key),
            quad9_enabled: AtomicBool::new(quad9),
            age_heuristic_enabled: AtomicBool::new(age_h),
            compat: Mutex::new(compat_store),
            storage_budget: Mutex::new(storage_budget),
            tab_budget_cfg: Mutex::new(tab_budget_cfg),
            screen_width_px: Mutex::new(1440),
            slm_shutdown: Mutex::new(None),
            sentinel: Mutex::new(sentinel),
            platform,
            decoy: Mutex::new(DecoyState::default()),
        })
    }

    pub fn workspace_id(&self) -> String {
        self.ws_id.lock().unwrap().clone()
    }

    pub fn switch_workspace(&self, ws_id: &str) -> anyhow::Result<()> {
        *self.ws_id.lock().unwrap() = ws_id.to_owned();
        self.db.set_setting("active_workspace_id", ws_id)?;
        *self.noise_seed.lock().unwrap() = rand::random();
        // [FIX-decoy-globals] Reset per-workspace noise state on switch
        self.decoy.lock().unwrap().reset_for_workspace();
        Ok(())
    }

    pub fn fire_workspace(&self, ws_id: &str) -> anyhow::Result<()> {
        // [FIX-17] Full cleanup: tabs, history, bookmarks, Museum bundles, workspace row
        self.tabs.lock().unwrap().close_workspace(ws_id);
        self.db.clear_history(ws_id)?;
        // Delete bookmarks for this workspace
        self.db.0.lock().unwrap().execute(
            "DELETE FROM bookmarks WHERE workspace_id=?1", [ws_id])?;
        // Delete Museum bundles (returns bundle_path list for file deletion)
        let bundle_paths = self.db.delete_bundles_for_workspace(ws_id)?;
        let bundles_dir = self.bundles_dir();
        for path in bundle_paths {
            let _ = std::fs::remove_file(bundles_dir.join(&path));
        }
        // Delete the workspace row itself
        self.db.0.lock().unwrap().execute(
            "DELETE FROM workspaces WHERE id=?1", [ws_id])?;
        Ok(())
    }

    pub fn bundles_dir(&self) -> std::path::PathBuf {
        self.data_dir.join("bundles")
    }

    pub fn master_key(&self) -> [u8; 32] {
        *self.master_key.lock().unwrap()
    }

    /// [FIX-08-ua] Returns a live dynamic UA when Sentinel is fresh and active,
    /// falling back to the compiled-in constant when not.
    /// prefer_safari: hint to prefer Safari UA on macOS (ignored if Sentinel
    /// has no cached Safari version).
    pub fn current_ua(&self, prefer_safari: bool) -> String {
        let cache = self.sentinel.lock().unwrap();
        if cache.is_fresh() {
            if let Some(ua) = crate::blocker::dynamic_ua(&cache, prefer_safari || self.platform == "macos") {
                return ua;
            }
        }
        crate::blocker::DIATOM_UA.to_owned()
    }
}
