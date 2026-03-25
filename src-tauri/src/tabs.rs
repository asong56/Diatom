// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/tabs.rs
//
// Tab lifecycle management with tiered sleep:
//   Awake → ShallowSleep (JS paused) → DeepSleep (LZ4-compressed ZRAM)
//
// Memory model:
//   A fully-loaded tab ≈ 80–200 MB RSS.
//   DeepSleep compresses the serialised DOM snapshot ~4:1 with LZ4.
//   The tab_budget module controls the maximum number of awake tabs
//   using the Resource-Aware Scaling formula (see tab_budget.rs).
// ─────────────────────────────────────────────────────────────────────────────

use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

// ── Sleep states ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SleepState {
    /// Full JavaScript execution — max memory footprint.
    Awake,
    /// JS timers paused, DOM intact — medium footprint.
    ShallowSleep,
    /// DOM serialised + LZ4 compressed in `zram` — minimal footprint.
    DeepSleep,
}

// ── Tab ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tab {
    pub id: String,
    pub workspace_id: String,
    pub url: String,
    pub title: String,
    pub sleep: SleepState,
    /// LZ4-compressed DOM snapshot (populated during DeepSleep).
    #[serde(skip)]
    pub zram: Option<Vec<u8>>,
    /// Estimated memory weight (bytes). Updated on navigation and sleep.
    pub mem_weight: u64,
    /// Unix timestamp of last user activity on this tab.
    pub last_active: i64,
}

impl Tab {
    pub fn new(id: &str, workspace_id: &str, url: &str) -> Self {
        Tab {
            id: id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            url: url.to_owned(),
            title: String::new(),
            sleep: SleepState::Awake,
            zram: None,
            // [FIX-06] 150 MB is a more realistic starting estimate
            mem_weight: 150 * 1024 * 1024,
            last_active: crate::db::unix_now(),
        }
    }

    /// Decompress the ZRAM snapshot.
    pub fn decompress(&self) -> Option<String> {
        let bytes = self.zram.as_ref()?;
        let decompressed = decompress_size_prepended(bytes).ok()?;
        String::from_utf8(decompressed).ok()
    }

    /// Compressed size (bytes), or 0 if awake.
    pub fn zram_size(&self) -> usize {
        self.zram.as_ref().map(|z| z.len()).unwrap_or(0)
    }
}

// ── TabStore ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TabStore {
    tabs: HashMap<String, Tab>,
    order: VecDeque<String>, // LRU: front = most recent, back = oldest
    active: Option<String>,
}

impl TabStore {
    pub fn create(&mut self, id: &str, workspace_id: &str, url: &str) -> &Tab {
        let tab = Tab::new(id, workspace_id, url);
        self.tabs.insert(id.to_owned(), tab);
        self.order.push_front(id.to_owned());
        self.active = Some(id.to_owned());
        self.tabs.get(id).unwrap()
    }

    pub fn get(&self, id: &str) -> Option<&Tab> {
        self.tabs.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Tab> {
        self.tabs.get_mut(id)
    }

    pub fn close(&mut self, id: &str) {
        self.tabs.remove(id);
        self.order.retain(|i| i != id);
        if self.active.as_deref() == Some(id) {
            self.active = self.order.front().cloned();
        }
    }

    pub fn activate(&mut self, id: &str) {
        if !self.tabs.contains_key(id) {
            return;
        }
        // Move to front of LRU
        self.order.retain(|i| i != id);
        self.order.push_front(id.to_owned());
        self.active = Some(id.to_owned());
        if let Some(tab) = self.tabs.get_mut(id) {
            tab.last_active = crate::db::unix_now();
        }
    }

    /// Shallow sleep: mark JS timers as paused (the frontend handles actual suspension).
    pub fn shallow_sleep(&mut self, id: &str) {
        if let Some(tab) = self.tabs.get_mut(id) {
            tab.sleep = SleepState::ShallowSleep;
        }
    }

    /// Deep sleep: compress DOM snapshot to ZRAM.
    pub fn deep_sleep(&mut self, id: &str, snapshot: &str) {
        if let Some(tab) = self.tabs.get_mut(id) {
            let compressed = compress_prepend_size(snapshot.as_bytes());
            let original_size = snapshot.len() as u64;
            let compressed_size = compressed.len() as u64;
            tab.zram = Some(compressed);
            tab.sleep = SleepState::DeepSleep;
            // Update mem weight to reflect compressed footprint
            tab.mem_weight = compressed_size;
            tracing::debug!(
                "tab {} deep-slept: {}B → {}B ({:.1}x)",
                id,
                original_size,
                compressed_size,
                original_size as f64 / compressed_size.max(1) as f64
            );
        }
    }

    pub fn close_workspace(&mut self, workspace_id: &str) {
        let ids: Vec<String> = self
            .tabs
            .values()
            .filter(|t| t.workspace_id == workspace_id)
            .map(|t| t.id.clone())
            .collect();
        for id in ids {
            self.close(&id);
        }
    }

    /// LRU candidate for automatic sleep (oldest awake tab, not the active one).
    pub fn lru_sleep_candidate(&self) -> Option<&Tab> {
        self.order
            .iter()
            .rev()
            .filter(|id| Some(id.as_str()) != self.active.as_deref())
            .filter_map(|id| self.tabs.get(id))
            .find(|t| t.sleep == SleepState::Awake)
    }

    /// All tabs, ordered by LRU (most recent first).
    pub fn all_lru(&self) -> Vec<&Tab> {
        self.order
            .iter()
            .filter_map(|id| self.tabs.get(id))
            .collect()
    }

    pub fn active_id(&self) -> Option<&str> {
        self.active.as_deref()
    }

    pub fn count(&self) -> usize {
        self.tabs.len()
    }

    pub fn awake_count(&self) -> usize {
        self.tabs
            .values()
            .filter(|t| t.sleep == SleepState::Awake)
            .count()
    }

    /// Average memory weight of all awake tabs (bytes).
    /// Used by the tab budget formula: ω_avg.
    pub fn avg_mem_weight(&self) -> u64 {
        let awake: Vec<u64> = self
            .tabs
            .values()
            .filter(|t| t.sleep == SleepState::Awake)
            .map(|t| t.mem_weight)
            .collect();
        if awake.is_empty() {
            return 150 * 1024 * 1024; // [FIX-06] conservative default
        }
        awake.iter().sum::<u64>() / awake.len() as u64
    }
}

// ── Serialisable snapshot for IPC ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct TabsState {
    pub tabs: Vec<TabInfo>,
    pub active_id: Option<String>,
    pub count: usize,
}

#[derive(Serialize)]
pub struct TabInfo {
    pub id: String,
    pub url: String,
    pub title: String,
    pub sleep: SleepState,
    pub mem_weight: u64,
    pub last_active: i64,
    pub zram_bytes: usize,
}

impl From<&TabStore> for TabsState {
    fn from(store: &TabStore) -> Self {
        let tabs = store
            .all_lru()
            .into_iter()
            .map(|t| TabInfo {
                id: t.id.clone(),
                url: t.url.clone(),
                title: t.title.clone(),
                sleep: t.sleep.clone(),
                mem_weight: t.mem_weight,
                last_active: t.last_active,
                zram_bytes: t.zram_size(),
            })
            .collect();
        TabsState {
            tabs,
            active_id: store.active_id().map(|s| s.to_owned()),
            count: store.count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_sleep_roundtrip() {
        let mut store = TabStore::default();
        store.create("t1", "ws-default", "https://example.com");
        let payload = "x".repeat(10_000);
        store.deep_sleep("t1", &payload);
        let tab = store.get("t1").unwrap();
        assert_eq!(tab.sleep, SleepState::DeepSleep);
        assert!(tab.zram.is_some());
        let recovered = tab.decompress().unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn lru_order() {
        let mut store = TabStore::default();
        store.create("a", "ws", "https://a.com");
        store.create("b", "ws", "https://b.com");
        store.create("c", "ws", "https://c.com");
        store.activate("a");
        // c is oldest non-active awake tab
        let candidate = store.lru_sleep_candidate();
        assert!(candidate.is_some());
        assert_ne!(candidate.unwrap().id, "a");
    }
}
