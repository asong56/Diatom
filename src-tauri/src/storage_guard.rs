// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/storage_guard.rs  — v7.2  RED-6 / YELLOW
//
// Museum Storage Guard — SSD Bloat Defence
//
// Problem: E-WBN bundles + Knowledge Packs can consume tens of GB.
//          A user who imports Wikipedia ZIM (~87 GB) would fill their SSD.
//
// Solution: Configurable storage budget with ambient (non-nagging) warnings.
//           Hard-cap enforcement is opt-in; defaults to warning only.
//
// Budget tiers (all configurable in diatom.json):
//   museum_budget_mb     default: 2 048 MB  (2 GB)
//   kpack_budget_mb      default: 4 096 MB  (4 GB, ZIM files are large)
//   warn_at_pct          default: 80%       (show indicator at 80% full)
//   hard_cap_enabled     default: false     (if true, new freezes rejected when over)
//
// Cleanup strategy: LRU eviction by frozen_at timestamp.
//   Evict oldest bundles first until under 70% of budget.
//   Knowledge Packs are never auto-evicted — user must delete explicitly.
//
// SQLite write-lock contention fix (RED-57):
//   Museum writes (freeze) and AI indexing (FTS5) compete for the write lock.
//   Solution: separate WAL checkpoint cadence and use BEGIN IMMEDIATE for
//   freeze writes so the indexer defers rather than spinning.
// ─────────────────────────────────────────────────────────────────────────────

use anyhow::Result;
use serde::{Deserialize, Serialize};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBudget {
    pub museum_budget_mb: u64,  // max for E-WBN bundles
    pub kpack_budget_mb: u64,   // max for knowledge packs
    pub warn_at_pct: u8,        // warn when used% >= this
    pub hard_cap_enabled: bool, // reject new freezes when over budget
}

impl Default for StorageBudget {
    fn default() -> Self {
        StorageBudget {
            museum_budget_mb: 2_048,
            kpack_budget_mb: 4_096,
            warn_at_pct: 80,
            hard_cap_enabled: false,
        }
    }
}

// ── Usage report ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageReport {
    pub museum_used_mb: f64,
    pub museum_budget_mb: u64,
    pub museum_pct: u8,
    pub kpack_used_mb: f64,
    pub kpack_budget_mb: u64,
    pub kpack_pct: u8,
    pub bundle_count: u32,
    pub oldest_bundle_iso: Option<String>,
    pub warn: bool,         // at or above warn_at_pct
    pub hard_blocked: bool, // hard cap hit AND hard_cap_enabled
}

/// Compute current storage usage from the DB.
pub fn report(db: &crate::db::Db, budget: &StorageBudget) -> StorageReport {
    let conn = db.0.lock().unwrap();

    let (museum_bytes, bundle_count, oldest_ts): (i64, u32, Option<i64>) = conn
        .query_row(
            "SELECT COALESCE(SUM(bundle_size),0), COUNT(*), MIN(frozen_at) FROM museum_bundles",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or((0, 0, None));

    let kpack_bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(size_bytes),0) FROM knowledge_packs WHERE enabled=1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let museum_mb = museum_bytes as f64 / 1_048_576.0;
    let kpack_mb = kpack_bytes as f64 / 1_048_576.0;
    let museum_pct = ((museum_mb / budget.museum_budget_mb as f64) * 100.0).min(100.0) as u8;
    let kpack_pct = ((kpack_mb / budget.kpack_budget_mb as f64) * 100.0).min(100.0) as u8;

    // [FIX-30] Use readable date format, not ISO week
    let oldest_iso = oldest_ts.map(|ts| {
        // [FIX-30] Use from_timestamp_opt (from_timestamp deprecated in chrono 0.4.24+)
        chrono::DateTime::from_timestamp_opt(ts, 0)
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    });
    let warn = museum_pct >= budget.warn_at_pct || kpack_pct >= budget.warn_at_pct;
    let hard_blocked = budget.hard_cap_enabled && museum_pct >= 100;

    StorageReport {
        museum_used_mb: museum_mb,
        museum_budget_mb: budget.museum_budget_mb,
        museum_pct,
        kpack_used_mb: kpack_mb,
        kpack_budget_mb: budget.kpack_budget_mb,
        kpack_pct,
        bundle_count,
        oldest_bundle_iso: oldest_iso,
        warn,
        hard_blocked,
    }
}

/// LRU eviction: delete oldest bundles (by frozen_at) until under target_pct.
/// Returns the number of bundles deleted and total bytes freed.
pub fn evict_lru(
    db: &crate::db::Db,
    budget: &StorageBudget,
    target_pct: u8,
    bundles_dir: &std::path::Path,
) -> Result<(u32, u64)> {
    let conn = db.0.lock().unwrap();
    let target_bytes =
        (budget.museum_budget_mb as f64 * target_pct as f64 / 100.0 * 1_048_576.0) as i64;

    // Fetch bundles ordered oldest-first with sizes
    let mut stmt = conn.prepare(
        "SELECT id, bundle_path, bundle_size FROM museum_bundles ORDER BY frozen_at ASC",
    )?;
    let bundles: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();

    // Current total
    let total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(bundle_size),0) FROM museum_bundles",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let mut current = total;
    let mut deleted = 0u32;
    let mut freed = 0u64;

    for (id, path, size) in &bundles {
        if current <= target_bytes {
            break;
        }
        // Delete physical file
        let full_path = bundles_dir.join(path);
        let _ = std::fs::remove_file(&full_path);
        // Delete DB row
        conn.execute("DELETE FROM museum_bundles WHERE id=?1", [id])?;
        current -= size;
        freed += *size as u64;
        deleted += 1;
        tracing::info!("evicted bundle {} ({} bytes)", id, size);
    }

    Ok((deleted, freed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_is_reasonable() {
        let b = StorageBudget::default();
        assert!(b.museum_budget_mb >= 1024, "at least 1 GB for museum");
        assert!(
            b.kpack_budget_mb >= 2048,
            "at least 2 GB for knowledge packs"
        );
        assert!(!b.hard_cap_enabled, "hard cap off by default");
    }
}
