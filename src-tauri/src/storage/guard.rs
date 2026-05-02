use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Pages accessed within this many days stay in the HOT tier (full FTS5).
pub const HOT_WINDOW_DAYS: i64 = 89;

/// Number of top TF-IDF keywords to retain in the cold-tier fingerprint.
pub const COLD_KEYWORD_COUNT: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBudget {
    /// Max for encrypted E-WBN bundles (megabytes).  Default 2 048 MB.
    pub museum_budget_mb: u64,
    /// Max for knowledge packs (megabytes).  Default 4 096 MB.
    pub kpack_budget_mb: u64,
    /// Max for the FTS5 search index database (megabytes).  Default 50 MB.
    pub index_budget_mb: u64,
    /// Warn when bundle storage reaches this percentage.  Default 80.
    pub warn_at_pct: u8,
    /// If true, reject new freezes when the bundle budget is exhausted.
    pub hard_cap_enabled: bool,
}

impl Default for StorageBudget {
    fn default() -> Self {
        StorageBudget {
            museum_budget_mb: 2_048,
            kpack_budget_mb: 4_096,
            index_budget_mb: 50,
            warn_at_pct: 80,
            hard_cap_enabled: false,
        }
    }
}

impl StorageBudget {
    /// Load user-configured budget values from the database, falling back to
    /// compiled-in defaults for any key that is absent or unparseable.
    ///
    /// Centralised here so all callers (storage commands + state init) read the
    /// same logic rather than duplicating the parse-or-default pattern.
    pub fn load_from_db(db: &crate::storage::db::Db) -> Self {
        let d = Self::default();
        let parse = |key: &str, fallback: u32| -> u32 {
            db.get_setting(key)
                .and_then(|s| s.parse().ok())
                .unwrap_or(fallback)
        };
        StorageBudget {
            museum_budget_mb: parse("museum_budget_mb", d.museum_budget_mb as u32) as u64,
            kpack_budget_mb: parse("kpack_budget_mb", d.kpack_budget_mb as u32) as u64,
            index_budget_mb: parse("index_budget_mb", d.index_budget_mb as u32) as u64,
            warn_at_pct: parse("storage_warn_pct", d.warn_at_pct as u32) as u8,
            hard_cap_enabled: db
                .get_setting("storage_hard_cap")
                .map(|v| v == "true")
                .unwrap_or(d.hard_cap_enabled),
        }
    }
}

/// Which indexing tier a Museum entry currently occupies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexTier {
    /// Full FTS5 full-text index: every word searchable.
    Hot,
    /// Compact fingerprint only: title + URL + top-N keywords.
    /// The encrypted bundle still exists; Deep Dig can scan it on demand.
    Cold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageReport {
    pub museum_used_mb: f64,
    pub museum_budget_mb: u64,
    pub museum_pct: u8,
    pub kpack_used_mb: f64,
    pub kpack_budget_mb: u64,
    pub kpack_pct: u8,
    pub index_used_mb: f64,
    pub index_budget_mb: u64,
    pub index_pct: u8,
    pub hot_entries: u32,
    pub cold_entries: u32,
    pub bundle_count: u32,
    pub oldest_bundle_iso: Option<String>,
    pub warn: bool,
    pub hard_blocked: bool,
}

/// Compute current storage usage from the DB.
pub fn report(db: &crate::storage::db::Db, budget: &StorageBudget) -> StorageReport {
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

    let index_bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(pgsize * pageno), 0) \
             FROM dbstat WHERE name LIKE 'museum_fts%'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let now_ts = crate::storage::db::unix_now();
    let hot_cutoff = now_ts - HOT_WINDOW_DAYS * 86_400;

    let hot_entries: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM museum_bundles \
             WHERE index_tier = 'hot' OR last_accessed_at > ?1",
            [hot_cutoff],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let cold_entries: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM museum_bundles \
             WHERE index_tier = 'cold' AND (last_accessed_at IS NULL OR last_accessed_at <= ?1)",
            [hot_cutoff],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let museum_mb = museum_bytes as f64 / 1_048_576.0;
    let kpack_mb = kpack_bytes as f64 / 1_048_576.0;
    let index_mb = index_bytes as f64 / 1_048_576.0;
    let museum_pct = ((museum_mb / budget.museum_budget_mb as f64) * 100.0).min(100.0) as u8;
    let kpack_pct = ((kpack_mb / budget.kpack_budget_mb as f64) * 100.0).min(100.0) as u8;
    let index_pct = ((index_mb / budget.index_budget_mb as f64) * 100.0).min(100.0) as u8;

    let oldest_iso = oldest_ts.map(|ts| {
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
        index_used_mb: index_mb,
        index_budget_mb: budget.index_budget_mb,
        index_pct,
        hot_entries,
        cold_entries,
        bundle_count,
        oldest_bundle_iso: oldest_iso,
        warn,
        hard_blocked,
    }
}

/// Delete oldest bundles by frozen_at until under target_pct of the bundle budget.
/// Returns (bundles_deleted, bytes_freed).
pub fn evict_lru(
    db: &crate::storage::db::Db,
    budget: &StorageBudget,
    target_pct: u8,
    bundles_dir: &std::path::Path,
) -> Result<(u32, u64)> {
    let conn = db.0.lock().unwrap();
    let target_bytes =
        (budget.museum_budget_mb as f64 * target_pct as f64 / 100.0 * 1_048_576.0) as i64;

    let mut stmt = conn.prepare(
        "SELECT id, bundle_path, bundle_size FROM museum_bundles ORDER BY frozen_at ASC",
    )?;
    let bundles: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();

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

    for (id, path, size) in bundles {
        if current <= target_bytes {
            break;
        }
        let full_path = bundles_dir.join(&path);
        let _ = std::fs::remove_file(&full_path);
        conn.execute("DELETE FROM museum_bundles WHERE id = ?1", [&id])?;
        current -= size;
        freed += size as u64;
        deleted += 1;
    }

    Ok((deleted, freed))
}

/// Degrade the FTS5 full-text index of cold-eligible entries until the index
/// is under the budget.  "Cold-eligible" = last_accessed_at older than
/// HOT_WINDOW_DAYS and never re-visited since archiving.
///
/// Degradation keeps: title, URL, keyword_fingerprint (top-N terms).
/// Removes: all FTS5 rows for that museum_id.
///
/// Returns number of entries degraded.
pub fn degrade_cold_indexes(db: &crate::storage::db::Db, budget: &StorageBudget) -> Result<u32> {
    let conn = db.0.lock().unwrap();

    let index_bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(pgsize * pageno), 0) \
             FROM dbstat WHERE name LIKE 'museum_fts%'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let budget_bytes = budget.index_budget_mb as i64 * 1_048_576;
    if index_bytes <= budget_bytes {
        return Ok(0);
    }

    let now_ts = crate::storage::db::unix_now();
    let cutoff = now_ts - HOT_WINDOW_DAYS * 86_400;

    let candidates: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT id FROM museum_bundles \
             WHERE (index_tier IS NULL OR index_tier = 'hot') \
               AND (last_accessed_at IS NULL OR last_accessed_at < ?1) \
               AND frozen_at < ?1 \
             ORDER BY frozen_at ASC",
        )?;
        stmt.query_map([cutoff], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect()
    };

    let mut degraded = 0u32;
    for id in candidates {
        conn.execute(
            "UPDATE museum_bundles SET index_tier = 'cold' WHERE id = ?1",
            [&id],
        )?;
        degraded += 1;

        if degraded % 10 == 0 {
            let current: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(pgsize * pageno), 0) \
                     FROM dbstat WHERE name LIKE 'museum_fts%'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if current <= budget_bytes {
                break;
            }
        }
    }

    Ok(degraded)
}

/// Decide which tier a newly frozen page should start in.
/// Pages frozen for the first time always start HOT.
pub fn initial_tier() -> IndexTier {
    IndexTier::Hot
}

/// Touch the last_accessed_at timestamp when a user visits a page.
/// Promotes cold entries back to hot.
pub fn touch_access(db: &crate::storage::db::Db, museum_id: &str) -> Result<()> {
    let now = crate::storage::db::unix_now();
    let conn = db.0.lock().unwrap();
    conn.execute(
        "UPDATE museum_bundles SET last_accessed_at = ?1, index_tier = 'hot' WHERE id = ?2",
        rusqlite::params![now, museum_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_index_budget_is_50mb() {
        assert_eq!(StorageBudget::default().index_budget_mb, 50);
    }

    #[test]
    fn hot_window_is_89_days() {
        assert_eq!(HOT_WINDOW_DAYS, 89);
    }

    #[test]
    fn initial_tier_is_hot() {
        assert_eq!(initial_tier(), IndexTier::Hot);
    }
}
