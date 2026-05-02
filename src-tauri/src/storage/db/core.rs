//! Database connection management and schema migrations.
//!
//! All methods on `Db` are defined across the sub-modules in this directory.
//! This file owns: open(), migrate(), get_setting(), set_setting().

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub use super::types::*;

/// Execute DDL statements idempotently.
/// Suppresses "already exists" and "duplicate column" errors so migrations
/// can be re-run safely; propagates all other SQLite errors.
fn exec_idempotent(conn: &Connection, sql: &str) -> rusqlite::Result<()> {
    match conn.execute_batch(sql) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
            if msg.contains("already exists") || msg.contains("duplicate column") =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

const MIGRATIONS: &[(u32, &str)] = &[
    (
        1,
        "
  CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY, name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#00d4ff',
  is_private INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS history (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
  url TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
  favicon_hex TEXT, visited_at INTEGER NOT NULL,
  dwell_ms INTEGER NOT NULL DEFAULT 0, visit_count INTEGER NOT NULL DEFAULT 1
  );
  CREATE UNIQUE INDEX IF NOT EXISTS uq_history ON history(url, workspace_id);
  CREATE INDEX IF NOT EXISTS idx_hist_time ON history(visited_at DESC);
  CREATE TABLE IF NOT EXISTS bookmarks (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
  url TEXT NOT NULL, title TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]', ephemeral INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER, created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_bk_workspace ON bookmarks(workspace_id);
  CREATE TABLE IF NOT EXISTS snapshots (
  tab_id TEXT NOT NULL, hash TEXT NOT NULL,
  text_body TEXT NOT NULL, saved_at INTEGER NOT NULL,
  PRIMARY KEY (tab_id, hash)
  );
  CREATE TABLE IF NOT EXISTS rss_feeds (
  id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL, category TEXT,
  fetch_interval_m INTEGER NOT NULL DEFAULT 60,
  last_fetched INTEGER, enabled INTEGER NOT NULL DEFAULT 1,
  added_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS rss_items (
  id TEXT PRIMARY KEY, feed_id TEXT NOT NULL,
  guid TEXT NOT NULL, title TEXT NOT NULL,
  url TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
  published INTEGER, read INTEGER NOT NULL DEFAULT 0,
  fetched_at INTEGER NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS uq_rss_item ON rss_items(feed_id, guid);
  CREATE TABLE IF NOT EXISTS privacy_stats (
  week_start INTEGER PRIMARY KEY,
  block_count INTEGER NOT NULL DEFAULT 0,
  noise_count INTEGER NOT NULL DEFAULT 0
  );
  ",
    ),
    (
        2,
        "
  CREATE TABLE IF NOT EXISTS museum_bundles (
  id TEXT PRIMARY KEY, url TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL,
  bundle_path TEXT NOT NULL, tfidf_tags TEXT NOT NULL DEFAULT '[]',
  bundle_size INTEGER NOT NULL DEFAULT 0,
  frozen_at INTEGER NOT NULL, workspace_id TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_bundle_ws  ON museum_bundles(workspace_id);
  CREATE INDEX IF NOT EXISTS idx_bundle_hash ON museum_bundles(content_hash);
  CREATE VIRTUAL TABLE IF NOT EXISTS museum_fts
  USING fts5(tfidf_tags, title, content=museum_bundles, content_rowid=rowid);
  CREATE TRIGGER IF NOT EXISTS museum_fts_ai AFTER INSERT ON museum_bundles BEGIN
  INSERT INTO museum_fts(rowid, tfidf_tags, title)
  VALUES (new.rowid, new.tfidf_tags, new.title);
  END;
  CREATE TRIGGER IF NOT EXISTS museum_fts_ad AFTER DELETE ON museum_bundles BEGIN
  INSERT INTO museum_fts(museum_fts, rowid, tfidf_tags, title)
  VALUES ('delete', old.rowid, old.tfidf_tags, old.title);
  END;
  CREATE TRIGGER IF NOT EXISTS museum_fts_au AFTER UPDATE ON museum_bundles BEGIN
  INSERT INTO museum_fts(museum_fts, rowid, tfidf_tags, title)
  VALUES ('delete', old.rowid, old.tfidf_tags, old.title);
  INSERT INTO museum_fts(rowid, tfidf_tags, title)
  VALUES (new.rowid, new.tfidf_tags, new.title);
  END;
  CREATE TABLE IF NOT EXISTS dom_blocks (
  id TEXT PRIMARY KEY, domain TEXT NOT NULL,
  selector TEXT NOT NULL, created_at INTEGER NOT NULL,
  UNIQUE (domain, selector)
  );
  CREATE INDEX IF NOT EXISTS idx_domblocks_domain ON dom_blocks(domain);
  CREATE TABLE IF NOT EXISTS knowledge_packs (
  id TEXT PRIMARY KEY, name TEXT NOT NULL,
  format TEXT NOT NULL CHECK(format IN ('docset','zim','filterlist')),
  pack_path TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0,
  added_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS reading_events (
  id TEXT PRIMARY KEY, url TEXT NOT NULL, domain TEXT NOT NULL,
  dwell_ms INTEGER NOT NULL DEFAULT 0, scroll_px_s REAL NOT NULL DEFAULT 0,
  reading_mode INTEGER NOT NULL DEFAULT 0, tab_switches INTEGER NOT NULL DEFAULT 0,
  recorded_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_re_time ON reading_events(recorded_at DESC);
  ",
    ),
    (
        3,
        "
  CREATE TABLE IF NOT EXISTS totp_entries (
  id TEXT PRIMARY KEY, issuer TEXT NOT NULL,
  account TEXT NOT NULL, secret_enc TEXT NOT NULL,
  domains TEXT NOT NULL DEFAULT '[]', added_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS trust_profiles (
  domain TEXT PRIMARY KEY, level TEXT NOT NULL DEFAULT 'standard',
  source TEXT NOT NULL DEFAULT 'user', set_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS filter_subscriptions (
  id TEXT PRIMARY KEY, name TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE, last_synced INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  rule_count INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS nostr_relays (
  id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1, added_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS onboarding (
  step TEXT PRIMARY KEY, completed INTEGER NOT NULL DEFAULT 0, done_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS zen_state (
  id INTEGER PRIMARY KEY CHECK(id = 1), active INTEGER NOT NULL DEFAULT 0,
  aphorism TEXT NOT NULL DEFAULT 'Now will always have been.',
  blocked_cats TEXT NOT NULL DEFAULT '[\"social\",\"entertainment\"]',
  activated_at INTEGER
  );
  INSERT OR IGNORE INTO zen_state(id) VALUES(1);
  ",
    ),
    (
        4,
        "
  ALTER TABLE totp_entries ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'SHA1';
  ALTER TABLE totp_entries ADD COLUMN digits INTEGER NOT NULL DEFAULT 6;
  ALTER TABLE totp_entries ADD COLUMN period INTEGER NOT NULL DEFAULT 30;
  CREATE TABLE IF NOT EXISTS vault_logins (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  password_enc TEXT NOT NULL,
  urls_json TEXT NOT NULL DEFAULT '[]',
  notes_enc TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  totp_uri TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_vault_login_updated ON vault_logins(updated_at DESC);
  CREATE VIRTUAL TABLE IF NOT EXISTS vault_logins_fts
  USING fts5(title, username, urls_json, content=vault_logins, content_rowid=rowid);
  CREATE TRIGGER IF NOT EXISTS vault_logins_fts_ai AFTER INSERT ON vault_logins BEGIN
  INSERT INTO vault_logins_fts(rowid, title, username, urls_json)
  VALUES (new.rowid, new.title, new.username, new.urls_json);
  END;
  CREATE TRIGGER IF NOT EXISTS vault_logins_fts_ad AFTER DELETE ON vault_logins BEGIN
  INSERT INTO vault_logins_fts(vault_logins_fts, rowid, title, username, urls_json)
  VALUES ('delete', old.rowid, old.title, old.username, old.urls_json);
  END;
  CREATE TRIGGER IF NOT EXISTS vault_logins_fts_au AFTER UPDATE ON vault_logins BEGIN
  INSERT INTO vault_logins_fts(vault_logins_fts, rowid, title, username, urls_json)
  VALUES ('delete', old.rowid, old.title, old.username, old.urls_json);
  INSERT INTO vault_logins_fts(rowid, title, username, urls_json)
  VALUES (new.rowid, new.title, new.username, new.urls_json);
  END;
  CREATE TABLE IF NOT EXISTS vault_cards (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  cardholder_enc TEXT NOT NULL DEFAULT '',
  number_enc TEXT NOT NULL,
  expiry TEXT NOT NULL DEFAULT '',
  cvv_enc TEXT NOT NULL DEFAULT '',
  notes_enc TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_vault_card_updated ON vault_cards(updated_at DESC);
  CREATE TABLE IF NOT EXISTS vault_notes (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content_enc TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_vault_note_updated ON vault_notes(updated_at DESC);
  ",
    ),
    (
        5,
        "
  CREATE TABLE IF NOT EXISTS boosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT '*',
  css TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  builtin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT 0
  );
  ",
    ),
    (
        6,
        "\
  ALTER TABLE museum_bundles ADD COLUMN index_tier TEXT NOT NULL DEFAULT 'hot';\
  ALTER TABLE museum_bundles ADD COLUMN last_accessed_at INTEGER;\
  CREATE INDEX IF NOT EXISTS idx_bundle_tier ON museum_bundles(index_tier, last_accessed_at);\
  DROP TRIGGER IF EXISTS museum_fts_au;\
  CREATE TRIGGER IF NOT EXISTS museum_fts_au_del AFTER UPDATE ON museum_bundles BEGIN\
  INSERT INTO museum_fts(museum_fts, rowid, tfidf_tags, title)\
  VALUES ('delete', old.rowid, old.tfidf_tags, old.title);\
  END;\
  CREATE TRIGGER IF NOT EXISTS museum_fts_au_hot AFTER UPDATE ON museum_bundles\
  WHEN NEW.index_tier != 'cold' BEGIN\
  INSERT INTO museum_fts(rowid, tfidf_tags, title)\
  VALUES (new.rowid, new.tfidf_tags, new.title);\
  END;\
  ",
    ),
    (
        7,
        "
  ALTER TABLE privacy_stats ADD COLUMN tracking_block_count INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE privacy_stats ADD COLUMN fingerprint_noise_count INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE privacy_stats ADD COLUMN ram_saved_mb REAL NOT NULL DEFAULT 0.0;
  ALTER TABLE privacy_stats ADD COLUMN time_saved_min REAL NOT NULL DEFAULT 0.0;
  CREATE TABLE IF NOT EXISTS tab_groups (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'Group',
    color TEXT NOT NULL DEFAULT '#60a5fa',
    collapsed INTEGER NOT NULL DEFAULT 0,
    project_mode INTEGER NOT NULL DEFAULT 0,
    tab_ids TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_tg_workspace ON tab_groups(workspace_id);
  ",
    ),
    (
        8,
        "\
  ALTER TABLE vault_logins ADD COLUMN breach_status TEXT NOT NULL DEFAULT 'unknown';\
  ALTER TABLE vault_logins ADD COLUMN breach_checked_at INTEGER;\
  ALTER TABLE vault_logins ADD COLUMN breach_pwned_count INTEGER NOT NULL DEFAULT 0;\
  ALTER TABLE vault_logins ADD COLUMN passkey_cred_id_enc TEXT;\
  ALTER TABLE vault_logins ADD COLUMN passkey_user_handle TEXT;\
  ALTER TABLE vault_logins ADD COLUMN passkey_rp_id TEXT;\
  ALTER TABLE vault_logins ADD COLUMN passkey_added_at INTEGER;\
  CREATE TABLE IF NOT EXISTS vault_breach_cache (\
    sha1_prefix TEXT NOT NULL,\
    suffixes_gz BLOB NOT NULL,\
    fetched_at  INTEGER NOT NULL,\
    PRIMARY KEY (sha1_prefix)\
  );\
  ",
    ),
];

/// A cloneable handle to a single SQLite WAL-mode connection.
///
/// All methods acquire `self.0.lock()` for the duration of the call.
/// For long-running queries (FTS5 full scans, cold-tier LIKE sweeps) call
/// sites inside async Tauri commands should wrap the call in
/// `tokio::task::spawn_blocking` to avoid blocking a tokio worker thread.
#[derive(Clone)]
pub struct Db(pub Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open SQLite")?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous  = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA mmap_size    = 268435456;
        ",
        )?;
        let db = Db(Arc::new(Mutex::new(conn)));
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.0.lock().unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);

        // Migrations containing ALTER TABLE ADD COLUMN must run statement-by-
        // statement so duplicate-column errors (re-running on an already-migrated
        // DB) are suppressed without masking genuine failures.
        const ALTER_MIGRATIONS: &[u32] = &[2, 4, 6, 7, 8];

        for (v, sql) in MIGRATIONS {
            if *v > version {
                if ALTER_MIGRATIONS.contains(v) {
                    for stmt in sql.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                        let upper = stmt.to_uppercase();
                        if upper.contains("ALTER TABLE") && upper.contains("ADD COLUMN") {
                            let _ = exec_idempotent(&conn, &format!("{};", stmt));
                        } else {
                            conn.execute_batch(&format!("{};", stmt)).with_context(|| {
                                format!("migration v{v}: {}", &stmt[..stmt.len().min(80)])
                            })?;
                        }
                    }
                } else {
                    conn.execute_batch(sql)
                        .with_context(|| format!("migration v{v}"))?;
                }
                conn.execute_batch(&format!("PRAGMA user_version = {v}"))?;
            }
        }
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn week_start(ts: i64) -> i64 {
    let dow = ((ts / 86_400) + 3) % 7;
    ts - (dow * 86_400) - (ts % 86_400)
}

pub(super) fn bundle_row(r: &rusqlite::Row) -> rusqlite::Result<BundleRow> {
    Ok(BundleRow {
        id: r.get(0)?,
        url: r.get(1)?,
        title: r.get(2)?,
        content_hash: r.get(3)?,
        bundle_path: r.get(4)?,
        tfidf_tags: r.get(5)?,
        bundle_size: r.get(6)?,
        frozen_at: r.get(7)?,
        workspace_id: r.get(8)?,
        index_tier: r.get::<_, String>(9).unwrap_or_else(|_| "hot".to_string()),
        last_accessed_at: r.get::<_, Option<i64>>(10).unwrap_or(None),
    })
}

pub(super) trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>>;
}
impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn week_start_monday() {
        let monday_ts: i64 = 20528 * 86_400;
        for d in 0i64..7 {
            let ws = week_start(monday_ts + d * 86_400 + 43_200);
            assert_eq!(ws, monday_ts);
            assert_eq!(ws % 86_400, 0);
        }
    }

    #[test]
    fn like_escape_chars() {
        let q = "50%_test";
        let esc = q
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        assert_eq!(esc, "50\\%\\_test");
    }
}
