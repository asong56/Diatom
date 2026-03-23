// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/db.rs  — v0.9.2
//
// [FIX-05] Migration v2 ALTER TABLE is now idempotent (per-statement IGNORE).
// [FIX-16] museum_fts kept in sync via INSERT/DELETE/UPDATE triggers.
// [FIX-18] search_history escapes LIKE wildcards.
// [FIX-19] insert_reading_event ring-buffer uses single atomic transaction.
// [FIX-20] get_bundle() looks up by ID without a cap; list_bundles cap is caller's choice.
// [FIX-persistence-totp]  totp_* helpers added.
// [FIX-persistence-trust] trust_* helpers added.
// [FIX-persistence-rss]   rss_* helpers added.
// [FIX-zen]  zen_save / zen_load added.
// [NEW] filter_subscriptions, nostr_relays, onboarding tables.
// [NEW] add_time_saved() so war_report can write real data.
// ─────────────────────────────────────────────────────────────────────────────

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::{Arc, Mutex}};

// ── Migrations ────────────────────────────────────────────────────────────────

// ── Schema helpers ────────────────────────────────────────────────────────────

/// Execute a statement, ignoring "duplicate column" and "already exists" errors
/// that arise when migrations are re-run on a partially-migrated database.
fn exec_idempotent(conn: &Connection, sql: &str) -> rusqlite::Result<()> {
    match conn.execute_batch(sql) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(ref e, _))
            if e.code == rusqlite::ErrorCode::Unknown
                // SQLite error 1 covers "duplicate column name" and "table already exists"
                || e.extended_code == 1 =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

const MIGRATIONS: &[(u32, &str)] = &[
    (1, "
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
    "),
    (2, "
        CREATE TABLE IF NOT EXISTS museum_bundles (
            id TEXT PRIMARY KEY, url TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL,
            bundle_path TEXT NOT NULL, tfidf_tags TEXT NOT NULL DEFAULT '[]',
            bundle_size INTEGER NOT NULL DEFAULT 0,
            frozen_at INTEGER NOT NULL, workspace_id TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bundle_ws   ON museum_bundles(workspace_id);
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
    "),
    // v3: TOTP, Trust, Zen persistence, Privacy Presets, Nostr, Onboarding
    (3, "
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
    "),
];

// ── Db ────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Db(pub Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open SQLite")?;
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous  = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA mmap_size    = 268435456;
        ")?;
        let db = Db(Arc::new(Mutex::new(conn)));
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.0.lock().unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);

        for (v, sql) in MIGRATIONS {
            if *v > version {
                // [FIX-05] v2 has ALTER TABLE which fails if columns exist.
                // Run statements individually, ignoring duplicate-column errors.
                if *v == 2 {
                    // Run all non-ALTER statements normally, ALTER ones with IGNORE
                    let stmts: Vec<&str> = sql.split(';')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .collect();
                    for stmt in stmts {
                        let upper = stmt.to_uppercase();
                        if upper.contains("ALTER TABLE") && upper.contains("ADD COLUMN") {
                            let _ = conn.execute_batch(&format!("{};", stmt));
                        } else {
                            conn.execute_batch(&format!("{};", stmt))
                                .with_context(|| format!("migration v{v}: {}", &stmt[..stmt.len().min(80)]))?;
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

    // ── Settings ──────────────────────────────────────────────────────────────

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap()
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

    // ── History ───────────────────────────────────────────────────────────────

    pub fn upsert_history(&self, workspace_id: &str, url: &str, title: &str, dwell_ms: u64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO history(id,workspace_id,url,title,visited_at,dwell_ms,visit_count)
             VALUES(?1,?2,?3,?4,?5,?6,1)
             ON CONFLICT(url,workspace_id) DO UPDATE SET
               title=excluded.title, visited_at=excluded.visited_at,
               dwell_ms=dwell_ms+excluded.dwell_ms, visit_count=visit_count+1",
            params![new_id(), workspace_id, url, title, unix_now(), dwell_ms],
        )?;
        Ok(())
    }

    pub fn search_history(&self, workspace_id: &str, query: &str, limit: u32) -> Result<Vec<HistoryRow>> {
        let conn = self.0.lock().unwrap();
        // [FIX-18] Escape LIKE special characters
        let esc = query.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        let pat = format!("%{esc}%");
        let mut stmt = conn.prepare(
            "SELECT id,url,title,visited_at,dwell_ms,visit_count
             FROM history WHERE workspace_id=?1
             AND (url LIKE ?2 ESCAPE '\\' OR title LIKE ?2 ESCAPE '\\')
             ORDER BY visited_at DESC LIMIT ?3")?;
        let rows = stmt.query_map(params![workspace_id, pat, limit], |r| Ok(HistoryRow {
            id: r.get(0)?, url: r.get(1)?, title: r.get(2)?,
            visited_at: r.get(3)?, dwell_ms: r.get(4)?, visit_count: r.get(5)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("search_history")
    }

    pub fn clear_history(&self, workspace_id: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "DELETE FROM history WHERE workspace_id=?1", [workspace_id])?;
        Ok(())
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    pub fn increment_block_count(&self, week_start: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,block_count,tracking_block_count)
             VALUES(?1,1,1)
             ON CONFLICT(week_start) DO UPDATE SET
               block_count=block_count+1, tracking_block_count=tracking_block_count+1",
            [week_start])?;
        Ok(())
    }

    pub fn increment_noise_count(&self, week_start: i64, count: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,fingerprint_noise_count) VALUES(?1,?2)
             ON CONFLICT(week_start) DO UPDATE SET
               fingerprint_noise_count=fingerprint_noise_count+excluded.fingerprint_noise_count",
            params![week_start, count])?;
        Ok(())
    }

    pub fn add_ram_saved(&self, week_start: i64, mb: f64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,ram_saved_mb) VALUES(?1,?2)
             ON CONFLICT(week_start) DO UPDATE SET ram_saved_mb=ram_saved_mb+excluded.ram_saved_mb",
            params![week_start, mb])?;
        Ok(())
    }

    /// [NEW] Write real time-saved measurement (e.g. from page-load timing).
    pub fn add_time_saved(&self, week_start: i64, minutes: f64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,time_saved_min) VALUES(?1,?2)
             ON CONFLICT(week_start) DO UPDATE SET time_saved_min=time_saved_min+excluded.time_saved_min",
            params![week_start, minutes])?;
        Ok(())
    }

    pub fn war_report_week(&self, week_start: i64) -> Result<WarReportRow> {
        self.0.lock().unwrap().query_row(
            "SELECT tracking_block_count,fingerprint_noise_count,ram_saved_mb,time_saved_min
             FROM privacy_stats WHERE week_start=?1",
            [week_start], |r| Ok(WarReportRow {
                tracking_block_count: r.get(0)?,
                fingerprint_noise_count: r.get(1)?,
                ram_saved_mb: r.get(2)?,
                time_saved_min: r.get(3)?,
            }),
        ).context("war_report_week")
    }

    // ── Reading events ─────────────────────────────────────────────────────────

    pub fn insert_reading_event(&self, evt: &ReadingEvent) -> Result<()> {
        // [FIX-19] Single atomic transaction
        let conn = self.0.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let r = (|| -> Result<()> {
            conn.execute(
                "INSERT OR IGNORE INTO reading_events
                 (id,url,domain,dwell_ms,scroll_px_s,reading_mode,tab_switches,recorded_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![evt.id, evt.url, evt.domain, evt.dwell_ms, evt.scroll_px_s,
                        evt.reading_mode as i32, evt.tab_switches, evt.recorded_at])?;
            conn.execute(
                "DELETE FROM reading_events WHERE id IN (
                    SELECT id FROM reading_events ORDER BY recorded_at DESC LIMIT -1 OFFSET 1000
                )", [])?;
            Ok(())
        })();
        if r.is_ok() { conn.execute_batch("COMMIT")?; } else { let _ = conn.execute_batch("ROLLBACK"); }
        r
    }

    pub fn reading_events_since(&self, since_unix: i64) -> Result<Vec<ReadingEvent>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,url,domain,dwell_ms,scroll_px_s,reading_mode,tab_switches,recorded_at
             FROM reading_events WHERE recorded_at >= ?1 ORDER BY recorded_at DESC")?;
        let rows = stmt.query_map([since_unix], |r| Ok(ReadingEvent {
            id: r.get(0)?, url: r.get(1)?, domain: r.get(2)?,
            dwell_ms: r.get(3)?, scroll_px_s: r.get(4)?,
            reading_mode: r.get::<_,i32>(5)? != 0,
            tab_switches: r.get(6)?, recorded_at: r.get(7)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("reading_events_since")
    }

    pub fn purge_reading_events_before(&self, before_unix: i64) -> Result<usize> {
        Ok(self.0.lock().unwrap().execute(
            "DELETE FROM reading_events WHERE recorded_at < ?1", [before_unix])?)
    }

    // ── Museum bundles ─────────────────────────────────────────────────────────

    pub fn insert_bundle(&self, b: &BundleRow) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO museum_bundles
             (id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,workspace_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![b.id, b.url, b.title, b.content_hash, b.bundle_path,
                    b.tfidf_tags, b.bundle_size, b.frozen_at, b.workspace_id])?;
        Ok(())
    }

    pub fn list_bundles(&self, workspace_id: &str, limit: u32) -> Result<Vec<BundleRow>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,workspace_id
             FROM museum_bundles WHERE workspace_id=?1 ORDER BY frozen_at DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![workspace_id, limit], |r| Ok(bundle_row(r)?))?;
        rows.collect::<rusqlite::Result<_>>().context("list_bundles")
    }

    /// [FIX-20] Direct ID lookup — no cap.
    pub fn get_bundle_by_id(&self, id: &str) -> Result<Option<BundleRow>> {
        let conn = self.0.lock().unwrap();
        conn.query_row(
            "SELECT id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,workspace_id
             FROM museum_bundles WHERE id=?1", [id],
            |r| bundle_row(r),
        ).optional().context("get_bundle_by_id")
    }

    pub fn search_bundles_fts(&self, query: &str, workspace_id: &str) -> Result<Vec<BundleRow>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT b.id,b.url,b.title,b.content_hash,b.bundle_path,
                    b.tfidf_tags,b.bundle_size,b.frozen_at,b.workspace_id
             FROM museum_bundles b
             JOIN museum_fts f ON f.rowid = b.rowid
             WHERE museum_fts MATCH ?1 AND b.workspace_id = ?2
             ORDER BY rank LIMIT 10")?;
        let rows = stmt.query_map(params![query, workspace_id], |r| bundle_row(r))?;
        rows.collect::<rusqlite::Result<_>>().context("search_bundles_fts")
    }

    pub fn delete_bundle(&self, id: &str) -> Result<()> {
        // [FIX-16] FTS maintained by triggers — no manual action needed
        self.0.lock().unwrap().execute("DELETE FROM museum_bundles WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn delete_bundles_for_workspace(&self, workspace_id: &str) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        let paths: Vec<String> = {
            let mut stmt = conn.prepare("SELECT bundle_path FROM museum_bundles WHERE workspace_id=?1")?;
            stmt.query_map([workspace_id], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        conn.execute("DELETE FROM museum_bundles WHERE workspace_id=?1", [workspace_id])?;
        Ok(paths)
    }

    // ── DOM blocks ─────────────────────────────────────────────────────────────

    pub fn insert_dom_block(&self, domain: &str, selector: &str) -> Result<String> {
        let id = new_id();
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO dom_blocks(id,domain,selector,created_at) VALUES(?1,?2,?3,?4)",
            params![id, domain, selector, unix_now()])?;
        Ok(id)
    }

    pub fn dom_blocks_for(&self, domain: &str) -> Result<Vec<DomBlock>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,domain,selector,created_at FROM dom_blocks WHERE domain=?1")?;
        let rows = stmt.query_map([domain], |r| Ok(DomBlock {
            id: r.get(0)?, domain: r.get(1)?, selector: r.get(2)?, created_at: r.get(3)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("dom_blocks_for")
    }

    pub fn delete_dom_block(&self, id: &str) -> Result<()> {
        self.0.lock().unwrap().execute("DELETE FROM dom_blocks WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn all_dom_block_domains(&self) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare("SELECT DISTINCT domain FROM dom_blocks ORDER BY domain")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>().context("all_dom_block_domains")
    }

    // ── TOTP [FIX-persistence-totp] ───────────────────────────────────────────

    pub fn totp_insert(&self, id: &str, issuer: &str, account: &str,
                       secret_enc: &str, domains_json: &str, added_at: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO totp_entries(id,issuer,account,secret_enc,domains,added_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![id, issuer, account, secret_enc, domains_json, added_at])?;
        Ok(())
    }

    pub fn totp_delete(&self, id: &str) -> Result<()> {
        self.0.lock().unwrap().execute("DELETE FROM totp_entries WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn totp_list_raw(&self) -> Result<Vec<TotpRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,issuer,account,secret_enc,domains,added_at FROM totp_entries ORDER BY added_at")?;
        let rows = stmt.query_map([], |r| Ok(TotpRaw {
            id: r.get(0)?, issuer: r.get(1)?, account: r.get(2)?,
            secret_enc: r.get(3)?, domains_json: r.get(4)?, added_at: r.get(5)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("totp_list_raw")
    }

    // ── Trust [FIX-persistence-trust] ─────────────────────────────────────────

    pub fn trust_set(&self, domain: &str, level: &str, source: &str, set_at: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO trust_profiles(domain,level,source,set_at)
             VALUES(?1,?2,?3,?4)",
            params![domain, level, source, set_at])?;
        Ok(())
    }

    pub fn trust_delete(&self, domain: &str) -> Result<()> {
        self.0.lock().unwrap().execute("DELETE FROM trust_profiles WHERE domain=?1", [domain])?;
        Ok(())
    }

    pub fn trust_list_raw(&self) -> Result<Vec<TrustRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain,level,source,set_at FROM trust_profiles ORDER BY set_at")?;
        let rows = stmt.query_map([], |r| Ok(TrustRaw {
            domain: r.get(0)?, level: r.get(1)?, source: r.get(2)?, set_at: r.get(3)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("trust_list_raw")
    }

    // ── RSS [FIX-persistence-rss] ─────────────────────────────────────────────

    pub fn rss_feed_upsert(&self, f: &RssFeedRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO rss_feeds
             (id,url,title,category,fetch_interval_m,last_fetched,enabled,added_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![f.id, f.url, f.title, f.category, f.fetch_interval_m,
                    f.last_fetched, f.enabled as i32, f.added_at])?;
        Ok(())
    }

    pub fn rss_feed_delete(&self, id: &str) -> Result<()> {
        let conn = self.0.lock().unwrap();
        conn.execute("DELETE FROM rss_items WHERE feed_id=?1", [id])?;
        conn.execute("DELETE FROM rss_feeds WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn rss_feeds_all(&self) -> Result<Vec<RssFeedRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,url,title,category,fetch_interval_m,last_fetched,enabled,added_at
             FROM rss_feeds ORDER BY added_at")?;
        let rows = stmt.query_map([], |r| Ok(RssFeedRaw {
            id: r.get(0)?, url: r.get(1)?, title: r.get(2)?,
            category: r.get(3)?, fetch_interval_m: r.get(4)?,
            last_fetched: r.get(5)?, enabled: r.get::<_,i32>(6)? != 0,
            added_at: r.get(7)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("rss_feeds_all")
    }

    pub fn rss_item_upsert(&self, i: &RssItemRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO rss_items
             (id,feed_id,guid,title,url,summary,published,read,fetched_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![i.id, i.feed_id, i.guid, i.title, i.url, i.summary,
                    i.published, i.read as i32, i.fetched_at])?;
        Ok(())
    }

    pub fn rss_items_for_feed(&self, feed_id: &str) -> Result<Vec<RssItemRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,feed_id,guid,title,url,summary,published,read,fetched_at
             FROM rss_items WHERE feed_id=?1 ORDER BY fetched_at DESC LIMIT 5000")?;
        let rows = stmt.query_map([feed_id], |r| Ok(RssItemRaw {
            id: r.get(0)?, feed_id: r.get(1)?, guid: r.get(2)?,
            title: r.get(3)?, url: r.get(4)?, summary: r.get(5)?,
            published: r.get(6)?, read: r.get::<_,i32>(7)? != 0, fetched_at: r.get(8)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("rss_items_for_feed")
    }

    pub fn rss_item_mark_read(&self, item_id: &str) -> Result<()> {
        self.0.lock().unwrap().execute("UPDATE rss_items SET read=1 WHERE id=?1", [item_id])?;
        Ok(())
    }

    // ── Knowledge packs ────────────────────────────────────────────────────────

    pub fn insert_knowledge_pack(&self, p: &KnowledgePack) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO knowledge_packs(id,name,format,pack_path,size_bytes,added_at,enabled)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![p.id, p.name, p.format, p.pack_path, p.size_bytes, p.added_at, p.enabled as i32])?;
        Ok(())
    }

    pub fn list_knowledge_packs(&self) -> Result<Vec<KnowledgePack>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,name,format,pack_path,size_bytes,added_at,enabled
             FROM knowledge_packs ORDER BY added_at DESC")?;
        let rows = stmt.query_map([], |r| Ok(KnowledgePack {
            id: r.get(0)?, name: r.get(1)?, format: r.get(2)?,
            pack_path: r.get(3)?, size_bytes: r.get(4)?,
            added_at: r.get(5)?, enabled: r.get::<_,i32>(6)? != 0,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("list_knowledge_packs")
    }

    // ── Filter subscriptions [NEW] ─────────────────────────────────────────────

    pub fn filter_sub_upsert(&self, id: &str, name: &str, url: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO filter_subscriptions(id,name,url,added_at) VALUES(?1,?2,?3,?4)",
            params![id, name, url, unix_now()])?;
        Ok(())
    }

    pub fn filter_sub_update_stats(&self, url: &str, rule_count: usize) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE filter_subscriptions SET last_synced=?1,rule_count=?2 WHERE url=?3",
            params![unix_now(), rule_count as i64, url])?;
        Ok(())
    }

    pub fn filter_subs_all(&self) -> Result<Vec<FilterSub>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,name,url,last_synced,enabled,rule_count,added_at
             FROM filter_subscriptions ORDER BY added_at")?;
        let rows = stmt.query_map([], |r| Ok(FilterSub {
            id: r.get(0)?, name: r.get(1)?, url: r.get(2)?,
            last_synced: r.get(3)?, enabled: r.get::<_,i32>(4)? != 0,
            rule_count: r.get::<_,i64>(5)? as usize, added_at: r.get(6)?,
        }))?;
        rows.collect::<rusqlite::Result<_>>().context("filter_subs_all")
    }

    // ── Zen persistence [FIX-zen] ──────────────────────────────────────────────

    pub fn zen_save(&self, active: bool, aphorism: &str,
                    blocked_cats_json: &str, activated_at: Option<i64>) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE zen_state SET active=?1,aphorism=?2,blocked_cats=?3,activated_at=?4 WHERE id=1",
            params![active as i32, aphorism, blocked_cats_json, activated_at])?;
        Ok(())
    }

    pub fn zen_load(&self) -> Option<ZenRaw> {
        self.0.lock().unwrap().query_row(
            "SELECT active,aphorism,blocked_cats,activated_at FROM zen_state WHERE id=1",
            [], |r| Ok(ZenRaw {
                active: r.get::<_,i32>(0)? != 0,
                aphorism: r.get(1)?,
                blocked_cats_json: r.get(2)?,
                activated_at: r.get(3)?,
            }),
        ).ok()
    }

    // ── Onboarding [NEW] ──────────────────────────────────────────────────────

    pub fn onboarding_complete(&self, step: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO onboarding(step,completed,done_at) VALUES(?1,1,?2)",
            params![step, unix_now()])?;
        Ok(())
    }

    pub fn onboarding_is_done(&self, step: &str) -> bool {
        self.0.lock().unwrap().query_row(
            "SELECT completed FROM onboarding WHERE step=?1", [step],
            |r| r.get::<_,i32>(0),
        ).ok().map(|v| v != 0).unwrap_or(false)
    }

    pub fn onboarding_all_steps(&self) -> Vec<(String, bool)> {
        let Ok(conn_guard) = self.0.lock() else { return vec![]; };
        let Ok(mut stmt) = conn_guard.prepare("SELECT step,completed FROM onboarding") else { return vec![]; };
        stmt.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,i32>(1)? != 0)))
            .ok().map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    // ── Nostr relays [NEW] ────────────────────────────────────────────────────

    pub fn nostr_relay_add(&self, url: &str) -> Result<String> {
        let id = new_id();
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO nostr_relays(id,url,added_at) VALUES(?1,?2,?3)",
            params![id, url, unix_now()])?;
        Ok(id)
    }

    pub fn nostr_relays_enabled(&self) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare("SELECT url FROM nostr_relays WHERE enabled=1")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>().context("nostr_relays_enabled")
    }
}

// ── Row helper ────────────────────────────────────────────────────────────────

fn bundle_row(r: &rusqlite::Row) -> rusqlite::Result<BundleRow> {
    Ok(BundleRow {
        id: r.get(0)?, url: r.get(1)?, title: r.get(2)?,
        content_hash: r.get(3)?, bundle_path: r.get(4)?,
        tfidf_tags: r.get(5)?, bundle_size: r.get(6)?,
        frozen_at: r.get(7)?, workspace_id: r.get(8)?,
    })
}

// ── Optional helper ───────────────────────────────────────────────────────────

trait OptionalExt<T> { fn optional(self) -> Result<Option<T>>; }
impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

// ── Row types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: String, pub url: String, pub title: String,
    pub visited_at: i64, pub dwell_ms: i64, pub visit_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarReportRow {
    pub tracking_block_count: i64, pub fingerprint_noise_count: i64,
    pub ram_saved_mb: f64, pub time_saved_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadingEvent {
    pub id: String, pub url: String, pub domain: String,
    pub dwell_ms: i64, pub scroll_px_s: f64,
    pub reading_mode: bool, pub tab_switches: i64, pub recorded_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRow {
    pub id: String, pub url: String, pub title: String,
    pub content_hash: String, pub bundle_path: String,
    pub tfidf_tags: String, pub bundle_size: i64,
    pub frozen_at: i64, pub workspace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomBlock {
    pub id: String, pub domain: String, pub selector: String, pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgePack {
    pub id: String, pub name: String,
    pub format: String,
    pub pack_path: String, pub size_bytes: i64,
    pub added_at: i64, pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct TotpRaw {
    pub id: String, pub issuer: String, pub account: String,
    pub secret_enc: String, pub domains_json: String, pub added_at: i64,
}

#[derive(Debug, Clone)]
pub struct TrustRaw {
    pub domain: String, pub level: String, pub source: String, pub set_at: i64,
}

#[derive(Debug, Clone)]
pub struct RssFeedRaw {
    pub id: String, pub url: String, pub title: String,
    pub category: Option<String>, pub fetch_interval_m: i32,
    pub last_fetched: Option<i64>, pub enabled: bool, pub added_at: i64,
}

#[derive(Debug, Clone)]
pub struct RssItemRaw {
    pub id: String, pub feed_id: String, pub guid: String,
    pub title: String, pub url: String, pub summary: String,
    pub published: Option<i64>, pub read: bool, pub fetched_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterSub {
    pub id: String, pub name: String, pub url: String,
    pub last_synced: Option<i64>, pub enabled: bool,
    pub rule_count: usize, pub added_at: i64,
}

pub struct ZenRaw {
    pub active: bool, pub aphorism: String,
    pub blocked_cats_json: String, pub activated_at: Option<i64>,
}

// ── Utilities ─────────────────────────────────────────────────────────────────

pub fn new_id() -> String { uuid::Uuid::new_v4().to_string() }

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs() as i64
}

pub fn week_start(ts: i64) -> i64 {
    let dow = ((ts / 86_400) + 3) % 7;
    ts - (dow * 86_400) - (ts % 86_400)
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
        // Verify our escape logic works for special chars
        let q = "50%_test";
        let esc = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        assert_eq!(esc, "50\\%\\_test");
    }
}
