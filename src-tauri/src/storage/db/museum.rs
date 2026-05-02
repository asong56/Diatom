//! Museum archive (bundle) and DOM-Crusher block queries.

use anyhow::{Context, Result};
use rusqlite::params;

use super::core::{Db, OptionalExt, bundle_row, new_id, unix_now};
use super::types::{BundleRow, DomBlock};

impl Db {
    pub fn insert_bundle(&self, b: &BundleRow) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO museum_bundles
             (id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,workspace_id,\
              index_tier,last_accessed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                b.id,
                b.url,
                b.title,
                b.content_hash,
                b.bundle_path,
                b.tfidf_tags,
                b.bundle_size,
                b.frozen_at,
                b.workspace_id,
                b.index_tier,
                b.last_accessed_at
            ],
        )?;
        Ok(())
    }

    /// List bundles for a workspace. Use `spawn_blocking` for > 1000 bundles.
    pub fn list_bundles(&self, workspace_id: &str, limit: u32) -> Result<Vec<BundleRow>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,\
                    workspace_id,index_tier,last_accessed_at
             FROM museum_bundles WHERE workspace_id=?1 ORDER BY frozen_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![workspace_id, limit], |r| Ok(bundle_row(r)?))?;
        rows.collect::<rusqlite::Result<_>>()
            .context("list_bundles")
    }

    pub fn get_bundle_by_id(&self, id: &str) -> Result<Option<BundleRow>> {
        let conn = self.0.lock().unwrap();
        conn.query_row(
            "SELECT id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,\
                    workspace_id,index_tier,last_accessed_at
             FROM museum_bundles WHERE id=?1",
            [id],
            |r| bundle_row(r),
        )
        .optional()
        .context("get_bundle_by_id")
    }

    /// Full-text search — only HOT-tier entries have FTS5 rows.
    pub fn search_bundles_fts(&self, query: &str, workspace_id: &str) -> Result<Vec<BundleRow>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT b.id,b.url,b.title,b.content_hash,b.bundle_path,
                    b.tfidf_tags,b.bundle_size,b.frozen_at,b.workspace_id,
                    b.index_tier,b.last_accessed_at
             FROM museum_bundles b
             JOIN museum_fts f ON f.rowid = b.rowid
             WHERE museum_fts MATCH ?1 AND b.workspace_id = ?2 AND b.index_tier = 'hot'
             ORDER BY rank LIMIT 10",
        )?;
        let rows = stmt.query_map(params![query, workspace_id], |r| bundle_row(r))?;
        rows.collect::<rusqlite::Result<_>>()
            .context("search_bundles_fts")
    }

    /// Mark a bundle accessed now and promote it back to the hot tier.
    pub fn touch_bundle_access(&self, id: &str) -> Result<()> {
        let now = unix_now();
        self.0.lock().unwrap().execute(
            "UPDATE museum_bundles SET last_accessed_at = ?1, index_tier = 'hot' WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Deep Dig: search cold-tier bundles by keyword fingerprint.
    ///
    /// Cold bundles have no FTS5 rows; instead we LIKE-match their tfidf_tags
    /// JSON string. Each whitespace-separated query token must appear in
    /// tfidf_tags. Maximum 5 tokens, 20 results.
    ///
    /// [AUDIT] Uses parameterised LIKE patterns — no SQL injection risk.
    pub fn search_cold_keyword(&self, query: &str, workspace_id: &str) -> Result<Vec<BundleRow>> {
        let tokens: Vec<String> = query
            .split_whitespace()
            .take(5)
            .map(|t| format!("%{}%", t.replace('%', "\\%").replace('_', "\\_")))
            .collect();
        if tokens.is_empty() {
            return Ok(vec![]);
        }
        let like_clauses: String = (2..=tokens.len() + 1)
            .map(|i| format!("b.tfidf_tags LIKE ?{i} ESCAPE '\\'"))
            .collect::<Vec<_>>()
            .join(" AND ");
        let sql = format!(
            "SELECT b.id,b.url,b.title,b.content_hash,b.bundle_path,\
                    b.tfidf_tags,b.bundle_size,b.frozen_at,b.workspace_id,\
                    b.index_tier,b.last_accessed_at \
             FROM museum_bundles b \
             WHERE b.workspace_id = ?1 AND b.index_tier = 'cold' AND {like_clauses} \
             ORDER BY b.frozen_at DESC LIMIT 20"
        );
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(&sql)?;
        let mut all_vals: Vec<String> = vec![workspace_id.to_string()];
        all_vals.extend(tokens);
        let rows = stmt.query_map(rusqlite::params_from_iter(all_vals.iter()), |r| {
            bundle_row(r)
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("search_cold_keyword")
    }

    pub fn delete_bundle(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM museum_bundles WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn delete_bundles_for_workspace(&self, workspace_id: &str) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        let paths: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT bundle_path FROM museum_bundles WHERE workspace_id=?1")?;
            stmt.query_map([workspace_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        conn.execute(
            "DELETE FROM museum_bundles WHERE workspace_id=?1",
            [workspace_id],
        )?;
        Ok(paths)
    }

    pub fn insert_dom_block(&self, domain: &str, selector: &str) -> Result<String> {
        let id = new_id();
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO dom_blocks(id,domain,selector,created_at) VALUES(?1,?2,?3,?4)",
            params![id, domain, selector, unix_now()],
        )?;
        Ok(id)
    }

    pub fn dom_blocks_for(&self, domain: &str) -> Result<Vec<DomBlock>> {
        let conn = self.0.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id,domain,selector,created_at FROM dom_blocks WHERE domain=?1")?;
        let rows = stmt.query_map([domain], |r| {
            Ok(DomBlock {
                id: r.get(0)?,
                domain: r.get(1)?,
                selector: r.get(2)?,
                created_at: r.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("dom_blocks_for")
    }

    pub fn delete_dom_block(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM dom_blocks WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn all_dom_block_domains(&self) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare("SELECT DISTINCT domain FROM dom_blocks ORDER BY domain")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()
            .context("all_dom_block_domains")
    }
}
