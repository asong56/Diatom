//! History, privacy-stats, and reading-event queries.

use anyhow::{Context, Result};
use rusqlite::params;

use super::core::{Db, new_id, unix_now};
use super::types::{HistoryRow, ReadingEvent, WarReportRow};

impl Db {
    pub fn top_domains(&self, workspace_id: &str, limit: u32) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT url, title, favicon_hex, SUM(visit_count) as total_visits
             FROM history WHERE workspace_id=?1
             GROUP BY SUBSTR(url, INSTR(url,'://')+3, INSTR(SUBSTR(url,INSTR(url,'://')+3),'/')-1)
             ORDER BY total_visits DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![workspace_id, limit], |r| {
            Ok(serde_json::json!({
                "url":          r.get::<_,String>(0)?,
                "title":        r.get::<_,String>(1)?,
                "favicon_hex":  r.get::<_,Option<String>>(2)?,
                "visit_count":  r.get::<_,i64>(3)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("top_domains")
    }

    /// Pinned bookmarks (tagged "pinned") for Home Base new-tab page.
    pub fn pinned_bookmarks(
        &self,
        workspace_id: &str,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT url, title FROM bookmarks
             WHERE workspace_id=?1 AND tags LIKE '%\"pinned\"%'
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![workspace_id, limit], |r| {
            Ok(serde_json::json!({
                "url":   r.get::<_,String>(0)?,
                "title": r.get::<_,String>(1)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("pinned_bookmarks")
    }

    pub fn upsert_history(
        &self,
        workspace_id: &str,
        url: &str,
        title: &str,
        dwell_ms: u64,
    ) -> Result<()> {
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

    /// Full-text LIKE scan — O(history_size). Use `spawn_blocking` for > 10 000 rows.
    pub fn search_history(
        &self,
        workspace_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<HistoryRow>> {
        let conn = self.0.lock().unwrap();
        let esc = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pat = format!("%{esc}%");
        let mut stmt = conn.prepare(
            "SELECT id,url,title,visited_at,dwell_ms,visit_count
             FROM history WHERE workspace_id=?1
             AND (url LIKE ?2 ESCAPE '\\' OR title LIKE ?2 ESCAPE '\\')
             ORDER BY visited_at DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![workspace_id, pat, limit], |r| {
            Ok(HistoryRow {
                id: r.get(0)?,
                url: r.get(1)?,
                title: r.get(2)?,
                visited_at: r.get(3)?,
                dwell_ms: r.get(4)?,
                visit_count: r.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("search_history")
    }

    pub fn clear_history(&self, workspace_id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM history WHERE workspace_id=?1", [workspace_id])?;
        Ok(())
    }

    pub fn increment_block_count(&self, week_start: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,block_count,tracking_block_count)
             VALUES(?1,1,1)
             ON CONFLICT(week_start) DO UPDATE SET
               block_count=block_count+1, tracking_block_count=tracking_block_count+1",
            [week_start],
        )?;
        Ok(())
    }

    pub fn increment_noise_count(&self, week_start: i64, count: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,fingerprint_noise_count) VALUES(?1,?2)
             ON CONFLICT(week_start) DO UPDATE SET
               fingerprint_noise_count=fingerprint_noise_count+excluded.fingerprint_noise_count",
            params![week_start, count],
        )?;
        Ok(())
    }

    pub fn add_ram_saved(&self, week_start: i64, mb: f64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,ram_saved_mb) VALUES(?1,?2)
             ON CONFLICT(week_start) DO UPDATE SET ram_saved_mb=ram_saved_mb+excluded.ram_saved_mb",
            params![week_start, mb],
        )?;
        Ok(())
    }

    pub fn add_time_saved(&self, week_start: i64, minutes: f64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO privacy_stats(week_start,time_saved_min) VALUES(?1,?2)
             ON CONFLICT(week_start) DO UPDATE SET time_saved_min=time_saved_min+excluded.time_saved_min",
            params![week_start, minutes])?;
        Ok(())
    }

    pub fn war_report_week(&self, week_start: i64) -> Result<WarReportRow> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT tracking_block_count,fingerprint_noise_count,ram_saved_mb,time_saved_min
             FROM privacy_stats WHERE week_start=?1",
                [week_start],
                |r| {
                    Ok(WarReportRow {
                        tracking_block_count: r.get(0)?,
                        fingerprint_noise_count: r.get(1)?,
                        ram_saved_mb: r.get(2)?,
                        time_saved_min: r.get(3)?,
                    })
                },
            )
            .context("war_report_week")
    }

    pub fn insert_reading_event(&self, evt: &ReadingEvent) -> Result<()> {
        let conn = self.0.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let r = (|| -> Result<()> {
            conn.execute(
                "INSERT OR IGNORE INTO reading_events
                 (id,url,domain,dwell_ms,scroll_px_s,reading_mode,tab_switches,recorded_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    evt.id,
                    evt.url,
                    evt.domain,
                    evt.dwell_ms,
                    evt.scroll_px_s,
                    evt.reading_mode as i32,
                    evt.tab_switches,
                    evt.recorded_at
                ],
            )?;
            // Trim ring buffer to 1000 rows
            conn.execute(
                "DELETE FROM reading_events WHERE id IN (
                    SELECT id FROM reading_events ORDER BY recorded_at DESC LIMIT -1 OFFSET 1000
                )",
                [],
            )?;
            Ok(())
        })();
        if r.is_ok() {
            conn.execute_batch("COMMIT")?;
        } else {
            let _ = conn.execute_batch("ROLLBACK");
        }
        r
    }

    pub fn reading_events_since(&self, since_unix: i64) -> Result<Vec<ReadingEvent>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,url,domain,dwell_ms,scroll_px_s,reading_mode,tab_switches,recorded_at
             FROM reading_events WHERE recorded_at >= ?1 ORDER BY recorded_at DESC",
        )?;
        let rows = stmt.query_map([since_unix], |r| {
            Ok(ReadingEvent {
                id: r.get(0)?,
                url: r.get(1)?,
                domain: r.get(2)?,
                dwell_ms: r.get(3)?,
                scroll_px_s: r.get(4)?,
                reading_mode: r.get::<_, i32>(5)? != 0,
                tab_switches: r.get(6)?,
                recorded_at: r.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("reading_events_since")
    }

    pub fn purge_reading_events_before(&self, before_unix: i64) -> Result<usize> {
        Ok(self.0.lock().unwrap().execute(
            "DELETE FROM reading_events WHERE recorded_at < ?1",
            [before_unix],
        )?)
    }
}
