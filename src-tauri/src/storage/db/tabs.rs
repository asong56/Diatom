//! Tab group persistence queries.

use anyhow::Result;

use super::core::Db;

impl Db {
    pub fn upsert_tab_group(
        &self,
        id: &str,
        workspace_id: &str,
        name: &str,
        color: &str,
        collapsed: bool,
        project_mode: bool,
        tab_ids: &[String],
        created_at: i64,
    ) -> Result<()> {
        let conn = self.0.lock().unwrap();
        let tab_ids_json = serde_json::to_string(tab_ids)?;
        conn.execute(
            "INSERT INTO tab_groups (id,workspace_id,name,color,collapsed,project_mode,tab_ids,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET
               name=excluded.name, color=excluded.color,
               collapsed=excluded.collapsed, project_mode=excluded.project_mode,
               tab_ids=excluded.tab_ids",
            rusqlite::params![id, workspace_id, name, color,
                collapsed as i64, project_mode as i64, tab_ids_json, created_at],
        )?;
        Ok(())
    }

    pub fn list_tab_groups(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, String, String, String, bool, bool, Vec<String>, i64)>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, name, color, collapsed, project_mode, tab_ids, created_at
             FROM tab_groups WHERE workspace_id=?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![workspace_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)? != 0,
                r.get::<_, i64>(5)? != 0,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })?;
        rows.map(|r| {
            r.map_err(anyhow::Error::from).and_then(|t| {
                let tab_ids: Vec<String> = serde_json::from_str(&t.6).unwrap_or_default();
                Ok((t.0, t.1, t.2, t.3, t.4, t.5, tab_ids, t.7))
            })
        })
        .collect()
    }

    pub fn delete_tab_group(&self, group_id: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "DELETE FROM tab_groups WHERE id=?1",
            rusqlite::params![group_id],
        )?;
        Ok(())
    }

    pub fn rename_tab_group(&self, group_id: &str, name: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE tab_groups SET name=?1 WHERE id=?2",
            rusqlite::params![name, group_id],
        )?;
        Ok(())
    }

    pub fn set_tab_group_collapsed(&self, group_id: &str, collapsed: bool) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE tab_groups SET collapsed=?1 WHERE id=?2",
            rusqlite::params![collapsed as i64, group_id],
        )?;
        Ok(())
    }

    pub fn set_tab_group_project_mode(&self, group_id: &str, pm: bool) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE tab_groups SET project_mode=?1 WHERE id=?2",
            rusqlite::params![pm as i64, group_id],
        )?;
        Ok(())
    }

    /// Atomically move a tab into a group (or out of all groups when `group_id` is `None`).
    pub fn move_tab_to_group(&self, tab_id: &str, group_id: Option<&str>) -> Result<()> {
        let conn = self.0.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result: Result<()> = (|| {
            let all: Vec<(String, String)> = {
                let mut stmt = conn.prepare("SELECT id, tab_ids FROM tab_groups")?;
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .filter_map(|r| r.ok())
                    .collect()
            };
            for (gid, ids_json) in &all {
                let mut ids: Vec<String> = serde_json::from_str(ids_json).unwrap_or_default();
                let before = ids.len();
                ids.retain(|id| id != tab_id);
                if Some(gid.as_str()) == group_id {
                    ids.push(tab_id.to_owned());
                }
                if ids.len() != before || Some(gid.as_str()) == group_id {
                    let json = serde_json::to_string(&ids)?;
                    conn.execute(
                        "UPDATE tab_groups SET tab_ids=?1 WHERE id=?2",
                        rusqlite::params![json, gid],
                    )?;
                }
            }
            Ok(())
        })();
        if result.is_ok() {
            conn.execute_batch("COMMIT")?;
        } else {
            let _ = conn.execute_batch("ROLLBACK");
        }
        result
    }
}
