use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoostRule {
    pub id: String,
    pub name: String,
    /// Domain pattern (e.g. "reddit.com" matches reddit.com and www.reddit.com).
    pub domain: String,
    pub css: String,
    pub enabled: bool,
    /// True for Diatom-shipped built-in Boosts (read-only in the UI).
    pub builtin: bool,
    pub created_at: i64,
}

pub fn builtin_boosts() -> Vec<BoostRule> {
    vec![
        BoostRule {
            id: "builtin-clean-reader".to_owned(),
            name: "Clean Reader".to_owned(),
            domain: "*".to_owned(), // global — applies to all domains
            css: include_str!("../../resources/boosts/clean-reader.css").to_owned(),
            enabled: false,
            builtin: true,
            created_at: 0,
        },
        BoostRule {
            id: "builtin-focus-dark".to_owned(),
            name: "Focus Dark".to_owned(),
            domain: "*".to_owned(),
            css: include_str!("../../resources/boosts/focus-dark.css").to_owned(),
            enabled: false,
            builtin: true,
            created_at: 0,
        },
        BoostRule {
            id: "builtin-print-friendly".to_owned(),
            name: "Print Friendly".to_owned(),
            domain: "*".to_owned(),
            css: include_str!("../../resources/boosts/print-friendly.css").to_owned(),
            enabled: false,
            builtin: true,
            created_at: 0,
        },
    ]
}

/// Returns true if `boost.domain` matches `page_domain`.
/// Wildcards: "*" matches everything. "reddit.com" also matches "www.reddit.com".
pub fn domain_matches(boost_domain: &str, page_domain: &str) -> bool {
    if boost_domain == "*" {
        return true;
    }
    if boost_domain.eq_ignore_ascii_case(page_domain) {
        return true;
    }
    let suffix = format!(".{}", boost_domain.to_lowercase());
    page_domain.to_lowercase().ends_with(&suffix)
}

/// Insert or replace a Boost rule in the DB.
pub fn upsert(db: &crate::storage::db::Db, rule: &BoostRule) -> Result<()> {
    let conn = db.0.lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO boosts \
         (id, name, domain, css, enabled, builtin, created_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![
            rule.id,
            rule.name,
            rule.domain,
            rule.css,
            rule.enabled as i64,
            rule.builtin as i64,
            rule.created_at
        ],
    )
    .context("boosts upsert")?;
    Ok(())
}

/// Delete a user Boost (built-ins cannot be deleted).
pub fn delete(db: &crate::storage::db::Db, id: &str) -> Result<()> {
    db.0.lock()
        .unwrap()
        .execute(
            "DELETE FROM boosts WHERE id = ?1 AND builtin = 0",
            rusqlite::params![id],
        )
        .context("boosts delete")?;
    Ok(())
}

/// Return all Boost rules matching `page_domain` that are enabled.
pub fn boosts_for_domain(db: &crate::storage::db::Db, page_domain: &str) -> Result<Vec<BoostRule>> {
    let conn = db.0.lock().unwrap();
    ensure_table(&conn)?;

    let mut stmt = conn.prepare(
        "SELECT id, name, domain, css, enabled, builtin, created_at \
         FROM boosts WHERE enabled = 1",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(BoostRule {
            id: r.get(0)?,
            name: r.get(1)?,
            domain: r.get(2)?,
            css: r.get(3)?,
            enabled: r.get::<_, i64>(4)? != 0,
            builtin: r.get::<_, i64>(5)? != 0,
            created_at: r.get(6)?,
        })
    })?;

    let all: Vec<BoostRule> = rows
        .filter_map(|r| r.ok())
        .filter(|b| domain_matches(&b.domain, page_domain))
        .collect();

    Ok(all)
}

/// Return all Boost rules (for the editor UI).
pub fn all_boosts(db: &crate::storage::db::Db) -> Result<Vec<BoostRule>> {
    let conn = db.0.lock().unwrap();
    ensure_table(&conn)?;
    let mut stmt = conn.prepare(
        "SELECT id, name, domain, css, enabled, builtin, created_at FROM boosts ORDER BY created_at"
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(BoostRule {
            id: r.get(0)?,
            name: r.get(1)?,
            domain: r.get(2)?,
            css: r.get(3)?,
            enabled: r.get::<_, i64>(4)? != 0,
            builtin: r.get::<_, i64>(5)? != 0,
            created_at: r.get(6)?,
        })
    })?;
    rows.collect::<rusqlite::Result<_>>().context("all_boosts")
}

/// Seed built-in Boosts into the DB on first run (idempotent).
pub fn seed_builtins(db: &crate::storage::db::Db) -> Result<()> {
    let conn = db.0.lock().unwrap();
    ensure_table(&conn)?;
    drop(conn); // release lock before calling upsert()
    for mut b in builtin_boosts() {
        let existing_enabled: Option<bool> =
            db.0.lock()
                .unwrap()
                .query_row(
                    "SELECT enabled FROM boosts WHERE id = ?1",
                    rusqlite::params![b.id],
                    |r| r.get::<_, i64>(0).map(|v| v != 0),
                )
                .ok();
        if let Some(e) = existing_enabled {
            b.enabled = e;
        }
        upsert(db, &b)?;
    }
    Ok(())
}

fn ensure_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS boosts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            domain TEXT NOT NULL DEFAULT '*',
            css TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 0,
            builtin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        );",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_wildcard_matches_all() {
        assert!(domain_matches("*", "reddit.com"));
        assert!(domain_matches("*", "news.ycombinator.com"));
    }

    #[test]
    fn domain_exact_match() {
        assert!(domain_matches("reddit.com", "reddit.com"));
    }

    #[test]
    fn domain_subdomain_match() {
        assert!(domain_matches("reddit.com", "www.reddit.com"));
        assert!(domain_matches("reddit.com", "old.reddit.com"));
    }

    #[test]
    fn domain_no_partial_match() {
        assert!(!domain_matches("reddit.com", "evil-reddit.com"));
    }
}
