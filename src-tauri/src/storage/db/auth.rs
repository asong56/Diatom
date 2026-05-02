//! Auth-adjacent and miscellaneous queries: TOTP, domain trust, RSS,
//! filter subscriptions, knowledge packs, Zen state, onboarding, Nostr relays.

use anyhow::{Context, Result};
use rusqlite::params;

use super::core::{Db, new_id, unix_now};
use super::types::*;

impl Db {
    pub fn totp_insert(
        &self,
        id: &str,
        issuer: &str,
        account: &str,
        secret_enc: &str,
        domains_json: &str,
        added_at: i64,
    ) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO totp_entries(id,issuer,account,secret_enc,domains,added_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![id, issuer, account, secret_enc, domains_json, added_at],
        )?;
        Ok(())
    }

    pub fn totp_delete(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM totp_entries WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn totp_list_raw(&self) -> Result<Vec<TotpRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, issuer, account, secret_enc, domains, added_at,
                    algorithm, digits, period
             FROM totp_entries ORDER BY added_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(TotpRaw {
                id: r.get(0)?,
                issuer: r.get(1)?,
                account: r.get(2)?,
                secret_enc: r.get(3)?,
                domains_json: r.get(4)?,
                added_at: r.get(5)?,
                algorithm: r.get(6)?,
                digits: r.get(7)?,
                period: r.get(8)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("totp_list_raw")
    }

    pub fn trust_set(&self, domain: &str, level: &str, source: &str, set_at: i64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO trust_profiles(domain,level,source,set_at)
             VALUES(?1,?2,?3,?4)",
            params![domain, level, source, set_at],
        )?;
        Ok(())
    }

    pub fn trust_delete(&self, domain: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM trust_profiles WHERE domain=?1", [domain])?;
        Ok(())
    }

    pub fn trust_list_raw(&self) -> Result<Vec<TrustRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT domain,level,source,set_at FROM trust_profiles ORDER BY set_at")?;
        let rows = stmt.query_map([], |r| {
            Ok(TrustRaw {
                domain: r.get(0)?,
                level: r.get(1)?,
                source: r.get(2)?,
                set_at: r.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("trust_list_raw")
    }

    pub fn rss_feed_upsert(&self, f: &RssFeedRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO rss_feeds
             (id,url,title,category,fetch_interval_m,last_fetched,enabled,added_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                f.id,
                f.url,
                f.title,
                f.category,
                f.fetch_interval_m,
                f.last_fetched,
                f.enabled as i32,
                f.added_at
            ],
        )?;
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
             FROM rss_feeds ORDER BY added_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RssFeedRaw {
                id: r.get(0)?,
                url: r.get(1)?,
                title: r.get(2)?,
                category: r.get(3)?,
                fetch_interval_m: r.get(4)?,
                last_fetched: r.get(5)?,
                enabled: r.get::<_, i32>(6)? != 0,
                added_at: r.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("rss_feeds_all")
    }

    pub fn rss_item_upsert(&self, i: &RssItemRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO rss_items
             (id,feed_id,guid,title,url,summary,published,read,fetched_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                i.id,
                i.feed_id,
                i.guid,
                i.title,
                i.url,
                i.summary,
                i.published,
                i.read as i32,
                i.fetched_at
            ],
        )?;
        Ok(())
    }

    pub fn rss_items_for_feed(&self, feed_id: &str) -> Result<Vec<RssItemRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,feed_id,guid,title,url,summary,published,read,fetched_at
             FROM rss_items WHERE feed_id=?1 ORDER BY fetched_at DESC LIMIT 5000",
        )?;
        let rows = stmt.query_map([feed_id], |r| {
            Ok(RssItemRaw {
                id: r.get(0)?,
                feed_id: r.get(1)?,
                guid: r.get(2)?,
                title: r.get(3)?,
                url: r.get(4)?,
                summary: r.get(5)?,
                published: r.get(6)?,
                read: r.get::<_, i32>(7)? != 0,
                fetched_at: r.get(8)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("rss_items_for_feed")
    }

    pub fn rss_item_mark_read(&self, item_id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("UPDATE rss_items SET read=1 WHERE id=?1", [item_id])?;
        Ok(())
    }

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
             FROM knowledge_packs ORDER BY added_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(KnowledgePack {
                id: r.get(0)?,
                name: r.get(1)?,
                format: r.get(2)?,
                pack_path: r.get(3)?,
                size_bytes: r.get(4)?,
                added_at: r.get(5)?,
                enabled: r.get::<_, i32>(6)? != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("list_knowledge_packs")
    }

    pub fn filter_sub_upsert(&self, id: &str, name: &str, url: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO filter_subscriptions(id,name,url,added_at) VALUES(?1,?2,?3,?4)",
            params![id, name, url, unix_now()],
        )?;
        Ok(())
    }

    pub fn filter_sub_update_stats(&self, url: &str, rule_count: usize) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE filter_subscriptions SET last_synced=?1,rule_count=?2 WHERE url=?3",
            params![unix_now(), rule_count as i64, url],
        )?;
        Ok(())
    }

    pub fn filter_subs_all(&self) -> Result<Vec<FilterSub>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,name,url,last_synced,enabled,rule_count,added_at
             FROM filter_subscriptions ORDER BY added_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(FilterSub {
                id: r.get(0)?,
                name: r.get(1)?,
                url: r.get(2)?,
                last_synced: r.get(3)?,
                enabled: r.get::<_, i32>(4)? != 0,
                rule_count: r.get::<_, i64>(5)? as usize,
                added_at: r.get(6)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("filter_subs_all")
    }

    pub fn zen_save(
        &self,
        active: bool,
        aphorism: &str,
        blocked_cats_json: &str,
        activated_at: Option<i64>,
    ) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE zen_state SET active=?1,aphorism=?2,blocked_cats=?3,activated_at=?4 WHERE id=1",
            params![active as i32, aphorism, blocked_cats_json, activated_at],
        )?;
        Ok(())
    }

    pub fn zen_load(&self) -> Option<ZenRaw> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT active,aphorism,blocked_cats,activated_at FROM zen_state WHERE id=1",
                [],
                |r| {
                    Ok(ZenRaw {
                        active: r.get::<_, i32>(0)? != 0,
                        aphorism: r.get(1)?,
                        blocked_cats_json: r.get(2)?,
                        activated_at: r.get(3)?,
                    })
                },
            )
            .ok()
    }

    pub fn onboarding_complete(&self, step: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO onboarding(step,completed,done_at) VALUES(?1,1,?2)",
            params![step, unix_now()],
        )?;
        Ok(())
    }

    pub fn onboarding_is_done(&self, step: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT completed FROM onboarding WHERE step=?1",
                [step],
                |r| r.get::<_, i32>(0),
            )
            .ok()
            .map(|v| v != 0)
            .unwrap_or(false)
    }

    pub fn onboarding_all_steps(&self) -> Vec<(String, bool)> {
        let Ok(conn_guard) = self.0.lock() else {
            return vec![];
        };
        let Ok(mut stmt) = conn_guard.prepare("SELECT step,completed FROM onboarding") else {
            return vec![];
        };
        stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i32>(1)? != 0))
        })
        .ok()
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    }

    pub fn nostr_relay_add(&self, url: &str) -> Result<String> {
        let id = new_id();
        self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO nostr_relays(id,url,added_at) VALUES(?1,?2,?3)",
            params![id, url, unix_now()],
        )?;
        Ok(id)
    }

    pub fn nostr_relays_enabled(&self) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare("SELECT url FROM nostr_relays WHERE enabled=1")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()
            .context("nostr_relays_enabled")
    }
}
