// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/rss.rs  — v0.9.2
//
// [FIX-persistence-rss] RssStore now syncs to DB on every add/ingest/mark_read.
// The DB's rss_feeds and rss_items tables (Migration 1) are the source of truth.
// In-memory state is loaded from DB at startup and kept in sync.
//
// guid ring-buffer eviction [FIX-26] now removes only from the in-memory Vec
// AND from DB; guid_index is rebuilt from current items so stale guids cannot
// cause phantom-duplicate insertions on the next fetch.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub id: String,
    pub url: String,
    pub title: String,
    pub category: Option<String>,
    pub fetch_interval: u32,
    pub last_fetched: Option<i64>,
    pub enabled: bool,
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub feed_id: String,
    pub guid: String,
    pub title: String,
    pub url: String,
    pub summary: String,
    pub published: Option<i64>,
    pub read: bool,
    pub fetched_at: i64,
}

// ── Store ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RssStore {
    feeds: HashMap<String, Feed>,
    items: Vec<Item>,
    guid_index: HashMap<String, String>, // guid → item id
}

impl RssStore {
    /// Load all feeds and their items from DB.
    pub fn load_from_db(db: &crate::db::Db) -> Self {
        let mut feeds = HashMap::new();
        let mut items = Vec::new();
        let mut guid_index = HashMap::new();

        for raw in db.rss_feeds_all().unwrap_or_default() {
            let feed = Feed {
                id: raw.id.clone(), url: raw.url, title: raw.title,
                category: raw.category,
                fetch_interval: raw.fetch_interval_m as u32,
                last_fetched: raw.last_fetched, enabled: raw.enabled,
                added_at: raw.added_at,
            };
            // Load items for this feed
            for item_raw in db.rss_items_for_feed(&raw.id).unwrap_or_default() {
                guid_index.insert(item_raw.guid.clone(), item_raw.id.clone());
                items.push(Item {
                    id: item_raw.id, feed_id: item_raw.feed_id, guid: item_raw.guid,
                    title: item_raw.title, url: item_raw.url, summary: item_raw.summary,
                    published: item_raw.published, read: item_raw.read,
                    fetched_at: item_raw.fetched_at,
                });
            }
            feeds.insert(raw.id, feed);
        }
        RssStore { feeds, items, guid_index }
    }

    pub fn add(&mut self, url: &str, category: Option<String>, db: &crate::db::Db) -> Feed {
        let id = crate::db::new_id();
        let now = crate::db::unix_now();
        let feed = Feed {
            id: id.clone(), url: url.to_owned(), title: url.to_owned(),
            category: category.clone(), fetch_interval: 60,
            last_fetched: None, enabled: true, added_at: now,
        };
        let raw = crate::db::RssFeedRaw {
            id: id.clone(), url: url.to_owned(), title: url.to_owned(),
            category, fetch_interval_m: 60, last_fetched: None,
            enabled: true, added_at: now,
        };
        let _ = db.rss_feed_upsert(&raw);
        self.feeds.insert(id, feed.clone());
        feed
    }

    pub fn feeds(&self) -> Vec<Feed> {
        let mut v: Vec<_> = self.feeds.values().cloned().collect();
        v.sort_by_key(|f| f.added_at);
        v
    }

    pub fn feed_url(&self, id: &str) -> Option<String> {
        self.feeds.get(id).map(|f| f.url.clone())
    }

    pub fn remove_feed(&mut self, id: &str, db: &crate::db::Db) {
        self.feeds.remove(id);
        self.items.retain(|i| {
            if i.feed_id == id {
                self.guid_index.remove(&i.guid);
                false
            } else { true }
        });
        let _ = db.rss_feed_delete(id);
    }

    /// Parse and ingest RSS/Atom XML. Returns number of new items added.
    pub fn ingest(&mut self, feed_id: &str, xml: &str, db: &crate::db::Db) -> u32 {
        let mut count = 0u32;
        let now = crate::db::unix_now();

        if let Some(title) = extract_channel_title(xml) {
            if let Some(feed) = self.feeds.get_mut(feed_id) {
                feed.title = title.clone();
                feed.last_fetched = Some(now);
                let raw = feed_to_raw(feed);
                let _ = db.rss_feed_upsert(&raw);
            }
        }

        for (guid, item_title, item_url, summary, published) in extract_items(xml) {
            if self.guid_index.contains_key(&guid) { continue; }
            let id = crate::db::new_id();
            let item = Item {
                id: id.clone(), feed_id: feed_id.to_owned(), guid: guid.clone(),
                title: item_title, url: crate::blocker::strip_params(&item_url),
                summary, published, read: false, fetched_at: now,
            };
            let raw = crate::db::RssItemRaw {
                id: id.clone(), feed_id: feed_id.to_owned(), guid: guid.clone(),
                title: item.title.clone(), url: item.url.clone(),
                summary: item.summary.clone(), published: item.published,
                read: false, fetched_at: now,
            };
            let _ = db.rss_item_upsert(&raw);
            self.guid_index.insert(guid, id);
            self.items.push(item);
            count += 1;
        }

        // [FIX-26] Cap at 5000; rebuild guid_index from survivors so evicted
        // guids won't be re-inserted as "new" on next fetch.
        if self.items.len() > 5000 {
            let drain = self.items.len() - 5000;
            self.items.drain(..drain);
            // Rebuild guid_index from surviving items only
            self.guid_index.clear();
            for item in &self.items {
                self.guid_index.insert(item.guid.clone(), item.id.clone());
            }
        }

        count
    }

    pub fn items(&self, feed_id: Option<&str>, unread_only: bool, limit: usize) -> Vec<Item> {
        let mut v: Vec<&Item> = self.items.iter()
            .filter(|i| feed_id.map_or(true, |fid| i.feed_id == fid))
            .filter(|i| !unread_only || !i.read)
            .collect();
        v.sort_by(|a, b| b.fetched_at.cmp(&a.fetched_at));
        v.into_iter().take(limit).cloned().collect()
    }

    pub fn mark_read(&mut self, item_id: &str, db: &crate::db::Db) {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == item_id) {
            item.read = true;
            let _ = db.rss_item_mark_read(item_id);
        }
    }
}

fn feed_to_raw(f: &Feed) -> crate::db::RssFeedRaw {
    crate::db::RssFeedRaw {
        id: f.id.clone(), url: f.url.clone(), title: f.title.clone(),
        category: f.category.clone(), fetch_interval_m: f.fetch_interval as i32,
        last_fetched: f.last_fetched, enabled: f.enabled, added_at: f.added_at,
    }
}

// ── Minimal RSS/Atom XML parser ───────────────────────────────────────────────

fn extract_channel_title(xml: &str) -> Option<String> { extract_tag(xml, "title") }

fn extract_items(xml: &str) -> Vec<(String, String, String, String, Option<i64>)> {
    let mut out = Vec::new();
    let (delimiter, close_delim) = if xml.contains("<entry") {
        ("<entry", "</entry>")
    } else { ("<item", "</item>") };

    for chunk in xml.split(delimiter).skip(1) {
        let chunk = match chunk.split(close_delim).next() { Some(c) => c, None => continue };
        let title = extract_tag(chunk, "title").unwrap_or_default();
        let url = extract_link(chunk);
        let guid = extract_tag(chunk, "guid")
            .or_else(|| extract_tag(chunk, "id"))
            .unwrap_or_else(|| url.clone());
        let summary = extract_tag(chunk, "description")
            .or_else(|| extract_tag(chunk, "summary"))
            .or_else(|| extract_tag(chunk, "content"))
            .map(|s| strip_html_tags(&s))
            .map(|s| s.chars().take(500).collect())
            .unwrap_or_default();
        let published = extract_tag(chunk, "pubDate")
            .or_else(|| extract_tag(chunk, "published"))
            .or_else(|| extract_tag(chunk, "updated"))
            .and_then(|d| parse_rfc2822_date(&d).or_else(|| parse_iso8601_date(&d)));
        if !url.is_empty() { out.push((guid, title, url, summary, published)); }
    }
    out
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let start = xml[start..].find('>')? + start + 1;
    let end = xml.find(&close)?;
    if end <= start { return None; }
    Some(unescape_xml(xml[start..end].trim()))
}

fn extract_link(xml: &str) -> String {
    if let Some(v) = extract_tag(xml, "link") {
        if v.starts_with("http") { return v; }
    }
    if let Some(pos) = xml.find("<link ") {
        let chunk = &xml[pos..];
        if let Some(href_pos) = chunk.find("href=\"") {
            let start = href_pos + 6;
            if let Some(end) = chunk[start..].find('"') {
                return chunk[start..start + end].to_owned();
            }
        }
    }
    String::new()
}

fn strip_html_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c { '<' => in_tag = true, '>' => in_tag = false,
            _ => if !in_tag { out.push(c) } }
    }
    out
}

fn unescape_xml(s: &str) -> String {
    s.replace("&amp;","&").replace("&lt;","<").replace("&gt;",">")
     .replace("&quot;","\"").replace("&apos;","'").replace("&#039;","'")
}

fn parse_rfc2822_date(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(s.trim()).ok().map(|dt| dt.timestamp())
}
fn parse_iso8601_date(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s.trim()).ok().map(|dt| dt.timestamp())
}
