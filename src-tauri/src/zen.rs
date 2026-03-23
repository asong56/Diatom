// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/zen.rs  — v0.9.2
//
// [FIX-zen] Zen state now persists across restarts via the zen_state table.
//   activate() and deactivate() write through to DB immediately.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ZenState { Off, Active }

impl Default for ZenState {
    fn default() -> Self { ZenState::Off }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenConfig {
    pub state: ZenState,
    pub aphorism: String,
    pub blocked_categories: Vec<String>,
    pub activated_at: Option<i64>,
}

impl Default for ZenConfig {
    fn default() -> Self {
        ZenConfig {
            state: ZenState::Off,
            aphorism: "Now will always have been.".to_owned(),
            blocked_categories: vec!["social".into(), "entertainment".into()],
            activated_at: None,
        }
    }
}

impl ZenConfig {
    /// Load from DB, falling back to defaults if no row exists yet.
    pub fn load_from_db(db: &crate::db::Db) -> Self {
        match db.zen_load() {
            Some(raw) => {
                let cats: Vec<String> = serde_json::from_str(&raw.blocked_cats_json)
                    .unwrap_or_else(|_| vec!["social".into(), "entertainment".into()]);
                ZenConfig {
                    state: if raw.active { ZenState::Active } else { ZenState::Off },
                    aphorism: raw.aphorism,
                    blocked_categories: cats,
                    activated_at: raw.activated_at,
                }
            }
            None => ZenConfig::default(),
        }
    }

    fn persist(&self, db: &crate::db::Db) {
        let cats_json = serde_json::to_string(&self.blocked_categories)
            .unwrap_or_else(|_| "[\"social\",\"entertainment\"]".to_owned());
        if let Err(e) = db.zen_save(
            self.is_active(), &self.aphorism, &cats_json, self.activated_at,
        ) {
            tracing::warn!("zen_save failed: {}", e);
        }
    }

    pub fn activate(&mut self, db: &crate::db::Db) {
        self.state = ZenState::Active;
        self.activated_at = Some(crate::db::unix_now());
        self.persist(db);
    }

    pub fn deactivate(&mut self, db: &crate::db::Db) {
        self.state = ZenState::Off;
        self.activated_at = None;
        self.persist(db);
    }

    pub fn is_active(&self) -> bool { self.state == ZenState::Active }

    pub fn blocks_domain(&self, domain: &str) -> Option<&'static str> {
        if !self.is_active() { return None; }
        domain_category(domain).filter(|cat| self.blocked_categories.iter().any(|c| c == cat))
    }
}

pub fn domain_category(domain: &str) -> Option<&'static str> {
    const SOCIAL: &[&str] = &[
        "twitter.com","x.com","instagram.com","facebook.com","tiktok.com",
        "weibo.com","douyin.com","threads.net","mastodon.social","bluesky.app",
        "reddit.com","discord.com","snapchat.com","linkedin.com","pinterest.com",
    ];
    const ENTERTAINMENT: &[&str] = &[
        "youtube.com","bilibili.com","netflix.com","twitch.tv","hulu.com",
        "disneyplus.com","primevideo.com","9gag.com","ifunny.co","tumblr.com",
        "buzzfeed.com","dailymotion.com","vimeo.com","rumble.com","odysee.com",
    ];

    let d = domain.to_lowercase();
    let d = d.trim_start_matches("www.");

    if SOCIAL.iter().any(|s| d == *s || d.ends_with(&format!(".{s}"))) {
        return Some("social");
    }
    if ENTERTAINMENT.iter().any(|s| d == *s || d.ends_with(&format!(".{s}"))) {
        return Some("entertainment");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_off() {
        let cfg = ZenConfig::default();
        assert!(!cfg.is_active());
        assert!(cfg.blocks_domain("twitter.com").is_none());
    }
}

// ── DB persistence helpers [FIX-zen] ─────────────────────────────────────────

impl ZenConfig {
    /// Construct from a DB ZenRaw row.
    pub fn from_raw(raw: &crate::db::ZenRaw) -> Self {
        let blocked_categories: Vec<String> =
            serde_json::from_str(&raw.blocked_cats_json).unwrap_or_else(|_| {
                vec!["social".into(), "entertainment".into()]
            });
        ZenConfig {
            state: if raw.active { ZenState::Active } else { ZenState::Off },
            aphorism: raw.aphorism.clone(),
            blocked_categories,
            activated_at: raw.activated_at,
        }
    }

    /// Persist current state to DB.
    pub fn save_to_db(&self, db: &crate::db::Db) {
        let cats = serde_json::to_string(&self.blocked_categories).unwrap_or_default();
        let _ = db.zen_save(self.is_active(), &self.aphorism, &cats, self.activated_at);
    }
}
