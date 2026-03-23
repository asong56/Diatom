// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/trust.rs  — v0.9.2
// [FIX-persistence-trust] TrustStore is now DB-backed.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel { Untrusted, Standard, Trusted, Allowlisted }

impl TrustLevel {
    pub fn from_str(s: &str) -> Self {
        match s {
            "untrusted"   => TrustLevel::Untrusted,
            "trusted"     => TrustLevel::Trusted,
            "allowlisted" => TrustLevel::Allowlisted,
            _             => TrustLevel::Standard,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Untrusted   => "untrusted",
            TrustLevel::Standard    => "standard",
            TrustLevel::Trusted     => "trusted",
            TrustLevel::Allowlisted => "allowlisted",
        }
    }
    pub fn blocker_active(&self) -> bool {
        matches!(self, TrustLevel::Untrusted | TrustLevel::Standard)
    }
    pub fn cookies_allowed(&self) -> bool {
        !matches!(self, TrustLevel::Untrusted)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustProfile {
    pub domain: String,
    pub level: TrustLevel,
    pub source: String,
    pub set_at: i64,
}

#[derive(Default)]
pub struct TrustStore {
    profiles: HashMap<String, TrustProfile>,
}

impl TrustStore {
    /// Load all trust profiles from DB.
    pub fn load_from_db(db: &crate::db::Db) -> Self {
        let mut profiles = HashMap::new();
        for raw in db.trust_list_raw().unwrap_or_default() {
            profiles.insert(raw.domain.clone(), TrustProfile {
                domain: raw.domain, level: TrustLevel::from_str(&raw.level),
                source: raw.source, set_at: raw.set_at,
            });
        }
        TrustStore { profiles }
    }

    pub fn get(&self, domain: &str) -> TrustProfile {
        self.profiles.get(domain).cloned().unwrap_or_else(|| TrustProfile {
            domain: domain.to_owned(), level: TrustLevel::Standard,
            source: "default".to_owned(), set_at: 0,
        })
    }

    pub fn set(&mut self, domain: &str, level: &str, source: &str, db: &crate::db::Db) {
        let now = crate::db::unix_now();
        let p = TrustProfile {
            domain: domain.to_owned(), level: TrustLevel::from_str(level),
            source: source.to_owned(), set_at: now,
        };
        self.profiles.insert(domain.to_owned(), p);
        let _ = db.trust_set(domain, level, source, now);
    }

    pub fn all(&self) -> Vec<TrustProfile> {
        let mut v: Vec<_> = self.profiles.values().cloned().collect();
        v.sort_by_key(|p| p.set_at);
        v
    }

    pub fn remove(&mut self, domain: &str, db: &crate::db::Db) {
        self.profiles.remove(domain);
        let _ = db.trust_delete(domain);
    }

    pub fn is_level(&self, domain: &str, level: TrustLevel) -> bool {
        self.get(domain).level == level
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_standard() {
        let store = TrustStore::default();
        assert_eq!(store.get("example.com").level, TrustLevel::Standard);
    }
}
