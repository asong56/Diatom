//! Row and raw data structs shared across all db sub-modules.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: String,
    pub url: String,
    pub title: String,
    pub visited_at: i64,
    pub dwell_ms: i64,
    pub visit_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarReportRow {
    pub tracking_block_count: i64,
    pub fingerprint_noise_count: i64,
    pub ram_saved_mb: f64,
    pub time_saved_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadingEvent {
    pub id: String,
    pub url: String,
    pub domain: String,
    pub dwell_ms: i64,
    pub scroll_px_s: f64,
    pub reading_mode: bool,
    pub tab_switches: i64,
    pub recorded_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRow {
    pub id: String,
    pub url: String,
    pub title: String,
    pub content_hash: String,
    pub bundle_path: String,
    pub tfidf_tags: String,
    pub bundle_size: i64,
    pub frozen_at: i64,
    pub workspace_id: String,
    /// Index tier: "hot" (full FTS5) or "cold" (keyword fingerprint only).
    #[serde(default = "default_hot")]
    pub index_tier: String,
    /// Unix timestamp of last user access; None for pages never re-visited.
    pub last_accessed_at: Option<i64>,
}

fn default_hot() -> String {
    "hot".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomBlock {
    pub id: String,
    pub domain: String,
    pub selector: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgePack {
    pub id: String,
    pub name: String,
    pub format: String,
    pub pack_path: String,
    pub size_bytes: i64,
    pub added_at: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct TotpRaw {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub secret_enc: String,
    pub domains_json: String,
    pub added_at: i64,
    pub algorithm: Option<String>,
    pub digits: Option<u8>,
    pub period: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TrustRaw {
    pub domain: String,
    pub level: String,
    pub source: String,
    pub set_at: i64,
}

#[derive(Debug, Clone)]
pub struct RssFeedRaw {
    pub id: String,
    pub url: String,
    pub title: String,
    pub category: Option<String>,
    pub fetch_interval_m: i32,
    pub last_fetched: Option<i64>,
    pub enabled: bool,
    pub added_at: i64,
}

#[derive(Debug, Clone)]
pub struct RssItemRaw {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterSub {
    pub id: String,
    pub name: String,
    pub url: String,
    pub last_synced: Option<i64>,
    pub enabled: bool,
    pub rule_count: usize,
    pub added_at: i64,
}

pub struct ZenRaw {
    pub active: bool,
    pub aphorism: String,
    pub blocked_cats_json: String,
    pub activated_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct VaultLoginRaw {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password_enc: String,
    pub urls_json: String,
    pub notes_enc: String,
    pub tags_json: String,
    /// Inline TOTP — otpauth:// URI, encrypted.  None if no 2FA on this record.
    pub totp_uri: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,

    /// "unknown" | "clean" | "pwned"
    pub breach_status: String,
    pub breach_checked_at: Option<i64>,
    pub breach_pwned_count: i64,

    /// Encrypted credential ID bytes (base64url of raw CBOR).
    pub passkey_cred_id_enc: Option<String>,
    /// Stable opaque user handle tied to this credential.
    pub passkey_user_handle: Option<String>,
    /// Relying-party ID (e.g. "github.com").
    pub passkey_rp_id: Option<String>,
    pub passkey_added_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct VaultCardRaw {
    pub id: String,
    pub title: String,
    pub cardholder_enc: String,
    pub number_enc: String,
    pub expiry: String,
    pub cvv_enc: String,
    pub notes_enc: String,
    pub tags_json: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct VaultNoteRaw {
    pub id: String,
    pub title: String,
    pub content_enc: String,
    pub tags_json: String,
    pub created_at: i64,
    pub updated_at: i64,
}
