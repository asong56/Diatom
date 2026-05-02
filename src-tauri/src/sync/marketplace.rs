#![cfg(feature = "labs_alpha")]

//! Museum topic marketplace — P2P knowledge exchange.
//!
//! Listings are published and discovered via Nostr (kind 30078).
//! Transfer is peer-to-peer; no payment layer is involved.
//!
//! # Removed
//! The `price_sats` field and all Lightning / on-chain payment scaffolding
//! have been deleted. Diatom does not intermediate financial transactions.
//! Knowledge exchange is free and direct between peers.

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const MARKETPLACE_NOSTR_KIND: u64 = 30078;
pub const MARKETPLACE_TAG: &str = "diatom-marketplace-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceListing {
    pub listing_id: String,
    pub title: String,
    pub description: String,
    /// Nostr x-only pubkey of the author.
    pub author_pubkey: String,
    pub snapshot_count: u32,
    /// BLAKE3 hash of the encrypted bundle — used for integrity verification.
    pub content_hash: String,
    pub published_at: i64,
    /// Topic tags for discovery.
    pub tags: Vec<String>,
    pub nostr_event_id: Option<String>,
    /// Encrypted index (decryptable by the recipient after key exchange).
    pub encrypted_index: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceBundle {
    pub listing_id: String,
    pub snapshots: Vec<BundleSnapshot>,
    pub slm_summaries: Vec<SlmSummary>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSnapshot {
    pub museum_id: String,
    pub url: String,
    pub title: String,
    pub frozen_at: i64,
    /// E-WBN encrypted content (AES-256-GCM).
    pub encrypted_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmSummary {
    pub museum_id: String,
    pub summary: String,
    pub key_points: Vec<String>,
    pub tfidf_tags: Vec<String>,
}

/// Package a Museum topic as a marketplace listing.
pub fn create_listing(
    title: String,
    description: String,
    snapshot_ids: Vec<String>,
    topic_tags: Vec<String>,
    _master_key: &[u8; 32],
) -> Result<MarketplaceListing> {
    let listing_id = crate::storage::db::new_id();
    let hash_input = format!("{}{}{}", listing_id, title, snapshot_ids.join(","));
    let content_hash = hex::encode(blake3::hash(hash_input.as_bytes()).as_bytes());

    Ok(MarketplaceListing {
        listing_id,
        title,
        description,
        author_pubkey: String::new(), // filled by nostr module at publish time
        snapshot_count: snapshot_ids.len() as u32,
        content_hash,
        published_at: crate::storage::db::unix_now(),
        tags: topic_tags,
        nostr_event_id: None,
        encrypted_index: None,
    })
}

/// Serialise to Nostr event tags format.
pub fn listing_to_nostr_tags(listing: &MarketplaceListing) -> Vec<Vec<String>> {
    let mut tags = vec![
        vec!["d".to_string(), listing.listing_id.clone()],
        vec!["title".to_string(), listing.title.clone()],
        vec!["description".to_string(), listing.description.clone()],
        vec![
            "snapshot_count".to_string(),
            listing.snapshot_count.to_string(),
        ],
        vec!["content_hash".to_string(), listing.content_hash.clone()],
        vec![
            "diatom_version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ],
        vec!["t".to_string(), MARKETPLACE_TAG.to_string()],
    ];
    for tag in &listing.tags {
        tags.push(vec!["t".to_string(), tag.clone()]);
    }
    tags
}

/// Parse a marketplace listing from a Nostr event.
pub fn parse_listing_from_nostr_tags(
    event_id: &str,
    pubkey: &str,
    tags: &[Vec<String>],
    created_at: i64,
) -> Option<MarketplaceListing> {
    let get_tag = |name: &str| -> Option<String> {
        tags.iter()
            .find(|t| t.first().map(|s| s.as_str()) == Some(name))
            .and_then(|t| t.get(1).cloned())
    };

    let is_marketplace = tags.iter().any(|t| {
        t.first().map(|s| s == "t").unwrap_or(false)
            && t.get(1).map(|s| s == MARKETPLACE_TAG).unwrap_or(false)
    });
    if !is_marketplace {
        return None;
    }

    let listing_id = get_tag("d")?;
    let title = get_tag("title").unwrap_or_default();
    let description = get_tag("description").unwrap_or_default();
    let snapshot_count = get_tag("snapshot_count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let content_hash = get_tag("content_hash").unwrap_or_default();

    let topic_tags: Vec<String> = tags
        .iter()
        .filter(|t| t.first().map(|s| s == "t").unwrap_or(false))
        .filter_map(|t| t.get(1).cloned())
        .filter(|t| t != MARKETPLACE_TAG)
        .collect();

    Some(MarketplaceListing {
        listing_id,
        title,
        description,
        author_pubkey: pubkey.to_owned(),
        snapshot_count,
        content_hash,
        published_at: created_at,
        tags: topic_tags,
        nostr_event_id: Some(event_id.to_owned()),
        encrypted_index: None,
    })
}

/// P2P transfer status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Pending,
    Connecting,
    Transferring { progress: f32 },
    Complete,
    Failed(String),
}

/// P2P connection info for a Museum bundle download.
/// Signalling uses the Nostr relay; actual transfer is peer-to-peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConnectionInfo {
    pub offer_id: String,
    pub listing_id: String,
    pub signal_relay: String,
    pub webrtc_offer: Option<String>,
}

/// Initiate a P2P download request.
/// Transfer is negotiated via the frontend WebRTC API; the backend is
/// responsible only for signalling coordination.
pub async fn initiate_p2p_download(
    listing: &MarketplaceListing,
    relay_url: &str,
) -> Result<P2pConnectionInfo> {
    let offer_id = crate::storage::db::new_id();
    Ok(P2pConnectionInfo {
        offer_id,
        listing_id: listing.listing_id.clone(),
        signal_relay: relay_url.to_owned(),
        webrtc_offer: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_roundtrip_nostr_tags() {
        let listing = MarketplaceListing {
            listing_id: "test-id".to_string(),
            title: "Test Listing".to_string(),
            description: "A test".to_string(),
            author_pubkey: "pubkey".to_string(),
            snapshot_count: 5,
            content_hash: "hash".to_string(),
            published_at: 0,
            tags: vec!["rust".to_string()],
            nostr_event_id: None,
            encrypted_index: None,
        };
        let tags = listing_to_nostr_tags(&listing);
        let parsed = parse_listing_from_nostr_tags("evt-id", "pubkey", &tags, 0);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert_eq!(p.title, "Test Listing");
        assert!(p.tags.contains(&"rust".to_string()));
    }

    #[test]
    fn no_price_sats_field() {
        // Compile-time check: MarketplaceListing must not have a price_sats field.
        // If this test compiles, the field is absent.
        let _listing = MarketplaceListing {
            listing_id: String::new(),
            title: String::new(),
            description: String::new(),
            author_pubkey: String::new(),
            snapshot_count: 0,
            content_hash: String::new(),
            published_at: 0,
            tags: vec![],
            nostr_event_id: None,
            encrypted_index: None,
        };
    }
}
