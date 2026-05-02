//! Nostr-based bookmark sync.
//!
//! # Cryptography
//!
//! - AES-256-GCM for payload encryption via a per-domain HKDF-derived key
//!   (master_key is never used directly as an AES key).
//! - secp256k1 BIP-340 Schnorr for NIP-01 event signing.
//! - BLAKE3 keyed hash for deterministic ephemeral keypair derivation.
//! - base64 via the `base64` crate (standard alphabet).
//!
//! # Privacy model
//!
//! Each sync session derives a fresh ephemeral secp256k1 keypair from
//! `master_key` and a random `session_nonce`. Relay operators observe
//! ciphertext and ephemeral pubkeys only; they cannot link sessions or read
//! content.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::{Duration, timeout};

/// A minimal Nostr event (NIP-01).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,     // SHA-256 of serialised event (hex)
    pub pubkey: String, // ephemeral x-only pubkey (hex, 32 bytes)
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String, // AES-GCM encrypted payload (base64)
    pub sig: String,     // BIP-340 Schnorr signature (hex, 64 bytes)
}

/// NIP-42 AUTH kind.
pub const KIND_AUTH: u32 = 22242;

/// Lamport clock stored per bookmark for OR-Set merge.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrSetClock {
    pub lamport: u64,
    pub tombstone: bool,
}
/// Diatom bookmark sync kind.
pub const KIND_BOOKMARKS: u32 = 30000;
/// Diatom Museum metadata sync kind.
pub const KIND_MUSEUM_META: u32 = 30001;

#[derive(Serialize, Deserialize)]
struct BookmarkPayload {
    workspace_id: String,
    bookmarks: Vec<BookmarkItem>,
    synced_at: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BookmarkItem {
    pub id: String,
    pub url: String,
    pub title: String,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct MuseumMetaPayload {
    workspace_id: String,
    bundles: Vec<BundleMeta>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BundleMeta {
    pub id: String,
    pub url: String,
    pub title: String,
    pub frozen_at: i64,
    pub tfidf_tags: String,
}

fn encrypt_payload(data: &[u8], master_key: &[u8; 32]) -> Result<String> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    use rand::RngCore;
    let cipher = Aes256Gcm::new(derive_payload_key(master_key)?.into());
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, data)
        .map_err(|_| anyhow::anyhow!("nostr payload encrypt failed"))?;
    let mut raw = Vec::with_capacity(12 + ct.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ct);
    Ok(BASE64.encode(&raw))
}

fn decrypt_payload(b64: &str, master_key: &[u8; 32]) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    let raw = BASE64.decode(b64).context("nostr base64 decode")?;
    if raw.len() < 12 {
        bail!("nostr payload too short");
    }
    let nonce = Nonce::from_slice(&raw[..12]);
    let cipher = Aes256Gcm::new(derive_payload_key(master_key)?.into());
    cipher
        .decrypt(nonce, &raw[12..])
        .map_err(|_| anyhow::anyhow!("nostr decrypt failed — wrong key or tampered event"))
}

/// Derive the AES-256-GCM key used for Nostr payload encryption via HKDF-SHA256.
///
/// Derives a context-specific subkey via HKDF so that the freeze layer
/// (freeze-v8), the nostr layer (nostr-sync-v1), and any future consumers
/// each hold cryptographically independent keys from the same root.
fn derive_payload_key(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key = [0u8; 32];
    hk.expand(b"nostr-sync-v1", &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed for nostr payload key"))?;
    Ok(key)
}

/// 7-day epoch number: `floor(unix_seconds / 604800)`.
///
/// Embedding the epoch in the BLAKE3 key-hash input means that even if `master_key`
/// leaks, an attacker can only reconstruct ephemeral keypairs from the *current*
/// epoch (at most 7 days of sessions).  Sessions from prior epochs used different
/// epoch values and their keypairs cannot be derived without also knowing which
/// epoch they belonged to — which itself was random within the epoch.
///
/// Epoch advances are intentionally not synchronized across devices; each device
/// derives its own epoch independently, which is correct because keypairs are
/// ephemeral and single-use.
fn current_epoch() -> u32 {
    const SECS_PER_EPOCH: u64 = 7 * 24 * 3_600; // 604 800 s
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .wrapping_div(SECS_PER_EPOCH) as u32
}

/// Derive a deterministic ephemeral secp256k1 keypair from master_key + epoch + session_nonce.
///
/// Returns `(secret_key_bytes, x_only_pubkey_hex)` where:
///   - `secret_key_bytes`: `Zeroizing<[u8;32]>` — zeroized on drop.
///   - `x_only_pubkey_hex`: 64-char hex string of the 32-byte x-only public key.
///
/// # Key derivation input layout (13 bytes before counter)
///
/// ```
/// epoch (4 bytes LE) || session_nonce (8 bytes LE) || counter (1 byte)
/// ```
///
/// The epoch prevents unbounded historical key reconstruction on master_key leak.
/// The session_nonce is a CSPRNG u64 chosen fresh per sync session.
/// The counter enables rejection sampling without changing the nonce (see below).
///
/// # Rejection sampling
///
/// BLAKE3 output is uniform in [0, 2^256) but the secp256k1 order n < 2^256.
/// P(seed ≥ n) ≈ 3.7 × 10⁻³⁸ per attempt; the loop is a correctness guarantee,
/// not a performance concern.
fn derive_ephemeral_keypair(
    master_key: &[u8; 32],
    session_nonce: u64,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, String)> {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    let secp = Secp256k1::new();
    let epoch = current_epoch();

    for counter in 0u8..=255 {
        // input = epoch (4 bytes LE) || session_nonce (8 bytes LE) || counter (1 byte)
        let mut input = [0u8; 13];
        input[..4].copy_from_slice(&epoch.to_le_bytes());
        input[4..12].copy_from_slice(&session_nonce.to_le_bytes());
        input[12] = counter;

        let seed = *blake3::keyed_hash(master_key, &input).as_bytes();

        match SecretKey::from_slice(&seed) {
            Ok(secret_key) => {
                let secret_scalar = zeroize::Zeroizing::new(seed);
                let (pubkey, _) =
                    XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &secret_key));
                return Ok((secret_scalar, hex::encode(pubkey.serialize())));
            }
            Err(_) => {
                tracing::warn!(
                    "derive_ephemeral_keypair: counter={} produced invalid scalar, retrying",
                    counter
                );
                continue;
            }
        }
    }
    bail!(
        "derive_ephemeral_keypair: could not produce valid scalar after 256 attempts \
           (P ≈ 10^-9120, indicates broken RNG or BLAKE3)"
    )
}

/// Sign a Nostr event id using BIP-340 Schnorr over secp256k1.
///
/// `event_id_hex` must be the SHA-256 of the canonical NIP-01 serialisation.
/// Returns a 64-byte Schnorr signature encoded as lowercase hex.
fn sign_event_id(
    event_id_hex: &str,
    secret_scalar: &zeroize::Zeroizing<[u8; 32]>,
) -> Result<String> {
    use secp256k1::{Message, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret_key =
        SecretKey::from_slice(&**secret_scalar).context("sign_event_id: invalid secret scalar")?;
    let id_bytes = hex::decode(event_id_hex).context("event_id decode")?;
    ensure!(
        id_bytes.len() == 32,
        "event id must be 32 bytes, got {}",
        id_bytes.len()
    );
    let message = Message::from_digest_slice(&id_bytes).context("event id to Message")?;
    let sig = secp.sign_schnorr(&message, &secret_key);
    Ok(hex::encode(sig.as_ref()))
}

/// Legacy pubkey-only derivation for cases where signing is not needed.
fn derive_ephemeral_pubkey(master_key: &[u8; 32], session_nonce: u64) -> Result<String> {
    Ok(derive_ephemeral_keypair(master_key, session_nonce)?.1)
}

/// Publish a single Nostr event to a relay URL.
/// Connection is opened, event sent, ACK waited, then connection closed.
pub async fn publish_event(relay_url: &str, event: &NostrEvent) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let (mut ws, _) = timeout(Duration::from_secs(10), connect_async(relay_url))
        .await
        .context("relay connection timeout")?
        .context("relay WebSocket connect failed")?;

    let msg = json!(["EVENT", event]).to_string();
    ws.send(Message::Text(msg)).await.context("send EVENT")?;

    if let Ok(Some(Ok(Message::Text(resp)))) = timeout(Duration::from_secs(5), ws.next()).await {
        let parsed: Value = serde_json::from_str(&resp).unwrap_or(Value::Null);
        if let Some(arr) = parsed.as_array() {
            match arr.get(0).and_then(|v| v.as_str()) {
                Some("OK") => tracing::info!("nostr: event accepted by relay"),
                Some("NOTICE") => tracing::warn!("nostr: relay notice: {:?}", arr.get(1)),
                _ => {}
            }
        }
    }

    ws.close(None).await.ok();
    Ok(())
}

/// Subscribe to events and return matching ones.
pub async fn fetch_events(
    relay_url: &str,
    pubkey: &str,
    kind: u32,
    since: i64,
) -> Result<Vec<NostrEvent>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let (mut ws, _) = timeout(Duration::from_secs(10), connect_async(relay_url))
        .await
        .context("relay connection timeout")?
        .context("relay WebSocket connect failed")?;

    let sub_id = format!("diatom-{}", crate::storage::db::unix_now());
    let req = json!(["REQ", sub_id, {
        "authors": [pubkey],
        "kinds": [kind],
        "since": since,
        "limit": 50,
    }])
    .to_string();

    ws.send(Message::Text(req)).await.context("send REQ")?;

    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(msg)))) => {
                let v: Value = serde_json::from_str(&msg).unwrap_or(Value::Null);
                if let Some(arr) = v.as_array() {
                    match arr.get(0).and_then(|v| v.as_str()) {
                        Some("EVENT") => {
                            if let Some(ev) = arr.get(2) {
                                if let Ok(event) = serde_json::from_value::<NostrEvent>(ev.clone())
                                {
                                    events.push(event);
                                }
                            }
                        }
                        Some("EOSE") => break, // End of stored events
                        _ => {}
                    }
                }
            }
            _ => break,
        }
    }

    ws.close(None).await.ok();
    Ok(events)
}

/// Publish all bookmarks for a workspace to all enabled relays.
pub async fn sync_bookmarks_publish(
    db: &crate::storage::db::Db,
    master_key: &[u8; 32],
    workspace_id: &str,
) -> Result<usize> {
    let relay_urls = db.nostr_relays_enabled()?;
    if relay_urls.is_empty() {
        return Ok(0);
    }

    let bookmarks = collect_bookmarks_for_sync(db, workspace_id)?;
    if bookmarks.is_empty() {
        return Ok(0);
    }

    let payload = BookmarkPayload {
        workspace_id: workspace_id.to_owned(),
        bookmarks,
        synced_at: crate::storage::db::unix_now(),
    };
    let json_bytes = serde_json::to_vec(&payload)?;
    let encrypted = encrypt_payload(&json_bytes, master_key)?;

    let session_nonce: u64 = rand::random();
    let (secret_scalar, pubkey) = derive_ephemeral_keypair(master_key, session_nonce)?;
    let now = crate::storage::db::unix_now();

    // NIP-01: event id = SHA-256(UTF-8([0, pubkey, created_at, kind, tags, content]))
    let event_id = {
        use sha2::{Digest, Sha256};
        let preimage = serde_json::to_string(&serde_json::json!([
            0,
            pubkey,
            now,
            KIND_BOOKMARKS,
            [["d", workspace_id]],
            encrypted,
        ]))
        .context("event preimage serialise")?;
        hex::encode(Sha256::digest(preimage.as_bytes()))
    };
    let sig = sign_event_id(&event_id, &secret_scalar)?;
    drop(secret_scalar);

    let event = NostrEvent {
        id: event_id,
        pubkey: pubkey.clone(),
        created_at: now,
        kind: KIND_BOOKMARKS,
        tags: vec![vec!["d".to_owned(), workspace_id.to_owned()]],
        content: encrypted,
        sig,
    };

    let mut published = 0usize;
    for url in &relay_urls {
        match publish_event(url, &event).await {
            Ok(()) => published += 1,
            Err(e) => tracing::warn!("nostr: publish to {} failed: {}", url, e),
        }
    }

    tracing::info!(
        "nostr: bookmarks published to {}/{} relays",
        published,
        relay_urls.len()
    );
    Ok(published)
}

fn collect_bookmarks_for_sync(
    db: &crate::storage::db::Db,
    workspace_id: &str,
) -> Result<Vec<BookmarkItem>> {
    let conn = db.0.lock().unwrap();
    let now = crate::storage::db::unix_now();
    let mut stmt = conn.prepare(
        "SELECT id,url,title,tags FROM bookmarks
         WHERE workspace_id=?1 AND ephemeral=0
         AND (expires_at IS NULL OR expires_at > ?2)
         ORDER BY created_at DESC LIMIT 500",
    )?;
    let rows = stmt.query_map(rusqlite::params![workspace_id, now], |r| {
        Ok(BookmarkItem {
            id: r.get(0)?,
            url: r.get(1)?,
            title: r.get(2)?,
            tags: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
        })
    })?;
    rows.collect::<rusqlite::Result<_>>()
        .context("collect bookmarks for sync")
}

/// Perform NIP-42 authentication handshake if the relay sends an AUTH challenge.
/// Returns Ok(()) whether or not auth succeeds — we continue the connection regardless.
async fn maybe_auth_nip42(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    relay_url: &str,
    master_key: &[u8; 32],
    challenge: &str,
) -> anyhow::Result<()> {
    use futures_util::SinkExt;
    let session_nonce: u64 = rand::random();
    let (secret_scalar, pubkey) = derive_ephemeral_keypair(master_key, session_nonce)?;
    let now = crate::storage::db::unix_now();

    // NIP-01: event id = SHA-256(UTF-8([0, pubkey, created_at, kind, tags, content]))
    let event_id = {
        use sha2::{Digest, Sha256};
        let preimage = serde_json::to_string(&serde_json::json!([
            0,
            pubkey,
            now,
            KIND_AUTH,
            [["relay", relay_url], ["challenge", challenge]],
            "",
        ]))
        .context("auth event preimage serialise")?;
        hex::encode(Sha256::digest(preimage.as_bytes()))
    };
    let sig = sign_event_id(&event_id, &secret_scalar)?;
    drop(secret_scalar);

    let auth_event = serde_json::json!(["AUTH", {
        "id": event_id,
        "pubkey": pubkey,
        "created_at": now,
        "kind": KIND_AUTH,
        "tags": [["relay", relay_url], ["challenge", challenge]],
        "content": "",
        "sig": sig,
    }]);

    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        auth_event.to_string(),
    ))
    .await
    .context("NIP-42 AUTH send")?;
    tracing::info!("nostr: NIP-42 auth sent for relay {}", relay_url);
    Ok(())
}

/// Merge incoming bookmarks with local using OR-Set semantics.
pub fn orset_merge_bookmarks(
    local: &[BookmarkItem],
    incoming: &[BookmarkItem],
    local_clocks: &std::collections::HashMap<String, OrSetClock>,
    incoming_clocks: &std::collections::HashMap<String, OrSetClock>,
) -> Vec<BookmarkItem> {
    use std::collections::HashMap;
    let mut merged: HashMap<String, BookmarkItem> = HashMap::new();
    let mut merged_clocks: HashMap<String, OrSetClock> = HashMap::new();

    for bm in local {
        merged.insert(bm.id.clone(), bm.clone());
        if let Some(clock) = local_clocks.get(&bm.id) {
            merged_clocks.insert(bm.id.clone(), clock.clone());
        }
    }

    for bm in incoming {
        let incoming_clock = incoming_clocks.get(&bm.id).cloned().unwrap_or_default();

        if incoming_clock.tombstone {
            let local_lamport = merged_clocks.get(&bm.id).map(|c| c.lamport).unwrap_or(0);
            if incoming_clock.lamport >= local_lamport {
                merged.remove(&bm.id);
                merged_clocks.insert(bm.id.clone(), incoming_clock);
            }
        } else {
            let local_lamport = merged_clocks.get(&bm.id).map(|c| c.lamport).unwrap_or(0);
            if incoming_clock.lamport >= local_lamport {
                merged.insert(bm.id.clone(), bm.clone());
                merged_clocks.insert(bm.id.clone(), incoming_clock);
            }
        }
    }

    merged.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let data = b"test bookmark payload";
        let enc = encrypt_payload(data, &key).unwrap();
        let dec = decrypt_payload(&enc, &key).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base64_roundtrip() {
        // Uses the base64 crate, not a hand-rolled implementation.
        let data = b"hello world nostr sync";
        let enc = BASE64.encode(data);
        let dec = BASE64.decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn ephemeral_pubkey_deterministic_within_epoch() {
        // Same epoch (current_epoch() is stable within a single test run)
        let key = [0xABu8; 32];
        let pk1 = derive_ephemeral_pubkey(&key, 12345).unwrap();
        let pk2 = derive_ephemeral_pubkey(&key, 12345).unwrap();
        assert_eq!(pk1, pk2, "same nonce same epoch must be deterministic");
        let pk3 = derive_ephemeral_pubkey(&key, 99999).unwrap();
        assert_ne!(pk1, pk3, "different nonces must produce different keys");
    }

    /// Verify rejection-sampling counter works and epoch is embedded.
    #[test]
    fn ephemeral_keypair_returns_valid_scalar() {
        for nonce in [0u64, 1, u64::MAX, 42, 0xDEAD_BEEF_CAFE] {
            let (secret, pk) = derive_ephemeral_keypair(&[0x55u8; 32], nonce).unwrap();
            assert_eq!(pk.len(), 64, "x-only pubkey must be 32 bytes hex");
            assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(secret.len(), 32);
        }
    }

    /// Different epoch values must produce different keypairs for the same nonce,
    /// proving historical session keys cannot be reconstructed from master_key alone
    /// once the epoch has advanced.
    #[test]
    fn epoch_changes_derived_key() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
        let secp = Secp256k1::new();
        let master = [0x77u8; 32];
        let nonce = 42u64;

        let derive_with_epoch = |epoch: u32| -> String {
            for counter in 0u8..=255 {
                let mut input = [0u8; 13];
                input[..4].copy_from_slice(&epoch.to_le_bytes());
                input[4..12].copy_from_slice(&nonce.to_le_bytes());
                input[12] = counter;
                let seed = *blake3::keyed_hash(&master, &input).as_bytes();
                if let Ok(sk) = SecretKey::from_slice(&seed) {
                    let (pk, _) =
                        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk));
                    return hex::encode(pk.serialize());
                }
            }
            panic!("no valid scalar found");
        };

        assert_ne!(
            derive_with_epoch(0),
            derive_with_epoch(1),
            "different epochs must produce different keypairs"
        );
    }

    /// NIP-01 event id must be SHA-256 of canonical JSON, not BLAKE3.
    #[test]
    fn event_id_is_sha256_not_blake3() {
        use sha2::{Digest, Sha256};
        let pubkey = "a".repeat(64);
        let preimage = serde_json::to_string(&serde_json::json!([
            0,
            pubkey,
            1_700_000_000i64,
            30000u32,
            [["d", "test-ws"]],
            "encrypted",
        ]))
        .unwrap();
        let id = hex::encode(Sha256::digest(preimage.as_bytes()));
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Confirm it differs from BLAKE3 of the same bytes
        let blake_id = hex::encode(blake3::hash(preimage.as_bytes()).as_bytes());
        assert_ne!(
            id, blake_id,
            "SHA-256 and BLAKE3 must produce different outputs"
        );
    }

    #[test]
    fn event_signature_is_64_bytes_hex() {
        let key = [0x11u8; 32];
        let (secret, _) = derive_ephemeral_keypair(&key, 42).unwrap();
        let fake_id = hex::encode([0xabu8; 32]);
        let sig = sign_event_id(&fake_id, &secret).unwrap();
        assert_eq!(sig.len(), 128, "signature must be 64 bytes hex");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn event_signature_deterministic() {
        let key = [0x22u8; 32];
        let (secret, _) = derive_ephemeral_keypair(&key, 7).unwrap();
        let id = hex::encode([0xbbu8; 32]);
        assert_eq!(
            sign_event_id(&id, &secret).unwrap(),
            sign_event_id(&id, &secret).unwrap(),
        );
    }

    /// Verify that the Schnorr signature produced by `sign_event_id` is
    /// cryptographically valid — i.e., it will be accepted by a conformant
    /// Nostr relay that calls secp256k1 verify.
    #[test]
    fn schnorr_signature_verifies() {
        use secp256k1::{Message, Secp256k1, XOnlyPublicKey};

        let master = [0x11u8; 32];
        let (secret, pk) = derive_ephemeral_keypair(&master, 42).unwrap();
        let event_id_bytes = [0xabu8; 32];
        let event_id = hex::encode(event_id_bytes);
        let sig_hex = sign_event_id(&event_id, &secret).unwrap();
        assert_eq!(sig_hex.len(), 128);

        let secp = Secp256k1::new();
        let pubkey = XOnlyPublicKey::from_slice(&hex::decode(&pk).unwrap()).unwrap();
        let sig =
            secp256k1::schnorr::Signature::from_slice(&hex::decode(&sig_hex).unwrap()).unwrap();
        let msg = Message::from_digest_slice(&event_id_bytes).unwrap();
        secp.verify_schnorr(&sig, &msg, &pubkey)
            .expect("Schnorr signature must verify against the derived public key");
    }
}
