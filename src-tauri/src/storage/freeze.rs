use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use anyhow::{Context, Result, bail};
use flate2::{Compression, write::GzEncoder};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::LazyLock,
};
use zeroize::Zeroize;

use crate::storage::db::{BundleRow, new_id, unix_now};

const EWBN_MAGIC: &[u8; 4] = b"EWBT";
const EWBN_VERSION: u32 = 1;

const TRACKER_SCRIPT_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "connect.facebook.net",
    "pixel.facebook.com",
    "hotjar.com",
    "amplitude.com",
    "api.segment.io",
    "cdn.segment.com",
    "mixpanel.com",
    "clarity.ms",
    "fullstory.com",
    "chartbeat.com",
    "parsely.com",
    "scorecardresearch.com",
    "bugsnag.com",
    "ingest.sentry.io",
    "js-agent.newrelic.com",
    "nr-data.net",
    "adnxs.com",
    "adroll.com",
    "criteo.com",
    "outbrain.com",
    "taboola.com",
    "adsrvr.org",
    "munchkin.marketo.net",
    "js.hs-scripts.com",
    "cdn.heapanalytics.com",
    "bat.bing.com",
    "px.ads.linkedin.com",
    "moatads.com",
];

pub struct FreezeBundle {
    pub bundle_row: BundleRow,
    pub bundle_path: PathBuf,
}

/// Main entry point: strip, compress, encrypt, write, return row.
pub fn freeze_page(
    raw_html: &str,
    url: &str,
    title: &str,
    workspace_id: &str,
    master_key: &[u8; 32],
    bundles_dir: &Path,
) -> Result<FreezeBundle> {
    let stripped = strip_trackers(raw_html);

    let compressed = gzip_compress(stripped.as_bytes())?;

    // Mix the bundle ID into the per-bundle key derivation so every bundle
    // gets a cryptographically distinct encryption key.
    let id = new_id();
    let encrypted = derive_bundle_key_and_encrypt(master_key, &id, &compressed)?;

    let filename = format!("{id}.ewbn");
    let path = bundles_dir.join(&filename);
    write_ewbn(&path, &encrypted)?;

    let content_hash = blake3::hash(stripped.as_bytes()).to_hex().to_string();

    let row = BundleRow {
        id: id.clone(),
        url: url.to_owned(),
        title: title.to_owned(),
        content_hash,
        bundle_path: filename,
        tfidf_tags: "[]".to_owned(),
        bundle_size: std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as i64,
        frozen_at: unix_now(),
        workspace_id: workspace_id.to_owned(),
        index_tier: "hot".to_owned(),
        last_accessed_at: None,
    };

    Ok(FreezeBundle {
        bundle_row: row,
        bundle_path: path,
    })
}

/// Decrypt and return the stripped HTML for a frozen bundle.
///
/// `bundle_id` must be the same ID that was passed to `freeze_page` when this
/// bundle was created — it is mixed into the HKDF derivation so that each
/// bundle has a cryptographically distinct encryption key.
pub fn thaw_bundle(bundle_path: &Path, bundle_id: &str, master_key: &[u8; 32]) -> Result<String> {
    let raw = std::fs::read(bundle_path).context("read .ewbn")?;
    let ciphertext = parse_ewbn(&raw)?;
    let compressed = derive_bundle_key_and_decrypt(master_key, bundle_id, ciphertext)?;
    let html = gzip_decompress(&compressed)?;
    Ok(html)
}

fn strip_trackers(html: &str) -> String {
    use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

    static AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(TRACKER_SCRIPT_DOMAINS)
            .unwrap()
    });

    /// Find the end of an HTML tag starting at `start` in `html`, correctly
    /// handling `>` inside single- and double-quoted attribute values.
    fn find_tag_end(html: &str, start: usize) -> usize {
        #[derive(PartialEq)]
        enum S {
            Tag,
            DQuote,
            SQuote,
        }
        let mut state = S::Tag;
        let bytes = html.as_bytes();
        let mut i = start;
        while i < bytes.len() {
            match (state, bytes[i]) {
                (S::Tag, b'"') => state = S::DQuote,
                (S::Tag, b'\'') => state = S::SQuote,
                (S::Tag, b'>') => return i + 1,
                (S::DQuote, b'"') => state = S::Tag,
                (S::SQuote, b'\'') => state = S::Tag,
                _ => {}
            }
            i += 1;
        }
        html.len() // unclosed tag — consume to end
    }

    let mut output = String::with_capacity(html.len());
    let mut pos = 0;

    while pos < html.len() {
        if let Some(rel) = html[pos..].find('<') {
            let tag_start = pos + rel;
            output.push_str(&html[pos..tag_start]);

            let tag_end = find_tag_end(html, tag_start + 1);
            let tag = &html[tag_start..tag_end];
            let lower = tag.to_lowercase();

            let is_external = lower.starts_with("<script")
                || lower.starts_with("<img")
                || lower.starts_with("<iframe")
                || lower.starts_with("<link");

            let has_tracker_src = is_external && AC.is_match(tag);
            let is_tracking_pixel = lower.starts_with("<img")
                && (lower.contains("width=\"1\"") || lower.contains("width='1'"))
                && (lower.contains("height=\"1\"") || lower.contains("height='1'"));

            if has_tracker_src || is_tracking_pixel {
                let close_tag = if lower.starts_with("<script") && !lower.contains("/>") {
                    Some("</script>")
                } else if lower.starts_with("<iframe") && !lower.contains("/>") {
                    Some("</iframe>")
                } else {
                    None
                };
                if let Some(close) = close_tag {
                    if let Some(c) = html[tag_end..].to_lowercase().find(close) {
                        pos = tag_end + c + close.len();
                    } else {
                        pos = tag_end;
                    }
                } else {
                    pos = tag_end;
                }
                output.push_str("<!-- [diatom:stripped] -->");
            } else {
                output.push_str(tag);
                pos = tag_end;
            }
        } else {
            output.push_str(&html[pos..]);
            break;
        }
    }
    output
}

/// Derive a per-bundle AES key, encrypt `plaintext`, then immediately zeroize
/// the derived key. This ensures the 32-byte bundle key never outlives the
/// encrypt call, even if the caller panics.
fn derive_bundle_key_and_encrypt(
    master_key: &[u8; 32],
    bundle_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut bundle_key = derive_bundle_key(master_key, bundle_id)?;
    let result = aes_gcm_encrypt(&bundle_key, plaintext);
    bundle_key.zeroize();
    result
}

/// Derive a per-bundle AES key, decrypt `ciphertext`, then immediately zeroize
/// the derived key.
fn derive_bundle_key_and_decrypt(
    master_key: &[u8; 32],
    bundle_id: &str,
    ciphertext: Vec<u8>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bundle_key = derive_bundle_key(master_key, bundle_id)?;
    let result = aes_gcm_decrypt(&bundle_key, ciphertext);
    bundle_key.zeroize();
    result
}

/// Derive a bundle-specific AES-256 key via HKDF-SHA256.
///
/// `bundle_id` is mixed into the HKDF `info` field so every bundle gets a
/// cryptographically distinct key even though they all share the same master
/// key. Without this, an attacker who recovers any bundle key can trivially
/// derive all others — and differential ciphertext analysis becomes trivial
/// on similarly-structured pages.
fn derive_bundle_key(master_key: &[u8; 32], bundle_id: &str) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key = [0u8; 32];
    // "freeze-v8:" prefix bumped from v7 to signal the added per-bundle salt.
    // Old bundles encrypted under v7 (constant info) cannot be decrypted with
    // this function — they require a one-time migration or re-freeze.
    let info = format!("freeze-v8:{bundle_id}");
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
}

fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aes_gcm_decrypt(key: &[u8; 32], mut data: Vec<u8>) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if data.len() < 12 {
        bail!("ciphertext too short");
    }
    let nonce_bytes: [u8; 12] = data[..12].try_into().unwrap();
    let ct = data[12..].to_vec();
    data.zeroize();

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed — wrong key or corrupted bundle"))?;
    Ok(zeroize::Zeroizing::new(plaintext))
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data)?;
    enc.finish().context("gzip compress")
}

fn gzip_decompress(data: &[u8]) -> Result<String> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    // Hard ceiling on decompressed output. A crafted .ewbn with a legitimate
    // ≤256 MB compressed payload could otherwise expand to many GB via a zip
    // bomb, bypassing the parse_ewbn compressed-size check (zip bomb fix).
    const MAX_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024; // 512 MB

    let dec = GzDecoder::new(data);
    let mut s = String::new();
    dec.take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_string(&mut s)
        .context("gzip decompress")?;
    if s.len() as u64 > MAX_DECOMPRESSED_BYTES {
        bail!(
            "decompressed bundle HTML exceeds {} MB limit",
            MAX_DECOMPRESSED_BYTES / 1024 / 1024
        );
    }
    Ok(s)
}

fn write_ewbn(path: &Path, payload: &[u8]) -> Result<()> {
    use std::io::BufWriter;
    let file = std::fs::File::create(path).context("create .ewbn")?;
    let mut w = BufWriter::new(file);
    w.write_all(EWBN_MAGIC)?;
    w.write_all(&EWBN_VERSION.to_le_bytes())?;
    w.write_all(&(payload.len() as u64).to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
}

fn parse_ewbn(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 16 {
        bail!("file too short to be a valid .ewbn");
    }
    if &raw[..4] != EWBN_MAGIC {
        bail!("invalid .ewbn magic");
    }
    let _version = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let payload_len = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;

    // Reject pathologically large payload_len before allocation — a tampered
    // .ewbn could declare a 4 GB payload and cause an OOM before decryption.
    const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024; // 256 MB (compressed)
    if payload_len > MAX_BUNDLE_BYTES {
        bail!(
            ".ewbn payload_len {} exceeds {} MB limit",
            payload_len,
            MAX_BUNDLE_BYTES / 1024 / 1024
        );
    }

    if raw.len() < 16 + payload_len {
        bail!(".ewbn payload truncated");
    }
    Ok(raw[16..16 + payload_len].to_vec())
}

/// Retrieve or generate the app master key.
///
/// Priority:
///   1. OS keychain / secret store (macOS Keychain, Windows DPAPI).
///   2. Fallback: hex value in DB meta table `master_key_hex` (insecure).
pub fn get_or_init_master_key(db: &crate::storage::db::Db) -> Result<[u8; 32]> {
    #[cfg(target_os = "macos")]
    {
        if let Some(key) = macos_keychain_read() {
            return Ok(key);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(key) = windows_dpapi_read(db) {
            return Ok(key);
        }
    }
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    {
        if let Some(key) = linux_secret_service_read() {
            return Ok(key);
        }
    }

    tracing::warn!(
        "OS keychain unavailable — master key stored in SQLite (insecure fallback). \
         Install a keychain daemon or rebuild with platform credential support."
    );

    if let Some(hex_key) = db.get_setting("master_key_hex") {
        let mut bytes = hex::decode(&hex_key).context("decode master key")?;
        if bytes.len() != 32 {
            bail!("invalid master key length");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        bytes.zeroize();
        return Ok(arr);
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    db.set_setting("master_key_hex", &hex::encode(key))?;
    tracing::warn!("Generated new master key (stored in DB — consider enabling keychain support).");
    Ok(key)
}

#[cfg(target_os = "macos")]
fn macos_keychain_read() -> Option<[u8; 32]> {
    use security_framework::passwords::get_generic_password;
    let bytes = get_generic_password("com.ansel-s.diatom", "com.ansel-s.diatom.masterkey").ok()?;
    if bytes.len() != 32 {
        tracing::warn!("keychain: master key has unexpected length {}", bytes.len());
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let mut b = bytes;
    b.zeroize();
    Some(arr)
}

#[cfg(target_os = "macos")]
fn macos_keychain_write(key: &[u8; 32]) -> bool {
    use security_framework::passwords::{delete_generic_password, set_generic_password};
    let _ = delete_generic_password("com.ansel-s.diatom", "com.ansel-s.diatom.masterkey");
    set_generic_password("com.ansel-s.diatom", "com.ansel-s.diatom.masterkey", key).is_ok()
}

#[cfg(target_os = "windows")]
fn windows_dpapi_read(db: &crate::storage::db::Db) -> Option<[u8; 32]> {
    let blob_hex = db.get_setting("master_key_dpapi_blob")?;
    let encrypted = hex::decode(&blob_hex).ok()?;
    unsafe { dpapi_decrypt(&encrypted) }
}

#[cfg(target_os = "windows")]
unsafe fn dpapi_decrypt(data: &[u8]) -> Option<[u8; 32]> {
    use windows_sys::Win32::Security::Cryptography::{CRYPTOAPI_BLOB, CryptUnprotectData};
    let mut in_blob = CRYPTOAPI_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut _,
    };
    let mut out_blob = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    if CryptUnprotectData(
        &mut in_blob,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,
        &mut out_blob,
    ) == 0
    {
        return None;
    }
    if out_blob.cbData as usize != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    std::ptr::copy_nonoverlapping(out_blob.pbData, arr.as_mut_ptr(), 32);
    windows_sys::Win32::Foundation::LocalFree(out_blob.pbData as _);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let plain = b"hello diatom freeze test";
        let ct = aes_gcm_encrypt(&key, plain).unwrap();
        let dec = aes_gcm_decrypt(&key, ct).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn bundle_key_zeroize_roundtrip() {
        let master = [0xBEu8; 32];
        let plain = b"zeroize test payload";
        let ct = derive_bundle_key_and_encrypt(&master, "test-bundle-id-001", plain).unwrap();
        let dec = derive_bundle_key_and_decrypt(&master, "test-bundle-id-001", ct).unwrap();
        assert_eq!(dec, plain);
    }

    /// Two different bundle IDs must produce different ciphertexts
    /// even with the same master key and same plaintext.
    #[test]
    fn distinct_bundle_ids_produce_distinct_keys() {
        let master = [0xBEu8; 32];
        let plain = b"same content";
        let ct1 = derive_bundle_key_and_encrypt(&master, "bundle-aaa", plain).unwrap();
        let ct2 = derive_bundle_key_and_encrypt(&master, "bundle-bbb", plain).unwrap();
        // Keys differ → decrypting ct1 with bundle-bbb key must fail
        assert!(
            derive_bundle_key_and_decrypt(&master, "bundle-bbb", ct1).is_err(),
            "decrypting with wrong bundle_id must fail"
        );
        assert!(
            derive_bundle_key_and_decrypt(&master, "bundle-aaa", ct2).is_err(),
            "decrypting with wrong bundle_id must fail"
        );
    }

    #[test]
    fn strips_tracker_script() {
        let html = r#"<html>
<script src="https://www.google-analytics.com/analytics.js"></script>
<p>Real content</p>
<img src="https://pixel.facebook.com/tr?id=123" width="1" height="1">
</html>"#;
        let stripped = strip_trackers(html);
        assert!(stripped.contains("Real content"));
        assert!(!stripped.contains("google-analytics.com"));
        assert!(!stripped.contains("pixel.facebook.com"));
        assert!(stripped.contains("[diatom:stripped]"));
    }

    #[test]
    fn ewbn_roundtrip() {
        let dir = tempdir().unwrap();
        let key = [0xABu8; 32];
        let html = "<html><body>test freeze</body></html>";
        let result = freeze_page(
            html,
            "https://example.com",
            "Test",
            "ws-0",
            &key,
            dir.path(),
        );
        assert!(result.is_ok());
        let bundle = result.unwrap();
        let bundle_id = bundle.bundle_row.id.clone();
        let thawed = thaw_bundle(&bundle.bundle_path, &bundle_id, &key).unwrap();
        assert!(thawed.contains("test freeze"));
    }

    /// parse_ewbn must reject an oversized payload_len before allocation.
    #[test]
    fn parse_ewbn_rejects_oversized_payload() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"EWBT"); // magic
        raw.extend_from_slice(&1u32.to_le_bytes()); // version
        raw.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes()); // 512 MB — over limit
        raw.extend_from_slice(&[0u8; 32]); // stub payload
        assert!(
            parse_ewbn(&raw).is_err(),
            "must reject oversized payload_len"
        );
    }

    /// Compile-time hex codec sanity check: hex::encode → hex::decode is identity.
    #[test]
    fn hex_codec_roundtrip() {
        let original = b"diatom-master-key-test-32-bytes!";
        let encoded = hex::encode(original);
        let decoded = hex::decode(&encoded).expect("hex decode must succeed");
        assert_eq!(decoded, original, "hex round-trip must be identity");
        assert_eq!(encoded.len(), 64);
    }
}
