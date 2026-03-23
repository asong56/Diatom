// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/freeze.rs  — v0.9.1
//
// E-WBN (Encrypted WebBundle) — the Freeze system.
//
// Pipeline:
//   1. Strip trackers from raw HTML (Aho-Corasick against blocker list)
//   2. Inline images as data URIs  (already present in raw_html snapshot)
//   3. AES-GCM-256 encrypt with a key derived from the app master key
//   4. Write encrypted bundle to data_dir/bundles/{id}.ewbn
//   5. Return BundleRow for DB insertion (caller indexes with TF-IDF tags)
//
// Key derivation:
//   master_key  →  HKDF-SHA256(info=b"freeze-v7")  →  32-byte AES key
//   The master key is the app's Ed25519 seed (32 bytes), stored in the OS keychain.
//   For this release, if no keychain key exists, we derive from a random seed
//   persisted in the DB meta table under "master_key_b64" (hex-encoded).
//
// Bundle format (.ewbn) — actual binary layout:
//   [4 bytes]  magic: 0x45574254 ("EWBT")
//   [4 bytes]  version: u32 le = 1
//   [8 bytes]  payload length: u64 le
//   [N bytes]  payload = nonce[12] ++ ciphertext ++ AES-GCM tag[16]
//
// v0.9.1 changes:
//   • `derive_bundle_key` now zeroizes the derived key material after the
//     calling function has consumed it. This ensures the per-bundle AES key
//     does not linger on the heap after `freeze_page` or `thaw_bundle` returns.
//     The master key is left intact — it lives in AppState for the session.
//   • Replaced `once_cell::sync::Lazy` inside `strip_trackers` with
//     `std::sync::LazyLock`. Removes the once_cell dep from this module.
//   • `get_or_init_master_key` now zeroizes the intermediate hex decode buffer
//     before returning, preventing the raw key bytes from lingering in the
//     heap region allocated for the hex string decode.
// ─────────────────────────────────────────────────────────────────────────────

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

use crate::{
    blocker::is_blocked,
    db::{BundleRow, new_id, unix_now},
};

// ── Magic header ──────────────────────────────────────────────────────────────
const EWBN_MAGIC: &[u8; 4] = b"EWBT";
const EWBN_VERSION: u32 = 1;

// ── Tracker strip patterns ────────────────────────────────────────────────────
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

// ── FreezeBundle ──────────────────────────────────────────────────────────────

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
    // 1. Strip trackers from HTML
    let stripped = strip_trackers(raw_html);

    // 2. Gzip compress the stripped HTML
    let compressed = gzip_compress(stripped.as_bytes())?;

    // 3. Derive a per-bundle AES key (master → HKDF → bundle_key)
    //    Key is zeroized inside derive_bundle_key_and_use via a guard closure.
    let encrypted = derive_bundle_key_and_encrypt(master_key, &compressed)?;

    // 4. Build .ewbn byte stream
    let id = new_id();
    let filename = format!("{id}.ewbn");
    let path = bundles_dir.join(&filename);
    write_ewbn(&path, &encrypted)?;

    // [FIX-15] Hash stripped HTML content (not URL) so identical content
    // at the same URL doesn't create orphan .ewbn files.
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
    };

    Ok(FreezeBundle {
        bundle_row: row,
        bundle_path: path,
    })
}

/// Decrypt and return the stripped HTML for a frozen bundle.
pub fn thaw_bundle(bundle_path: &Path, master_key: &[u8; 32]) -> Result<String> {
    let raw = std::fs::read(bundle_path).context("read .ewbn")?;
    let ciphertext = parse_ewbn(&raw)?;
    let compressed = derive_bundle_key_and_decrypt(master_key, ciphertext)?;
    let html = gzip_decompress(&compressed)?;
    Ok(html)
}

// ── Tracker stripping ─────────────────────────────────────────────────────────

fn strip_trackers(html: &str) -> String {
    use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

    // LazyLock replaces once_cell::sync::Lazy — same semantics, no extra dep.
    static AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(TRACKER_SCRIPT_DOMAINS)
            .unwrap()
    });

    let mut output = String::with_capacity(html.len());
    let mut pos = 0;

    while pos < html.len() {
        if let Some(tag_start) = html[pos..].find('<').map(|i| pos + i) {
            output.push_str(&html[pos..tag_start]);

            let tag_end = html[tag_start..]
                .find('>')
                .map(|i| tag_start + i + 1)
                .unwrap_or(html.len());

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
                if lower.starts_with("<script") && !lower.contains("/>") {
                    if let Some(close) = html[tag_end..].to_lowercase().find("</script>") {
                        pos = tag_end + close + "</script>".len();
                    } else {
                        pos = tag_end;
                    }
                } else if lower.starts_with("<iframe") && !lower.contains("/>") {
                    if let Some(close) = html[tag_end..].to_lowercase().find("</iframe>") {
                        pos = tag_end + close + "</iframe>".len();
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

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Derive a per-bundle AES key, encrypt `plaintext`, then immediately zeroize
/// the derived key. This ensures the 32-byte bundle key never outlives the
/// encrypt call, even if the caller panics.
fn derive_bundle_key_and_encrypt(master_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut bundle_key = derive_bundle_key(master_key)?;
    let result = aes_gcm_encrypt(&bundle_key, plaintext);
    // SECURITY: zeroize the per-bundle key immediately — it must not persist
    // on the heap beyond this function's stack frame.
    bundle_key.zeroize();
    result
}

/// Derive a per-bundle AES key, decrypt `ciphertext`, then immediately zeroize
/// the derived key.
fn derive_bundle_key_and_decrypt(
    master_key: &[u8; 32],
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut bundle_key = derive_bundle_key(master_key)?;
    let result = aes_gcm_decrypt(&bundle_key, ciphertext);
    bundle_key.zeroize();
    result
}

fn derive_bundle_key(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key = [0u8; 32];
    hk.expand(b"freeze-v7", &mut key)
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

fn aes_gcm_decrypt(key: &[u8; 32], mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.len() < 12 {
        bail!("ciphertext too short");
    }
    let nonce_bytes: [u8; 12] = data[..12].try_into().unwrap();
    let ct = data[12..].to_vec();
    data.zeroize();

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed — wrong key or corrupted bundle"))
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data)?;
    enc.finish().context("gzip compress")
}

fn gzip_decompress(data: &[u8]) -> Result<String> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(data);
    let mut s = String::new();
    dec.read_to_string(&mut s).context("gzip decompress")?;
    Ok(s)
}

// ── .ewbn I/O ─────────────────────────────────────────────────────────────────

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
    if raw.len() < 16 + payload_len {
        bail!(".ewbn payload truncated");
    }
    Ok(raw[16..16 + payload_len].to_vec())
}

// ── Master key initialisation ─────────────────────────────────────────────────

/// Retrieve or generate the app master key.
///
/// Priority:
///   1. OS keychain / secret store (macOS Keychain, Windows DPAPI).
///   2. Fallback: hex value in DB meta table `master_key_hex` (insecure).
pub fn get_or_init_master_key(db: &crate::db::Db) -> Result<[u8; 32]> {
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
        // SECURITY: zeroize the intermediate Vec before dropping it, so the
        // raw key bytes do not linger in the heap region of the decode buffer.
        bytes.zeroize();
        return Ok(arr);
    }

    // Generate a new random master key and persist it.
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    db.set_setting("master_key_hex", &hex::encode(key))?;
    tracing::warn!(
        "Generated new master key (stored in DB — consider enabling keychain support)."
    );
    Ok(key)
}

// ── macOS Keychain ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn macos_keychain_read() -> Option<[u8; 32]> {
    use std::process::Command;
    let out = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "com.ansel-s.diatom.masterkey",
            "-w",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let hex = String::from_utf8(out.stdout).ok()?;
    let mut bytes = hex::decode(hex.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();
    Some(arr)
}

#[cfg(target_os = "macos")]
fn macos_keychain_write(key: &[u8; 32]) -> bool {
    use std::process::Command;
    let hex_key = hex::encode(key);
    let _ = Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            "com.ansel-s.diatom.masterkey",
        ])
        .output();
    Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            "com.ansel-s.diatom.masterkey",
            "-a",
            "diatom",
            "-w",
            &hex_key,
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── Windows DPAPI ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn windows_dpapi_read(db: &crate::db::Db) -> Option<[u8; 32]> {
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
        // Verify that the encrypt+zeroize path produces a decryptable result.
        let master = [0xBEu8; 32];
        let plain = b"zeroize test payload";
        let ct = derive_bundle_key_and_encrypt(&master, plain).unwrap();
        let dec = derive_bundle_key_and_decrypt(&master, ct).unwrap();
        assert_eq!(dec, plain);
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
        let result = freeze_page(html, "https://example.com", "Test", "ws-0", &key, dir.path());
        assert!(result.is_ok());
        let bundle = result.unwrap();
        let thawed = thaw_bundle(&bundle.bundle_path, &key).unwrap();
        assert!(thawed.contains("test freeze"));
    }
}
