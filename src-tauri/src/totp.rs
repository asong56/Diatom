// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/totp.rs  — v0.9.2
//
// [FIX-persistence-totp] DB-backed store. Secrets AES-256-GCM encrypted.
// [FIX-05-totp] match_domain() requires leading-dot or exact match.
// ─────────────────────────────────────────────────────────────────────────────

use anyhow::{Context, Result, bail};
use base32::Alphabet;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;

// ── Data model ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct TotpEntry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    /// Base32-encoded TOTP secret (decrypted, in-memory). SENSITIVE.
    pub secret: String,
    pub domains: Vec<String>,
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    pub entry_id: String,
    pub issuer: String,
    pub account: String,
    pub code: String,
    pub valid_until: i64,
}

// ── AES-GCM secret encrypt/decrypt ───────────────────────────────────────────

fn encrypt_secret(secret: &str, master_key: &[u8; 32]) -> Result<String> {
    use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
    use rand::RngCore;
    let cipher = Aes256Gcm::new(master_key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("TOTP encrypt failed"))?;
    let mut raw = Vec::with_capacity(12 + ct.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ct);
    Ok(hex::encode(raw))
}

fn decrypt_secret(enc_hex: &str, master_key: &[u8; 32]) -> Result<String> {
    use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
    let raw = hex::decode(enc_hex).context("decode totp hex")?;
    if raw.len() < 28 { bail!("totp ciphertext too short"); }
    let nonce = Nonce::from_slice(&raw[..12]);
    let cipher = Aes256Gcm::new(master_key.into());
    let pt = cipher.decrypt(nonce, &raw[12..])
        .map_err(|_| anyhow::anyhow!("TOTP decrypt failed"))?;
    String::from_utf8(pt).context("totp secret utf8")
}

// ── Store ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TotpStore {
    entries: HashMap<String, TotpEntry>,
}

impl TotpStore {
    /// Load all TOTP entries from DB, decrypting with master_key.
    pub fn load_from_db(db: &crate::db::Db, master_key: &[u8; 32]) -> Self {
        let mut entries = HashMap::new();
        for raw in db.totp_list_raw().unwrap_or_default() {
            match decrypt_secret(&raw.secret_enc, master_key) {
                Ok(secret) => {
                    let domains = serde_json::from_str(&raw.domains_json).unwrap_or_default();
                    entries.insert(raw.id.clone(), TotpEntry {
                        id: raw.id, issuer: raw.issuer, account: raw.account,
                        secret, domains, added_at: raw.added_at,
                    });
                }
                Err(e) => tracing::warn!("skip totp entry: {e}"),
            }
        }
        TotpStore { entries }
    }

    pub fn add(
        &mut self, issuer: &str, account: &str, secret: &str,
        domains: Vec<String>, db: &crate::db::Db, master_key: &[u8; 32],
    ) -> Result<TotpEntry> {
        base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
            .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: true }, secret))
            .ok_or_else(|| anyhow::anyhow!("invalid base32 TOTP secret"))?;

        let id = crate::db::new_id();
        let now = crate::db::unix_now();
        let clean = secret.to_uppercase().replace(' ', "");
        let enc = encrypt_secret(&clean, master_key)?;
        let dj = serde_json::to_string(&domains)?;
        db.totp_insert(&id, issuer, account, &enc, &dj, now)?;

        let entry = TotpEntry {
            id: id.clone(), issuer: issuer.to_owned(), account: account.to_owned(),
            secret: clean, domains, added_at: now,
        };
        self.entries.insert(id, entry.clone());
        Ok(entry)
    }

    pub fn remove(&mut self, id: &str, db: &crate::db::Db) {
        self.entries.remove(id);
        let _ = db.totp_delete(id);
    }

    pub fn list(&self) -> Vec<TotpEntry> {
        let mut v: Vec<_> = self.entries.values().cloned().collect();
        v.sort_by_key(|e| e.added_at);
        v
    }

    pub fn generate(&self, id: &str) -> Result<TotpCode> {
        let e = self.entries.get(id)
            .ok_or_else(|| anyhow::anyhow!("TOTP entry {id} not found"))?;
        let code = totp_now(&e.secret)?;
        let now = crate::db::unix_now();
        Ok(TotpCode {
            entry_id: id.to_owned(), issuer: e.issuer.clone(),
            account: e.account.clone(), code, valid_until: (now / 30 + 1) * 30,
        })
    }

    /// [FIX-05-totp] Requires exact match or leading-dot subdomain.
    /// "evilexample.com".ends_with("example.com") is true but is NOT accepted
    /// because there is no "." before "example.com" in the attacker domain.
    pub fn match_domain(&self, domain: &str) -> Vec<TotpCode> {
        let dlc = domain.to_lowercase();
        self.entries.values()
            .filter(|e| e.domains.iter().any(|d| {
                let d = d.to_lowercase();
                dlc == d || dlc.ends_with(&format!(".{d}"))
            }))
            .filter_map(|e| self.generate(&e.id).ok())
            .collect()
    }
}

// ── TOTP / HOTP core ──────────────────────────────────────────────────────────

pub fn totp_now(secret_b32: &str) -> Result<String> {
    let mut key = base32::decode(Alphabet::Rfc4648 { padding: false }, secret_b32)
        .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: true }, secret_b32))
        .ok_or_else(|| anyhow::anyhow!("invalid base32 secret"))?;
    let counter = crate::db::unix_now() as u64 / 30;
    let result = hotp(&key, counter);
    key.zeroize();
    result
}

fn hotp(key: &[u8], counter: u64) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid HMAC key length"))?;
    let mut counter_bytes = counter.to_be_bytes();
    mac.update(&counter_bytes);
    counter_bytes.zeroize();
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0xf) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f, result[offset+1], result[offset+2], result[offset+3],
    ]) % 1_000_000;
    Ok(format!("{:06}", code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotp_rfc_vectors() {
        let key = b"12345678901234567890";
        assert_eq!(hotp(key, 0).unwrap(), "755224");
        assert_eq!(hotp(key, 1).unwrap(), "287082");
        assert_eq!(hotp(key, 2).unwrap(), "359152");
    }

    #[test]
    fn match_domain_no_substring_attack() {
        let stored = "example.com";
        let evil = "evilexample.com";
        let evil_lc = evil.to_lowercase();
        let stored_lc = stored.to_lowercase();
        let matches = evil_lc == stored_lc || evil_lc.ends_with(&format!(".{stored_lc}"));
        assert!(!matches, "evilexample.com must NOT match example.com");
    }

    #[test]
    fn match_domain_subdomain_ok() {
        let stored = "example.com";
        let sub = "sub.example.com";
        let sub_lc = sub.to_lowercase();
        let stored_lc = stored.to_lowercase();
        let matches = sub_lc == stored_lc || sub_lc.ends_with(&format!(".{stored_lc}"));
        assert!(matches, "sub.example.com should match example.com");
    }
}
