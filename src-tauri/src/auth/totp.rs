use anyhow::{Context, Result, bail};
use base32::Alphabet;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
    Steam,
}

impl TotpAlgorithm {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "SHA256" | "SHA-256" => Self::Sha256,
            "SHA512" | "SHA-512" => Self::Sha512,
            "STEAM" => Self::Steam,
            _ => Self::Sha1,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            Self::Steam => "STEAM",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct TotpEntry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
    pub domains: Vec<String>,
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    pub entry_id: String,
    pub issuer: String,
    pub account: String,
    pub code: String,
    pub next_code: String,
    pub valid_until: i64,
    pub period: u32,
}

fn encrypt_secret(secret: &str, master_key: &[u8; 32]) -> Result<String> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    use rand::RngCore;
    let cipher = Aes256Gcm::new(master_key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("TOTP encrypt failed"))?;
    let mut raw = Vec::with_capacity(12 + ct.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ct);
    Ok(hex::encode(raw))
}

fn decrypt_secret(enc_hex: &str, master_key: &[u8; 32]) -> Result<String> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    let raw = hex::decode(enc_hex).context("decode totp hex")?;
    if raw.len() < 28 {
        bail!("totp ciphertext too short");
    }
    let nonce = Nonce::from_slice(&raw[..12]);
    let cipher = Aes256Gcm::new(master_key.into());
    let pt = cipher
        .decrypt(nonce, &raw[12..])
        .map_err(|_| anyhow::anyhow!("TOTP decrypt failed"))?;
    String::from_utf8(pt).context("totp secret utf8")
}

#[derive(Default)]
pub struct TotpStore {
    entries: HashMap<String, TotpEntry>,
}

impl TotpStore {
    pub fn load_from_db(db: &crate::storage::db::Db, master_key: &[u8; 32]) -> Self {
        let mut entries = HashMap::new();
        for raw in db.totp_list_raw().unwrap_or_default() {
            match decrypt_secret(&raw.secret_enc, master_key) {
                Ok(secret) => {
                    let domains = serde_json::from_str(&raw.domains_json).unwrap_or_default();
                    let algorithm = raw
                        .algorithm
                        .as_deref()
                        .map(TotpAlgorithm::from_str)
                        .unwrap_or_default();
                    let digits = raw.digits.unwrap_or(6).clamp(4, 10);
                    let period = raw.period.unwrap_or(30).max(1);
                    entries.insert(
                        raw.id.clone(),
                        TotpEntry {
                            id: raw.id,
                            issuer: raw.issuer,
                            account: raw.account,
                            secret,
                            algorithm,
                            digits,
                            period,
                            domains,
                            added_at: raw.added_at,
                        },
                    );
                }
                Err(e) => tracing::warn!("skip totp entry: {e}"),
            }
        }
        TotpStore { entries }
    }

    pub fn add(
        &mut self,
        issuer: &str,
        account: &str,
        secret: &str,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u32,
        domains: Vec<String>,
        db: &crate::storage::db::Db,
        master_key: &[u8; 32],
    ) -> Result<TotpEntry> {
        let clean = secret.to_uppercase().replace(' ', "");
        if algorithm != TotpAlgorithm::Steam {
            base32::decode(Alphabet::Rfc4648 { padding: false }, &clean)
                .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: true }, &clean))
                .ok_or_else(|| anyhow::anyhow!("invalid base32 TOTP secret"))?;
        }
        let id = crate::storage::db::new_id();
        let now = crate::storage::db::unix_now();
        let enc = encrypt_secret(&clean, master_key)?;
        let dj = serde_json::to_string(&domains)?;
        db.totp_insert_v2(
            &id,
            issuer,
            account,
            &enc,
            &dj,
            now,
            algorithm.as_str(),
            digits,
            period,
        )?;
        let entry = TotpEntry {
            id: id.clone(),
            issuer: issuer.to_owned(),
            account: account.to_owned(),
            secret: clean,
            algorithm,
            digits,
            period,
            domains,
            added_at: now,
        };
        self.entries.insert(id, entry.clone());
        Ok(entry)
    }

    pub fn add_from_uri(
        &mut self,
        uri: &str,
        domains: Vec<String>,
        db: &crate::storage::db::Db,
        master_key: &[u8; 32],
    ) -> Result<TotpEntry> {
        let p = parse_otpauth_uri(uri)?;
        self.add(
            &p.issuer.unwrap_or_default(),
            &p.account.unwrap_or_default(),
            &p.secret,
            p.algorithm,
            p.digits,
            p.period,
            domains,
            db,
            master_key,
        )
    }

    pub fn remove(&mut self, id: &str, db: &crate::storage::db::Db) {
        self.entries.remove(id);
        let _ = db.totp_delete(id);
    }

    pub fn list(&self) -> Vec<TotpEntry> {
        let mut v: Vec<_> = self.entries.values().cloned().collect();
        v.sort_by_key(|e| e.added_at);
        v
    }

    pub fn generate(&self, id: &str) -> Result<TotpCode> {
        let e = self
            .entries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("TOTP entry {id} not found"))?;
        let now = crate::storage::db::unix_now() as u64;
        let counter = now / e.period as u64;
        let code = generate_code(&e.secret, e.algorithm, e.digits, counter)?;
        let next_code = generate_code(&e.secret, e.algorithm, e.digits, counter + 1)?;
        let valid_until = ((counter + 1) * e.period as u64) as i64;
        Ok(TotpCode {
            entry_id: id.to_owned(),
            issuer: e.issuer.clone(),
            account: e.account.clone(),
            code,
            next_code,
            valid_until,
            period: e.period,
        })
    }

    pub fn match_domain(&self, domain: &str) -> Vec<TotpCode> {
        let dlc = domain.to_lowercase();
        self.entries
            .values()
            .filter(|e| {
                e.domains.iter().any(|d| {
                    let d = d.to_lowercase();
                    dlc == d || dlc.ends_with(&format!(".{d}"))
                })
            })
            .filter_map(|e| self.generate(&e.id).ok())
            .collect()
    }

    pub fn import_aegis(
        &mut self,
        json: &str,
        db: &crate::storage::db::Db,
        master_key: &[u8; 32],
    ) -> Result<usize> {
        #[derive(Deserialize)]
        struct AInfo {
            secret: String,
            algo: String,
            digits: u8,
            period: u32,
        }
        #[derive(Deserialize)]
        struct AEntry {
            #[serde(rename = "type")]
            kind: String,
            issuer: Option<String>,
            name: Option<String>,
            info: AInfo,
        }
        #[derive(Deserialize)]
        struct ARoot {
            entries: Vec<AEntry>,
        }

        let root: ARoot = serde_json::from_str(json).context("Aegis JSON")?;
        let mut n = 0usize;
        for e in root.entries {
            let algo = if e.kind.to_lowercase() == "steam" {
                TotpAlgorithm::Steam
            } else {
                TotpAlgorithm::from_str(&e.info.algo)
            };
            if self
                .add(
                    e.issuer.as_deref().unwrap_or(""),
                    e.name.as_deref().unwrap_or(""),
                    &e.info.secret,
                    algo,
                    e.info.digits,
                    e.info.period,
                    vec![],
                    db,
                    master_key,
                )
                .is_ok()
            {
                n += 1;
            }
        }
        Ok(n)
    }

    pub fn import_bitwarden_json(
        &mut self,
        json: &str,
        db: &crate::storage::db::Db,
        master_key: &[u8; 32],
    ) -> Result<usize> {
        #[derive(Deserialize)]
        struct BwLogin {
            #[serde(default)]
            totp: Option<String>,
            #[serde(default)]
            username: Option<String>,
        }
        #[derive(Deserialize)]
        struct BwItem {
            name: String,
            #[serde(default, rename = "type")]
            kind: u8,
            login: Option<BwLogin>,
        }
        #[derive(Deserialize)]
        struct BwRoot {
            items: Vec<BwItem>,
        }

        let root: BwRoot = serde_json::from_str(json).context("Bitwarden JSON")?;
        let mut n = 0usize;
        for item in root.items {
            if item.kind != 1 {
                continue;
            }
            if let Some(login) = item.login {
                if let Some(totp) = login.totp.filter(|t| !t.is_empty()) {
                    let ok = if totp.starts_with("otpauth://") {
                        self.add_from_uri(&totp, vec![], db, master_key).is_ok()
                    } else {
                        self.add(
                            &item.name,
                            login.username.as_deref().unwrap_or(""),
                            &totp,
                            TotpAlgorithm::Sha1,
                            6,
                            30,
                            vec![],
                            db,
                            master_key,
                        )
                        .is_ok()
                    };
                    if ok {
                        n += 1;
                    }
                }
            }
        }
        Ok(n)
    }

    pub fn import_uri_list(
        &mut self,
        text: &str,
        db: &crate::storage::db::Db,
        master_key: &[u8; 32],
    ) -> Result<usize> {
        let mut n = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("otpauth://") || line.starts_with("steam://") {
                if self.add_from_uri(line, vec![], db, master_key).is_ok() {
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    pub fn import_2fas(
        &mut self,
        json: &str,
        db: &crate::storage::db::Db,
        master_key: &[u8; 32],
    ) -> Result<usize> {
        #[derive(Deserialize)]
        struct TfOtp {
            account: Option<String>,
            issuer: Option<String>,
            secret: String,
            #[serde(rename = "tokenType")]
            token_type: Option<String>,
            algorithm: Option<String>,
            digits: Option<u8>,
            period: Option<u32>,
        }
        #[derive(Deserialize)]
        struct TfSvc {
            otp: TfOtp,
        }
        #[derive(Deserialize)]
        struct TfRoot {
            services: Vec<TfSvc>,
        }

        let root: TfRoot = serde_json::from_str(json).context("2FAS JSON")?;
        let mut n = 0usize;
        for svc in root.services {
            let otp = svc.otp;
            let algo = if otp.token_type.as_deref() == Some("STEAM") {
                TotpAlgorithm::Steam
            } else {
                TotpAlgorithm::from_str(otp.algorithm.as_deref().unwrap_or("SHA1"))
            };
            if self
                .add(
                    otp.issuer.as_deref().unwrap_or(""),
                    otp.account.as_deref().unwrap_or(""),
                    &otp.secret,
                    algo,
                    otp.digits.unwrap_or(6),
                    otp.period.unwrap_or(30),
                    vec![],
                    db,
                    master_key,
                )
                .is_ok()
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Export all entries to Aegis-compatible unencrypted JSON.
    /// Callers MUST gate this behind biometric auth.
    pub fn export_aegis_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct ExInfo {
            secret: String,
            algo: String,
            digits: u8,
            period: u32,
        }
        #[derive(Serialize)]
        struct ExEntry {
            #[serde(rename = "type")]
            kind: &'static str,
            issuer: String,
            name: String,
            info: ExInfo,
        }
        #[derive(Serialize)]
        struct ExRoot {
            version: u8,
            entries: Vec<ExEntry>,
        }

        let entries: Vec<ExEntry> = self
            .entries
            .values()
            .map(|e| ExEntry {
                kind: if e.algorithm == TotpAlgorithm::Steam {
                    "steam"
                } else {
                    "totp"
                },
                issuer: e.issuer.clone(),
                name: e.account.clone(),
                info: ExInfo {
                    secret: e.secret.clone(),
                    algo: e.algorithm.as_str().to_owned(),
                    digits: e.digits,
                    period: e.period,
                },
            })
            .collect();
        serde_json::to_string_pretty(&ExRoot {
            version: 1,
            entries,
        })
        .context("serialize aegis export")
    }
}

pub struct ParsedOtpUri {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub secret: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

pub fn parse_otpauth_uri(uri: &str) -> Result<ParsedOtpUri> {
    use url::Url;

    if uri.starts_with("steam://") {
        return Ok(ParsedOtpUri {
            issuer: Some("Steam".to_owned()),
            account: None,
            secret: uri.trim_start_matches("steam://").to_owned(),
            algorithm: TotpAlgorithm::Steam,
            digits: 5,
            period: 30,
        });
    }

    let parsed = Url::parse(uri).context("parse otpauth URI")?;
    if parsed.scheme() != "otpauth" {
        bail!("not an otpauth URI");
    }

    let label_raw = parsed.path().trim_start_matches('/');
    let label_dec = urlencoding::decode(label_raw)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| label_raw.to_owned());
    let (path_issuer, account) = if let Some(pos) = label_dec.find(':') {
        (
            Some(label_dec[..pos].trim().to_owned()),
            Some(label_dec[pos + 1..].trim().to_owned()).filter(|s| !s.is_empty()),
        )
    } else {
        (
            None,
            Some(label_dec.trim().to_owned()).filter(|s| !s.is_empty()),
        )
    };

    let mut secret = String::new();
    let mut issuer = path_issuer;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6u8;
    let mut period = 30u32;

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "secret" => secret = v.to_uppercase().replace(' ', ""),
            "issuer" => issuer = Some(v.into_owned()),
            "algorithm" => algorithm = TotpAlgorithm::from_str(&v),
            "digits" => digits = v.parse().unwrap_or(6),
            "period" => period = v.parse().unwrap_or(30),
            _ => {}
        }
    }
    if secret.is_empty() {
        bail!("otpauth URI missing secret");
    }

    if issuer.as_deref().map(|s| s.to_lowercase()) == Some("steam".to_owned()) {
        algorithm = TotpAlgorithm::Steam;
    }
    Ok(ParsedOtpUri {
        issuer,
        account,
        secret,
        algorithm,
        digits,
        period,
    })
}

static STEAM_CHARS: [char; 26] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P',
    'Q', 'R', 'T', 'V', 'W', 'X', 'Y',
];

pub fn generate_code(
    secret: &str,
    algorithm: TotpAlgorithm,
    digits: u8,
    counter: u64,
) -> Result<String> {
    if algorithm == TotpAlgorithm::Steam {
        return steam_code(secret, counter);
    }
    let mut key = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
        .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: true }, secret))
        .ok_or_else(|| anyhow::anyhow!("invalid base32 secret"))?;
    let trunc = match algorithm {
        TotpAlgorithm::Sha256 => hotp_sha256(&key, counter)?,
        TotpAlgorithm::Sha512 => hotp_sha512(&key, counter)?,
        _ => hotp_sha1_trunc(&key, counter)?,
    };
    key.zeroize();
    let code = trunc % 10u32.pow(digits as u32);
    Ok(format!("{:0width$}", code, width = digits as usize))
}

fn steam_code(secret: &str, counter: u64) -> Result<String> {
    let key = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
        .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: true }, secret))
        .or_else(|| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(secret)
                .ok()
                .or_else(|| {
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(secret)
                        .ok()
                })
        })
        .ok_or_else(|| anyhow::anyhow!("invalid Steam secret"))?;
    let raw = hotp_sha1_raw(&key, counter)?;
    let offset = (raw[19] & 0xf) as usize;
    let mut n = ((raw[offset] as u32 & 0x7f) << 24)
        | ((raw[offset + 1] as u32) << 16)
        | ((raw[offset + 2] as u32) << 8)
        | (raw[offset + 3] as u32);
    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        code.push(STEAM_CHARS[n as usize % 26]);
        n /= 26;
    }
    Ok(code)
}

fn hotp_sha1_trunc(key: &[u8], counter: u64) -> Result<u32> {
    let raw = hotp_sha1_raw(key, counter)?;
    let offset = (raw[19] & 0xf) as usize;
    Ok(u32::from_be_bytes([
        raw[offset] & 0x7f,
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]))
}

fn hotp_sha1_raw(key: &[u8], counter: u64) -> Result<[u8; 20]> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| anyhow::anyhow!("HMAC-SHA1 key"))?;
    mac.update(&counter.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn hotp_sha256(key: &[u8], counter: u64) -> Result<u32> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| anyhow::anyhow!("HMAC-SHA256 key"))?;
    mac.update(&counter.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let o = (r[31] & 0xf) as usize;
    Ok(u32::from_be_bytes([
        r[o] & 0x7f,
        r[o + 1],
        r[o + 2],
        r[o + 3],
    ]))
}

fn hotp_sha512(key: &[u8], counter: u64) -> Result<u32> {
    let mut mac =
        HmacSha512::new_from_slice(key).map_err(|_| anyhow::anyhow!("HMAC-SHA512 key"))?;
    mac.update(&counter.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let o = (r[63] & 0xf) as usize;
    Ok(u32::from_be_bytes([
        r[o] & 0x7f,
        r[o + 1],
        r[o + 2],
        r[o + 3],
    ]))
}

pub fn totp_now(secret_b32: &str) -> Result<String> {
    let counter = crate::storage::db::unix_now() as u64 / 30;
    generate_code(secret_b32, TotpAlgorithm::Sha1, 6, counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotp_rfc_vectors() {
        let key = b"12345678901234567890";
        assert_eq!(hotp_sha1_trunc(key, 0).unwrap(), 755224);
        assert_eq!(hotp_sha1_trunc(key, 1).unwrap(), 287082);
        assert_eq!(hotp_sha1_trunc(key, 2).unwrap(), 359152);
    }

    #[test]
    fn match_domain_no_substring_attack() {
        let stored = "example.com";
        let evil = "evilexample.com";
        let lc = evil.to_lowercase();
        let slc = stored.to_lowercase();
        assert!(!(lc == slc || lc.ends_with(&format!(".{slc}"))));
    }

    #[test]
    fn match_domain_subdomain_ok() {
        let stored = "example.com";
        let sub = "sub.example.com";
        let slc = stored.to_lowercase();
        let sublc = sub.to_lowercase();
        assert!(sublc == slc || sublc.ends_with(&format!(".{slc}")));
    }

    #[test]
    fn steam_code_is_5_chars() {
        let key = base32::encode(
            Alphabet::Rfc4648 { padding: false },
            b"steamguardkey1234567",
        );
        let code = generate_code(&key, TotpAlgorithm::Steam, 5, 59).unwrap();
        assert_eq!(code.len(), 5);
        for ch in code.chars() {
            assert!(STEAM_CHARS.contains(&ch));
        }
    }

    #[test]
    fn algorithm_roundtrip() {
        for a in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
            TotpAlgorithm::Steam,
        ] {
            assert_eq!(TotpAlgorithm::from_str(a.as_str()), a);
        }
    }

    #[test]
    fn parse_otpauth_steam_uri() {
        let uri = "steam://JBSWY3DPEHPK3PXP";
        let p = parse_otpauth_uri(uri).unwrap();
        assert_eq!(p.algorithm, TotpAlgorithm::Steam);
        assert_eq!(p.digits, 5);
    }
}
