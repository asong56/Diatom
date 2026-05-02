use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, bail};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;
use zeroize::Zeroize;

pub(crate) fn encrypt_field(plaintext: &str, key: &[u8; 32]) -> Result<String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("vault encrypt failed"))?;
    let mut raw = Vec::with_capacity(12 + ct.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ct);
    Ok(hex::encode(raw))
}

pub(crate) fn decrypt_field(enc_hex: &str, key: &[u8; 32]) -> Result<String> {
    let raw = hex::decode(enc_hex).context("vault hex decode")?;
    if raw.len() < 28 {
        bail!("vault ciphertext too short");
    }
    let nonce = Nonce::from_slice(&raw[..12]);
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher
        .decrypt(nonce, &raw[12..])
        .map_err(|_| anyhow::anyhow!("vault decrypt failed"))?;
    String::from_utf8(pt).context("vault plaintext utf8")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultEntryKind {
    Login,
    Card,
    Note,
}

/// Decrypted vault login entry (in-memory only; never serialised to DB).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct VaultLogin {
    pub id: String,
    pub title: String,
    pub username: String,
    /// Decrypted password. Marked Zeroize so stack copies are wiped on drop.
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub tags: Vec<String>,
    pub totp_uri: Option<String>, // linked TOTP URI (stored separately in totp_entries)
    pub created_at: i64,
    pub updated_at: i64,
}

/// Decrypted vault card entry.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct VaultCard {
    pub id: String,
    pub title: String,
    pub cardholder: String,
    pub number: String, // decrypted card number
    pub expiry: String, // MM/YY — not sensitive but stored encrypted for consistency
    pub cvv: String,    // decrypted CVV
    pub notes: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Decrypted vault secure note.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct VaultNote {
    pub id: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub has_totp: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardSummary {
    pub id: String,
    pub title: String,
    pub cardholder: String,
    pub last_four: String, // last 4 digits of card number
    pub expiry: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteSummary {
    pub id: String,
    pub title: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

static WORDLIST: &[&str] = &[
    "apple", "bridge", "castle", "dancer", "earth", "forest", "garden", "harbor", "island",
    "jungle", "kite", "lemon", "mountain", "night", "ocean", "planet", "quest", "river", "sunset",
    "tower", "umbrella", "valley", "winter", "yellow", "zenith", "anchor", "breeze", "candle",
    "diamond", "ember", "falcon", "glacier", "honey", "ivory", "jasper", "lantern", "marble",
    "nectar", "opal", "pearl", "quartz", "rainbow", "silver", "thunder", "ultra", "violet",
    "walnut", "xenon", "yacht", "zephyr", "amber", "bronze", "coral", "dusk", "eclipse", "flame",
    "grove", "haze", "iris", "jade", "karma", "lotus", "mist", "nova", "orbit", "prism", "ripple",
    "storm", "tide", "unity", "venom", "wave", "xerus", "yarn", "zest", "blaze", "cipher", "delta",
    "echo", "flint", "glyph", "halo", "index", "jewel", "knight", "lyric", "manor", "neon", "onyx",
    "pixel", "quill", "raven", "spark", "thorn", "umber", "vortex", "warden", "xray", "yield",
    "zeal",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    pub length: usize,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            numbers: true,
            symbols: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseConfig {
    pub word_count: usize,
    pub separator: String,
    pub capitalise: bool,
    pub include_number: bool,
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            word_count: 4,
            separator: "-".to_owned(),
            capitalise: true,
            include_number: true,
        }
    }
}

pub fn generate_password(cfg: &PasswordConfig) -> String {
    let mut rng = rand::thread_rng();
    let mut charset: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    if cfg.uppercase {
        charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if cfg.numbers {
        charset.extend_from_slice(b"0123456789");
    }
    if cfg.symbols {
        charset.extend_from_slice(b"!@#$%^&*()-_=+[]{}|;:,.<>?");
    }

    let len = cfg.length.clamp(8, 128);
    let mut pw: Vec<u8> = (0..len)
        .map(|_| charset[rng.gen_range(0..charset.len())])
        .collect();

    let mut ensure = |chars: &[u8]| {
        let pos = rng.gen_range(0..len);
        pw[pos] = chars[rng.gen_range(0..chars.len())];
    };
    if cfg.uppercase {
        ensure(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if cfg.numbers {
        ensure(b"0123456789");
    }
    if cfg.symbols {
        ensure(b"!@#$%^&*");
    }

    String::from_utf8(pw).unwrap_or_default()
}

pub fn generate_passphrase(cfg: &PassphraseConfig) -> String {
    let mut rng = rand::thread_rng();
    let count = cfg.word_count.clamp(2, 10);
    let mut words: Vec<String> = (0..count)
        .map(|_| {
            let word = WORDLIST[rng.gen_range(0..WORDLIST.len())];
            if cfg.capitalise {
                let mut c = word.chars();
                c.next()
                    .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                    .unwrap_or_default()
            } else {
                word.to_owned()
            }
        })
        .collect();
    if cfg.include_number {
        let pos = rng.gen_range(0..count);
        words[pos].push_str(&rng.gen_range(0u32..100).to_string());
    }
    words.join(&cfg.separator)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrengthScore {
    pub score: u8,           // 0–4 (like zxcvbn)
    pub label: &'static str, // "Very Weak" .. "Very Strong"
    pub entropy_bits: f64,
}

pub fn score_password(pw: &str) -> StrengthScore {
    if pw.is_empty() {
        return StrengthScore {
            score: 0,
            label: "Empty",
            entropy_bits: 0.0,
        };
    }
    let len = pw.len() as f64;
    let mut pool = 0u32;
    let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_alphanumeric());
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 32;
    }
    let entropy = len * (pool as f64).log2().max(0.0);

    let (score, label) = match entropy as u32 {
        0..=27 => (0, "Very Weak"),
        28..=35 => (1, "Weak"),
        36..=59 => (2, "Fair"),
        60..=99 => (3, "Strong"),
        _ => (4, "Very Strong"),
    };
    StrengthScore {
        score,
        label,
        entropy_bits: entropy,
    }
}

#[derive(Default)]
pub struct VaultStore {
    logins: HashMap<String, VaultLogin>,
    cards: HashMap<String, VaultCard>,
    notes: HashMap<String, VaultNote>,
}

impl VaultStore {
    /// Load all entries from DB, decrypting with master_key.
    pub fn load_from_db(db: &crate::storage::db::Db, key: &[u8; 32]) -> Self {
        let mut logins = HashMap::new();
        let mut cards = HashMap::new();
        let mut notes = HashMap::new();

        for raw in db.vault_logins_raw().unwrap_or_default() {
            match Self::decrypt_login(&raw, key) {
                Ok(login) => {
                    logins.insert(login.id.clone(), login);
                }
                Err(e) => tracing::warn!("skip vault login {}: {e}", raw.id),
            }
        }
        for raw in db.vault_cards_raw().unwrap_or_default() {
            match Self::decrypt_card(&raw, key) {
                Ok(card) => {
                    cards.insert(card.id.clone(), card);
                }
                Err(e) => tracing::warn!("skip vault card {}: {e}", raw.id),
            }
        }
        for raw in db.vault_notes_raw().unwrap_or_default() {
            match Self::decrypt_note(&raw, key) {
                Ok(note) => {
                    notes.insert(note.id.clone(), note);
                }
                Err(e) => tracing::warn!("skip vault note {}: {e}", raw.id),
            }
        }
        VaultStore {
            logins,
            cards,
            notes,
        }
    }

    fn decrypt_login(
        raw: &crate::storage::db::VaultLoginRaw,
        key: &[u8; 32],
    ) -> Result<VaultLogin> {
        let password = decrypt_field(&raw.password_enc, key).context("decrypt password")?;
        let notes = if raw.notes_enc.is_empty() {
            String::new()
        } else {
            decrypt_field(&raw.notes_enc, key).context("decrypt notes")?
        };
        Ok(VaultLogin {
            id: raw.id.clone(),
            title: raw.title.clone(),
            username: raw.username.clone(),
            password,
            urls: serde_json::from_str(&raw.urls_json).unwrap_or_default(),
            notes,
            tags: serde_json::from_str(&raw.tags_json).unwrap_or_default(),
            totp_uri: raw.totp_uri.clone(),
            created_at: raw.created_at,
            updated_at: raw.updated_at,
        })
    }

    fn decrypt_card(raw: &crate::storage::db::VaultCardRaw, key: &[u8; 32]) -> Result<VaultCard> {
        let number = decrypt_field(&raw.number_enc, key).context("decrypt card number")?;
        let cvv = if raw.cvv_enc.is_empty() {
            String::new()
        } else {
            decrypt_field(&raw.cvv_enc, key).context("decrypt cvv")?
        };
        let cardholder = if raw.cardholder_enc.is_empty() {
            String::new()
        } else {
            decrypt_field(&raw.cardholder_enc, key).context("decrypt cardholder")?
        };
        let notes = if raw.notes_enc.is_empty() {
            String::new()
        } else {
            decrypt_field(&raw.notes_enc, key).context("decrypt card notes")?
        };
        Ok(VaultCard {
            id: raw.id.clone(),
            title: raw.title.clone(),
            cardholder,
            number,
            expiry: raw.expiry.clone(),
            cvv,
            notes,
            tags: serde_json::from_str(&raw.tags_json).unwrap_or_default(),
            created_at: raw.created_at,
            updated_at: raw.updated_at,
        })
    }

    fn decrypt_note(raw: &crate::storage::db::VaultNoteRaw, key: &[u8; 32]) -> Result<VaultNote> {
        let content = decrypt_field(&raw.content_enc, key).context("decrypt note content")?;
        Ok(VaultNote {
            id: raw.id.clone(),
            title: raw.title.clone(),
            content,
            tags: serde_json::from_str(&raw.tags_json).unwrap_or_default(),
            created_at: raw.created_at,
            updated_at: raw.updated_at,
        })
    }

    pub fn add_login(
        &mut self,
        title: &str,
        username: &str,
        password: &str,
        urls: Vec<String>,
        notes: &str,
        tags: Vec<String>,
        totp_uri: Option<String>,
        db: &crate::storage::db::Db,
        key: &[u8; 32],
    ) -> Result<LoginSummary> {
        let id = crate::storage::db::new_id();
        let now = crate::storage::db::unix_now();
        let password_enc = encrypt_field(password, key)?;
        let notes_enc = if notes.is_empty() {
            String::new()
        } else {
            encrypt_field(notes, key)?
        };
        let urls_json = serde_json::to_string(&urls)?;
        let tags_json = serde_json::to_string(&tags)?;

        let raw = crate::storage::db::VaultLoginRaw {
            id: id.clone(),
            title: title.to_owned(),
            username: username.to_owned(),
            password_enc,
            notes_enc,
            urls_json,
            tags_json,
            totp_uri: totp_uri.clone(),
            created_at: now,
            updated_at: now,
        };
        db.vault_login_upsert(&raw)?;

        let login = VaultLogin {
            id: id.clone(),
            title: title.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            urls: urls.clone(),
            notes: notes.to_owned(),
            tags: tags.clone(),
            totp_uri,
            created_at: now,
            updated_at: now,
        };
        let summary = self.login_summary(&login);
        self.logins.insert(id, login);
        Ok(summary)
    }

    pub fn update_login(
        &mut self,
        id: &str,
        title: Option<String>,
        username: Option<String>,
        password: Option<String>,
        urls: Option<Vec<String>>,
        notes: Option<String>,
        tags: Option<Vec<String>>,
        totp_uri: Option<Option<String>>,
        db: &crate::storage::db::Db,
        key: &[u8; 32],
    ) -> Result<LoginSummary> {
        let entry = self
            .logins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("vault login {id} not found"))?
            .clone();

        let new_title = title.unwrap_or(entry.title.clone());
        let new_username = username.unwrap_or(entry.username.clone());
        let new_password = password.unwrap_or(entry.password.clone());
        let new_urls = urls.unwrap_or(entry.urls.clone());
        let new_notes = notes.unwrap_or(entry.notes.clone());
        let new_tags = tags.unwrap_or(entry.tags.clone());
        let new_totp_uri = totp_uri.unwrap_or(entry.totp_uri.clone());
        let now = crate::storage::db::unix_now();

        let password_enc = encrypt_field(&new_password, key)?;
        let notes_enc = if new_notes.is_empty() {
            String::new()
        } else {
            encrypt_field(&new_notes, key)?
        };
        let urls_json = serde_json::to_string(&new_urls)?;
        let tags_json = serde_json::to_string(&new_tags)?;

        let raw = crate::storage::db::VaultLoginRaw {
            id: id.to_owned(),
            title: new_title.clone(),
            username: new_username.clone(),
            password_enc,
            notes_enc,
            urls_json,
            tags_json,
            totp_uri: new_totp_uri.clone(),
            created_at: entry.created_at,
            updated_at: now,
        };
        db.vault_login_upsert(&raw)?;

        let updated = VaultLogin {
            id: id.to_owned(),
            title: new_title,
            username: new_username,
            password: new_password,
            urls: new_urls,
            notes: new_notes,
            tags: new_tags,
            totp_uri: new_totp_uri,
            created_at: entry.created_at,
            updated_at: now,
        };
        let summary = self.login_summary(&updated);
        self.logins.insert(id.to_owned(), updated);
        Ok(summary)
    }

    pub fn delete_login(&mut self, id: &str, db: &crate::storage::db::Db) -> Result<()> {
        self.logins.remove(id);
        db.vault_login_delete(id)
    }

    pub fn get_login_secret(&self, id: &str) -> Option<&VaultLogin> {
        self.logins.get(id)
    }

    pub fn list_logins(&self) -> Vec<LoginSummary> {
        let mut v: Vec<_> = self
            .logins
            .values()
            .map(|l| self.login_summary(l))
            .collect();
        v.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        v
    }

    pub fn search_logins(&self, query: &str) -> Vec<LoginSummary> {
        let q = query.to_lowercase();
        self.logins
            .values()
            .filter(|l| {
                l.title.to_lowercase().contains(&q)
                    || l.username.to_lowercase().contains(&q)
                    || l.urls.iter().any(|u| u.to_lowercase().contains(&q))
                    || l.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .map(|l| self.login_summary(l))
            .collect()
    }

    /// Return logins whose URLs match `domain` (exact or subdomain).

    pub fn match_domain(&self, domain: &str) -> Vec<LoginSummary> {
        let dlc = domain.to_lowercase();
        self.logins
            .values()
            .filter(|l| {
                l.urls.iter().any(|u| {
                    let host = Url::parse(u)
                        .ok()
                        .and_then(|p| p.host_str().map(|h| h.to_lowercase()));
                    match host {
                        Some(h) => h == dlc || dlc.ends_with(&format!(".{h}")),
                        None => false,
                    }
                })
            })
            .map(|l| self.login_summary(l))
            .collect()
    }

    fn login_summary(&self, l: &VaultLogin) -> LoginSummary {
        LoginSummary {
            id: l.id.clone(),
            title: l.title.clone(),
            username: l.username.clone(),
            urls: l.urls.clone(),
            tags: l.tags.clone(),
            has_totp: l.totp_uri.is_some(),
            created_at: l.created_at,
            updated_at: l.updated_at,
        }
    }

    pub fn add_card(
        &mut self,
        title: &str,
        cardholder: &str,
        number: &str,
        expiry: &str,
        cvv: &str,
        notes: &str,
        tags: Vec<String>,
        db: &crate::storage::db::Db,
        key: &[u8; 32],
    ) -> Result<CardSummary> {
        let id = crate::storage::db::new_id();
        let now = crate::storage::db::unix_now();
        let cardholder_enc = if cardholder.is_empty() {
            String::new()
        } else {
            encrypt_field(cardholder, key)?
        };
        let number_enc = encrypt_field(number, key)?;
        let cvv_enc = if cvv.is_empty() {
            String::new()
        } else {
            encrypt_field(cvv, key)?
        };
        let notes_enc = if notes.is_empty() {
            String::new()
        } else {
            encrypt_field(notes, key)?
        };
        let tags_json = serde_json::to_string(&tags)?;

        let raw = crate::storage::db::VaultCardRaw {
            id: id.clone(),
            title: title.to_owned(),
            cardholder_enc,
            number_enc,
            expiry: expiry.to_owned(),
            cvv_enc,
            notes_enc,
            tags_json,
            created_at: now,
            updated_at: now,
        };
        db.vault_card_upsert(&raw)?;

        let card = VaultCard {
            id: id.clone(),
            title: title.to_owned(),
            cardholder: cardholder.to_owned(),
            number: number.to_owned(),
            expiry: expiry.to_owned(),
            cvv: cvv.to_owned(),
            notes: notes.to_owned(),
            tags: tags.clone(),
            created_at: now,
            updated_at: now,
        };
        let summary = Self::card_summary(&card);
        self.cards.insert(id, card);
        Ok(summary)
    }

    pub fn delete_card(&mut self, id: &str, db: &crate::storage::db::Db) -> Result<()> {
        self.cards.remove(id);
        db.vault_card_delete(id)
    }

    pub fn get_card_secret(&self, id: &str) -> Option<&VaultCard> {
        self.cards.get(id)
    }

    pub fn list_cards(&self) -> Vec<CardSummary> {
        let mut v: Vec<_> = self.cards.values().map(|c| Self::card_summary(c)).collect();
        v.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        v
    }

    fn card_summary(c: &VaultCard) -> CardSummary {
        let last_four = c
            .number
            .chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        CardSummary {
            id: c.id.clone(),
            title: c.title.clone(),
            cardholder: c.cardholder.clone(),
            last_four,
            expiry: c.expiry.clone(),
            tags: c.tags.clone(),
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }

    pub fn add_note(
        &mut self,
        title: &str,
        content: &str,
        tags: Vec<String>,
        db: &crate::storage::db::Db,
        key: &[u8; 32],
    ) -> Result<NoteSummary> {
        let id = crate::storage::db::new_id();
        let now = crate::storage::db::unix_now();
        let content_enc = encrypt_field(content, key)?;
        let tags_json = serde_json::to_string(&tags)?;

        let raw = crate::storage::db::VaultNoteRaw {
            id: id.clone(),
            title: title.to_owned(),
            content_enc,
            tags_json,
            created_at: now,
            updated_at: now,
        };
        db.vault_note_upsert(&raw)?;

        let note = VaultNote {
            id: id.clone(),
            title: title.to_owned(),
            content: content.to_owned(),
            tags: tags.clone(),
            created_at: now,
            updated_at: now,
        };
        let summary = Self::note_summary(&note);
        self.notes.insert(id, note);
        Ok(summary)
    }

    pub fn delete_note(&mut self, id: &str, db: &crate::storage::db::Db) -> Result<()> {
        self.notes.remove(id);
        db.vault_note_delete(id)
    }

    pub fn get_note_secret(&self, id: &str) -> Option<&VaultNote> {
        self.notes.get(id)
    }

    pub fn list_notes(&self) -> Vec<NoteSummary> {
        let mut v: Vec<_> = self.notes.values().map(|n| Self::note_summary(n)).collect();
        v.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        v
    }

    fn note_summary(n: &VaultNote) -> NoteSummary {
        NoteSummary {
            id: n.id.clone(),
            title: n.title.clone(),
            tags: n.tags.clone(),
            created_at: n.created_at,
            updated_at: n.updated_at,
        }
    }

    /// Import from a CSV export.
    /// Recognised columns (case-insensitive):
    ///   `name`/`title`, `username`/`login_username`, `password`/`login_password`,
    ///   `url`/`login_uri`, `notes`, `type`
    pub fn import_csv(
        &mut self,
        csv: &str,
        db: &crate::storage::db::Db,
        key: &[u8; 32],
    ) -> Result<usize> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(csv.as_bytes());

        let headers: Vec<String> = reader.headers()?.iter().map(|h| h.to_lowercase()).collect();

        let col = |names: &[&str]| -> Option<usize> {
            names
                .iter()
                .find_map(|n| headers.iter().position(|h| h == n))
        };

        let c_title = col(&["name", "title", "item name"]);
        let c_user = col(&["username", "login_username", "user_name", "email"]);
        let c_password = col(&["password", "login_password"]);
        let c_url = col(&["url", "login_uri", "uri", "website"]);
        let c_notes = col(&["notes", "extra", "comment"]);

        let mut imported = 0usize;
        for result in reader.records() {
            let record = result?;
            let get = |idx: Option<usize>| -> &str {
                idx.and_then(|i| record.get(i)).unwrap_or("").trim()
            };
            let title = get(c_title);
            let username = get(c_user);
            let password = get(c_password);
            let url_raw = get(c_url);
            let notes = get(c_notes);

            if title.is_empty() && username.is_empty() && password.is_empty() {
                continue;
            }
            let urls = if url_raw.is_empty() {
                vec![]
            } else {
                vec![url_raw.to_owned()]
            };
            self.add_login(
                if title.is_empty() { "Imported" } else { title },
                username,
                password,
                urls,
                notes,
                vec![],
                None,
                db,
                key,
            )?;
            imported += 1;
        }
        Ok(imported)
    }

    pub fn stats(&self) -> VaultStats {
        let weak_count = self
            .logins
            .values()
            .filter(|l| score_password(&l.password).score < 2)
            .count();
        let reused: HashMap<&str, usize> = {
            let mut m: HashMap<&str, usize> = HashMap::new();
            for l in self.logins.values() {
                *m.entry(l.password.as_str()).or_insert(0) += 1;
            }
            m
        };
        let reused_count = reused.values().filter(|&&c| c > 1).count();

        VaultStats {
            login_count: self.logins.len(),
            card_count: self.cards.len(),
            note_count: self.notes.len(),
            weak_count,
            reused_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStats {
    pub login_count: usize,
    pub card_count: usize,
    pub note_count: usize,
    pub weak_count: usize,
    pub reused_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_strength_empty() {
        let s = score_password("");
        assert_eq!(s.score, 0);
    }

    #[test]
    fn password_strength_weak() {
        assert!(score_password("abc").score < 2);
    }

    #[test]
    fn password_strength_strong() {
        assert!(score_password("X9#mTqLv@2KrP!nBzW&8").score >= 3);
    }

    #[test]
    fn generate_password_respects_length() {
        let cfg = PasswordConfig {
            length: 24,
            uppercase: true,
            numbers: true,
            symbols: true,
        };
        let pw = generate_password(&cfg);
        assert_eq!(pw.len(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_passphrase_word_count() {
        let cfg = PassphraseConfig {
            word_count: 4,
            separator: "-".to_owned(),
            capitalise: false,
            include_number: false,
        };
        let pp = generate_passphrase(&cfg);
        assert_eq!(pp.split('-').count(), 4);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = "hunter2";
        let enc = encrypt_field(plaintext, &key).unwrap();
        let dec = decrypt_field(&enc, &key).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encrypt_different_nonce_each_call() {
        let key = [1u8; 32];
        let enc1 = encrypt_field("secret", &key).unwrap();
        let enc2 = encrypt_field("secret", &key).unwrap();
        assert_ne!(enc1, enc2);
    }
}
