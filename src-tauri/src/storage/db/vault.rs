//! Encrypted vault (passwords, cards, notes) raw storage queries.
//!
//! # Unified credential model (migration 8)
//!
//! Each `vault_logins` row is the canonical record for a site credential.
//! It now carries:
//!   - `totp_uri`             — inline TOTP (otpauth://…), replacing standalone
//!                              `totp_entries` rows for web credentials.
//!   - `passkey_cred_id_enc` / `passkey_user_handle` / `passkey_rp_id` —
//!     the WebAuthn/Passkey credential associated with this login, so the
//!     user sees one record per site rather than three silos.
//!   - `breach_status` / `breach_checked_at` / `breach_pwned_count` —
//!     per-record breach state driven by the HIBP k-anonymity API, so the
//!     "breach monitor" is a property of a credential, not a separate feature.
//!
//! The standalone `totp_entries` table is kept for non-web TOTP codes
//! (hardware tokens, SSH OTPs, etc.) that have no associated password record.

use anyhow::{Context, Result};
use rusqlite::params;

use super::core::Db;
use super::types::{VaultCardRaw, VaultLoginRaw, VaultNoteRaw};

impl Db {
    pub fn vault_login_upsert(&self, r: &VaultLoginRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO vault_logins
             (id,title,username,password_enc,urls_json,notes_enc,tags_json,totp_uri,
              breach_status,breach_checked_at,breach_pwned_count,
              passkey_cred_id_enc,passkey_user_handle,passkey_rp_id,passkey_added_at,
              created_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                r.id,
                r.title,
                r.username,
                r.password_enc,
                r.urls_json,
                r.notes_enc,
                r.tags_json,
                r.totp_uri,
                r.breach_status,
                r.breach_checked_at,
                r.breach_pwned_count,
                r.passkey_cred_id_enc,
                r.passkey_user_handle,
                r.passkey_rp_id,
                r.passkey_added_at,
                r.created_at,
                r.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn vault_login_delete(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM vault_logins WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn vault_logins_raw(&self) -> Result<Vec<VaultLoginRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,title,username,password_enc,urls_json,notes_enc,tags_json,totp_uri,
                    breach_status,breach_checked_at,breach_pwned_count,
                    passkey_cred_id_enc,passkey_user_handle,passkey_rp_id,passkey_added_at,
                    created_at,updated_at
             FROM vault_logins ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(VaultLoginRaw {
                id: r.get(0)?,
                title: r.get(1)?,
                username: r.get(2)?,
                password_enc: r.get(3)?,
                urls_json: r.get(4)?,
                notes_enc: r.get(5)?,
                tags_json: r.get(6)?,
                totp_uri: r.get(7)?,
                breach_status: r
                    .get::<_, Option<String>>(8)?
                    .unwrap_or_else(|| "unknown".into()),
                breach_checked_at: r.get(9)?,
                breach_pwned_count: r.get::<_, Option<i64>>(10)?.unwrap_or(0),
                passkey_cred_id_enc: r.get(11)?,
                passkey_user_handle: r.get(12)?,
                passkey_rp_id: r.get(13)?,
                passkey_added_at: r.get(14)?,
                created_at: r.get(15)?,
                updated_at: r.get(16)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("vault_logins_raw")
    }

    /// Update only the breach fields for a single login — avoids re-encrypting
    /// the credential payload on a background check.
    pub fn vault_login_set_breach(
        &self,
        id: &str,
        status: &str, // "clean" | "pwned"
        pwned_count: i64,
        checked_at: i64,
    ) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE vault_logins
             SET breach_status=?1, breach_pwned_count=?2, breach_checked_at=?3
             WHERE id=?4",
            params![status, pwned_count, checked_at, id],
        )?;
        Ok(())
    }

    /// Attach (or replace) a passkey credential to an existing login record.
    pub fn vault_login_set_passkey(
        &self,
        id: &str,
        cred_id_enc: &str,
        user_handle: &str,
        rp_id: &str,
        added_at: i64,
    ) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE vault_logins
             SET passkey_cred_id_enc=?1, passkey_user_handle=?2,
                 passkey_rp_id=?3, passkey_added_at=?4
             WHERE id=?5",
            params![cred_id_enc, user_handle, rp_id, added_at, id],
        )?;
        Ok(())
    }

    /// Remove passkey from a login record (credential deleted by user or RP).
    pub fn vault_login_clear_passkey(&self, id: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE vault_logins
             SET passkey_cred_id_enc=NULL, passkey_user_handle=NULL,
                 passkey_rp_id=NULL, passkey_added_at=NULL
             WHERE id=?1",
            [id],
        )?;
        Ok(())
    }

    /// Returns cached suffix list for a 5-char SHA-1 prefix, if still fresh
    /// (fetched within `max_age_secs`).
    pub fn breach_cache_get(&self, sha1_prefix: &str, max_age_secs: i64) -> Option<Vec<u8>> {
        let min_ts = super::core::unix_now() - max_age_secs;
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT suffixes_gz FROM vault_breach_cache
             WHERE sha1_prefix=?1 AND fetched_at>=?2",
                params![sha1_prefix, min_ts],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .ok()
    }

    pub fn breach_cache_set(&self, sha1_prefix: &str, suffixes_gz: &[u8]) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO vault_breach_cache(sha1_prefix,suffixes_gz,fetched_at)
             VALUES(?1,?2,?3)",
            params![sha1_prefix, suffixes_gz, super::core::unix_now()],
        )?;
        Ok(())
    }

    pub fn breach_cache_evict_old(&self, max_age_secs: i64) -> Result<usize> {
        let cutoff = super::core::unix_now() - max_age_secs;
        let n = self.0.lock().unwrap().execute(
            "DELETE FROM vault_breach_cache WHERE fetched_at < ?1",
            [cutoff],
        )?;
        Ok(n)
    }

    pub fn vault_card_upsert(&self, r: &VaultCardRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO vault_cards
             (id,title,cardholder_enc,number_enc,expiry,cvv_enc,notes_enc,tags_json,created_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![r.id, r.title, r.cardholder_enc, r.number_enc, r.expiry,
                    r.cvv_enc, r.notes_enc, r.tags_json, r.created_at, r.updated_at],
        )?;
        Ok(())
    }

    pub fn vault_card_delete(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM vault_cards WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn vault_cards_raw(&self) -> Result<Vec<VaultCardRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,title,cardholder_enc,number_enc,expiry,cvv_enc,notes_enc,tags_json,created_at,updated_at
             FROM vault_cards ORDER BY updated_at DESC")?;
        let rows = stmt.query_map([], |r| {
            Ok(VaultCardRaw {
                id: r.get(0)?,
                title: r.get(1)?,
                cardholder_enc: r.get(2)?,
                number_enc: r.get(3)?,
                expiry: r.get(4)?,
                cvv_enc: r.get(5)?,
                notes_enc: r.get(6)?,
                tags_json: r.get(7)?,
                created_at: r.get(8)?,
                updated_at: r.get(9)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("vault_cards_raw")
    }

    pub fn vault_note_upsert(&self, r: &VaultNoteRaw) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO vault_notes
             (id,title,content_enc,tags_json,created_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                r.id,
                r.title,
                r.content_enc,
                r.tags_json,
                r.created_at,
                r.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn vault_note_delete(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM vault_notes WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn vault_notes_raw(&self) -> Result<Vec<VaultNoteRaw>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,title,content_enc,tags_json,created_at,updated_at
             FROM vault_notes ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(VaultNoteRaw {
                id: r.get(0)?,
                title: r.get(1)?,
                content_enc: r.get(2)?,
                tags_json: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("vault_notes_raw")
    }
}
