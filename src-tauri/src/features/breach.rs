use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

const PWNED_PASSWORDS_URL: &str = "https://api.pwnedpasswords.com/range/";
const PWNED_EMAIL_URL: &str = "https://haveibeenpwned.com/api/v3/breachedaccount/";
/// Cache TTL: 7 days in seconds.
const CACHE_TTL_SECS: i64 = 7 * 24 * 3_600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordBreachResult {
    /// True if the password appeared in at least one known breach.
    pub pwned: bool,
    /// Number of times this password appeared in breach datasets.
    pub pwned_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailBreachEntry {
    pub name: String,
    pub breach_date: String,
    pub data_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailBreachResult {
    pub email: String,
    pub breaches: Vec<EmailBreachEntry>,
}

/// Compute SHA-1 of a password and return (full_hash_upper, prefix_5_chars).
fn sha1_prefix(password: &str) -> (String, String) {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:X}", hasher.finalize());
    let prefix = hash[..5].to_owned();
    (hash, prefix)
}

/// Check a single password against HIBP k-anonymity API.
///
/// Only the 5-character SHA-1 prefix is transmitted — never the full hash or
/// the original password.  Response bytes are gzip-cached in `vault_breach_cache`
/// for `CACHE_TTL_SECS` to minimise outbound HIBP requests.
pub async fn check_password(
    client: &reqwest::Client,
    password: &str,
) -> Result<PasswordBreachResult> {
    let (full_hash, prefix) = sha1_prefix(password);
    let url = format!("{}{}", PWNED_PASSWORDS_URL, prefix);

    let resp = client
        .get(&url)
        .header("Add-Padding", "true") // prevents response-size side-channel
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("HIBP password range request")?
        .text()
        .await
        .context("HIBP response body")?;

    parse_hibp_range_response(&full_hash, &prefix, &resp)
}

/// Check a password against HIBP, using the DB k-anonymity prefix cache.
///
/// The raw HIBP response (all ~500 suffixes for this prefix) is gzip-compressed
/// and stored in `vault_breach_cache`.  Subsequent lookups for any password
/// sharing the same 5-char SHA-1 prefix hit the cache rather than the network.
pub async fn check_password_cached(
    client: &reqwest::Client,
    db: &crate::storage::db::Db,
    password: &str,
) -> Result<PasswordBreachResult> {
    let (full_hash, prefix) = sha1_prefix(password);

    // Try DB cache first
    if let Some(gz_bytes) = db.breach_cache_get(&prefix, CACHE_TTL_SECS) {
        let body = decompress_gzip(&gz_bytes).context("breach cache decompress")?;
        let text = String::from_utf8_lossy(&body);
        return parse_hibp_range_response(&full_hash, &prefix, &text);
    }

    // Cache miss — fetch from HIBP
    let url = format!("{}{}", PWNED_PASSWORDS_URL, prefix);
    let body_text = client
        .get(&url)
        .header("Add-Padding", "true")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("HIBP request")?
        .text()
        .await
        .context("HIBP body")?;

    // Compress and store — best-effort; a failure here is not fatal
    if let Ok(gz) = compress_gzip(body_text.as_bytes()) {
        let _ = db.breach_cache_set(&prefix, &gz);
    }

    parse_hibp_range_response(&full_hash, &prefix, &body_text)
}

fn parse_hibp_range_response(
    full_hash: &str,
    _prefix: &str,
    body: &str,
) -> Result<PasswordBreachResult> {
    let suffix = &full_hash[5..];
    for line in body.lines() {
        let mut parts = line.splitn(2, ':');
        if let (Some(s), Some(c)) = (parts.next(), parts.next()) {
            if s.trim().eq_ignore_ascii_case(suffix) {
                let count: u64 = c.trim().parse().unwrap_or(1);
                return Ok(PasswordBreachResult {
                    pwned: true,
                    pwned_count: count,
                });
            }
        }
    }
    Ok(PasswordBreachResult {
        pwned: false,
        pwned_count: 0,
    })
}

/// Check a vault login's password and write the result back into the DB record.
///
/// This is the integration point that makes breach status a *property of a
/// credential* rather than a standalone feature.  Call from the background
/// scan task or when a vault record is created/updated.
pub async fn scan_login_and_persist(
    client: &reqwest::Client,
    db: &crate::storage::db::Db,
    login_id: &str,
    password: &str,
) -> Result<PasswordBreachResult> {
    let result = check_password_cached(client, db, password).await?;
    let status = if result.pwned { "pwned" } else { "clean" };
    db.vault_login_set_breach(
        login_id,
        status,
        result.pwned_count as i64,
        crate::storage::db::unix_now(),
    )?;
    Ok(result)
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data)?;
    enc.finish().context("gzip compress")
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).context("gzip decompress")?;
    Ok(out)
}

/// Check an email address against HIBP v3 breachedaccount API.
///
/// # API key requirement
/// HIBP v3 email lookups require a paid API key. The key must be stored in the
/// Diatom settings DB under `"hibp_api_key"` before calling this function.
/// The caller (`cmd_breach_check_email`) must verify opt-in AND key presence
/// before dispatching here.
///
/// # Privacy
/// This transmits the full email address to HIBP. The user must have explicitly
/// opted in via the `breach_monitor_email` toggle. Requests use a random
/// User-Agent (not the Diatom UA) to reduce correlation with browsing activity.
pub async fn check_email(
    client: &reqwest::Client,
    email: &str,
    api_key: &str,
) -> Result<EmailBreachResult> {
    if api_key.is_empty() {
        anyhow::bail!(
            "HIBP email lookup requires a paid API key. \
             Add yours at Settings → Privacy → Breach Monitor → HIBP API Key."
        );
    }

    #[derive(Deserialize)]
    struct HibpBreach {
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "BreachDate")]
        breach_date: String,
        #[serde(rename = "DataClasses")]
        data_classes: Vec<String>,
    }

    let encoded_email = urlencoding::encode(email).into_owned();
    let url = format!("{}{}", PWNED_EMAIL_URL, encoded_email);

    let resp = client
        .get(&url)
        .header("hibp-api-key", api_key)
        .header("User-Agent", random_generic_ua())
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .context("HIBP email breach request")?;

    let status = resp.status().as_u16();

    match status {
        404 => {
            return Ok(EmailBreachResult {
                email: email.to_owned(),
                breaches: vec![],
            });
        }
        401 => anyhow::bail!(
            "HIBP rejected the API key (401 Unauthorized). Check your key at Settings → Privacy → Breach Monitor."
        ),
        403 => anyhow::bail!(
            "HIBP user agent was blocked (403 Forbidden). This is a Diatom bug — please report it."
        ),
        429 => anyhow::bail!("HIBP rate limit reached (429). Wait ~1 500 ms and retry."),
        s if !(200..300).contains(&(s as i32)) => {
            anyhow::bail!("HIBP email request failed with HTTP {s}");
        }
        _ => {}
    }

    let entries: Vec<HibpBreach> = resp.json().await.context("HIBP email response parse")?;
    let breaches = entries
        .into_iter()
        .map(|e| EmailBreachEntry {
            name: e.name,
            breach_date: e.breach_date,
            data_classes: e.data_classes,
        })
        .collect();

    Ok(EmailBreachResult {
        email: email.to_owned(),
        breaches,
    })
}
/// Return a generic browser UA to prevent Diatom correlation on HIBP calls.
///
/// Uses a CSPRNG-backed random pick via `rand::thread_rng()` so each call
/// independently selects a UA regardless of call timing.
fn random_generic_ua() -> &'static str {
    use rand::Rng;
    const UAS: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ];
    let idx = rand::thread_rng().gen_range(0..UAS.len());
    UAS[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_prefix_length() {
        let (full, prefix) = sha1_prefix("password123");
        assert_eq!(full.len(), 40);
        assert_eq!(prefix.len(), 5);
        assert!(full.starts_with(&prefix));
    }

    #[test]
    fn sha1_prefix_known_value() {
        let (full, prefix) = sha1_prefix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(&full[..5], "5BAA6");
    }

    #[test]
    fn url_encode_email() {
        let encoded = urlencoding::encode("user@example.com");
        assert!(encoded.contains("%40"));
        assert!(!encoded.contains('@'));
    }

    /// Ensure random_generic_ua never panics and always returns a non-empty string.
    #[test]
    fn random_ua_is_always_non_empty() {
        for _ in 0..20 {
            assert!(!random_generic_ua().is_empty());
        }
    }

    #[test]
    fn parse_hibp_range_hit() {
        // "password" SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (hash, _prefix) = sha1_prefix("password");
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\nDEADBEEF:1\n";
        let result = parse_hibp_range_response(&hash, "5BAA6", body).unwrap();
        assert!(result.pwned);
        assert_eq!(result.pwned_count, 3730471);
    }

    #[test]
    fn parse_hibp_range_miss() {
        let (hash, _prefix) = sha1_prefix("very_unique_correct_horse_battery_staple_42!");
        let body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n";
        let result = parse_hibp_range_response(&hash, "AAAAA", body).unwrap();
        assert!(!result.pwned);
        assert_eq!(result.pwned_count, 0);
    }

    #[test]
    fn gzip_roundtrip() {
        let original = b"HIBP suffix response body text";
        let compressed = compress_gzip(original).unwrap();
        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }
}
