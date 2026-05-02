use anyhow::{Context, Result};

/// Cached conditional-GET metadata for a single filter list URL.
///

/// The body is NEVER stored in the DB — only the ETag and Last-Modified headers
/// that allow us to send a conditional GET on the next cold start.
/// If the server replies 304, we treat it as a prompt to re-download the full
/// list unconditionally (see `conditional_get`).
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// ETag header value from the last successful response.
    pub etag: Option<String>,
    /// Last-Modified header value from the last successful response.
    pub last_modified: Option<String>,
}

/// Derive a short stable key from a URL for use in the settings table.
pub fn url_cache_key(url: &str) -> String {
    let hash = blake3::hash(url.as_bytes());
    format!("etag_cache:{}", hex::encode(&hash.as_bytes()[..8]))
}

/// Load cached ETag + Last-Modified for `url` from the database.
///

pub fn load(db: &crate::storage::db::Db, url: &str) -> CachedResponse {
    let key = url_cache_key(url);
    let etag = db.get_setting(&format!("{key}:etag"));
    let last_modified = db.get_setting(&format!("{key}:lm"));
    CachedResponse {
        etag,
        last_modified,
    }
}

/// Persist ETag and Last-Modified headers after a 200 OK response.
/// The rule body is held only in-memory; on next cold start the conditional
/// GET either fetches fresh content (200) or triggers a full re-download (304).
pub fn store(
    db: &crate::storage::db::Db,
    url: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
) {
    let key = url_cache_key(url);
    if let Some(e) = etag {
        let _ = db.set_setting(&format!("{key}:etag"), e);
    }
    if let Some(lm) = last_modified {
        let _ = db.set_setting(&format!("{key}:lm"), lm);
    }
    let _ = db.0.lock().unwrap().execute(
        "DELETE FROM meta WHERE key = ?1",
        rusqlite::params![format!("{key}:body")],
    );
}

/// Perform a conditional HTTP GET for `url`.
///
/// Sends If-None-Match / If-Modified-Since if cached values exist.
/// On 304, performs an unconditional GET to retrieve the complete rule set.
///
///   Ok(content)  — fresh content fetched (200 or 304→full re-download)
///   Err(_)       — network/HTTP error
pub async fn conditional_get(
    client: &reqwest::Client,
    url: &str,
    cached: &CachedResponse,
    user_agent: &str,
) -> Result<String> {
    let mut req = client
        .get(url)
        .header("User-Agent", user_agent)
        .header("Accept-Encoding", "gzip")
        .timeout(std::time::Duration::from_secs(30));

    if let Some(etag) = &cached.etag {
        req = req.header("If-None-Match", etag.as_str());
    } else if let Some(lm) = &cached.last_modified {
        req = req.header("If-Modified-Since", lm.as_str());
    }

    let resp = req.send().await.context("conditional GET send")?;

    match resp.status().as_u16() {
        304 => {
            tracing::debug!(
                "[etag] 304 Not Modified (no cached body) — re-downloading full list: {url}"
            );
            let full = client
                .get(url)
                .header("User-Agent", user_agent)
                .header("Accept-Encoding", "gzip")
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await
                .context("unconditional re-download after 304")?
                .text()
                .await
                .context("re-download body")?;
            tracing::debug!("[etag] re-download OK ({} bytes): {url}", full.len());
            Ok(full)
        }
        200 => {
            let content = resp.text().await.context("response body")?;
            tracing::debug!("[etag] 200 OK ({} bytes): {url}", content.len());
            Ok(content)
        }
        s => {
            anyhow::bail!("unexpected status {s} for {url}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_cache_key_stable() {
        let k1 = url_cache_key("https://easylist.to/easylist/easylist.txt");
        let k2 = url_cache_key("https://easylist.to/easylist/easylist.txt");
        assert_eq!(k1, k2);
        assert!(k1.starts_with("etag_cache:"));
    }

    #[test]
    fn different_urls_different_keys() {
        let k1 = url_cache_key("https://example.com/a.txt");
        let k2 = url_cache_key("https://example.com/b.txt");
        assert_ne!(k1, k2);
    }

    /// Compile-time check: CachedResponse must not carry a body field.
    #[test]
    fn cached_response_has_no_body_field() {
        let cr = CachedResponse {
            etag: Some("\"abc123\"".to_owned()),
            last_modified: None,
        };
        assert!(cr.etag.is_some());
    }
}
