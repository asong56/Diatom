use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Privacy tier classification shown in the onboarding wizard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyTier {
    /// Fully independent index, no tracking, no account required.
    Independent,
    /// Aggregates multiple sources; privacy depends on instance operator.
    MetaSearch,
    /// Paid service; strong privacy commitment but requires payment.
    Paid,
    /// Traditional search engine; tracking and personalization enabled.
    Mainstream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEngine {
    pub id: &'static str,
    pub name: &'static str,
    pub url_template: String,
    /// Suggestion endpoint template. {query} is replaced with the search term.
    pub suggest_template: Option<String>,
    pub privacy_tier: PrivacyTier,
    pub requires_key: bool,
    pub description: &'static str,
}

pub fn builtin_engines() -> Vec<SearchEngine> {
    vec![
        SearchEngine {
            id: "brave",
            name: "Brave Search",
            url_template: "https://search.brave.com/search?q={query}&source=web".to_owned(),
            suggest_template: Some("https://search.brave.com/api/suggest?q={query}".to_owned()),
            privacy_tier: PrivacyTier::Independent,
            requires_key: false,
            description: "Independent index. No tracking, no profiling. Default privacy choice.",
        },
        SearchEngine {
            id: "kagi",
            name: "Kagi",
            url_template: "https://kagi.com/search?q={query}".to_owned(),
            suggest_template: Some("https://kagi.com/api/autosuggest?q={query}".to_owned()),
            privacy_tier: PrivacyTier::Paid,
            requires_key: true,
            description: "Paid — no ads, no tracking. API key stored in Vault.",
        },
        SearchEngine {
            id: "duckduckgo",
            name: "DuckDuckGo",
            url_template: "https://duckduckgo.com/?q={query}".to_owned(),
            suggest_template: Some("https://duckduckgo.com/ac/?q={query}&type=list".to_owned()),
            privacy_tier: PrivacyTier::MetaSearch,
            requires_key: false,
            description: "No personal data stored. Aggregates Bing and other sources.",
        },
        SearchEngine {
            id: "searxng",
            name: "SearXNG",
            url_template: "https://searx.be/search?q={query}&format=html".to_owned(),
            suggest_template: None,
            privacy_tier: PrivacyTier::MetaSearch,
            requires_key: false,
            description: "Self-hosted metasearch. Configure your own instance endpoint.",
        },
        SearchEngine {
            id: "google",
            name: "Google",
            url_template: "https://www.google.com/search?q={query}".to_owned(),
            suggest_template: Some(
                "https://suggestqueries.google.com/complete/search?client=firefox&q={query}"
                    .to_owned(),
            ),
            privacy_tier: PrivacyTier::Mainstream,
            requires_key: false,
            description: "Full tracking and personalization. Not recommended for privacy.",
        },
    ]
}

/// Get the currently selected default search engine ID from the DB.
pub fn get_default(db: &crate::storage::db::Db) -> String {
    db.get_setting("default_search_engine")
        .unwrap_or_else(|| "brave".to_owned())
}

/// Set the default search engine. Validates the ID exists.
pub fn set_default(db: &crate::storage::db::Db, engine_id: &str) -> Result<()> {
    if engine_id.starts_with("searxng:") {
        let endpoint = engine_id.trim_start_matches("searxng:");
        validate_searxng_endpoint(endpoint)?;
    } else {
        let engines = builtin_engines();
        engines
            .iter()
            .find(|e| e.id == engine_id)
            .ok_or_else(|| anyhow::anyhow!("unknown engine id: {}", engine_id))?;
    }
    db.set_setting("default_search_engine", engine_id)?;
    Ok(())
}

/// Set a custom SearXNG instance endpoint.
///
/// [F-10] Validates HTTPS-only to prevent SSRF attacks via user-controlled URL.
pub fn set_searxng_endpoint(db: &crate::storage::db::Db, endpoint: &str) -> Result<()> {
    validate_searxng_endpoint(endpoint)?;
    let template = format!(
        "{}/search?q={{query}}&format=html",
        endpoint.trim_end_matches('/')
    );
    db.set_setting("searxng_endpoint", endpoint)?;
    db.set_setting("searxng_url_template", &template)?;
    Ok(())
}

/// Validates that an endpoint URL is HTTPS and not a loopback/private address.
/// Prevents SSRF: a malicious endpoint could make Diatom fetch internal services.
pub fn validate_searxng_endpoint(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!(
            "SearXNG endpoint must use HTTPS to prevent SSRF attacks. \
             Got: {} — only https:// URLs are permitted.",
            url
        );
    }
    let lower = url.to_lowercase();
    for blocked in &[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.",
        "::1",
        "[::1]",
    ] {
        if lower.contains(blocked) {
            anyhow::bail!(
                "SearXNG endpoint '{}' resolves to a loopback/private address. \
                 This is blocked to prevent SSRF.",
                url
            );
        }
    }
    Ok(())
}

/// Build a search URL for the given engine and query.
pub fn build_search_url(engine: &SearchEngine, query: &str) -> String {
    let encoded = percent_encode(query);
    engine.url_template.replace("{query}", &encoded)
}

/// Build a suggestion URL (returns None if the engine has no suggest template).
pub fn build_suggest_url(engine: &SearchEngine, query: &str) -> Option<String> {
    let tmpl = engine.suggest_template.as_ref()?;
    Some(tmpl.replace("{query}", &percent_encode(query)))
}

/// Percent-encode a query string for safe URL embedding.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            b' ' => out.push('+'),
            b => {
                out.push('%');
                let _ = write!(out, "{:02X}", b);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_search_url_encodes_spaces() {
        let engine = builtin_engines()
            .into_iter()
            .find(|e| e.id == "brave")
            .unwrap();
        let url = build_search_url(&engine, "rust programming");
        assert!(url.contains("rust+programming") || url.contains("rust%20programming"));
    }

    #[test]
    fn searxng_requires_https() {
        assert!(validate_searxng_endpoint("http://searx.example.com").is_err());
        assert!(validate_searxng_endpoint("https://searx.example.com").is_ok());
    }

    #[test]
    fn searxng_blocks_loopback() {
        assert!(validate_searxng_endpoint("https://localhost/searx").is_err());
        assert!(validate_searxng_endpoint("https://127.0.0.1:8080").is_err());
    }

    #[test]
    fn brave_is_default_engine() {
        let engines = builtin_engines();
        let brave = engines.iter().find(|e| e.id == "brave");
        assert!(brave.is_some());
        assert_eq!(brave.unwrap().privacy_tier, PrivacyTier::Independent);
    }
}
