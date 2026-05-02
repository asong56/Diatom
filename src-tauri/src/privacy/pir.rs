use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use std::time::Duration;
use tokio::time::sleep;

/// Number of cover requests per real request (K in the PIR-T scheme).
pub const DEFAULT_K: usize = 3;

/// All publicly known blocklist URLs that Diatom understands.
/// Cover requests are drawn randomly from this catalogue.
const BLOCKLIST_CATALOGUE: &[&str] = &[
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://easylist.to/easylist/fanboy-annoyance.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://raw.githubusercontent.com/nicehash/nicehash-blocks/master/hosts.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
    "https://v.firebog.net/hosts/static/w3kbl.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
];

/// A PIR-private fetch result.
pub struct PirResult {
    /// Content of the real (target) URL.
    pub content: String,
    /// Number of cover requests sent alongside the real one.
    pub cover_count: usize,
}

/// Fetch `target_url` with PIR-T cover traffic.
///
/// - `k`: number of total requests (1 real + k−1 cover).  Minimum 1 (no cover).
/// - `client`: shared reqwest client (caller manages keep-alive pooling).
/// - `max_jitter_ms`: random delay per request to prevent timing correlation.
pub async fn pir_fetch(
    client: &reqwest::Client,
    target_url: &str,
    k: usize,
    max_jitter_ms: u64,
) -> Result<PirResult> {
    let k = k.max(1);
    let cover_count = k - 1;

    let mut rng = rand::thread_rng();
    let covers: Vec<&str> = BLOCKLIST_CATALOGUE
        .iter()
        .filter(|&&u| u != target_url)
        .copied()
        .collect::<Vec<_>>()
        .choose_multiple(&mut rng, cover_count)
        .copied()
        .collect();

    let mut handles = Vec::with_capacity(k);

    {
        let c = client.clone();
        let url = target_url.to_owned();
        let jitter = rand::random::<u64>() % max_jitter_ms.max(1);
        handles.push(tokio::spawn(async move {
            if jitter > 0 {
                sleep(Duration::from_millis(jitter)).await;
            }
            c.get(&url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .ok()
        }));
    }

    for cover_url in &covers {
        let c = client.clone();
        let url = cover_url.to_string();
        let jitter = rand::random::<u64>() % max_jitter_ms.max(1);
        tokio::spawn(async move {
            if jitter > 0 {
                sleep(Duration::from_millis(jitter)).await;
            }
            let _ = c.get(&url).timeout(Duration::from_secs(15)).send().await;
        });
    }

    let real_resp = handles
        .into_iter()
        .next()
        .expect("at least one handle")
        .await
        .context("real request task")?
        .context("real request failed")?;

    let content = real_resp
        .error_for_status()
        .context("real request HTTP error")?
        .text()
        .await
        .context("real request body")?;

    Ok(PirResult {
        content,
        cover_count,
    })
}

/// Convenience wrapper: PIR-fetch a blocklist URL using the app's HTTP client.
/// Returns the raw text content.
pub async fn fetch_blocklist_private(
    client: &reqwest::Client,
    url: &str,
    k: usize,
) -> Result<String> {
    let result = pir_fetch(client, url, k, 200)
        .await
        .with_context(|| format!("PIR fetch {url}"))?;
    tracing::debug!(
        "[pir] fetched {} with {} cover requests",
        url,
        result.cover_count
    );
    Ok(result.content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_nonempty() {
        assert!(BLOCKLIST_CATALOGUE.len() >= DEFAULT_K);
    }

    #[test]
    fn cover_selection_excludes_target() {
        let target = BLOCKLIST_CATALOGUE[0];
        let mut rng = rand::thread_rng();
        let covers: Vec<&str> = BLOCKLIST_CATALOGUE
            .iter()
            .filter(|&&u| u != target)
            .copied()
            .collect::<Vec<_>>()
            .choose_multiple(&mut rng, DEFAULT_K - 1)
            .copied()
            .collect();
        assert!(covers.iter().all(|&u| u != target));
        assert_eq!(covers.len(), DEFAULT_K - 1);
    }
}
