use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const DOH_ENDPOINTS: &[(&str, &str)] = &[
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Google", "https://dns.google/dns-query"),
    ("Quad9", "https://dns.quad9.net/dns-query"),
    ("NextDNS", "https://dns.nextdns.io"),
    ("AdGuard", "https://dns.adguard.com/dns-query"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPipeConfig {
    pub enabled: bool,
    /// Which DoH endpoints to use (multiple endpoints enable shredder distribution)
    pub endpoints: Vec<String>,
    /// Routes outbound requests through DoH to prevent traffic analysis.
    pub packet_fragmentation: bool,
    /// Protects only Diatom's own requests (browser-native mode; web content is unaffected)
    pub diatom_own_only: bool,
}

impl Default for GhostPipeConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default; user must opt in.
            endpoints: vec![
                "https://cloudflare-dns.com/dns-query".to_owned(),
                "https://dns.google/dns-query".to_owned(),
            ],
            packet_fragmentation: false,
            diatom_own_only: true,
        }
    }
}

/// Resolves a hostname via DoH (returns the first resolved IP address).
/// in DNS Diatom outboundrequest Resolve
pub async fn resolve_via_doh(domain: &str, endpoint: &str) -> Result<Vec<std::net::IpAddr>> {
    let url = format!("{}?name={}&type=A", endpoint, domain);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let resp = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await?
        .json::<DohJsonResponse>()
        .await?;

    let addrs = resp
        .answer
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.rtype == 1) // A record
        .filter_map(|r| r.data.parse::<std::net::IpAddr>().ok())
        .collect();

    Ok(addrs)
}

#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohRecord>>,
}

#[derive(Debug, Deserialize)]
struct DohRecord {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
}

/// Checks whether a request URL matches configured tunnel patterns; routes via DoH if so.
/// to prevent a DNS queries
pub async fn resolve_fragmented(
    domain: &str,
    endpoints: &[String],
) -> Result<Vec<std::net::IpAddr>> {
    let futures: Vec<_> = endpoints
        .iter()
        .map(|ep| {
            let domain = domain.to_owned();
            let ep = ep.clone();
            async move { resolve_via_doh(&domain, &ep).await }
        })
        .collect();

    let (result, _) = futures::future::select_ok(futures)
        .await
        .map_err(|_| anyhow::anyhow!("All DoH endpoints failed for {}", domain))?;

    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPipeStatus {
    pub enabled: bool,
    pub mode: &'static str,
    pub active_endpoints: Vec<String>,
    pub requests_tunneled: u64,
    pub last_resolution_ms: Option<u64>,
}

impl GhostPipeStatus {
    pub fn from_config(cfg: &GhostPipeConfig, requests_tunneled: u64) -> Self {
        Self {
            enabled: cfg.enabled,
            mode: if cfg.diatom_own_only {
                "browser-integrated"
            } else {
                "system-wide"
            },
            active_endpoints: cfg.endpoints.clone(),
            requests_tunneled,
            last_resolution_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled() {
        let cfg = GhostPipeConfig::default();
        assert!(!cfg.enabled, "GhostPipe must be disabled by default");
        assert!(
            cfg.diatom_own_only,
            "Must default to browser-integrated only"
        );
    }

    #[test]
    fn default_config_has_endpoints() {
        let cfg = GhostPipeConfig::default();
        assert!(!cfg.endpoints.is_empty());
        assert!(cfg.endpoints.iter().all(|e| e.starts_with("https://")));
    }
}
