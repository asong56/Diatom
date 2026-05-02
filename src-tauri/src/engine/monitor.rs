use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetDirection {
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetPurpose {
    /// Sentinel: queries for the latest Chrome/Safari version (required for UA spoofing).
    SentinelVersionCheck,
    /// Threat list updates (URLhaus/PhishTank).
    ThreatListUpdate,
    /// Filter rule lists (EasyList etc.)
    FilterListUpdate,
    /// Nostr relay sync (user-enabled)
    NostrRelay,
    /// Quad9 DoH domain security check (optional, user-enabled).
    Quad9DohCheck,
    /// User-initiated web page request (pass-through; not Diatom-originated)
    PageContent,
    /// Other (logged but flagged)
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEvent {
    pub ts_ms: u64,
    pub direction: NetDirection,
    pub purpose: NetPurpose,
    pub host: String,
    pub url_redacted: String, // Never logs full URL; records host + first 32 chars of path only.
    pub bytes_approx: Option<u64>,
    pub status: Option<u16>,
}

pub struct NetMonitor {
    log: Mutex<VecDeque<NetEvent>>,
}

impl Default for NetMonitor {
    fn default() -> Self {
        Self {
            log: Mutex::new(VecDeque::with_capacity(MAX_LOG)),
        }
    }
}

impl NetMonitor {
    pub fn record(&self, purpose: NetPurpose, url: &str, status: Option<u16>, bytes: Option<u64>) {
        let host = extract_host(url);
        let url_redacted = redact_url(url);
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let event = NetEvent {
            ts_ms,
            direction: NetDirection::Outgoing,
            purpose,
            host,
            url_redacted,
            bytes_approx: bytes,
            status,
        };

        let mut log = self.log.lock().unwrap();
        if log.len() >= MAX_LOG {
            log.pop_front();
        }
        log.push_back(event);
    }

    pub fn recent(&self, limit: usize) -> Vec<NetEvent> {
        let log = self.log.lock().unwrap();
        log.iter().rev().take(limit).cloned().collect()
    }

    pub fn clear(&self) {
        self.log.lock().unwrap().clear();
    }

    pub fn summary(&self) -> NetMonitorSummary {
        let log = self.log.lock().unwrap();
        let total = log.len();
        let diatom_own = log
            .iter()
            .filter(|e| !matches!(e.purpose, NetPurpose::PageContent))
            .count();
        let unique_hosts: std::collections::HashSet<&str> = log
            .iter()
            .filter(|e| !matches!(e.purpose, NetPurpose::PageContent))
            .map(|e| e.host.as_str())
            .collect();
        NetMonitorSummary {
            total_events: total,
            diatom_own_requests: diatom_own,
            unique_diatom_hosts: unique_hosts.len(),
            page_content_requests: total - diatom_own,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetMonitorSummary {
    pub total_events: usize,
    /// Number of requests initiated by the Diatom process itself (excluding user web content)
    pub diatom_own_requests: usize,
    /// Diatom request aHost
    pub unique_diatom_hosts: usize,
    /// Number of user web content requests (pass-through count only)
    pub page_content_requests: usize,
}

fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_owned()))
        .unwrap_or_else(|| url.chars().take(40).collect())
}

fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let path: String = u.path().chars().take(32).collect();
            let ellipsis = if u.path().len() > 32 { "…" } else { "" };
            format!(
                "{}://{}{}{}",
                u.scheme(),
                u.host_str().unwrap_or("?"),
                path,
                ellipsis
            )
        }
        Err(_) => url.chars().take(60).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve() {
        let m = NetMonitor::default();
        m.record(
            NetPurpose::SentinelVersionCheck,
            "https://versionhistory.googleapis.com/v1/chrome",
            Some(200),
            Some(1024),
        );
        let events = m.recent(10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, "versionhistory.googleapis.com");
        assert!(!events[0].url_redacted.contains('?'));
    }

    #[test]
    fn summary_counts_correctly() {
        let m = NetMonitor::default();
        m.record(
            NetPurpose::SentinelVersionCheck,
            "https://example.com/sentinel",
            Some(200),
            None,
        );
        m.record(
            NetPurpose::PageContent,
            "https://news.ycombinator.com/",
            Some(200),
            None,
        );
        let s = m.summary();
        assert_eq!(s.diatom_own_requests, 1);
        assert_eq!(s.page_content_requests, 1);
    }
}
