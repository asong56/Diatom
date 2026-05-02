use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-domain or global bandwidth rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthRule {
    /// Glob pattern: "*.example.com", "example.com", or "*" for global.
    pub domain_pattern: String,
    /// Rate limit in kilobits per second. 0 = unlimited.
    pub limit_kbps: u32,
    pub enabled: bool,
}

impl BandwidthRule {
    /// Bytes per second derived from limit_kbps.
    pub fn bytes_per_sec(&self) -> u64 {
        (self.limit_kbps as u64) * 1024 / 8
    }
}

#[derive(Debug)]
struct TokenBucket {
    /// Maximum bytes (bucket capacity).
    capacity: u64,
    /// Current available bytes.
    tokens: f64,
    /// Refill rate in bytes per second.
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity_bytes: u64, bytes_per_sec: u64) -> Self {
        Self {
            capacity: capacity_bytes,
            tokens: capacity_bytes as f64,
            refill_rate: bytes_per_sec as f64,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time since last call.
    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = Instant::now();
    }

    /// Attempt to consume `bytes` tokens. Returns the delay needed if depleted.
    /// Returns Duration::ZERO if tokens are available immediately.
    fn consume(&mut self, bytes: u64) -> Duration {
        self.refill();
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            Duration::ZERO
        } else {
            let deficit = bytes as f64 - self.tokens;
            self.tokens = 0.0;
            let wait_secs = deficit / self.refill_rate;
            Duration::from_secs_f64(wait_secs.min(30.0)) // cap at 30s
        }
    }
}

/// Domains that are always exempt from bandwidth limiting.
const DIATOM_INTERNAL_DOMAINS: &[&str] = &[
    "easylist.to",
    "easylistchina.github.io",
    "versionhistory.googleapis.com",
    "developer.apple.com",
    "api.pwnedpasswords.com",
    "haveibeenpwned.com",
    "chromereleases.googleblog.com",
];

pub struct BandwidthLimiter {
    rules: Mutex<Vec<BandwidthRule>>,
    buckets: Mutex<HashMap<String, TokenBucket>>,
    global_limit_kbps: Mutex<u32>,
    global_bucket: Mutex<Option<TokenBucket>>,
}

impl BandwidthLimiter {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            buckets: Mutex::new(HashMap::new()),
            global_limit_kbps: Mutex::new(0), // 0 = no global limit
            global_bucket: Mutex::new(None),
        }
    }

    /// Check and consume bandwidth for a request. Returns delay if throttled.
    /// Returns Duration::ZERO to proceed immediately, or a delay to wait.
    pub fn check(&self, domain: &str, estimated_bytes: u64) -> Duration {
        if self.is_internal(domain) {
            return Duration::ZERO;
        }

        let mut max_delay = Duration::ZERO;

        {
            let limit = *self.global_limit_kbps.lock().unwrap();
            if limit > 0 {
                let mut global = self.global_bucket.lock().unwrap();
                if global.is_none() {
                    let bps = (limit as u64) * 1024 / 8;
                    *global = Some(TokenBucket::new(bps * 10, bps)); // 10-second burst
                }
                if let Some(ref mut bucket) = *global {
                    let delay = bucket.consume(estimated_bytes);
                    if delay > max_delay {
                        max_delay = delay;
                    }
                }
            }
        }

        {
            let rules = self.rules.lock().unwrap();
            for rule in rules.iter().filter(|r| r.enabled && r.limit_kbps > 0) {
                if glob_matches(&rule.domain_pattern, domain) {
                    let bps = rule.bytes_per_sec();
                    let mut buckets = self.buckets.lock().unwrap();
                    let bucket = buckets
                        .entry(rule.domain_pattern.clone())
                        .or_insert_with(|| TokenBucket::new(bps * 10, bps));
                    let delay = bucket.consume(estimated_bytes);
                    if delay > max_delay {
                        max_delay = delay;
                    }
                    break; // Use the first matching rule only
                }
            }
        }

        max_delay
    }

    /// Set the global bandwidth limit in kbps. 0 = no limit.
    pub fn set_global_limit(&self, kbps: u32) {
        *self.global_limit_kbps.lock().unwrap() = kbps;
        *self.global_bucket.lock().unwrap() = None;
    }

    /// Add or replace a per-domain rule.
    pub fn upsert_rule(&self, rule: BandwidthRule) {
        let mut rules = self.rules.lock().unwrap();
        if let Some(existing) = rules
            .iter_mut()
            .find(|r| r.domain_pattern == rule.domain_pattern)
        {
            *existing = rule.clone();
        } else {
            rules.push(rule.clone());
        }
        self.buckets.lock().unwrap().remove(&rule.domain_pattern);
    }

    /// Remove a per-domain rule.
    pub fn remove_rule(&self, domain_pattern: &str) {
        self.rules
            .lock()
            .unwrap()
            .retain(|r| r.domain_pattern != domain_pattern);
        self.buckets.lock().unwrap().remove(domain_pattern);
    }

    fn is_internal(&self, domain: &str) -> bool {
        DIATOM_INTERNAL_DOMAINS
            .iter()
            .any(|d| domain.eq_ignore_ascii_case(d) || domain.ends_with(&format!(".{}", d)))
    }

    /// Load rules from DB.
    pub fn load_from_db(&self, db: &crate::storage::db::Db) {
        if let Some(json) = db.get_setting("bandwidth_rules") {
            if let Ok(rules) = serde_json::from_str::<Vec<BandwidthRule>>(&json) {
                *self.rules.lock().unwrap() = rules;
            }
        }
        if let Some(limit) = db
            .get_setting("bandwidth_global_kbps")
            .and_then(|v| v.parse::<u32>().ok())
        {
            self.set_global_limit(limit);
        }
    }

    /// Persist rules to DB.
    pub fn save_to_db(&self, db: &crate::storage::db::Db) -> Result<()> {
        let rules = self.rules.lock().unwrap();
        db.set_setting("bandwidth_rules", &serde_json::to_string(&*rules)?)?;
        let global = *self.global_limit_kbps.lock().unwrap();
        db.set_setting("bandwidth_global_kbps", &global.to_string())?;
        Ok(())
    }
}

impl Default for BandwidthLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple glob matching: "*" matches everything, "*.domain.com" matches subdomains.
fn glob_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".domain.com"
        return domain.eq_ignore_ascii_case(&pattern[2..]) // exact match of root
            || domain.to_lowercase().ends_with(suffix);
    }
    pattern.eq_ignore_ascii_case(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_immediate_when_full() {
        let mut bucket = TokenBucket::new(1024 * 1024, 100 * 1024); // 1MB cap, 100KB/s
        let delay = bucket.consume(1024); // consume 1KB
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn token_bucket_delay_when_empty() {
        let mut bucket = TokenBucket::new(1024, 1024); // 1KB cap, 1KB/s
        bucket.tokens = 0.0;
        let delay = bucket.consume(1024);
        assert!(
            delay > Duration::ZERO,
            "depleted bucket should produce delay"
        );
    }

    #[test]
    fn glob_matches_wildcard() {
        assert!(glob_matches("*", "any.domain.com"));
        assert!(glob_matches("*.example.com", "sub.example.com"));
        assert!(glob_matches("*.example.com", "example.com"));
    }

    #[test]
    fn internal_domains_exempt() {
        let limiter = BandwidthLimiter::new();
        limiter.set_global_limit(10); // 10kbps — very restrictive
        let delay = limiter.check("easylist.to", 1024 * 1024);
        assert_eq!(
            delay,
            Duration::ZERO,
            "internal domains must always be exempt"
        );
    }
}
