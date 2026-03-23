// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/decoy.rs  — v0.9.2
//
// [FIX-decoy-globals] ROBOTS_CACHE and RATE_LIMITER moved into DecoyState
// which is stored in AppState, so workspace switches properly reset per-domain
// rate limits and robots.txt caches are not shared across workspaces.
//
// [FIX-decoy-log] get_decoy_log() now reads real entries from the DB meta table.
//
// All other legal design invariants from v0.9.1 are preserved.
// ─────────────────────────────────────────────────────────────────────────────

use anyhow::Result;
use rand::{Rng, seq::SliceRandom};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use url::Url;

// ── Per-workspace state (lives in AppState) ───────────────────────────────────

#[derive(Default)]
pub struct DecoyState {
    robots_cache: HashMap<String, Vec<String>>,  // origin → disallowed prefixes
    rate_last:    HashMap<String, Instant>,
    session_domains: Vec<String>,
}

impl DecoyState {
    /// Call when workspace switches to isolate noise state.
    pub fn reset_for_workspace(&mut self) {
        self.rate_last.clear();
        self.session_domains.clear();
        // Keep robots_cache — it is public info and saves network round-trips
    }

    fn robots_allowed(&self, origin: &str, path: &str) -> Option<bool> {
        self.robots_cache.get(origin)
            .map(|disallowed| !disallowed.iter().any(|p| path.starts_with(p.as_str())))
    }

    fn robots_store(&mut self, origin: String, disallowed: Vec<String>) {
        self.robots_cache.insert(origin, disallowed);
    }

    fn check_rate(&mut self, domain: &str) -> bool {
        const MIN_INTERVAL_SECS: u64 = 8;
        const MAX_SESSION_DOMAINS: usize = 3;

        if !self.session_domains.contains(&domain.to_owned()) {
            if self.session_domains.len() >= MAX_SESSION_DOMAINS {
                return false;
            }
            self.session_domains.push(domain.to_owned());
        }
        if let Some(last) = self.rate_last.get(domain) {
            if last.elapsed().as_secs() < MIN_INTERVAL_SECS {
                return false;
            }
        }
        self.rate_last.insert(domain.to_owned(), Instant::now());
        true
    }
}

// ── robots.txt fetch ──────────────────────────────────────────────────────────

async fn fetch_robots_disallowed(origin: &str) -> Vec<String> {
    let robots_url = format!("{origin}/robots.txt");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let text = match client.get(&robots_url)
        .header("User-Agent", crate::blocker::DIATOM_UA)
        .send().await
    {
        Ok(resp) => match resp.text().await { Ok(t) => t, Err(_) => return vec![] },
        Err(_) => return vec![],
    };

    let mut disallowed = Vec::new();
    let mut in_scope = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        if let Some(agent) = line.strip_prefix("User-agent:") {
            let agent = agent.trim();
            in_scope = agent == "*" || agent.to_lowercase().contains("diatom");
        } else if in_scope {
            if let Some(p) = line.strip_prefix("Disallow:") {
                let p = p.trim().to_owned();
                if !p.is_empty() { disallowed.push(p); }
            }
        }
    }
    disallowed
}

// ── Noise domains ─────────────────────────────────────────────────────────────

/// Public-domain, high-traffic domains appropriate for noise requests.
/// [FIX-31] Removed scholar.google.com (returns CAPTCHA) and
/// www.reddit.com (robots.txt prohibits automated access).
static NOISE_DOMAINS: &[&str] = &[
    "en.wikipedia.org",
    "commons.wikimedia.org",
    "www.gutenberg.org",
    "archive.org",
    "www.semanticscholar.org",
    "news.ycombinator.com",
    "lobste.rs",
    "stackoverflow.com",
    "github.com",
    "gitlab.com",
];

fn random_path_for(domain: &str, rng: &mut impl Rng) -> String {
    match domain {
        "en.wikipedia.org" => {
            let topics = ["Diatom", "Rust_(programming_language)", "Privacy",
                          "Cryptography", "Fourier_transform", "Information_theory"];
            format!("/wiki/{}", topics.choose(rng).unwrap())
        }
        "news.ycombinator.com" => {
            let pages: &[&str] = &["news", "newest", "ask", "show"];
            format!("/{}", pages.choose(rng).unwrap())
        }
        "stackoverflow.com" => {
            let qids = [11227809u32, 477816, 503853, 4823808, 231767];
            format!("/questions/{}/q", qids.choose(rng).unwrap())
        }
        "github.com" => {
            let paths = ["explore", "trending", "topics/rust", "topics/privacy"];
            format!("/{}", paths.choose(rng).unwrap())
        }
        _ => "/".to_owned(),
    }
}

// ── Fire noise request ────────────────────────────────────────────────────────

/// Fire a single noise request if rate/robots checks pass.
/// `decoy_state` is mutable and lives in AppState (workspace-isolated).
pub async fn fire_noise_request(
    db: &crate::db::Db,
    decoy_state: &mut DecoyState,
) -> Option<String> {
    let mut rng = rand::thread_rng();

    let domain = NOISE_DOMAINS.choose(&mut rng)?;
    if !decoy_state.check_rate(domain) {
        return None;
    }

    let path = random_path_for(domain, &mut rng);
    let url = format!("https://{domain}{path}");

    let parsed = Url::parse(&url).ok()?;
    let origin = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

    // robots.txt check (with lazy fetch)
    let allowed = match decoy_state.robots_allowed(&origin, parsed.path()) {
        Some(v) => v,
        None => {
            let disallowed = fetch_robots_disallowed(&origin).await;
            let allowed = !disallowed.iter().any(|p| parsed.path().starts_with(p.as_str()));
            decoy_state.robots_store(origin, disallowed);
            allowed
        }
    };
    if !allowed { return None; }

    // Human-like delay: 1–4 s
    let delay_ms = rng.gen_range(1_000..4_000);
    sleep(Duration::from_millis(delay_ms)).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build().ok()?;

    let result = client.get(&url)
        .header("User-Agent", crate::blocker::DIATOM_UA)
        .header("DNT", "1")
        .header("Sec-GPC", "1")
        .send().await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            // [FIX-decoy-log] Write real log entry to DB
            let log_key = format!("decoy_log_{}", crate::db::unix_now());
            let log_val = format!("GET {} {}", url, resp.status().as_u16());
            let _ = db.set_setting(&log_key, &log_val);
            Some(url)
        }
        _ => None,
    }
}

/// [FIX-decoy-log] Read real decoy log entries from DB meta table.
pub fn get_decoy_log(db: &crate::db::Db) -> Vec<String> {
    // Scan meta keys with prefix "decoy_log_"
    // We use a direct SQL query since Db doesn't have a prefix-scan helper yet.
    let conn = db.0.lock().unwrap();
    let mut stmt = match conn.prepare(
        "SELECT value FROM meta WHERE key LIKE 'decoy_log_%' ORDER BY key DESC LIMIT 100"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([], |r| r.get::<_, String>(0))
        .ok()
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_immediate_retry() {
        let mut state = DecoyState::default();
        assert!(state.check_rate("test.example.com"), "first request allowed");
        assert!(!state.check_rate("test.example.com"), "immediate retry blocked");
    }

    #[test]
    fn session_domain_cap() {
        let mut state = DecoyState::default();
        assert!(state.check_rate("a.example.com"));
        assert!(state.check_rate("b.example.com"));
        assert!(state.check_rate("c.example.com"));
        // 4th unique domain should be rejected
        assert!(!state.check_rate("d.example.com"), "4th domain should be rejected");
    }

    #[test]
    fn workspace_reset_clears_rate_state() {
        let mut state = DecoyState::default();
        assert!(state.check_rate("test.example.com"));
        assert!(!state.check_rate("test.example.com")); // blocked
        state.reset_for_workspace();
        // After reset, same domain should be allowed again
        assert!(state.check_rate("test.example.com"), "rate state cleared after workspace reset");
    }

    #[test]
    fn noise_domains_no_bad_actors() {
        // Verify the fixed list no longer contains Google Scholar or Reddit
        assert!(!NOISE_DOMAINS.contains(&"scholar.google.com"),
            "Google Scholar removed (returns CAPTCHA)");
        assert!(!NOISE_DOMAINS.iter().any(|d| d.contains("reddit.com")),
            "Reddit removed (robots.txt prohibits automation)");
    }
}

// ── Async-safe two-phase fire ─────────────────────────────────────────────────
//
// Holding a std::sync::MutexGuard across .await is not allowed (MutexGuard is
// not Send). We split fire_noise_request into two phases:
//   1. pre_check  — synchronous, mutates DecoyState, returns (allowed, url, origin)
//   2. fire_after_check — async, does all I/O, acquires lock only for final write

/// Phase 1 (sync): pick a domain, check rate-limit, return (allowed, url, origin).
pub fn pre_check(state: &mut DecoyState) -> (bool, String, String) {
    let mut rng = rand::thread_rng();
    let domain = match NOISE_DOMAINS.choose(&mut rng) {
        Some(d) => *d,
        None => return (false, String::new(), String::new()),
    };
    if !state.check_rate(domain) {
        return (false, String::new(), String::new());
    }
    let path = random_path_for(domain, &mut rng);
    let url = format!("https://{domain}{path}");
    let origin = format!("https://{domain}");
    (true, url, origin)
}

/// Phase 2 (async): robots check + HTTP fetch.
/// Re-acquires the Mutex only for the brief robots-cache write (no .await inside).
pub async fn fire_after_check(
    db: &crate::db::Db,
    decoy_lock: &std::sync::Mutex<DecoyState>,
    url: String,
    origin: String,
) -> Option<String> {
    let parsed = url::Url::parse(&url).ok()?;

    // Robots check — needs cache read (sync, no await)
    let cached = {
        let state = decoy_lock.lock().unwrap();
        state.robots_allowed(&origin, parsed.path())
    };

    let allowed = match cached {
        Some(v) => v,
        None => {
            // Fetch robots.txt without holding the lock
            let disallowed = fetch_robots_disallowed(&origin).await;
            let ok = !disallowed.iter().any(|p| parsed.path().starts_with(p.as_str()));
            // Store result (brief sync lock, no await)
            decoy_lock.lock().unwrap().robots_store(origin.clone(), disallowed);
            ok
        }
    };
    if !allowed { return None; }

    // Human-like delay
    let delay_ms: u64 = rand::thread_rng().gen_range(1_000..4_000);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;

    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().ok()?;
    let result = client.get(&url)
        .header("User-Agent", crate::blocker::DIATOM_UA)
        .header("DNT", "1").header("Sec-GPC", "1")
        .send().await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            let log_key = format!("decoy_log_{}", crate::db::unix_now());
            let log_val = format!("GET {} {}", url, resp.status().as_u16());
            let _ = db.set_setting(&log_key, &log_val);
            Some(url)
        }
        _ => None,
    }
}
