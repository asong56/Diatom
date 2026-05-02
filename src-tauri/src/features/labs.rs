use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LabStability {
    Alpha,
    Beta,
    Stable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LabRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lab {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub stability: LabStability,
    pub risk: LabRisk,
    pub risk_note: &'static str,
    pub enabled: bool,
    pub restart_required: bool,
    pub added_in: &'static str,
}
/// Compact constructor macro — eliminates the 10-field repetition across all lab entries.
/// Each argument maps positionally to a Lab field in declaration order.
macro_rules! lab {
    ($id:literal, $name:literal, $desc:literal, $cat:literal,
     $stab:ident, $risk:ident, $note:literal,
     $on:literal, $rs:literal, $ver:literal) => {
        Lab {
            id: $id,
            name: $name,
            description: $desc,
            category: $cat,
            stability: LabStability::$stab,
            risk: LabRisk::$risk,
            risk_note: $note,
            enabled: $on,
            restart_required: $rs,
            added_in: $ver,
        }
    };
}

/// All built-in lab definitions. Allocated once at startup via `LazyLock`.
pub static ALL_LABS: LazyLock<Vec<Lab>> = LazyLock::new(build_labs);

/// Return a reference to the immutable built-in lab list.
#[inline]
pub fn all_labs() -> &'static [Lab] {
    &ALL_LABS
}

fn build_labs() -> Vec<Lab> {
    vec![
        lab!(
            "sentinel_ua",
            "Dynamic User-Agent (Sentinel)",
            "Automatically tracks the current stable Chrome and Safari versions \
                          and synthesises a matching User-Agent string. Diatom blends into \
                          the most common browser population rather than advertising itself.",
            "Privacy",
            Beta,
            Low,
            "Requires one network poll per hour to versionhistory.googleapis.com \
                        and developer.apple.com. Polls use the generic fallback UA so Diatom \
                        does not fingerprint itself during the poll.",
            true,
            false,
            "v0.9.1"
        ),
        lab!(
            "pqc_envelope",
            "Post-Quantum Freeze Encryption",
            "Encrypts Museum bundles with Kyber-768 + AES-256-GCM hybrid envelope.",
            "Privacy",
            Beta,
            Low,
            "Bundles encrypted with this flag cannot be decrypted by older Diatom versions.",
            false,
            false,
            "v0.8.0"
        ),
        lab!(
            "fingerprint_norm",
            "Fingerprint Normalisation",
            "Overrides hardware-concurrency, device-memory, WebGL vendor/renderer, \
                          AudioContext sample-rate, and Canvas toDataURL with the statistical \
                          mode for desktop hardware. Every Diatom instance presents an identical \
                          fingerprint surface, making individual identification impractical. \
                          All values are static constants — no randomness, no per-session drift.",
            "Privacy",
            Stable,
            Low,
            "Canvas perturbation is deterministic per-domain (hostname-keyed seed). \
                        Sites that depend on hardware-concurrency for thread-pool sizing may \
                        behave differently. No effect on audio playback quality.",
            true,
            false,
            "v0.16.0"
        ),
        lab!(
            "zkp_age_gate",
            "Zero-Knowledge Age Verification",
            "Proves age threshold to participating sites without revealing birth year.",
            "Privacy",
            Alpha,
            High,
            "Proof transport is non-standard. Sites must opt-in.",
            false,
            false,
            "v0.8.0"
        ),
        lab!(
            "timezone_spoof",
            "Timezone Normalisation",
            "Overrides JS timezone APIs to report UTC, preventing locale fingerprinting.",
            "Privacy",
            Beta,
            Medium,
            "Calendar apps and trading platforms may display incorrect times.",
            false,
            false,
            "v0.9.0"
        ),
        lab!(
            "jitter_all_requests",
            "Global Request Jitter",
            "Adds 0–50ms cryptographic delay to every outbound request, \
                          defeating timing correlation attacks.",
            "Privacy",
            Stable,
            Low,
            "Adds up to 50ms latency per request. Imperceptible on most connections.",
            false,
            false,
            "v0.8.0"
        ),
        lab!(
            "slm_server",
            "Local AI Microkernel",
            "Starts an OpenAI-compatible API server at 127.0.0.1:11435.",
            "AI",
            Beta,
            Low,
            "Opens a local TCP port. Bound to loopback — not accessible from the network.",
            false,
            true,
            "v0.9.0"
        ),
        lab!(
            "slm_extreme_privacy",
            "AI Extreme Privacy Mode",
            "Forces all AI inference into the Wasm sandbox. \
                          Disables Ollama and llama.cpp backends.",
            "AI",
            Alpha,
            Low,
            "Wasm inference is 5–20× slower. Only works for short prompts.",
            false,
            false,
            "v0.9.0"
        ),
        lab!(
            "page_summarise",
            "Instant Page Summariser",
            "Adds a ⌘K shortcut that summarises the current page using the active SLM.",
            "AI",
            Beta,
            Low,
            "Page content is sent to the local model only — never to external servers.",
            false,
            false,
            "v0.9.0"
        ),
        lab!(
            "entropy_sleep",
            "Entropy-Reduction Sleep",
            "Shortens auto-sleep timer as tabs approach the budget limit.",
            "Performance",
            Stable,
            Low,
            "May surprise users who expect tabs to stay alive longer under load.",
            true,
            false,
            "v0.9.0"
        ),
        lab!(
            "crdt_museum_sync",
            "P2P Museum Sync (mDNS)",
            "Synchronises frozen page archives between local devices using OR-Set CRDTs.",
            "Sync",
            Alpha,
            Medium,
            "Requires both devices on the same LAN simultaneously.",
            false,
            false,
            "v0.8.0"
        ),
        lab!(
            "nostr_relay_sync",
            "Async Nostr Relay Sync",
            "Push encrypted Museum bundles to a user-chosen Nostr relay. \
                          Relay sees only ciphertext. Enables async sync across devices \
                          without requiring simultaneous online presence.",
            "Sync",
            Alpha,
            Medium,
            "Encrypted bundle ciphertext is visible to the relay operator. \
                        Content is AES-256-GCM protected; relay cannot read it.",
            false,
            false,
            "v0.9.2"
        ),
        lab!(
            "bloom_startup",
            "Bloom Startup Animation",
            "Procedural geometric animation on first load. Pure CSS.",
            "Interface",
            Stable,
            Low,
            "None.",
            true,
            false,
            "v0.9.0"
        ),
        lab!(
            "webauthn_bridge",
            "WebAuthn / Passkey Bridge",
            "Bridges platform authenticators (Face ID, Touch ID, Windows Hello, \
                          YubiKey) to Diatom's credential manager. Passkeys are stored locally \
                          and can be synced via the Nostr relay in encrypted form. \
                          Supports the full WebAuthn Level 3 spec including conditional UI \
                          (passkey autofill) and cross-device flows via CTAP2.",
            "Security",
            Stable,
            Low,
            "Passkey sync across devices requires the Nostr Relay Sync lab. \
                        Hardware keys (YubiKey, SoloKey) require platform-specific drivers \
                        already present on most systems.",
            true,
            false,
            "v0.9.2"
        ),
        lab!(
            "privacy_presets",
            "Privacy Preset Subscriptions",
            "Download and apply community-maintained filter lists (EasyList, \
                          uBlock Origin lists, AdGuard DNS filters) with one click. \
                          Diatom acts as a downloader only — rule responsibility lies with \
                          the user. Updates are fetched weekly in the background.",
            "Privacy",
            Beta,
            Low,
            "Fetching filter lists makes one outbound network request per list per week. \
                        Lists are cached locally; no personal data is sent.",
            false,
            false,
            "v0.9.2"
        ),
        lab!(
            "mcp_host",
            "MCP Host (IDE Bridge)",
            "Exposes Diatom Museum as a Model Context Protocol server on localhost:39012. \
                          Allows VS Code, Cursor, and other MCP-capable tools to search your personal \
                          web archive without opening the browser. A single-session token is written \
                          to data_dir/mcp.token and expires when Diatom quits.",
            "Developer",
            Beta,
            Low,
            "Only accessible from localhost. Token expires on quit. \
                        Do not expose port 39012 through firewall rules.",
            false,
            true,
            "v0.9.8"
        ),
        lab!(
            "ghostpipe",
            "GhostPipe (DNS-over-HTTPS Tunnel)",
            "Routes Diatom's own outgoing requests (filter list updates, Sentinel checks) \
                          through DNS-over-HTTPS endpoints, camouflaging them as standard DNS traffic. \
                          Supports multi-endpoint packet fragmentation to prevent traffic analysis. \
                          Browser-integrated mode only — does not affect system-wide DNS.",
            "Privacy",
            Alpha,
            Low,
            "Only protects Diatom's own requests, not webpage content. \
                        System-wide tunneling (GhostPipe Pro) is a planned separate application.",
            false,
            false,
            "v0.9.8"
        ),
        lab!(
            "pricing_radar",
            "Pricing Radar (Anti-Algo Dynamic Pricing)",
            "Detects dynamic pricing discrimination on e-commerce sites. \
                          Extracts the price you see, anonymously queries P2P network nodes for \
                          comparison prices, and alerts you if your price is significantly higher \
                          than the network average. Suggests switching fingerprint profiles.",
            "Privacy",
            Beta,
            Low,
            "Price queries are anonymized (product hash only, no user identity). \
                        Requires at least some P2P peers to be online for comparison data.",
            false,
            false,
            "v0.9.8"
        ),
        lab!(
            "museum_marketplace",
            "Museum Marketplace (P2P Knowledge Market)",
            "Publish curated Museum collections to the Nostr network and exchange them \
                          P2P with other Diatom users. Free exchange uses trust points; paid listings \
                          use Lightning Network micropayments. Files transfer directly device-to-device \
                          — Diatom never sees your content.",
            "Social",
            Alpha,
            Low,
            "Requires active Nostr relay connections. Lightning payments are optional. \
                        P2P transfer uses WebRTC — ensure your firewall allows direct connections.",
            false,
            false,
            "v0.9.8"
        ),
        lab!(
            "tos_auditor",
            "ToS Red-Flag Auditor",
            "Automatically extracts and analyzes privacy policies and Terms of Service \
                          when you visit registration pages. Flags dangerous clauses: AI training consent, \
                          data sharing, account deletion restrictions, perpetual IP licenses, and more. \
                          Powered entirely by local rules — no cloud processing.",
            "Privacy",
            Stable,
            Low,
            "Analysis is heuristic-based. Always read the full policy for legal matters.",
            true,
            false,
            "v0.9.8"
        ),
        lab!(
            "shadow_index",
            "Shadow Index (Human-Curated Search)",
            "Search your Museum archives with TF-IDF full-text ranking. \
                          Optionally connects to the P2P network to find matching archives from other \
                          Diatom users (keyword hashes only — your actual queries never leave your device). \
                          Includes Bias Contrast View: automatically surfaces opposing perspectives on \
                          news articles from your Museum collection.",
            "Discovery",
            Beta,
            Low,
            "Local mode is fully offline. P2P mode broadcasts anonymized keyword hashes \
                        using per-session random salts to prevent correlation attacks.",
            false,
            false,
            "v0.9.8"
        ),
        lab!(
            "emotion_filter",
            "Digital Zen Garden (Emotion Filter)",
            "Scans page text for high-emotion vocabulary (outrage bait, panic language, \
                          sensationalism) and applies configurable visual dampening: opacity reduction, \
                          blur, and saturation decrease. Helps maintain a calmer browsing experience \
                          on news-heavy sites. Integrated into Zen Mode settings.",
            "Wellbeing",
            Beta,
            Low,
            "Detection is vocabulary-based heuristic, not semantic. May affect some \
                        legitimate urgent content. Adjust sensitivity in Zen settings.",
            false,
            false,
            "v0.9.8"
        ),
        lab!(
            "panic_button",
            "Panic Button",
            "Cmd/Ctrl+Shift+. instantly hides all browser windows and replaces the \
                          active tab with a configurable decoy page. Restoration via second keypress \
                          or tray icon. Optional total workspace wipe mode.",
            "Privacy",
            Stable,
            Low,
            "Registers a global hotkey. On some platforms, global hotkeys conflict with \
                        OS shortcuts. Configurable key binding available in Labs settings.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "video_pip",
            "PiP Video Engine",
            "Promotes the video controller to a first-class Picture-in-Picture engine. \
                          Adds requestPictureInPicture() API binding, a floating overlay window for \
                          sites that block native PiP, and a media session toolbar.",
            "UX",
            Beta,
            Low,
            "Fallback PiP opens a second Tauri window. Ensure privacy initialization \
                        scripts are inherited by the secondary window.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "per_tab_proxy",
            "Per-Tab Proxy",
            "Assign an independent SOCKS5 or HTTP proxy to each tab, enabling true IP \
                          isolation between browsing contexts without separate workspaces. Integrates \
                          with workspace default proxy settings.",
            "Privacy",
            Alpha,
            High,
            "HIGH risk. Incorrect proxy config silences the tab. Requires a loopback \
                        CONNECT proxy daemon on 127.0.0.1:3182x. Test on all three platforms before \
                        production use.",
            false,
            true,
            "v0.12.0"
        ),
        lab!(
            "breach_monitor",
            "Dark Web Leak Monitor",
            "Uses the Have I Been Pwned k-anonymity API to check vault email addresses \
                          and password hashes for known breaches. Only the first 5 hex characters of \
                          SHA-1(password) are transmitted — the full hash never leaves the device.",
            "Security",
            Beta,
            Medium,
            "Email lookup sends the full email address to the HIBP API. Password check \
                        uses k-anonymity (safe: only 5-char prefix transmitted). Toggle email and \
                        password checks independently.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "wifi_trust_scanner",
            "Wi-Fi Trust Scanner",
            "Detects open (unencrypted) Wi-Fi networks and automatically activates \
                          GhostPipe DoH tunneling for all Diatom-internal requests. Also upgrades \
                          all HTTP navigations to HTTPS on untrusted networks.",
            "Privacy",
            Beta,
            Low,
            "SSID spoofing risk: a malicious AP can clone a trusted SSID name. Mitigated \
                        by BSSID check but not eliminated. Open Wi-Fi detection only — does not \
                        protect against compromised WPA2 networks.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "peek_preview",
            "Peek Link Preview",
            "Hovering over a hyperlink for 600ms shows a compact preview card (title, \
                          domain, OG description, OG image if available). Previously-visited URLs \
                          resolve from the Museum cache with zero network requests.",
            "UX",
            Beta,
            Low,
            "Sends a HEAD request to hovered URLs. Adds network activity on hover. \
                        Disabled automatically when Zen mode is active.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "page_boosts",
            "Page Boosts",
            "Inject custom CSS rules per domain, transforming any website's visual \
                          design. Ships with three built-in Boosts: Clean Reader, Focus Dark, and \
                          Print Friendly. Extends DOM Crusher's blocking capability into positive \
                          CSS injection territory.",
            "UX",
            Beta,
            Low,
            "User CSS is injected before page paint. Malformed CSS can break page layout. \
                        CSS input is sandboxed. Built-in Boosts are read-only; user Boosts are editable.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "ai_download_rename",
            "AI Download Renamer",
            "When a file is downloaded, the local SLM (diatom-fast / Qwen 2.5 3B) \
                          analyzes the page title, URL, and first 2 KB of file content to suggest a \
                          semantically meaningful filename. Shown as a non-blocking toast. \
                          No file content leaves the device.",
            "AI",
            Alpha,
            Low,
            "Requires slm_server lab to be active. Graceful degradation: if SLM \
                        unavailable, shows original filename with an on-demand AI rename button.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "home_base",
            "Home Base New Tab",
            "Replaces the blank new-tab page with a privacy-respecting Frequency Map \
                          showing pinned shortcuts, top-visited domains, recent Museum saves, RSS \
                          unread count, and SLM status. All data is computed locally — zero external \
                          requests on new-tab load.",
            "UX",
            Beta,
            Low,
            "Low risk. Zero external requests on new-tab load. Disable to restore the \
                        blank new-tab page.",
            true,
            false,
            "v0.12.0"
        ),
        lab!(
            "privacy_search",
            "Privacy Search Engines",
            "Expands search engine options to include Brave Search (zero-tracking, \
                          independent index), SearXNG (self-hosted metasearch), and Kagi (paid, no \
                          ads, no tracking). All queries routed through GhostPipe if enabled.",
            "Privacy",
            Stable,
            Low,
            "SearXNG endpoint is user-configurable — validate HTTPS scheme to prevent \
                        SSRF. Kagi requires an API key stored in the Vault.",
            true,
            false,
            "v0.12.0"
        ),
        lab!(
            "tab_group_stacking",
            "Tab Group Stacking",
            "Visually collapses tab groups into a single stacked pill when not in \
                          focus, reducing tab bar clutter without closing tabs. Auto-collapses under \
                          memory pressure. Additive to existing tab groups.",
            "UX",
            Beta,
            Low,
            "Additive to tab-groups. Does not break existing groups. Auto-collapses under \
                        memory pressure — tabs remain alive in background.",
            false,
            false,
            "v0.12.0"
        ),
        lab!(
            "bandwidth_limiter",
            "Bandwidth Limiter",
            "Extends NetMonitor with per-domain and global bandwidth rate limiting \
                          using a token-bucket algorithm. Useful for metered connections, background \
                          tab throttling, and preventing a single media-heavy tab from saturating \
                          the connection.",
            "Performance",
            Alpha,
            Medium,
            "MEDIUM risk. Token bucket math must be correct to avoid starvation. Large \
                        file downloads need a separate 'unlimited' bypass toggle. Diatom-internal \
                        requests (filter list updates, Sentinel) are exempted from limiting.",
            false,
            false,
            "v0.12.0"
        ),
    ]
}

pub fn load_labs(db: &crate::storage::db::Db) -> Vec<Lab> {
    let mut labs = all_labs().to_vec();
    for lab in &mut labs {
        let key = format!("lab_{}", lab.id);
        if let Some(val) = db.get_setting(&key) {
            lab.enabled = val == "true";
        }
    }
    labs
}

pub fn set_lab(db: &crate::storage::db::Db, id: &str, enabled: bool) -> anyhow::Result<bool> {
    let lab = all_labs()
        .iter()
        .find(|l| l.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown lab id: {}", id))?;
    let key = format!("lab_{}", id);
    db.set_setting(&key, if enabled { "true" } else { "false" })?;
    Ok(lab.restart_required)
}

pub fn is_lab_enabled(db: &crate::storage::db::Db, id: &str) -> bool {
    let key = format!("lab_{}", id);
    db.get_setting(&key)
        .map(|v| v == "true")
        .unwrap_or_else(|| {
            all_labs()
                .iter()
                .find(|l| l.id == id)
                .map(|l| l.enabled)
                .unwrap_or(false)
        })
}

//
// Every Lab feature exposes two local-only feedback signals:
//   "useful"   — user found value in it
//   "never_use" — user has not used it / wants it gone
//
// Neither signal is transmitted anywhere. "never_use" accumulates a local day
// counter; when it exceeds RETIREMENT_THRESHOLD_DAYS the Lab is flagged as
// a retirement candidate and the UI displays it in a collapsed "Consider
// retiring" section with a link to the GitHub discussion.
//
// This mechanism exists entirely on-device. No analytics, no server, no voting.
// The GitHub link is for community discussion, not data collection.

/// Days of continuous "never_use" marks before a Lab enters the retirement queue.
pub const RETIREMENT_THRESHOLD_DAYS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LabFeedback {
    /// Whether the user has ever marked this lab "useful".
    pub marked_useful: bool,
    /// Unix timestamp when the user first marked "never_use". 0 = never marked.
    pub never_use_since: u64,
    /// True when the lab has been flagged as a retirement candidate.
    pub retirement_candidate: bool,
}

impl LabFeedback {
    /// Returns true if this lab has been "never_use" for long enough to show
    /// the retirement suggestion in the UI.
    pub fn is_retirement_candidate(&self) -> bool {
        self.never_use_since > 0
            && !self.marked_useful
            && crate::storage::db::unix_now() as u64
                >= self.never_use_since + RETIREMENT_THRESHOLD_DAYS * 86_400
    }
}

fn feedback_key(lab_id: &str) -> String {
    format!("lab_feedback_{}", lab_id)
}

/// Load persisted feedback for `lab_id`. Returns default if none stored.
pub fn load_feedback(db: &crate::storage::db::Db, lab_id: &str) -> LabFeedback {
    db.get_setting(&feedback_key(lab_id))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Record that the user found `lab_id` useful.
///
/// Clears any "never_use" counter — one "useful" signal resets the retirement
/// clock entirely.
pub fn mark_useful(db: &crate::storage::db::Db, lab_id: &str) -> anyhow::Result<()> {
    if !all_labs().iter().any(|l| l.id == lab_id) {
        anyhow::bail!("unknown lab id: {}", lab_id);
    }
    let mut fb = load_feedback(db, lab_id);
    fb.marked_useful = true;
    fb.never_use_since = 0;
    fb.retirement_candidate = false;
    let json = serde_json::to_string(&fb)?;
    db.set_setting(&feedback_key(lab_id), &json)?;
    Ok(())
}

pub fn mark_never_use(db: &crate::storage::db::Db, lab_id: &str) -> anyhow::Result<LabFeedback> {
    if !all_labs().iter().any(|l| l.id == lab_id) {
        anyhow::bail!("unknown lab id: {}", lab_id);
    }
    let mut fb = load_feedback(db, lab_id);
    if fb.never_use_since == 0 {
        fb.never_use_since = crate::storage::db::unix_now() as u64;
    }
    fb.retirement_candidate = fb.is_retirement_candidate();
    let json = serde_json::to_string(&fb)?;
    db.set_setting(&feedback_key(lab_id), &json)?;
    Ok(fb)
}

pub fn retirement_candidates(db: &crate::storage::db::Db) -> Vec<String> {
    all_labs()
        .iter()
        .filter(|l| {
            let fb = load_feedback(db, l.id);
            fb.is_retirement_candidate()
        })
        .map(|l| l.id.to_owned())
        .collect()
}

#[cfg(test)]
mod retirement_tests {
    use super::*;

    fn now() -> u64 {
        crate::storage::db::unix_now() as u64
    }

    #[test]
    fn fresh_feedback_is_not_candidate() {
        let fb = LabFeedback {
            never_use_since: now(),
            ..Default::default()
        };
        assert!(
            !fb.is_retirement_candidate(),
            "should not be a candidate immediately after first mark"
        );
    }

    #[test]
    fn feedback_past_threshold_is_candidate() {
        let old_ts = now() - (RETIREMENT_THRESHOLD_DAYS + 1) * 86_400;
        let fb = LabFeedback {
            never_use_since: old_ts,
            marked_useful: false,
            retirement_candidate: false,
        };
        assert!(fb.is_retirement_candidate());
    }

    #[test]
    fn useful_mark_clears_candidate() {
        let old_ts = now() - (RETIREMENT_THRESHOLD_DAYS + 1) * 86_400;
        let fb = LabFeedback {
            never_use_since: old_ts,
            marked_useful: true,
            retirement_candidate: false,
        };
        assert!(!fb.is_retirement_candidate());
    }
}
