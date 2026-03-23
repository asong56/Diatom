// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/labs.rs  — v0.9.2
//
// [FIX-14] sentinel_ua lab added to all_labs() catalogue.
// [NEW] privacy_presets, nostr_relay, webauthn_bridge labs added.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LabStability { Alpha, Beta, Stable }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LabRisk { Low, Medium, High }

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

pub fn all_labs() -> Vec<Lab> {
    vec![
        // ── Privacy ──────────────────────────────────────────────────────────
        Lab {
            id: "sentinel_ua",
            name: "Dynamic User-Agent (Sentinel)",
            description: "Automatically tracks the current stable Chrome and Safari versions \
                          and synthesises a matching User-Agent string. Diatom blends into \
                          the most common browser population rather than advertising itself.",
            category: "Privacy",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Requires one network poll per hour to versionhistory.googleapis.com \
                        and developer.apple.com. Polls use the generic fallback UA so Diatom \
                        does not fingerprint itself during the poll.",
            enabled: true,   // Default ON — this is a core privacy feature
            restart_required: false,
            added_in: "v0.9.1",
        },
        Lab {
            id: "pqc_envelope",
            name: "Post-Quantum Freeze Encryption",
            description: "Encrypts Museum bundles with Kyber-768 + AES-256-GCM hybrid envelope.",
            category: "Privacy",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Bundles encrypted with this flag cannot be decrypted by older Diatom versions.",
            enabled: false,
            restart_required: false,
            added_in: "v0.8.0",
        },
        Lab {
            id: "ohttp_decoy",
            name: "OHTTP Decoy Relay",
            description: "Routes privacy-noise requests through Oblivious HTTP relays.",
            category: "Privacy",
            stability: LabStability::Alpha,
            risk: LabRisk::Medium,
            risk_note: "Response decapsulation is not yet implemented — decoy requests only.",
            enabled: false,
            restart_required: false,
            added_in: "v0.8.0",
        },
        Lab {
            id: "zkp_age_gate",
            name: "Zero-Knowledge Age Verification",
            description: "Proves age threshold to participating sites without revealing birth year.",
            category: "Privacy",
            stability: LabStability::Alpha,
            risk: LabRisk::High,
            risk_note: "Proof transport is non-standard. Sites must opt-in.",
            enabled: false,
            restart_required: false,
            added_in: "v0.8.0",
        },
        Lab {
            id: "timezone_spoof",
            name: "Timezone Normalisation",
            description: "Overrides JS timezone APIs to report UTC, preventing locale fingerprinting.",
            category: "Privacy",
            stability: LabStability::Beta,
            risk: LabRisk::Medium,
            risk_note: "Calendar apps and trading platforms may display incorrect times.",
            enabled: false,
            restart_required: false,
            added_in: "v0.9.0",
        },
        Lab {
            id: "jitter_all_requests",
            name: "Global Request Jitter",
            description: "Adds 0–50ms cryptographic delay to every outbound request, \
                          defeating timing correlation attacks.",
            category: "Privacy",
            stability: LabStability::Stable,
            risk: LabRisk::Low,
            risk_note: "Adds up to 50ms latency per request. Imperceptible on most connections.",
            enabled: false,
            restart_required: false,
            added_in: "v0.8.0",
        },
        // ── AI ────────────────────────────────────────────────────────────────
        Lab {
            id: "slm_server",
            name: "Local AI Microkernel",
            description: "Starts an OpenAI-compatible API server at 127.0.0.1:11435.",
            category: "AI",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Opens a local TCP port. Bound to loopback — not accessible from the network.",
            enabled: false,
            restart_required: true,
            added_in: "v0.9.0",
        },
        Lab {
            id: "slm_extreme_privacy",
            name: "AI Extreme Privacy Mode",
            description: "Forces all AI inference into the Wasm sandbox. \
                          Disables Ollama and llama.cpp backends.",
            category: "AI",
            stability: LabStability::Alpha,
            risk: LabRisk::Low,
            risk_note: "Wasm inference is 5–20× slower. Only works for short prompts.",
            enabled: false,
            restart_required: false,
            added_in: "v0.9.0",
        },
        Lab {
            id: "page_summarise",
            name: "Instant Page Summariser",
            description: "Adds a ⌘K shortcut that summarises the current page using the active SLM.",
            category: "AI",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Page content is sent to the local model only — never to external servers.",
            enabled: false,
            restart_required: false,
            added_in: "v0.9.0",
        },
        // ── Performance ───────────────────────────────────────────────────────
        Lab {
            id: "dynamic_tab_budget",
            name: "Adaptive Tab Limit",
            description: "Memory-aware tab limit using Resource-Aware Scaling, \
                          Golden Ratio zones, and Screen Gravity.",
            category: "Performance",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Budget recalculates every 60 seconds.",
            enabled: true,
            restart_required: false,
            added_in: "v0.9.0",
        },
        Lab {
            id: "golden_ratio_zones",
            name: "Golden Ratio Tab Zones",
            description: "Focus zone (61.8%) vs Buffer zone (38.2%) tab scheduling.",
            category: "Performance",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "None. Cosmetic behavioural change only.",
            enabled: true,
            restart_required: false,
            added_in: "v0.9.0",
        },
        Lab {
            id: "entropy_sleep",
            name: "Entropy-Reduction Sleep",
            description: "Shortens auto-sleep timer as tabs approach the budget limit.",
            category: "Performance",
            stability: LabStability::Stable,
            risk: LabRisk::Low,
            risk_note: "May surprise users who expect tabs to stay alive longer under load.",
            enabled: true,
            restart_required: false,
            added_in: "v0.9.0",
        },
        // ── Sync ─────────────────────────────────────────────────────────────
        Lab {
            id: "crdt_museum_sync",
            name: "P2P Museum Sync (mDNS)",
            description: "Synchronises frozen page archives between local devices using OR-Set CRDTs.",
            category: "Sync",
            stability: LabStability::Alpha,
            risk: LabRisk::Medium,
            risk_note: "Requires both devices on the same LAN simultaneously.",
            enabled: false,
            restart_required: false,
            added_in: "v0.8.0",
        },
        Lab {
            id: "nostr_relay_sync",
            name: "Async Nostr Relay Sync",
            description: "Push encrypted Museum bundles to a user-chosen Nostr relay. \
                          Relay sees only ciphertext. Enables async sync across devices \
                          without requiring simultaneous online presence.",
            category: "Sync",
            stability: LabStability::Alpha,
            risk: LabRisk::Medium,
            risk_note: "Encrypted bundle ciphertext is visible to the relay operator. \
                        Content is AES-256-GCM protected; relay cannot read it.",
            enabled: false,
            restart_required: false,
            added_in: "v0.9.2",
        },
        // ── Interface ─────────────────────────────────────────────────────────
        Lab {
            id: "bloom_startup",
            name: "Bloom Startup Animation",
            description: "Procedural geometric animation on first load. Pure CSS.",
            category: "Interface",
            stability: LabStability::Stable,
            risk: LabRisk::Low,
            risk_note: "None.",
            enabled: true,
            restart_required: false,
            added_in: "v0.9.0",
        },
        Lab {
            id: "screen_gravity",
            name: "Screen Gravity Tab Ceiling",
            description: "Adjusts maximum tab count by display width.",
            category: "Interface",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Ceiling adjusts within 60 seconds of a window resize.",
            enabled: true,
            restart_required: false,
            added_in: "v0.9.0",
        },
        // ── Security ──────────────────────────────────────────────────────────
        Lab {
            id: "webauthn_bridge",
            name: "WebAuthn / Passkey Bridge",
            description: "Bridges platform authenticators (Face ID, Touch ID, Windows Hello, \
                          YubiKey) to Diatom's credential manager. Passkeys are stored locally \
                          and can be synced via the Nostr relay in encrypted form.",
            category: "Security",
            stability: LabStability::Alpha,
            risk: LabRisk::Medium,
            risk_note: "Passkey sync across devices requires the Nostr Relay Sync lab. \
                        Hardware keys require platform-specific setup.",
            enabled: false,
            restart_required: false,
            added_in: "v0.9.2",
        },
        // ── Discovery ─────────────────────────────────────────────────────────
        Lab {
            id: "privacy_presets",
            name: "Privacy Preset Subscriptions",
            description: "Download and apply community-maintained filter lists (EasyList, \
                          uBlock Origin lists, AdGuard DNS filters) with one click. \
                          Diatom acts as a downloader only — rule responsibility lies with \
                          the user. Updates are fetched weekly in the background.",
            category: "Privacy",
            stability: LabStability::Beta,
            risk: LabRisk::Low,
            risk_note: "Fetching filter lists makes one outbound network request per list per week. \
                        Lists are cached locally; no personal data is sent.",
            enabled: false,
            restart_required: false,
            added_in: "v0.9.2",
        },
    ]
}

// ── Labs store ────────────────────────────────────────────────────────────────

pub fn load_labs(db: &crate::db::Db) -> Vec<Lab> {
    let mut labs = all_labs();
    for lab in &mut labs {
        let key = format!("lab_{}", lab.id);
        if let Some(val) = db.get_setting(&key) {
            lab.enabled = val == "true";
        }
    }
    labs
}

pub fn set_lab(db: &crate::db::Db, id: &str, enabled: bool) -> anyhow::Result<bool> {
    if !all_labs().iter().any(|l| l.id == id) {
        anyhow::bail!("unknown lab id: {}", id);
    }
    let key = format!("lab_{}", id);
    db.set_setting(&key, if enabled { "true" } else { "false" })?;
    let restart = all_labs().iter()
        .find(|l| l.id == id)
        .map(|l| l.restart_required)
        .unwrap_or(false);
    Ok(restart)
}

pub fn is_lab_enabled(db: &crate::db::Db, id: &str) -> bool {
    let key = format!("lab_{}", id);
    db.get_setting(&key)
        .map(|v| v == "true")
        .unwrap_or_else(|| {
            all_labs().iter()
                .find(|l| l.id == id)
                .map(|l| l.enabled)
                .unwrap_or(false)
        })
}
