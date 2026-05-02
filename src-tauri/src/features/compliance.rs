use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureLegal {
    pub id: &'static str,
    pub display_name: &'static str,
    pub legal_class: &'static str,
    pub requires_consent: bool,
    pub consent_text: &'static str,
    pub controls: &'static [&'static str],
    pub residual_risk: &'static str,
}

/// All features with non-trivial legal surface area.
pub static FEATURE_LEGAL_REGISTRY: &[FeatureLegal] = &[
    FeatureLegal {
        id: "dom_crusher",
        display_name: "DOM Crusher (Permanent Element Blocking)",
        legal_class: "User Stylesheet — legally identical to a browser's 'Reader mode' or \
                      user-defined CSS overrides. Hides elements via display:none; does NOT \
                      delete, modify, or redistribute page content.",
        requires_consent: false,
        consent_text: "",
        controls: &[
            "implementation: CSS display:none !important injected via <style> tag",
            "DOM nodes are hidden, not removed — scripts continue to execute",
            "rules are stored locally per-domain; never shared or synced externally",
            "selector validator rejects dangerous patterns (html, :root, *)",
        ],
        residual_risk: "Some site ToS prohibit ad-blocking. Diatom does not screen ToS; \
                        users are responsible for compliance with site-specific terms.",
    },
    FeatureLegal {
        id: "ghost_redirect",
        display_name: "Museum Archive Suggestion (Offline Fallback)",
        legal_class: "Local file search — equivalent to macOS Spotlight surfacing a locally \
                      cached file. Only surfaces content the USER personally froze on their \
                      own device. Does not fetch, mirror, or distribute third-party content. \
                      Presents a passive suggestion banner; never auto-redirects without user action.",
        requires_consent: false,
        consent_text: "",
        controls: &[
            "BYOD only: indexes user-frozen E-WBN bundles exclusively",
            "no P2P sharing of frozen pages between users",
            "no automatic background crawling of third-party sites",
            "stale-content warning shown for bundles > 30 days old",
            "user must click a link to navigate — no silent redirect",
        ],
        residual_risk: "Frozen pages may contain copyrighted content. Diatom does not screen \
                        content at freeze time. Users are responsible for compliance with \
                        applicable copyright law when freezing pages.",
    },
    // Echo (Persona Evolution Reflection) removed — P1 deletion. See architecture doc §3.5.
    FeatureLegal {
        id: "mesh_sync",
        display_name: "Diatom Mesh (Local Network Sync)",
        legal_class: "Private P2P local network protocol — equivalent to AirDrop. \
                      No central index server. Device discovery via mDNS (LAN only).",
        requires_consent: false,
        consent_text: "",
        controls: &[
            "no Diatom-operated index server; all discovery is mDNS/BLE local",
            "end-to-end encrypted: Noise_XX handshake, AES-GCM payload",
            "no automatic content sync without user-initiated action",
            "E-WBN bundles transferred only between the user's own authenticated devices",
        ],
        residual_risk: "Napster-style liability requires a centralised index facilitating \
                        infringing distribution. Diatom Mesh has no central index and no \
                        inter-user sharing, so this risk is negligible.",
    },
];

/// Check whether the user has consented to a feature that requires it.
pub fn check_consent(feature_id: &str, db: &crate::storage::db::Db) -> Result<(), String> {
    let feature = FEATURE_LEGAL_REGISTRY.iter().find(|f| f.id == feature_id);
    let Some(f) = feature else {
        return Ok(());
    };
    if !f.requires_consent {
        return Ok(());
    }
    let key = format!("consent:{}", feature_id);
    if db.get_setting(&key).as_deref() == Some("true") {
        return Ok(());
    }
    Err(f.consent_text.to_owned())
}

pub fn record_consent(feature_id: &str, db: &crate::storage::db::Db) -> anyhow::Result<()> {
    db.set_setting(&format!("consent:{}", feature_id), "true")
}

pub fn revoke_consent(feature_id: &str, db: &crate::storage::db::Db) -> anyhow::Result<()> {
    db.set_setting(&format!("consent:{}", feature_id), "false")
}

pub fn feature_legal(feature_id: &str) -> Option<&'static FeatureLegal> {
    FEATURE_LEGAL_REGISTRY.iter().find(|f| f.id == feature_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_consent_features_have_text() {
        for f in FEATURE_LEGAL_REGISTRY {
            if f.requires_consent {
                assert!(
                    !f.consent_text.is_empty(),
                    "Feature '{}' requires consent but has no consent text",
                    f.id
                );
            }
        }
    }

    #[test]
    fn all_features_have_controls() {
        for f in FEATURE_LEGAL_REGISTRY {
            assert!(
                !f.controls.is_empty(),
                "Feature '{}' has no compliance controls listed",
                f.id
            );
        }
    }

    #[test]
    fn no_decoy_traffic_in_registry() {
        assert!(
            FEATURE_LEGAL_REGISTRY
                .iter()
                .all(|f| f.id != "decoy_traffic"),
            "decoy_traffic must not appear in the legal registry"
        );
    }
}
