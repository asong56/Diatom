//! Zen Mode — distraction blocking with a commitment gate (Axiom 2).
//!
//! `ZenConfig` is the single source of truth for all Zen Mode state. It is
//! persisted to the database via `zen_save` / `zen_load` and loaded at startup
//! via `ZenConfig::load_from_db`.
//!
//! ## Axiom 2 compliance
//!
//! The 50-character intent gate is **on by default** for all new installs.
//! A user may opt out via `Settings → Focus → Require intent declaration`,
//! which sets `require_intent_gate: false`. This is a deliberate user choice,
//! not a skip button. The gate is never disabled silently or by default.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ZenState {
    Off,
    Active,
}

impl Default for ZenState {
    fn default() -> Self {
        ZenState::Off
    }
}

/// All Zen Mode configuration for one user session.
///
/// This struct is the authoritative representation of Zen Mode state; it
/// supersedes the two separate `ZenConfig` definitions that existed in earlier
/// versions (which caused a compile error and a conceptual split between
/// operational state and gate preference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenConfig {
    /// Current activation state.
    pub state: ZenState,

    /// The aphorism shown on the blocked-domain overlay.
    pub aphorism: String,

    /// Domain categories currently blocked (e.g. `["social", "entertainment"]`).
    pub blocked_categories: Vec<String>,

    /// Unix timestamp when Zen Mode was last activated. `None` when off.
    pub activated_at: Option<i64>,

    /// When `true` (the default), opening a blocked domain requires the user
    /// to type a 50-character intent declaration before proceeding.
    ///
    /// Users who have genuinely internalised the ritual may set this to
    /// `false` via `Settings → Focus → Require intent declaration`. This is a
    /// deliberate opt-out; the default is immutable (Axiom 2).
    #[serde(default = "zen_defaults::intent_gate")]
    pub require_intent_gate: bool,
}

mod zen_defaults {
    pub fn intent_gate() -> bool {
        true
    }
}

impl Default for ZenConfig {
    fn default() -> Self {
        ZenConfig {
            state: ZenState::Off,
            aphorism: "Now will always have been.".to_owned(),
            blocked_categories: vec!["social".into(), "entertainment".into()],
            activated_at: None,
            require_intent_gate: true,
        }
    }
}

impl ZenConfig {
    /// Load from DB, falling back to defaults if no row exists yet.
    pub fn load_from_db(db: &crate::storage::db::Db) -> Self {
        match db.zen_load() {
            Some(raw) => Self::from_raw(&raw),
            None => ZenConfig::default(),
        }
    }

    /// Construct from a DB `ZenRaw` row.
    pub fn from_raw(raw: &crate::storage::db::ZenRaw) -> Self {
        let blocked_categories: Vec<String> = serde_json::from_str(&raw.blocked_cats_json)
            .unwrap_or_else(|_| vec!["social".into(), "entertainment".into()]);
        ZenConfig {
            state: if raw.active {
                ZenState::Active
            } else {
                ZenState::Off
            },
            aphorism: raw.aphorism.clone(),
            blocked_categories,
            activated_at: raw.activated_at,
            // require_intent_gate is not stored in the legacy db row schema;
            // default to `true` so existing users are unaffected.
            require_intent_gate: true,
        }
    }

    /// Persist current state to DB.
    pub fn save_to_db(&self, db: &crate::storage::db::Db) {
        let cats_json = serde_json::to_string(&self.blocked_categories)
            .unwrap_or_else(|_| "[\"social\",\"entertainment\"]".to_owned());
        if let Err(e) = db.zen_save(
            self.is_active(),
            &self.aphorism,
            &cats_json,
            self.activated_at,
        ) {
            tracing::warn!("zen_save failed: {}", e);
        }
    }

    pub fn activate(&mut self, db: &crate::storage::db::Db) {
        self.state = ZenState::Active;
        self.activated_at = Some(crate::storage::db::unix_now());
        self.save_to_db(db);
    }

    pub fn deactivate(&mut self, db: &crate::storage::db::Db) {
        self.state = ZenState::Off;
        self.activated_at = None;
        self.save_to_db(db);
    }

    pub fn is_active(&self) -> bool {
        self.state == ZenState::Active
    }

    /// Returns the category name if `domain` should be blocked, else `None`.
    pub fn blocks_domain(&self, domain: &str) -> Option<&'static str> {
        if !self.is_active() {
            return None;
        }
        domain_category(domain).filter(|cat| self.blocked_categories.iter().any(|c| c == cat))
    }
}

pub fn domain_category(domain: &str) -> Option<&'static str> {
    const SOCIAL: &[&str] = &[
        "twitter.com",
        "x.com",
        "instagram.com",
        "facebook.com",
        "tiktok.com",
        "weibo.com",
        "douyin.com",
        "threads.net",
        "mastodon.social",
        "bluesky.app",
        "reddit.com",
        "discord.com",
        "snapchat.com",
        "linkedin.com",
        "pinterest.com",
    ];
    const ENTERTAINMENT: &[&str] = &[
        "youtube.com",
        "bilibili.com",
        "netflix.com",
        "twitch.tv",
        "hulu.com",
        "disneyplus.com",
        "primevideo.com",
        "9gag.com",
        "ifunny.co",
        "tumblr.com",
        "buzzfeed.com",
        "dailymotion.com",
        "vimeo.com",
        "rumble.com",
        "odysee.com",
    ];

    let d = domain.to_lowercase();
    let d = d.trim_start_matches("www.");

    if SOCIAL
        .iter()
        .any(|s| d == *s || d.ends_with(&format!(".{s}")))
    {
        return Some("social");
    }
    if ENTERTAINMENT
        .iter()
        .any(|s| d == *s || d.ends_with(&format!(".{s}")))
    {
        return Some("entertainment");
    }
    None
}

/// Intensity levels for the emotion-signal CSS filter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmotionFilterStrength {
    /// Slightly desaturate high-emotion words.
    Subtle,
    /// Blur and desaturate high-emotion words.
    Moderate,
    /// Maximum reduction; routes through local SLM when available.
    Heavy,
}

impl Default for EmotionFilterStrength {
    fn default() -> Self {
        Self::Subtle
    }
}

/// Generate the JS snippet that applies the emotion filter to the page.
///
/// The filter identifies lexically high-emotion words and reduces their
/// visual salience via CSS `opacity` and `blur`. It does not modify or
/// remove any content.
pub fn emotion_filter_script(strength: &EmotionFilterStrength) -> String {
    let (opacity, blur) = match strength {
        EmotionFilterStrength::Subtle => ("0.75", "0px"),
        EmotionFilterStrength::Moderate => ("0.50", "0.8px"),
        EmotionFilterStrength::Heavy => ("0.30", "1.5px"),
    };

    // High-emotion English signal words. Extend this list as needed; do not
    // include proper nouns or topic words (they vary per user).
    let words = [
        "outrage",
        "furious",
        "rage",
        "shock",
        "horrifying",
        "devastating",
        "catastrophic",
        "explosive",
        "bombshell",
        "breaking",
        "urgent",
        "crisis",
        "chaos",
        "panic",
        "scandal",
        "disaster",
        "collapse",
        "attack",
        "threat",
        "danger",
        "alarming",
        "shocking",
        "terrifying",
        "infuriating",
        "disgusting",
    ];
    let words_json = serde_json::to_string(&words).unwrap_or_else(|_| "[]".to_owned());

    format!(
        r#"
(function diatomEmotionFilter() {{
  const HIGH_EMOTION_WORDS = {words_json};

  function emotionScore(text) {{
    const lower = text.toLowerCase();
    return HIGH_EMOTION_WORDS.filter(w => lower.includes(w)).length;
  }}

  function applyFilter(el) {{
    const score = emotionScore(el.textContent || '');
    if (score >= 2) {{
      el.style.opacity = '{opacity}';
      el.style.filter  = 'blur({blur}) saturate(0.6)';
      el.title = `[Diatom Zen: emotional load ${{score}}]`;
    }}
  }}

  document.querySelectorAll('p, h1, h2, h3, article, .headline, .title')
    .forEach(applyFilter);

  const observer = new MutationObserver(mutations => {{
    for (const m of mutations) {{
      for (const node of m.addedNodes) {{
        if (node.nodeType === 1) applyFilter(node);
      }}
    }}
  }});
  observer.observe(document.body, {{ childList: true, subtree: true }});
}})();
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_with_gate_enabled() {
        let cfg = ZenConfig::default();
        assert!(!cfg.is_active());
        assert!(
            cfg.require_intent_gate,
            "gate must default to true (Axiom 2)"
        );
        assert!(
            cfg.blocks_domain("twitter.com").is_none(),
            "inactive Zen must not block"
        );
    }

    #[test]
    fn active_zen_blocks_social_domain() {
        let mut cfg = ZenConfig::default();
        cfg.state = ZenState::Active;
        assert_eq!(cfg.blocks_domain("twitter.com"), Some("social"));
        assert_eq!(cfg.blocks_domain("youtube.com"), Some("entertainment"));
        assert!(cfg.blocks_domain("example.com").is_none());
    }

    #[test]
    fn subdomain_blocked() {
        let mut cfg = ZenConfig::default();
        cfg.state = ZenState::Active;
        assert!(cfg.blocks_domain("old.reddit.com").is_some());
    }

    #[test]
    fn emotion_filter_script_contains_words() {
        let script = emotion_filter_script(&EmotionFilterStrength::Subtle);
        assert!(script.contains("outrage"), "word list must be in script");
        assert!(script.contains("0.75"), "opacity must be in script");
    }

    #[test]
    fn single_zen_config_struct() {
        // Compile-time check: there is exactly one ZenConfig.
        // If this compiles, the duplicate-struct bug is fixed.
        let _: ZenConfig = ZenConfig {
            state: ZenState::Off,
            aphorism: String::new(),
            blocked_categories: vec![],
            activated_at: None,
            require_intent_gate: true,
        };
    }
}
