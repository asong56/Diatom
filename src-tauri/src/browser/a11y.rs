use serde::Serialize;

/// Injected into the chrome WebView on startup.
/// Each entry maps a CSS selector to an ARIA attribute set.
#[derive(Debug, Serialize)]
pub struct AriaRule {
    pub selector: &'static str,
    pub role: Option<&'static str>,
    pub label: Option<&'static str>,
    pub live: Option<&'static str>, // "polite" | "assertive" | "off"
    pub expanded: Option<bool>,
}

pub const CHROME_ARIA_RULES: &[AriaRule] = &[
    AriaRule {
        selector: "#omnibox",
        role: Some("combobox"),
        label: Some("Address bar and search"),
        live: None,
        expanded: Some(false),
    },
    AriaRule {
        selector: "#tab-bar",
        role: Some("tablist"),
        label: Some("Tab list"),
        live: None,
        expanded: None,
    },
    AriaRule {
        selector: ".tab-btn",
        role: Some("tab"),
        label: None,
        live: None,
        expanded: None,
    },
    AriaRule {
        selector: ".tab-btn.active",
        role: Some("tab"),
        label: None,
        live: None,
        expanded: None,
    },
    AriaRule {
        selector: "#notes-zone",
        role: Some("region"),
        label: Some("Draft notification zone"),
        live: Some("polite"),
        expanded: None,
    },
    AriaRule {
        selector: "#ai-panel",
        role: Some("dialog"),
        label: Some("AI conversation panel"),
        live: Some("polite"),
        expanded: None,
    },
    AriaRule {
        selector: "#vc-badge",
        role: Some("status"),
        label: Some("Video playback speed"),
        live: Some("polite"),
        expanded: None,
    },
    AriaRule {
        selector: "#index-progress",
        role: Some("progressbar"),
        label: Some("Museum indexing progress"),
        live: Some("polite"),
        expanded: None,
    },
    AriaRule {
        selector: ".devnet-panel",
        role: Some("log"),
        label: Some("Network request log"),
        live: Some("off"),
        expanded: None,
    },
];

/// Generate the JS snippet that applies ARIA rules to the chrome DOM.
/// Called once on startup, injected via win.eval().
pub fn generate_aria_injection_script() -> String {
    let mut parts = Vec::new();
    parts.push("(function applyA11y() {".to_owned());
    parts.push("  'use strict';".to_owned());
    parts.push("  function apply(sel, role, label, live, expanded) {".to_owned());
    parts.push("    document.querySelectorAll(sel).forEach(el => {".to_owned());
    parts.push("      if (role)     el.setAttribute('role', role);".to_owned());
    parts.push("      if (label)    el.setAttribute('aria-label', label);".to_owned());
    parts.push("      if (live)     el.setAttribute('aria-live', live);".to_owned());
    parts.push("      if (expanded !== null && expanded !== undefined)".to_owned());
    parts.push("        el.setAttribute('aria-expanded', String(expanded));".to_owned());
    parts.push("    });".to_owned());
    parts.push("  }".to_owned());

    for rule in CHROME_ARIA_RULES {
        let role = rule.role.map(|r| format!("'{r}'")).unwrap_or("null".into());
        let label = rule
            .label
            .map(|l| format!("'{l}'"))
            .unwrap_or("null".into());
        let live = rule.live.map(|v| format!("'{v}'")).unwrap_or("null".into());
        let expanded = match rule.expanded {
            Some(true) => "true".to_owned(),
            Some(false) => "false".to_owned(),
            None => "null".to_owned(),
        };
        parts.push(format!(
            "  apply('{}', {}, {}, {}, {});",
            rule.selector, role, label, live, expanded
        ));
    }

    parts.push(
        "  document.querySelectorAll('.tab-btn,.tab-close,[data-action]').forEach((el,i) => {"
            .to_owned(),
    );
    parts
        .push("    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');".to_owned());
    parts.push("  });".to_owned());

    parts.push("  let liveRegion = document.getElementById('__a11y_live');".to_owned());
    parts.push("  if (!liveRegion) {".to_owned());
    parts.push("    liveRegion = document.createElement('div');".to_owned());
    parts.push("    liveRegion.id = '__a11y_live';".to_owned());
    parts.push("    liveRegion.setAttribute('aria-live', 'assertive');".to_owned());
    parts.push("    liveRegion.setAttribute('aria-atomic', 'true');".to_owned());
    parts.push("    liveRegion.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;';".to_owned());
    parts.push("    document.body.appendChild(liveRegion);".to_owned());
    parts.push("  }".to_owned());
    parts.push("  window.__diatomA11yAnnounce = (msg) => { liveRegion.textContent = ''; setTimeout(() => liveRegion.textContent = msg, 50); };".to_owned());

    parts.push("})();".to_owned());
    parts.join("\n")
}

/// Returns JS that enforces full keyboard navigation for Diatom chrome.
/// Handles Tab-through-panels and Escape-to-close for all overlay panels.
pub fn keyboard_nav_script() -> &'static str {
    r#"(function() {
  'use strict';
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    const panel = document.querySelector(
      '.devnet-panel, .crusher-panel, #ai-panel, #zen-interstitial'
    );
    if (panel) {
      const closeBtn = panel.querySelector('button[class*="close"], #crusher-close');
      if (closeBtn) closeBtn.click();
    }
  }, { capture: true });

  const tabBar = document.getElementById('tab-bar');
  if (tabBar) {
    tabBar.addEventListener('keydown', e => {
      const tabs = [...tabBar.querySelectorAll('.tab-btn')];
      const idx  = tabs.findIndex(t => t === document.activeElement);
      if (idx === -1) return;
      if (e.key === 'ArrowRight') { e.preventDefault(); tabs[(idx + 1) % tabs.length]?.focus(); }
      if (e.key === 'ArrowLeft')  { e.preventDefault(); tabs[(idx - 1 + tabs.length) % tabs.length]?.focus(); }
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tabs[idx]?.click(); }
      if (e.key === 'Delete' || e.key === 'Backspace') {
        e.preventDefault();
        tabs[idx]?.querySelector('.tab-close')?.click();
      }
    });
  }
})();"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aria_script_is_valid_js_ish() {
        let script = generate_aria_injection_script();
        assert!(script.contains("applyA11y"));
        assert!(script.contains("aria-label"));
        assert!(script.contains("__diatomA11yAnnounce"));
        let count = script.matches("apply(").count();
        assert_eq!(count, CHROME_ARIA_RULES.len() + 1); // +1 for the function def
    }

    #[test]
    fn all_rules_have_selector() {
        for rule in CHROME_ARIA_RULES {
            assert!(!rule.selector.is_empty());
            assert!(rule.role.is_some() || rule.label.is_some() || rule.live.is_some());
        }
    }
}
