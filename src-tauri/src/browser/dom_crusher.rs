use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAX_SELECTOR_LEN: usize = 512;

/// Selectors that would crush the entire visible page.
const DISALLOWED_ROOTS: &[&str] = &[
    ":root", ":host", "html ", "html>", "html,", "body ", "body>", "body,", "* {", "*{",
];

/// Validate a CSS selector before storing it.
pub fn validate_selector(selector: &str) -> Result<()> {
    let s = selector.trim();
    if s.is_empty() {
        bail!("selector cannot be empty");
    }
    if s.len() > MAX_SELECTOR_LEN {
        bail!("selector too long (max {MAX_SELECTOR_LEN} chars)");
    }
    if s.contains('<') || s.contains("javascript:") {
        bail!("selector contains forbidden characters");
    }
    let lower = s.to_lowercase();
    if lower.trim_start() == "*" || lower.trim_start().starts_with("* ") {
        bail!("wildcard-only selectors are not allowed");
    }
    for dis in DISALLOWED_ROOTS {
        if lower.starts_with(dis) || lower == dis.trim() {
            bail!("selector targets a root element — this would crush the entire page");
        }
    }
    Ok(())
}

/// Normalise whitespace and strip trailing punctuation from a selector.
pub fn clean_selector(selector: &str) -> String {
    selector
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|c: char| c == ',' || c == ';')
        .to_owned()
}

/// Validate, clean, and insert a DOM-crusher block rule for `domain`.
/// Returns the new rule ID.
pub fn add_rule(db: &crate::storage::db::Db, domain: &str, selector: &str) -> Result<String> {
    let clean = clean_selector(selector);
    validate_selector(&clean).context("invalid selector")?;
    db.insert_dom_block(domain, &clean)
        .context("insert_dom_block")
}

/// Return all CSS selectors currently blocking elements on `domain`.
pub fn rules_for_domain(db: &crate::storage::db::Db, domain: &str) -> Result<Vec<String>> {
    Ok(db
        .dom_blocks_for(domain)
        .context("dom_blocks_for")?
        .into_iter()
        .map(|b| b.selector)
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshuffleRule {
    pub rule_id: String,
    /// Domain glob — supports "*" (all) and "*.example.com" (subdomains).
    pub domain_pattern: String,
    /// Valid CSS selector (validated by `validate_selector` on insert).
    pub selector: String,
    pub replacement: ReplacementContent,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ReplacementContent {
    /// Replace matched elements with a randomly selected Museum archive card.
    MuseumCard { museum_id: Option<String> },
    /// Replace matched elements with a live TOTP code display.
    TotpWidget { issuer_filter: Option<String> },
    /// Replace matched elements with arbitrary HTML.
    CustomHtml { html: String },
    /// Hide matched elements (visibility:hidden) without removing them from the DOM.
    Blank,
}

/// Build the DOM Reshuffler injection script for a set of rules.
/// Returns an empty string when `rules` is empty (no script tag needed).
pub fn reshuffle_script(rules: &[ReshuffleRule]) -> String {
    if rules.is_empty() {
        return String::new();
    }
    let rules_json = serde_json::to_string(rules).unwrap_or_default();
    format!(
        r#"(function diatomReshuffler() {{
  const RULES = {rules_json};
  const host = location.hostname;

  function matchesDomain(pattern) {{
    if (pattern === '*') return true;
    if (pattern.startsWith('*.')) return host.endsWith(pattern.slice(1));
    return host === pattern || host.endsWith('.' + pattern);
  }}

  function applyRule(rule) {{
    if (!rule.enabled || !matchesDomain(rule.domain_pattern)) return;
    document.querySelectorAll(rule.selector).forEach(el => {{
      switch (rule.replacement.type) {{
        case 'blank':
          el.style.cssText = 'visibility:hidden!important;height:0!important;overflow:hidden!important;';
          break;
        case 'custom_html':
          el.innerHTML = rule.replacement.html;
          el.style.border = '1px dashed rgba(96,165,250,.3)';
          el.title = 'Reshaped by Diatom';
          break;
        case 'museum_card':
          el.innerHTML = '<div style="padding:1rem;background:var(--c-surface,#1e293b);border:1px solid rgba(96,165,250,.2);border-radius:.5rem;color:#94a3b8;font-size:.75rem">📚 Museum archive (loading...)</div>';
          window.__TAURI__?.core?.invoke('cmd_museum_random_card').then(card => {{
            if (card) el.innerHTML = `<div style="padding:.75rem;background:var(--c-surface,#1e293b);border:1px solid rgba(96,165,250,.2);border-radius:.5rem"><a href="${{card.url}}" style="color:#60a5fa;text-decoration:none;font-size:.8rem;font-weight:500">${{card.title}}</a><p style="color:#94a3b8;font-size:.72rem;margin:.3rem 0 0">${{card.snippet}}</p></div>`;
          }}).catch(() => {{}});
          break;
      }}
    }});
  }}

  function runAll() {{ RULES.forEach(applyRule); }}
  runAll();
  const obs = new MutationObserver(runAll);
  obs.observe(document.body, {{ childList: true, subtree: true }});
}})();"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_selector_passes() {
        assert!(validate_selector(".cookie-banner").is_ok());
        assert!(validate_selector("#newsletter-modal").is_ok());
        assert!(validate_selector("div.sticky-header > button.close").is_ok());
        assert!(validate_selector("[data-testid='promo-bar']").is_ok());
    }

    #[test]
    fn dangerous_selectors_blocked() {
        assert!(validate_selector("*").is_err());
        assert!(validate_selector("html").is_err());
        assert!(validate_selector(":root").is_err());
        assert!(validate_selector("<script>alert(1)</script>").is_err());
        assert!(validate_selector("div[onclick='javascript:void(0)']").is_err());
    }

    #[test]
    fn length_limit_enforced() {
        let long = "a".repeat(513);
        assert!(validate_selector(&long).is_err());
    }

    #[test]
    fn clean_selector_normalises_whitespace() {
        assert_eq!(clean_selector("  .foo   .bar  "), ".foo .bar");
        assert_eq!(clean_selector(".foo,"), ".foo");
    }

    #[test]
    fn reshuffle_script_empty_returns_empty() {
        assert!(reshuffle_script(&[]).is_empty());
    }
}
