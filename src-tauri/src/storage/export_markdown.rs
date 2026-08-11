//! Museum Markdown export — Axiom 20 (User Data Must Be Portable).
//!
//! Converts Diatom's encrypted E-WBN Museum bundles to plain Markdown files
//! — one `.md` file per bundle, written into a destination directory, each
//! with a small frontmatter header (title, source URL, freeze date, content
//! hash) followed by a best-effort Markdown rendering of the archived page.
//!
//! Replaces the earlier WARC exporter (see DEAD_CODE.md) after Axiom 20 was
//! amended to require Markdown instead of WARC/HTML-archive for Museum data.
//!
//! ## What is exported
//! - Frontmatter: title, source URL, freeze date (ISO 8601), content hash.
//! - Body: headings, paragraphs, line breaks, bold/italic, list items, and
//!   links are converted to Markdown syntax. Anything else collapses to its
//!   text content — this is a lightweight, dependency-free renderer (no
//!   HTML-parser crate in the dependency tree), not a full HTML5
//!   implementation. Good enough to read the archived content back; not a
//!   pixel-perfect reproduction of the original page.
//!
//! ## What is NOT exported
//! - The E-WBN encryption key or any key material.
//! - SLM summaries (derived data; export separately as JSON from Shadow Index).
//! - Marketplace metadata or Nostr event IDs.
//!
//! ## Security note
//! The exported Markdown files are **unencrypted plaintext**. It is the
//! user's responsibility to protect them at rest after export. Diatom writes
//! them to the user-specified directory with no additional encryption.
//!
//! ## Verification note
//! This module was written and reviewed without a Rust toolchain available
//! in the authoring environment (no `cargo build`/`cargo test` was run
//! against it). The HTML→Markdown conversion in particular is hand-rolled
//! string scanning rather than a real parser — please run the test module
//! below and skim `html_to_markdown` before relying on this in production.

use anyhow::{Context, Result};
use std::{fs, path::Path};

use crate::storage::db::{BundleRow, Db};
use crate::storage::freeze::thaw_bundle;

fn list_all_bundles(db: &Db) -> Result<Vec<BundleRow>> {
    let conn = db.0.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id,url,title,content_hash,bundle_path,tfidf_tags,bundle_size,frozen_at,\
                workspace_id,index_tier,last_accessed_at
         FROM museum_bundles ORDER BY frozen_at ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(BundleRow {
            id: r.get(0)?,
            url: r.get(1)?,
            title: r.get(2)?,
            content_hash: r.get(3)?,
            bundle_path: r.get(4)?,
            tfidf_tags: r.get(5)?,
            bundle_size: r.get(6)?,
            frozen_at: r.get(7)?,
            workspace_id: r.get(8)?,
            index_tier: r.get::<_, String>(9).unwrap_or_else(|_| "hot".to_string()),
            last_accessed_at: r.get::<_, Option<i64>>(10).unwrap_or(None),
        })
    })?;
    rows.collect::<rusqlite::Result<_>>()
        .context("list_all_bundles for Markdown export")
}

// Bundles that fail to decrypt (e.g. master key rotated) are skipped with a
// warning rather than aborting the whole export; caller gets the skip count.
pub fn export_markdown(
    db: &Db,
    bundles_dir: &Path,
    master_key: &[u8; 32],
    dest_dir: &Path,
) -> Result<(usize, usize)> {
    fs::create_dir_all(dest_dir).context("create Markdown export directory")?;

    let rows = list_all_bundles(db).context("list Museum bundles")?;

    let mut ok = 0usize;
    let mut skipped = 0usize;

    for row in &rows {
        let bundle_file = bundles_dir.join(&row.bundle_path);
        match thaw_bundle(&bundle_file, &row.id, master_key) {
            Ok(html) => {
                let md = render_markdown(row, &html);
                let filename = format!("{}.md", sanitize_filename(&row.id));
                fs::write(dest_dir.join(filename), md).context("write Markdown file")?;
                ok += 1;
            }
            Err(e) => {
                tracing::warn!(
                    "export_markdown: skipping bundle {} ({}): {e}",
                    row.id,
                    row.url
                );
                skipped += 1;
            }
        }
    }

    tracing::info!("export_markdown: wrote {ok} files, skipped {skipped}");
    Ok((ok, skipped))
}

fn sanitize_filename(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn render_markdown(row: &BundleRow, html: &str) -> String {
    let date = unix_ts_to_iso8601(row.frozen_at);
    let title = row.title.replace('"', "'");
    let body = html_to_markdown(html);
    format!(
        "---\ntitle: \"{title}\"\nsource: {url}\nfrozen_at: {date}\ncontent_hash: {hash}\n---\n\n{body}\n",
        url = row.url,
        hash = row.content_hash,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML → Markdown (dependency-free, best-effort — see module doc note above)
// ─────────────────────────────────────────────────────────────────────────────

fn html_to_markdown(html: &str) -> String {
    let stripped = strip_tag_blocks(html, "script");
    let stripped = strip_tag_blocks(&stripped, "style");

    let mut out = String::with_capacity(stripped.len());
    let mut rest: &str = &stripped;
    let mut pending_href: Option<String> = None;
    let mut link_start: Option<usize> = None;

    while let Some(lt) = rest.find('<') {
        out.push_str(&decode_entities(&rest[..lt]));

        let after_lt = &rest[lt + 1..];
        let Some(gt) = after_lt.find('>') else {
            // Unterminated tag in malformed input — treat the rest as text.
            out.push_str(&decode_entities(after_lt));
            rest = "";
            break;
        };
        let tag_content = &after_lt[..gt];
        rest = &after_lt[gt + 1..];

        let closing = tag_content.starts_with('/');
        let name_part = if closing {
            &tag_content[1..]
        } else {
            tag_content
        };
        let name: String = name_part
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();

        match name.as_str() {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                if !closing {
                    let level: usize = name[1..].parse().unwrap_or(1);
                    out.push_str("\n\n");
                    out.push_str(&"#".repeat(level));
                    out.push(' ');
                } else {
                    out.push('\n');
                }
            }
            "p" | "div" | "tr" => out.push_str("\n\n"),
            "br" => out.push('\n'),
            "li" => {
                if !closing {
                    out.push_str("\n- ");
                }
            }
            "strong" | "b" => out.push_str("**"),
            "em" | "i" => out.push('_'),
            "a" => {
                if !closing {
                    pending_href = extract_attr(tag_content, "href");
                    link_start = Some(out.len());
                } else if let (Some(href), Some(start)) = (pending_href.take(), link_start.take()){
                    let text = out[start..].trim().to_string();
                    out.truncate(start);
                    if text.is_empty() {
                        out.push_str(&href);
                    } else {
                        out.push('[');
                        out.push_str(&text);
                        out.push_str("](");
                        out.push_str(&href);
                        out.push(')');
                    }
                }
            }
            _ => {} // unrecognised tag: drop the tag, keep scanning for its text content
        }
    }
    out.push_str(&decode_entities(rest));

    collapse_blank_lines(&out)
}

fn strip_tag_blocks(html: &str, tag: &str) -> String {
    let open_needle = format!("<{tag}");
    let close_needle = format!("</{tag}>");
    let lower = html.to_ascii_lowercase();

    let mut out = String::with_capacity(html.len());
    let mut pos = 0usize;
    loop {
        match lower[pos..].find(&open_needle) {
            None => {
                out.push_str(&html[pos..]);
                break;
            }
            Some(rel_open) => {
                let open_abs = pos + rel_open;
                out.push_str(&html[pos..open_abs]);
                match lower[open_abs..].find(&close_needle) {
                    None => break, // unterminated block: drop the remainder
                    Some(rel_close) => {
                        pos = open_abs + rel_close + close_needle.len();
                    }
                }
            }
        }
    }
    out
}

/// Extract an attribute value from a tag's inner content, e.g. `extract_attr(r#"a href="x""#, "href")` → `Some("x")`.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{attr}=");
    let pos = lower.find(&needle)?;
    let after = &tag[pos + needle.len()..];
    let mut chars = after.chars();
    let quote = chars.next()?;
    if quote == '"' || quote == '\'' {
        let rest = &after[quote.len_utf8()..];
        let end = rest.find(quote)?;
        Some(rest[..end].to_string())
    } else {
        let end = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

fn collapse_blank_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut newline_run = 0u32;
    for c in s.chars() {
        if c == '\n' {
            newline_run += 1;
            if newline_run <= 2 {
                out.push(c);
            }
        } else {
            newline_run = 0;
            out.push(c);
        }
    }
    out.trim().to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Date formatting (unchanged from the earlier WARC exporter — no external
// date/time crate in the dependency tree, so this stays hand-rolled)
// ─────────────────────────────────────────────────────────────────────────────

fn unix_ts_to_iso8601(ts: i64) -> String {
    if ts <= 0 {
        return "1970-01-01T00:00:00Z".to_owned();
    }
    let secs = ts as u64;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm: https://www.howardhinnant.com/date_algorithms.html (civil_from_days)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}

/// Public re-export of the ISO 8601 formatter for integration testing.
/// Not part of the stable API.
#[doc(hidden)]
pub fn unix_ts_to_iso8601_pub(ts: i64) -> String {
    unix_ts_to_iso8601(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_epoch() {
        assert_eq!(unix_ts_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_known_date() {
        assert_eq!(unix_ts_to_iso8601(1705320000), "2024-01-15T12:00:00Z");
    }

    #[test]
    fn headings_and_paragraphs() {
        let md = html_to_markdown("<h1>Title</h1><p>Hello <strong>world</strong>.</p>");
        assert!(md.contains("# Title"));
        assert!(md.contains("Hello **world**."));
    }

    #[test]
    fn link_conversion() {
        let md = html_to_markdown(r#"<a href="https://example.com">click here</a>"#);
        assert_eq!(md, "[click here](https://example.com)");
    }

    #[test]
    fn script_and_style_are_stripped() {
        let md =
            html_to_markdown("<style>body{color:red}</style><p>text</p><script>alert(1)</script>",);
        assert!(md.contains("text"));
        assert!(!md.contains("alert"));
        assert!(!md.contains("color:red"));
    }

    #[test]
    fn entities_decoded() {
        let md = html_to_markdown("<p>Tom &amp; Jerry &lt;3&gt;</p>");
        assert!(md.contains("Tom & Jerry <3>"));
    }

    #[test]
    fn render_markdown_includes_frontmatter() {
        let row = BundleRow {
            id: "test-id".to_owned(),
            url: "https://example.com/page".to_owned(),
            title: "Example Page".to_owned(),
            content_hash: "abc123".to_owned(),
            bundle_path: "test.ewbn".to_owned(),
            tfidf_tags: "[]".to_owned(),
            bundle_size: 0,
            frozen_at: 1705320000,
            workspace_id: "default".to_owned(),
            index_tier: "hot".to_owned(),
            last_accessed_at: None,
        };
        let out = render_markdown(&row, "<p>hello</p>");
        assert!(out.starts_with("---\n"));
        assert!(out.contains("source: https://example.com/page"));
        assert!(out.contains("frozen_at: 2024-01-15T12:00:00Z"));
        assert!(out.contains("hello"));
    }
}
