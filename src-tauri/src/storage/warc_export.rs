//! Museum WARC export — Axiom 20 (User Data Must Be Portable).
//!
//! Converts Diatom's encrypted E-WBN Museum bundles to standard
//! WARC 1.1 format (ISO 28500 / Library of Congress specification).
//!
//! WARC is the open archive format used by the Internet Archive, wget,
//! HTTrack, and every major web archiving tool. A `.warc` file produced
//! here can be opened in any conforming WARC reader without Diatom installed.
//!
//! ## What is exported
//!
//! Each Museum bundle becomes one WARC "response" record containing:
//! - `WARC-Type: response`
//! - `WARC-Target-URI`: the original page URL
//! - `WARC-Date`: the freeze timestamp in ISO 8601 format
//! - `Content-Type: text/html; charset=utf-8`
//! - Block: the stripped HTML content (decrypted from the E-WBN bundle)
//!
//! A `warcinfo` record is prepended to identify the producing software.
//!
//! ## What is NOT exported
//!
//! - The E-WBN encryption key or any key material.
//! - SLM summaries (these are derived data; users may export them separately
//!   as JSON from the Shadow Index export path).
//! - Marketplace metadata or Nostr event IDs.
//!
//! ## Security note
//!
//! The exported WARC file is **unencrypted plaintext HTML**. It is the
//! user's responsibility to protect it at rest after export. Diatom writes
//! it to the user-specified path with no additional encryption.

use anyhow::{Context, Result};
use std::{
    io::{BufWriter, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::storage::db::{BundleRow, Db};
use crate::storage::freeze::thaw_bundle;

/// Export all Museum bundles in `db` to a single WARC 1.1 file at `dest`.
///
/// Bundles whose encrypted content cannot be decrypted (e.g. because the
/// master key has been rotated) are skipped with a warning rather than
/// aborting the export; the caller receives the skip count.
///
/// Returns `(records_written, records_skipped)`.
pub fn export_warc(
    db: &Db,
    bundles_dir: &Path,
    master_key: &[u8; 32],
    dest: &Path,
) -> Result<(usize, usize)> {
    let rows = db.list_bundles().context("list Museum bundles")?;

    if rows.is_empty() {
        // Write a valid but empty WARC (just the warcinfo record).
        let file = std::fs::File::create(dest).context("create WARC file")?;
        let mut w = BufWriter::new(file);
        write_warcinfo(&mut w)?;
        return Ok((0, 0));
    }

    let file = std::fs::File::create(dest).context("create WARC file")?;
    let mut w = BufWriter::new(file);
    let mut ok = 0usize;
    let mut err = 0usize;

    write_warcinfo(&mut w)?;

    for row in &rows {
        let bundle_file = bundles_dir.join(&row.bundle_path);
        match thaw_bundle(&bundle_file, &row.id, master_key) {
            Ok(html) => {
                write_response_record(&mut w, row, &html)?;
                ok += 1;
            }
            Err(e) => {
                tracing::warn!("warc_export: skipping bundle {} ({}): {e}", row.id, row.url);
                err += 1;
            }
        }
    }

    w.flush().context("flush WARC file")?;
    tracing::info!("warc_export: wrote {ok} records, skipped {err}");
    Ok((ok, err))
}

/// Write the mandatory `warcinfo` record at the start of the file.
fn write_warcinfo<W: Write>(w: &mut W) -> Result<()> {
    let body = format!(
        "software: Diatom/{ver}\r\n\
         format: WARC File Format 1.1\r\n\
         conformsTo: http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/\r\n\
         description: Museum archive export\r\n",
        ver = env!("CARGO_PKG_VERSION"),
    );
    let body_bytes = body.as_bytes();

    write!(
        w,
        "WARC/1.1\r\n\
         WARC-Type: warcinfo\r\n\
         WARC-Date: {date}\r\n\
         WARC-Filename: diatom-museum-export.warc\r\n\
         WARC-Record-ID: <urn:uuid:{id}>\r\n\
         Content-Type: application/warc-fields\r\n\
         Content-Length: {len}\r\n\
         \r\n",
        date = iso8601_now(),
        id = Uuid::new_v4(),
        len = body_bytes.len(),
    )?;

    w.write_all(body_bytes)?;
    write!(w, "\r\n\r\n")?;
    Ok(())
}

/// Write one `response` record for a frozen page.
fn write_response_record<W: Write>(w: &mut W, row: &BundleRow, html: &str) -> Result<()> {
    // Synthesise a minimal HTTP response header so the WARC is valid.
    let http_header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {html_len}\r\n\
         X-Diatom-Frozen-At: {ts}\r\n\
         \r\n",
        html_len = html.len(),
        ts = row.frozen_at,
    );

    let block = format!("{http_header}{html}");
    let block_bytes = block.as_bytes();

    let date = unix_ts_to_iso8601(row.frozen_at);

    write!(
        w,
        "WARC/1.1\r\n\
         WARC-Type: response\r\n\
         WARC-Target-URI: {url}\r\n\
         WARC-Date: {date}\r\n\
         WARC-Record-ID: <urn:uuid:{id}>\r\n\
         Content-Type: application/http; msgtype=response\r\n\
         Content-Length: {len}\r\n\
         \r\n",
        url = row.url,
        date = date,
        id = Uuid::new_v4(),
        len = block_bytes.len(),
    )?;

    w.write_all(block_bytes)?;
    write!(w, "\r\n\r\n")?;
    Ok(())
}

fn iso8601_now() -> String {
    unix_ts_to_iso8601(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    )
}

fn unix_ts_to_iso8601(ts: i64) -> String {
    // Format as YYYY-MM-DDTHH:MM:SSZ without pulling in chrono.
    // ts is seconds since Unix epoch.
    if ts <= 0 {
        return "1970-01-01T00:00:00Z".to_owned();
    }
    let secs = ts as u64;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Gregorian calendar reconstruction (no leap-second handling needed for WARC dates).
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
        // 2024-01-15T12:00:00Z = 1705320000
        assert_eq!(unix_ts_to_iso8601(1705320000), "2024-01-15T12:00:00Z");
    }

    #[test]
    fn warc_warcinfo_record_has_correct_prefix() {
        let mut buf: Vec<u8> = Vec::new();
        write_warcinfo(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("WARC/1.1\r\n"));
        assert!(text.contains("WARC-Type: warcinfo"));
        assert!(text.contains("software: Diatom/"));
    }

    #[test]
    fn warc_response_record_contains_url() {
        let row = BundleRow {
            id: "test-id".to_owned(),
            url: "https://example.com/page".to_owned(),
            title: "Example Page".to_owned(),
            frozen_at: 1705320000,
            bundle_path: "test.ewbn".to_owned(),
            bundle_size: 0,
            workspace_id: "default".to_owned(),
        };
        let mut buf: Vec<u8> = Vec::new();
        write_response_record(&mut buf, &row, "<html><body>hello</body></html>").unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("WARC-Target-URI: https://example.com/page"));
        assert!(text.contains("WARC-Type: response"));
        assert!(text.contains("hello"));
    }
}
