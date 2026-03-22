// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/war_report.rs  — v7
//
// Diatom War Report: anti-tracking metrics + narrative prose.
//
// Counters are written to privacy_stats by db.rs helpers called from:
//   • blocker.rs:    increment_block_count (every blocked request)
//   • privacy.rs:    increment_noise_count (every fingerprint noise injection)
//   • tabs.rs:       add_ram_saved (on deep-sleep compression)
//   • blocker.rs:    time_saved via heuristic (blocked request count × avg load time)
//
// The narrative layer is a pure Rust template engine.
// No LLM required. No network call.
// ─────────────────────────────────────────────────────────────────────────────

use crate::db::WarReportRow;
use serde::{Deserialize, Serialize};

/// Average time (seconds) a user would spend on a page with trackers before
/// they loaded / caused distractions. Conservative heuristic.
const AVG_TRACKER_TIME_SAVED_S: f64 = 0.9;

/// Average RAM per suppressed tracker payload (KB).
const AVG_TRACKER_RAM_KB: f64 = 12.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarReport {
    pub tracking_blocks: i64,
    pub noise_injections: i64,
    pub ram_saved_mb: f64,
    pub time_saved_min: f64,
    // Narrative strings
    pub block_narrative: String,
    pub noise_narrative: String,
    pub ram_narrative: String,
    pub time_narrative: String,
    pub summary_headline: String,
}

impl WarReport {
    pub fn from_row(row: &WarReportRow) -> Self {
        // Compute derived metrics
        let time_from_blocks = (row.tracking_block_count as f64 * AVG_TRACKER_TIME_SAVED_S) / 60.0;
        let time_saved_min = row.time_saved_min + time_from_blocks;
        let ram_from_blocks = row.tracking_block_count as f64 * AVG_TRACKER_RAM_KB / 1024.0;
        let ram_saved_mb = row.ram_saved_mb + ram_from_blocks;

        WarReport {
            tracking_blocks: row.tracking_block_count,
            noise_injections: row.fingerprint_noise_count,
            ram_saved_mb,
            time_saved_min,
            block_narrative: block_narrative(row.tracking_block_count),
            noise_narrative: noise_narrative(row.fingerprint_noise_count),
            ram_narrative: ram_narrative(ram_saved_mb),
            time_narrative: time_narrative(time_saved_min),
            summary_headline: summary_headline(
                row.tracking_block_count,
                row.fingerprint_noise_count,
            ),
        }
    }
}

fn block_narrative(n: i64) -> String {
    match n {
        0 => "The trackers are eerily quiet this week. Maybe they've given up?".to_owned(),
        1..=99 => format!(
            "Diatom intercepted {n} monitoring probes this week, neutralizing them before they could reach the renderer."
        ),
        100..=999 => {
            format!(
                "This week, {n} tracking requests were severed at the protocol layer. Each one was data harvesting you never had to experience."
            )
        }
        1000..=9999 => {
            format!(
                "{n} times. That is {n} attempts to build a profile on you. Diatom made every single one of them futile."
            )
        }
        _ => format!(
            "{n} surveillance vectors — all neutralised. The data economy hit a wall at your device boundary this week."
        ),
    }
}

fn noise_narrative(n: i64) -> String {
    match n {
        0 => "Fingerprint noise injection was paused this week. Check your privacy settings to re-enable it.".to_owned(),
        1..=999 => format!(
            "Your device broadcast {n} synthetic identities to the outside world this week. The real you never appeared."
        ),
        1000..=99_999 => format!(
            "{n} random noise injections. Each one plants a corrupted Canvas fingerprint and a false WebGL signature. What trackers harvested was a phantom city."
        ),
        _ => format!(
            "{n} noise injections — your digital fingerprint was never consistent between any two requests. This is the last line of privacy defence."
        ),
    }
}

fn ram_narrative(mb: f64) -> String {
    if mb < 1.0 {
        return "Deep Sleep has not produced significant memory savings this week.".to_owned();
    }
    if mb < 100.0 {
        return format!(
            "Deep Sleep reclaimed approximately {mb:.0} MB of RAM for your device. \
            This memory would have been permanently consumed by zombie tabs."
        );
    }
    if mb < 500.0 {
        return format!(
            "Approximately {mb:.0} MB of memory was reclaimed this week. \
            {browser_name} would have let it silently burn until you closed the browser. Diatom does not.",
            browser_name = "some browsers"
        );
    }
    format!(
        "{mb:.0} MB of RAM — rescued from tab hell this week. \
        Your fan did not spin an extra revolution for it, and your battery lasted a little longer."
    )
}

fn time_narrative(min: f64) -> String {
    if min < 1.0 {
        return "Time saved by filtering this week was negligible — perhaps your browsing habits were already quite disciplined.".to_owned();
    }
    if min < 10.0 {
        return format!(
            "Blocking trackers and content farms saved you approximately {min:.0} minutes of loading and noise."
        );
    }
    if min < 60.0 {
        return format!(
            "Approximately {min:.0} minutes this week were not consumed by low-quality content. \
            That time is yours. Do something worth doing."
        );
    }
    let hrs = min / 60.0;
    format!(
        "{hrs:.1} hours. That is the time you did not waste this week thanks to Diatom's filtering. \
        Not because an algorithm served you better content — but because the junk never got in."
    )
}

fn summary_headline(blocks: i64, noise: i64) -> String {
    let total = blocks + noise;
    if total == 0 {
        return "Clean week.".to_owned();
    }
    if total < 500 {
        return format!("{total} adversarial events this week. Digital boundaries held firm.");
    }
    if total < 5000 {
        return format!(
            "{total} blocks and noise injections. The data economy failed to reach you."
        );
    }
    format!("{total} attempts. They have not stopped trying. Neither have you.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_renders_without_panic() {
        let row = WarReportRow {
            tracking_block_count: 4200,
            fingerprint_noise_count: 150_000,
            ram_saved_mb: 1200.0,
            time_saved_min: 18.0,
        };
        let r = WarReport::from_row(&row);
        assert!(!r.block_narrative.is_empty());
        assert!(!r.summary_headline.is_empty());
        assert!(r.ram_saved_mb > 1200.0); // derived adds block-based estimate
    }

    #[test]
    fn zero_report_graceful() {
        let row = WarReportRow {
            tracking_block_count: 0,
            fingerprint_noise_count: 0,
            ram_saved_mb: 0.0,
            time_saved_min: 0.0,
        };
        let r = WarReport::from_row(&row);
        assert!(!r.block_narrative.is_empty());
    }
}
