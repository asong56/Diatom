use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuseumVersion {
    pub version_id: String,
    pub museum_id: String,
    pub url: String,
    pub frozen_at: i64,
    pub content_hash: String,           // Blake3 hex
    pub diff_from_prev: Option<String>, // unified diff, None for first version
    pub size_bytes: u64,
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiffResult {
    pub version_a_id: String,
    pub version_b_id: String,
    pub frozen_a: i64,
    pub frozen_b: i64,
    pub unified_diff: String,
    pub lines_added: usize,
    pub lines_removed: usize,
    pub change_ratio: f32, // 0.0–1.0
    pub verdict: TamperVerdict,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperVerdict {
    /// contentidenticalmatches
    Identical,
    /// Negligible difference (<2%) — likely just ads or timestamps updating.
    MinorUpdate,
    /// Minor change (2–20%) — worth noting to the user.
    SignificantChange,
    /// Significant change (>20%) — triggers the "Historical Truth" audit banner.
    MajorAlteration,
}

/// computetwo versions Myers unified diff
pub fn compute_diff(old_text: &str, new_text: &str) -> String {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let lcs = lcs_lines(&old_lines, &new_lines);
    let mut result = String::new();
    let mut oi = 0usize;
    let mut ni = 0usize;
    let mut lcs_i = 0usize;

    while oi < old_lines.len() || ni < new_lines.len() {
        if lcs_i < lcs.len()
            && oi < old_lines.len()
            && ni < new_lines.len()
            && old_lines[oi] == lcs[lcs_i]
            && new_lines[ni] == lcs[lcs_i]
        {
            let _ = write!(result, " {}\n", old_lines[oi]);
            oi += 1;
            ni += 1;
            lcs_i += 1;
        } else if ni < new_lines.len() && (lcs_i >= lcs.len() || new_lines[ni] != lcs[lcs_i]) {
            let _ = write!(result, "+{}\n", new_lines[ni]);
            ni += 1;
        } else {
            let _ = write!(result, "-{}\n", old_lines[oi]);
            oi += 1;
        }
        if result.len() > 65536 {
            result.push_str("\n[diff truncated at 64KB]\n");
            break;
        }
    }
    result
}

/// Longest Common Subsequence (line-level)
fn lcs_lines<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<&'a str> {
    let m = a.len().min(500); // cap for performance
    let n = b.len().min(500);
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let mut result = Vec::new();
    let (mut i, mut j) = (m, n);
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            result.push(a[i - 1]);
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] > dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    result.reverse();
    result
}

/// Compute the content-change ratio
pub fn change_ratio(old_text: &str, new_text: &str) -> f32 {
    let _old_len = old_text.len().max(1);
    let _new_len = new_text.len();
    let diff = compute_diff(old_text, new_text);
    let changed_lines = diff
        .lines()
        .filter(|l| l.starts_with('+') || l.starts_with('-'))
        .count();
    let total_lines = old_text.lines().count().max(1);
    (changed_lines as f32 / total_lines as f32).clamp(0.0, 1.0)
}

pub fn tamper_verdict(ratio: f32) -> TamperVerdict {
    match ratio {
        r if r < 0.001 => TamperVerdict::Identical,
        r if r < 0.02 => TamperVerdict::MinorUpdate,
        r if r < 0.20 => TamperVerdict::SignificantChange,
        _ => TamperVerdict::MajorAlteration,
    }
}

/// Blake3 hash (used for version deduplication)
pub fn content_hash(text: &str) -> String {
    hex::encode(blake3::hash(text.as_bytes()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_content_zero_ratio() {
        let t = "Hello\nWorld\n";
        assert!(change_ratio(t, t) < 0.001);
    }

    #[test]
    fn added_line_detected() {
        let old = "Line1\nLine2\n";
        let new = "Line1\nLine2\nLine3\n";
        let diff = compute_diff(old, new);
        assert!(diff.contains("+Line3"));
    }

    #[test]
    fn major_alteration_verdict() {
        assert!(matches!(
            tamper_verdict(0.5),
            TamperVerdict::MajorAlteration
        ));
    }
}
