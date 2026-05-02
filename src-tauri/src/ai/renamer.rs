use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadContext {
    pub original_filename: String,
    pub page_title: String,
    pub url: String,
    /// First 2 KB of file content as base64 (text files) or empty for binary.
    pub content_preview_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameResult {
    pub suggested_name: String,
    /// True if the suggestion came from the SLM; false if it's a deterministic slug.
    pub ai_generated: bool,
}

/// Request a filename suggestion from the local SLM.
///
/// Sends a structured JSON prompt to cmd_slm_chat. The model is instructed to
/// return ONLY a JSON object: {"suggested_name": "filename.ext"}.
pub async fn suggest_via_slm(ctx: &DownloadContext) -> Result<RenameResult> {
    let prompt = format!(
        "You are a file renaming assistant. Suggest a clear, descriptive filename.\n\
         Original filename: {}\n\
         Page title: {}\n\
         URL: {}\n\
         File preview (first 2KB, base64): {}\n\n\
         Return ONLY a JSON object with this exact structure: \
         {{\"suggested_name\": \"descriptive-filename.ext\"}}\n\
         Rules: lowercase, hyphens for spaces, keep extension, max 80 chars, no path separators.",
        ctx.original_filename,
        ctx.page_title,
        ctx.url,
        if ctx.content_preview_b64.len() > 200 {
            &ctx.content_preview_b64[..200]
        } else {
            &ctx.content_preview_b64
        }
    );

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            crate::slm::SLM_PORT
        ))
        .json(&serde_json::json!({
            "model": "diatom-fast",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 80,
            "temperature": 0.2
        }))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .context("SLM rename request")?
        .json()
        .await
        .context("SLM rename response parse")?;

    let content = resp["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");

    let clean = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: serde_json::Value =
        serde_json::from_str(clean).context("SLM output not valid JSON")?;

    let suggested = parsed["suggested_name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("SLM did not return suggested_name"))?;

    let safe = sanitize_filename(suggested, &ctx.original_filename);
    Ok(RenameResult {
        suggested_name: safe,
        ai_generated: true,
    })
}

/// Generate a deterministic slug from the page title when SLM is unavailable.
///
/// Example: "TensorFlow 2.0 Release Notes — Google AI" → "tensorflow-2-0-release-notes.pdf"
pub fn suggest_from_title(ctx: &DownloadContext) -> RenameResult {
    let ext = Path::new(&ctx.original_filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let slug = slugify(&ctx.page_title, 60);
    let name = if slug.is_empty() {
        ctx.original_filename.clone()
    } else if ext.is_empty() {
        slug
    } else {
        format!("{}.{}", slug, ext)
    };

    RenameResult {
        suggested_name: name,
        ai_generated: false,
    }
}

fn slugify(s: &str, max_len: usize) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(max_len)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned()
}

/// Sanitize a model-suggested filename: enforce safe characters, preserve extension.
fn sanitize_filename(suggested: &str, original: &str) -> String {
    let orig_ext = Path::new(original)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let base = Path::new(suggested)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(suggested);

    let safe: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();

    let sugg_ext = Path::new(&safe)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if !orig_ext.is_empty() && sugg_ext != orig_ext {
        let stem = Path::new(&safe)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&safe);
        format!("{}.{}", stem, orig_ext)
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_basic() {
        assert_eq!(
            slugify("TensorFlow 2.0 Release Notes", 60),
            "tensorflow-2-0-release-notes"
        );
    }

    #[test]
    fn slugify_max_len() {
        let long = "a".repeat(100);
        assert!(slugify(&long, 20).len() <= 20);
    }

    #[test]
    fn sanitize_preserves_extension() {
        let result = sanitize_filename("my-report", "report.pdf");
        assert!(result.ends_with(".pdf"), "got: {result}");
    }

    #[test]
    fn sanitize_strips_path_components() {
        let result = sanitize_filename("../../etc/passwd.pdf", "report.pdf");
        assert!(!result.contains('/'));
        assert!(
            !result
                .contains('.')
                .then_some(())
                .map(|_| result.starts_with("."))
                .unwrap_or(false)
        );
    }

    #[test]
    fn fallback_slug_uses_title() {
        let ctx = DownloadContext {
            original_filename: "report.pdf".to_owned(),
            page_title: "Q3 Financial Results 2024".to_owned(),
            url: "https://example.com/report.pdf".to_owned(),
            content_preview_b64: String::new(),
        };
        let result = suggest_from_title(&ctx);
        assert!(!result.ai_generated);
        assert!(result.suggested_name.contains("q3"));
        assert!(result.suggested_name.ends_with(".pdf"));
    }
}
