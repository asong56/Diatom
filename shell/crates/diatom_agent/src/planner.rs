//! `planner.rs` — Turn a free-form user goal into an ordered list of
//! micro-steps the executor can tackle one at a time.
//!
//! ## Why a separate planning pass?
//!
//! Small models (< 4 B parameters) lose coherence when asked to both *plan*
//! and *act* in a single context window. Splitting into two prompts gives:
//!
//! 1. **Planning call** — model sees only the goal; outputs a short JSON array
//!    of step strings. Context: < 512 tokens in, < 128 tokens out.
//! 2. **Execution calls** — model sees only the current step + live page
//!    state; outputs a single tool-call JSON object.
//!
//! Both prompts are tuned to keep context tiny, which is the #1 factor for
//! keeping Candle inference fast on CPU/mobile-GPU.
//!
//! ## Prompt design
//!
//! The planner system prompt explicitly forbids meta-commentary and requires
//! a JSON array as the sole output. The array is limited to ≤ 8 steps — if a
//! goal needs more the model will produce a collapsed version (acceptable).

use anyhow::{bail, Context, Result};
use diatom_bridge::slm_adapter::{ChatMessage, DiatomSlmClient};

/// Maximum steps allowed in a single plan. Keeps execution bounded.
const MAX_STEPS: usize = 8;
/// Maximum tokens the planner is allowed to emit.
const PLANNER_MAX_TOKENS: u32 = 256;

/// Call the SLM to decompose `goal` into ≤ [`MAX_STEPS`] ordered steps.
///
/// Returns a `Vec<String>` where each entry is a one-sentence step
/// description in the same language as the goal.
///
/// ## Retry behaviour
/// If the model's output is not valid JSON or the array is empty, retries
/// once with a stricter prompt before propagating the error.
pub async fn plan(client: &DiatomSlmClient, goal: &str) -> Result<Vec<String>> {
    let steps = try_plan(client, goal, false).await;
    match steps {
        Ok(s) if !s.is_empty() => Ok(s),
        _ => {
            log::warn!("[agent-planner] first attempt failed, retrying with strict prompt");
            try_plan(client, goal, true).await
        }
    }
}

async fn try_plan(client: &DiatomSlmClient, goal: &str, strict: bool) -> Result<Vec<String>> {
    let system = if strict {
        "You are a browser-automation planner. \
         Respond with ONLY a JSON array of strings (no explanation, no markdown). \
         Each string is one atomic browser step. Max 8 steps. \
         Example: [\"Navigate to site\",\"Click login\",\"Enter password\",\"Submit form\"]"
    } else {
        "You are a browser-automation planner. \
         Given a goal, output a JSON array of short step descriptions. \
         Rules: (1) JSON array only, no other text. \
         (2) Max 8 steps. (3) Each step is one sentence. \
         (4) Steps must be ordered and independently executable."
    };

    let messages = vec![
        ChatMessage {
            role: "system".into(),
            content: system.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!("Goal: {goal}"),
        },
    ];

    let raw = client
        .complete(&messages, Some(PLANNER_MAX_TOKENS))
        .await
        .context("planner SLM call")?;

    parse_plan(&raw)
}

fn parse_plan(raw: &str) -> Result<Vec<String>> {
    let trimmed = raw.trim();

    // Strip optional ```json … ``` wrapper.
    let json = if let Some(inner) = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
    {
        inner.trim_end_matches("```").trim()
    } else {
        trimmed
    };

    // Find the first '[' in case there is preamble text.
    let start = json
        .find('[')
        .ok_or_else(|| anyhow::anyhow!("no JSON array in planner output"))?;
    let json = &json[start..];

    let steps: Vec<String> = serde_json::from_str(json).context("parse planner JSON array")?;

    if steps.is_empty() {
        bail!("planner returned empty steps array");
    }
    if steps.len() > MAX_STEPS {
        bail!("planner returned {} steps (max {MAX_STEPS})", steps.len());
    }
    if steps.iter().any(|s| s.trim().is_empty()) {
        bail!("planner returned a blank step");
    }

    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clean_array() {
        let raw = r#"["Navigate to booking site","Search for flights","Select cheapest"]"#;
        let steps = parse_plan(raw).unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0], "Navigate to booking site");
    }

    #[test]
    fn parse_with_fences() {
        let raw = "```json\n[\"Step 1\",\"Step 2\"]\n```";
        let steps = parse_plan(raw).unwrap();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn parse_with_preamble() {
        let raw = "Sure! Here is the plan:\n[\"Do A\",\"Do B\"]";
        let steps = parse_plan(raw).unwrap();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn rejects_empty_array() {
        assert!(parse_plan("[]").is_err());
    }

    #[test]
    fn rejects_too_many_steps() {
        let many: Vec<String> = (0..10).map(|i| format!("step {i}")).collect();
        let json = serde_json::to_string(&many).unwrap();
        assert!(parse_plan(&json).is_err());
    }
}
