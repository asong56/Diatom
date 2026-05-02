//! `tools.rs` — The typed tool-call schema the SLM emits as JSON.
//!
//! Design rule: every variant maps to a *single, atomic* browser action.
//! No multi-action payloads — the state machine ensures exactly one tool
//! call is executed per SLM turn. This keeps the output envelope tiny and
//! gives small models (< 4 B params) the best chance of staying on-format.
//!
//! ## Wire format
//!
//! The SLM is instructed (see `executor.rs`) to respond with **only** a
//! JSON object matching this schema, e.g.:
//!
//! ```json
//! {"action":"click","target":"#submit-btn"}
//! {"action":"type","target":"input[name=q]","text":"flights BJ-SH"}
//! {"action":"navigate","url":"https://example.com"}
//! {"action":"wait_ms","ms":800}
//! {"action":"read_page"}
//! {"action":"screenshot","x":120,"y":340,"w":128,"h":128}
//! {"action":"scroll","direction":"down","px":400}
//! {"action":"done","summary":"Ticket booked — confirmation #ABC123"}
//! {"action":"fail","reason":"Payment form not found after 3 attempts"}
//! ```
//!
//! ## Validation
//!
//! [`ToolCall::from_str`] parses and validates the JSON. Invalid / unknown
//! actions return an `Err` so the executor can inject an error result back
//! to the model and retry (up to `MAX_RETRIES`).

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

// ── Tool call (model output) ──────────────────────────────────────────────────

/// A single browser action emitted by the SLM.
///
/// Each variant corresponds to a `window.diatom_action(...)` call on the
/// JS side. The JS dispatcher maps it to real DOM / webview operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ToolCall {
    /// Click the first element matching `target` (CSS selector or text label).
    Click { target: String },

    /// Type `text` into the element matching `target`.
    Type { target: String, text: String },

    /// Navigate the active tab to an absolute URL.
    Navigate { url: String },

    /// Wait for `ms` milliseconds before proceeding.
    WaitMs { ms: u64 },

    /// Request a DOM summary of the current page.
    /// The JS bridge returns visible interactive elements (tag, id, text, href).
    ReadPage,

    /// Capture a 128×128 pixel crop at viewport-relative (x, y).
    /// Returns base64-encoded JPEG. Used when DOM parsing is insufficient.
    Screenshot { x: u32, y: u32, w: u32, h: u32 },

    /// Scroll the page by `px` pixels in `direction`.
    Scroll { direction: ScrollDir, px: u32 },

    /// Signal successful task completion.
    Done { summary: String },

    /// Signal unrecoverable failure.
    Fail { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDir {
    Up,
    Down,
    Left,
    Right,
}

impl ToolCall {
    /// Parse and validate a raw JSON string from the SLM.
    /// Strips markdown fences in case the model wraps its output in ```json…```.
    pub fn from_str(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();

        // Strip optional ```json … ``` fences.
        let json = if let Some(inner) = trimmed
            .strip_prefix("```json")
            .or_else(|| trimmed.strip_prefix("```"))
        {
            inner.trim_end_matches("```").trim()
        } else {
            trimmed
        };

        // Find the first `{` in case the model emits preamble text.
        let start = json
            .find('{')
            .ok_or_else(|| anyhow::anyhow!("no JSON object found"))?;
        let json = &json[start..];

        let call: ToolCall = serde_json::from_str(json)?;
        call.validate()?;
        Ok(call)
    }

    fn validate(&self) -> Result<()> {
        match self {
            ToolCall::WaitMs { ms } if *ms > 30_000 => {
                bail!("wait_ms exceeds 30 s safety cap (got {ms} ms)")
            }
            ToolCall::Screenshot { w, h, .. } if *w > 512 || *h > 512 => {
                bail!("screenshot crop too large ({w}×{h}, max 512×512)")
            }
            ToolCall::Navigate { url } if !url.starts_with("http") => {
                bail!("navigate url must be absolute (got: {url})")
            }
            _ => Ok(()),
        }
    }

    /// True when this call terminates the current plan (success or failure).
    pub fn is_terminal(&self) -> bool {
        matches!(self, ToolCall::Done { .. } | ToolCall::Fail { .. })
    }
}

// ── Tool result (JS → Rust) ───────────────────────────────────────────────────

/// The outcome reported by the JS bridge after executing a [`ToolCall`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// `true` if the action succeeded.
    pub ok: bool,
    /// Human-readable description returned to the model in the next turn.
    pub output: String,
    /// Optional base64-encoded JPEG (only set by `screenshot`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_b64: Option<String>,
}

impl ToolResult {
    pub fn success(output: impl Into<String>) -> Self {
        Self {
            ok: true,
            output: output.into(),
            image_b64: None,
        }
    }

    pub fn failure(output: impl Into<String>) -> Self {
        Self {
            ok: false,
            output: output.into(),
            image_b64: None,
        }
    }
}

// ── JSON system prompt fragment ───────────────────────────────────────────────

/// The tool-schema block injected into every executor system prompt.
/// Written in concise English to keep prompt token count low (< 300 tokens).
pub const TOOL_SCHEMA_PROMPT: &str = r#"
You control a web browser. For EACH message, output EXACTLY ONE JSON object
(no preamble, no markdown fences) from this schema:

  click        {"action":"click","target":"<css-selector or visible text>"}
  type         {"action":"type","target":"<selector>","text":"<value>"}
  navigate     {"action":"navigate","url":"<absolute-url>"}
  wait_ms      {"action":"wait_ms","ms":<number ≤ 5000>}
  read_page    {"action":"read_page"}
  screenshot   {"action":"screenshot","x":<px>,"y":<px>,"w":128,"h":128}
  scroll       {"action":"scroll","direction":"down","px":<number>}
  done         {"action":"done","summary":"<outcome>"}
  fail         {"action":"fail","reason":"<why>"}

Rules:
- Output ONLY the JSON object. Nothing else.
- Prefer CSS id/class selectors over XPath.
- Use read_page when unsure what is on screen.
- Use screenshot only when the DOM summary is insufficient.
- Call done as soon as the goal is achieved.
- Call fail after 3 failed attempts on the same action.
"#;
