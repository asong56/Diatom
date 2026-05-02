use anyhow::{Context, Result};
use futures::Stream;
use serde::{Deserialize, Serialize};

/// The local SLM endpoint provided by Diatom's `slm.rs`.
const SLM_BASE: &str = "http://127.0.0.1:11435";

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Deserialize, Debug)]
struct ChatChunk {
    choices: Vec<ChunkChoice>,
}

#[derive(Deserialize, Debug)]
struct ChunkChoice {
    delta: DeltaContent,
    finish_reason: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct DeltaContent {
    #[serde(default)]
    content: String,
}

/// Stateless HTTP client for Diatom's SLM endpoint.
/// Cheap to clone — wraps a `reqwest::Client` (connection-pooled internally).
#[derive(Clone, Debug)]
pub struct DiatomSlmClient {
    http: reqwest::Client,
    model: String,
}

impl DiatomSlmClient {
    /// Create a client targeting the given model name.
    /// Model names come from Diatom's curated catalogue (e.g. "phi-3-mini").
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            model: model.into(),
        }
    }

    /// List models available from the local SLM server.
    /// Returns an empty vec if the server is not running.
    pub async fn available_models(&self) -> Vec<String> {
        #[derive(Deserialize)]
        struct ModelsResp {
            data: Vec<ModelEntry>,
        }
        #[derive(Deserialize)]
        struct ModelEntry {
            id: String,
        }

        match self.http.get(format!("{SLM_BASE}/v1/models")).send().await {
            Ok(resp) => resp
                .json::<ModelsResp>()
                .await
                .map(|r| r.data.into_iter().map(|m| m.id).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        }
    }

    /// Send a chat completion request and collect the full response.
    pub async fn complete(
        &self,
        messages: &[ChatMessage],
        max_tokens: Option<u32>,
    ) -> Result<String> {
        let body = ChatRequest {
            model: &self.model,
            messages,
            stream: false,
            max_tokens,
        };

        #[derive(Deserialize)]
        struct Resp {
            choices: Vec<FullChoice>,
        }
        #[derive(Deserialize)]
        struct FullChoice {
            message: ChatMessage,
        }

        let resp: Resp = self
            .http
            .post(format!("{SLM_BASE}/v1/chat/completions"))
            .json(&body)
            .send()
            .await
            .context("SLM request")?
            .error_for_status()
            .context("SLM error status")?
            .json()
            .await
            .context("SLM response parse")?;

        Ok(resp
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default())
    }

    /// Stream a chat completion, yielding text deltas.
    pub fn stream_complete(
        &self,
        messages: Vec<ChatMessage>,
        max_tokens: Option<u32>,
    ) -> impl Stream<Item = Result<String>> + 'static {
        let http = self.http.clone();
        let model = self.model.clone();

        async_stream::try_stream! {
            let body = ChatRequest {
                model:    &model,
                messages: &messages,
                stream:   true,
                max_tokens,
            };

            let mut resp = http
                .post(format!("{SLM_BASE}/v1/chat/completions"))
                .json(&body)
                .send()
                .await
                .context("SLM stream request")?
                .error_for_status()
                .context("SLM stream error status")?;

            let mut buf = String::new();
            while let Some(bytes) = resp.chunk().await.context("read chunk")? {
                buf.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(nl) = buf.find("\n\n") {
                    let line = buf.drain(..nl + 2).collect::<String>();
                    let trimmed = line.trim();
                    if trimmed == "data: [DONE]" {
                        return;
                    }
                    if let Some(json_str) = trimmed.strip_prefix("data: ") {
                        if let Ok(parsed) = serde_json::from_str::<ChatChunk>(json_str) {
                            for choice in parsed.choices {
                                if !choice.delta.content.is_empty() {
                                    yield choice.delta.content;
                                }
                                if choice.finish_reason.is_some() {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Ask the SLM to complete `prefix` in the language `lang`.
/// Used by the DevPanel editor for inline ghost-text completion.
pub async fn inline_complete(client: &DiatomSlmClient, prefix: &str, lang: &str) -> Result<String> {
    let messages = vec![
        ChatMessage {
            role: "system".into(),
            content: format!(
                "You are a code completion assistant. \
                 Complete the following {lang} code. \
                 Output ONLY the completion, no explanations."
            ),
        },
        ChatMessage {
            role: "user".into(),
            content: prefix.to_string(),
        },
    ];
    client.complete(&messages, Some(256)).await
}
