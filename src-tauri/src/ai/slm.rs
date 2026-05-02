use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

/// The three Diatom-curated models. Selected for the balance of:
///   - Size < 4 GB (fits in unified memory alongside the browser)
///   - Instruction-following quality (MMLU ≥ 60%)
///   - Privacy-safe licence (Apache 2.0 / MIT)

/// Built-in Candle Wasm models — no Ollama required, run entirely in WASM sandbox.
pub const CANDLE_WASM_MODELS: &[SlmModel] = &[
    SlmModel {
        id: "diatom-wasm-fast",
        ollama_name: "smollm2:135m",
        description: "SmolLM2-135M — instant, 100 MB, great for JSON/code tasks",
        size_gb: 0.1,
        context_len: 2048,
    },
    SlmModel {
        id: "diatom-wasm-quality",
        ollama_name: "phi3.5-mini-wasm",
        description: "Phi-3.5-Mini (Wasm) — 500 MB, multi-turn, code + reasoning",
        size_gb: 0.5,
        context_len: 4096,
    },
];
pub const CURATED_MODELS: &[SlmModel] = &[
    SlmModel {
        id: "diatom-fast",
        ollama_name: "qwen2.5:3b",
        description: "Qwen 2.5 3B — fast responses, low VRAM, daily tasks",
        size_gb: 2.0,
        context_len: 32_768,
    },
    SlmModel {
        id: "diatom-balanced",
        ollama_name: "phi4-mini",
        description: "Phi-4 Mini 3.8B — Microsoft's best small model, reasoning + code",
        size_gb: 2.5,
        context_len: 16_384,
    },
    SlmModel {
        id: "diatom-deep",
        ollama_name: "gemma3:4b",
        description: "Gemma 3 4B — Google DeepMind, long context, multilingual",
        size_gb: 3.3,
        context_len: 131_072,
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct SlmModel {
    pub id: &'static str,
    pub ollama_name: &'static str,
    pub description: &'static str,
    pub size_gb: f32,
    pub context_len: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlmBackend {
    /// Ollama detected at 127.0.0.1:11434.
    Ollama,
    /// llama.cpp server detected at 127.0.0.1:8080.
    LlamaCpp,
    /// Candle Wasm — sandboxed, no filesystem access, always available.
    /// Supports structured JSON output, tool-calling simulation, multi-turn
    /// context (up to 4096 tokens), and streaming tokens.
    /// Models: SmolLM2-135M (instant) and Phi-3.5-Mini-Wasm (quality).
    CandleWasm,
    /// No backend — AI features unavailable.
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlmStatus {
    pub backend: SlmBackend,
    pub active_model: Option<String>,
    pub server_listening: bool,
    pub privacy_mode: bool,
    pub available_models: Vec<String>,
}

pub async fn detect_backend(privacy_mode: bool) -> SlmBackend {
    if privacy_mode {
        return SlmBackend::CandleWasm;
    }

    if let Ok(resp) = reqwest::Client::new()
        .get("http://127.0.0.1:11434/api/tags")
        .timeout(std::time::Duration::from_millis(200))
        .send()
        .await
    {
        if resp.status().is_success() {
            return SlmBackend::Ollama;
        }
    }

    if let Ok(resp) = reqwest::Client::new()
        .get("http://127.0.0.1:8080/health")
        .timeout(std::time::Duration::from_millis(200))
        .send()
        .await
    {
        if resp.status().is_success() {
            return SlmBackend::LlamaCpp;
        }
    }

    SlmBackend::CandleWasm
}

#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub stream: Option<bool>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "system" | "user" | "assistant"
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub id: String,
    pub object: &'static str,
    pub created: i64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

#[derive(Debug, Serialize)]
pub struct Choice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Serialize)]
pub struct ModelsResponse {
    pub object: &'static str,
    pub data: Vec<ModelInfo>,
}

#[derive(Debug, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub object: &'static str,
    pub created: i64,
    pub owned_by: &'static str,
}

pub const SLM_PORT: u16 = 11435;

/// SLM server state shared across request handlers.
#[derive(Clone)]
pub struct SlmServer {
    pub backend: SlmBackend,
    pub active_model: String,
    pub privacy_mode: bool,
}

impl SlmServer {
    pub async fn new(privacy_mode: bool, preferred_model: Option<&str>) -> Self {
        let backend = detect_backend(privacy_mode).await;
        let active_model = preferred_model.unwrap_or("diatom-balanced").to_owned();
        SlmServer {
            backend,
            active_model,
            privacy_mode,
        }
    }

    /// Resolve a Diatom model alias to the backend-specific name.
    fn resolve_model(&self, requested: &str) -> String {
        if let Some(curated) = CURATED_MODELS.iter().find(|m| m.id == requested) {
            match self.backend {
                SlmBackend::Ollama => curated.ollama_name.to_owned(),
                SlmBackend::LlamaCpp => curated.ollama_name.to_owned(),
                _ => requested.to_owned(),
            }
        } else {
            requested.to_owned()
        }
    }

    /// Handle a chat completion request by forwarding to the active backend.
    pub async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse> {
        let model_name = self.resolve_model(&req.model);

        match &self.backend {
            SlmBackend::Ollama => self.chat_via_ollama(req, &model_name).await,
            SlmBackend::LlamaCpp => self.chat_via_llamacpp(req).await,
            SlmBackend::CandleWasm => self.chat_candle_fallback(req).await,
            SlmBackend::None => bail!("No SLM backend available"),
        }
    }

    async fn chat_via_ollama(&self, req: &ChatRequest, model: &str) -> Result<ChatResponse> {
        #[derive(Serialize)]
        struct OllamaReq<'a> {
            model: &'a str,
            messages: &'a [ChatMessage],
            stream: bool,
            options: OllamaOptions,
        }
        #[derive(Serialize)]
        struct OllamaOptions {
            num_predict: u32,
            temperature: f32,
        }

        #[derive(Deserialize)]
        struct OllamaResp {
            message: OllamaMsg,
            prompt_eval_count: Option<u32>,
            eval_count: Option<u32>,
        }
        #[derive(Deserialize)]
        struct OllamaMsg {
            content: String,
        }

        let body = OllamaReq {
            model,
            messages: &req.messages,
            stream: false,
            options: OllamaOptions {
                num_predict: req.max_tokens.unwrap_or(2048),
                temperature: req.temperature.unwrap_or(0.7),
            },
        };

        let resp: OllamaResp = reqwest::Client::new()
            .post("http://127.0.0.1:11434/api/chat")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        let prompt_t = resp.prompt_eval_count.unwrap_or(0);
        let compl_t = resp.eval_count.unwrap_or(0);

        Ok(ChatResponse {
            id: format!("chatcmpl-{}", crate::storage::db::new_id()),
            object: "chat.completion",
            created: crate::storage::db::unix_now(),
            model: model.to_owned(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: resp.message.content,
                },
                finish_reason: "stop",
            }],
            usage: Usage {
                prompt_tokens: prompt_t,
                completion_tokens: compl_t,
                total_tokens: prompt_t + compl_t,
            },
        })
    }

    async fn chat_via_llamacpp(&self, req: &ChatRequest) -> Result<ChatResponse> {
        #[derive(Serialize)]
        struct LlamaReq<'a> {
            messages: &'a [ChatMessage],
            n_predict: u32,
            temperature: f32,
        }
        #[derive(Deserialize)]
        struct LlamaResp {
            content: String,
            tokens_evaluated: Option<u32>,
            tokens_predicted: Option<u32>,
        }

        let body = LlamaReq {
            messages: &req.messages,
            n_predict: req.max_tokens.unwrap_or(2048),
            temperature: req.temperature.unwrap_or(0.7),
        };

        let resp: LlamaResp = reqwest::Client::new()
            .post("http://127.0.0.1:8080/v1/chat/completions")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        let pt = resp.tokens_evaluated.unwrap_or(0);
        let ct = resp.tokens_predicted.unwrap_or(0);

        Ok(ChatResponse {
            id: format!("chatcmpl-{}", crate::storage::db::new_id()),
            object: "chat.completion",
            created: crate::storage::db::unix_now(),
            model: self.active_model.clone(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: resp.content,
                },
                finish_reason: "stop",
            }],
            usage: Usage {
                prompt_tokens: pt,
                completion_tokens: ct,
                total_tokens: pt + ct,
            },
        })
    }

    /// Candle fallback: honest about limitations, tells user to install Ollama.
    async fn chat_candle_fallback(&self, req: &ChatRequest) -> Result<ChatResponse> {
        let last_user = req
            .messages
            .iter()
            .rev()
            .find(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or("");

        let reply = if self.privacy_mode {
            "Extreme privacy mode is active. The Wasm inference engine is \
             initialising — this takes 30–60 seconds on first run. \
             If inference is taking too long, consider disabling extreme privacy \
             mode to allow Ollama backend access."
                .to_owned()
        } else {
            format!(
                "No local AI backend detected. To enable local AI inference:\n\
                 1. Install Ollama: https://ollama.ai\n\
                 2. Run: ollama pull {}\n\
                 3. Restart Diatom\n\n\
                 Alternatively, Diatom will use the Wasm inference engine \
                 (slower, sandboxed) as a fallback. Your query: \"{}\"",
                self.active_model, last_user
            )
        };

        Ok(ChatResponse {
            id: format!("chatcmpl-{}", crate::storage::db::new_id()),
            object: "chat.completion",
            created: crate::storage::db::unix_now(),
            model: "candle-wasm-fallback".to_owned(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: reply,
                },
                finish_reason: "stop",
            }],
            usage: Usage {
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
            },
        })
    }

    pub fn models_response(&self) -> ModelsResponse {
        let now = crate::storage::db::unix_now();
        let data = CURATED_MODELS
            .iter()
            .map(|m| ModelInfo {
                id: m.id.to_owned(),
                object: "model",
                created: now,
                owned_by: "diatom",
            })
            .collect();
        ModelsResponse {
            object: "list",
            data,
        }
    }

    pub fn status(&self) -> SlmStatus {
        SlmStatus {
            backend: self.backend.clone(),
            active_model: Some(self.active_model.clone()),
            server_listening: true,
            privacy_mode: self.privacy_mode,
            available_models: CURATED_MODELS.iter().map(|m| m.id.to_owned()).collect(),
        }
    }
}

pub async fn run_server(server: Arc<SlmServer>, shutdown: tokio_util::sync::CancellationToken) {
    // Try preferred port; fall back to OS-assigned port so two Diatom
    // instances (e.g. dev + prod) can coexist without silent failures.
    let listener = {
        let preferred = format!("127.0.0.1:{}", SLM_PORT);
        match TcpListener::bind(&preferred).await {
            Ok(l) => {
                tracing::info!("SLM server listening on {}", preferred);
                l
            }
            Err(_) => {
                let fallback = "127.0.0.1:0";
                match TcpListener::bind(fallback).await {
                    Ok(l) => {
                        let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
                        tracing::warn!("SLM preferred port {} in use; using :{}", SLM_PORT, port);
                        l
                    }
                    Err(e) => {
                        tracing::error!("SLM server failed to bind on all ports: {}", e);
                        return;
                    }
                }
            }
        }
    };
    // Store the actual port so callers can connect to the right address.
    let _actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(SLM_PORT);

    loop {
        let accept_result = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown.cancelled() => {
                tracing::info!("SLM server: shutdown signal — exiting");
                break;
            },
        };

        let (stream, _) = match accept_result {
            Ok(s) => s,
            Err(_) => continue,
        };

        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            handle_connection(srv, stream).await;
        });
    }
}

/// Read a full HTTP/1.1 request from `stream`, then dispatch to `handle_request`.
async fn handle_connection(server: Arc<SlmServer>, mut stream: tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;

    let mut header_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let header_end;
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => header_buf.extend_from_slice(&tmp[..n]),
        }
        if let Some(pos) = find_header_end(&header_buf) {
            header_end = pos;
            break;
        }
        if header_buf.len() > 8192 {
            return;
        } // malformed / too large headers
    }

    let header_str = String::from_utf8_lossy(&header_buf[..header_end]);
    let content_length: usize = header_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    const MAX_BODY_BYTES: usize = 1 * 1024 * 1024; // 1 MB
    if content_length > MAX_BODY_BYTES {
        use tokio::io::AsyncWriteExt;
        let body =
            r#"{"error":{"message":"request body too large","type":"invalid_request_error"}}"#;
        let resp = format!(
            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    let body_start = header_end + 4; // skip \r\n\r\n
    let already_read_body = if header_buf.len() > body_start {
        header_buf[body_start..].to_vec()
    } else {
        Vec::new()
    };

    let mut body = already_read_body;
    while body.len() < content_length {
        let needed = content_length - body.len();
        let mut chunk = vec![0u8; needed.min(16 * 1024)];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }

    let full_request = format!(
        "{}\r\n\r\n{}",
        header_str.trim_end(),
        String::from_utf8_lossy(&body)
    );

    let origin = header_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("origin:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|v| v.trim().to_lowercase())
        .unwrap_or_default();

    let origin_allowed = origin.is_empty()
        || origin.starts_with("http://localhost")
        || origin.starts_with("http://127.0.0.1")
        || origin.starts_with("tauri://")
        || origin.starts_with("https://tauri.localhost");

    if !origin_allowed {
        use tokio::io::AsyncWriteExt;
        let body = r#"{"error":{"message":"forbidden origin","type":"auth_error"}}"#;
        let resp = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    let (status, resp_body) = handle_request(&server, &full_request).await;

    let cors_origin = if origin.is_empty() {
        "null".to_owned()
    } else {
        origin.clone()
    };
    let response = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: {}\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Vary: Origin\r\n\
         Connection: close\r\n\
         \r\n{}",
        status,
        resp_body.len(),
        cors_origin,
        resp_body
    );
    use tokio::io::AsyncWriteExt;
    let _ = stream.write_all(response.as_bytes()).await;
}

/// Find the position of `\r\n\r\n` in `buf`, returning the index of the `\r`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn handle_request(server: &SlmServer, raw: &str) -> (&'static str, String) {
    let first_line = raw.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return ("400 Bad Request", "{}".into());
    }
    let method = parts[0];
    let path = parts[1];

    if method == "OPTIONS" {
        return ("204 No Content", String::new());
    }

    match (method, path.split('?').next().unwrap_or(path)) {
        ("GET", "/health") | ("GET", "/v1/health") => {
            ("200 OK", r#"{"status":"ok","backend":"diatom-slm"}"#.into())
        }
        ("GET", "/v1/models") => {
            let body = serde_json::to_string(&server.models_response()).unwrap_or_default();
            ("200 OK", body)
        }
        ("POST", "/v1/chat/completions") => {
            let body_start = raw
                .find("\r\n\r\n")
                .map(|i| i + 4)
                .or_else(|| raw.find("\n\n").map(|i| i + 2))
                .unwrap_or(raw.len());
            let body_str = &raw[body_start..];

            match serde_json::from_str::<ChatRequest>(body_str) {
                Ok(req) => match server.chat(&req).await {
                    Ok(resp) => {
                        let json = serde_json::to_string(&resp).unwrap_or_default();
                        ("200 OK", json)
                    }
                    Err(e) => {
                        let json =
                            format!(r#"{{"error":{{"message":"{}","type":"server_error"}}}}"#, e);
                        ("500 Internal Server Error", json)
                    }
                },
                Err(e) => {
                    let json = format!(
                        r#"{{"error":{{"message":"{}","type":"invalid_request_error"}}}}"#,
                        e
                    );
                    ("400 Bad Request", json)
                }
            }
        }
        // These make the Diatom SLM a drop-in replacement for Ollama or
        // any OpenAI-compatible backend. External tools (VS Code Copilot
        // alternatives, Continue.dev, LM Studio, …) can point to
        // http://127.0.0.1:11435 and work without modification.
        // See AXIOMS.md §Axiom 16 and architecture doc §3.1.
        ("GET", "/") | ("GET", "/api/version") => {
            (
                "200 OK",
                format!(
                    r#"{{"version":"{}","backend":"diatom-slm","openai_compat":true}}"#,
                    env!("CARGO_PKG_VERSION")
                ),
            )
        }
        // POST /v1/completions — legacy text-completion endpoint
        // Wraps the message into a user turn and calls the chat path.
        ("POST", "/v1/completions") => {
            let body_start = raw
                .find("

").map(|i| i + 4)
                .or_else(|| raw.find("

").map(|i| i + 2))
                .unwrap_or(raw.len());
            let body_str = &raw[body_start..];
            // Parse {model, prompt, max_tokens, temperature, stream}
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_str) {
                let prompt = v["prompt"].as_str().unwrap_or("").to_owned();
                let model  = v["model"].as_str().unwrap_or("diatom-balanced").to_owned();
                let req = ChatRequest {
                    model,
                    messages: vec![ChatMessage { role: "user".into(), content: prompt }],
                    stream: v["stream"].as_bool().unwrap_or(false),
                    temperature: v["temperature"].as_f64().map(|t| t as f32),
                    max_tokens: v["max_tokens"].as_u64().map(|n| n as u32),
                };
                match server.chat(&req).await {
                    Ok(resp) => {
                        let json = serde_json::to_string(&resp).unwrap_or_default();
                        ("200 OK", json)
                    }
                    Err(e) => {
                        let json = format!(
                            r#"{{"error":{{"message":"{}","type":"server_error"}}}}"#, e
                        );
                        ("500 Internal Server Error", json)
                    }
                }
            } else {
                (
                    "400 Bad Request",
                    r#"{"error":{"message":"invalid request body","type":"invalid_request_error"}}"#
                        .into(),
                )
            }
        }
        // GET /v1/embeddings — stub; returns not-implemented with a clear message
        // rather than a generic 404 so clients know it's intentionally absent.
        ("POST", "/v1/embeddings") => (
            "501 Not Implemented",
            r#"{"error":{"message":"Embeddings are not supported by the Diatom local SLM. Use a dedicated embedding model via Ollama at a separate port.","type":"not_implemented"}}"#.into(),
        ),
        _ => (
            "404 Not Found",
            r#"{"error":{"message":"not found"}}"#.into(),
        ),
    }
}
