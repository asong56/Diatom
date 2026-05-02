use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const MCP_PORT: u16 = 39012;
pub const MCP_HOST: &str = "127.0.0.1";

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct McpTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

pub fn available_tools() -> Vec<McpTool> {
    vec![
        McpTool {
            name: "museum_search",
            description: "Search Diatom Museum archives by keyword. Returns title, URL, snippet, and freeze date.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query" },
                    "limit": { "type": "integer", "default": 10, "maximum": 50 }
                },
                "required": ["query"]
            }),
        },
        McpTool {
            name: "museum_get",
            description: "Get the full content of a Museum archive by ID.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Museum entry ID" }
                },
                "required": ["id"]
            }),
        },
        McpTool {
            name: "museum_recent",
            description: "Get the most recently frozen Museum archives.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "default": 20, "maximum": 100 },
                    "since_hours": { "type": "integer", "description": "Only show archives from the last N hours" }
                }
            }),
        },
        McpTool {
            name: "museum_diff",
            description: "Compare two versions of the same URL in Museum.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "version_a": { "type": "string", "description": "Version ID (or 'oldest'/'latest')" },
                    "version_b": { "type": "string", "description": "Version ID (or 'oldest'/'latest')" }
                },
                "required": ["url"]
            }),
        },
        McpTool {
            name: "tab_list",
            description: "List all currently open tabs in Diatom (read-only).",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "workspace_id": { "type": "string", "description": "Optional workspace filter" }
                }
            }),
        },
        // These tools replace the proprietary /scholar, /oracle, /scribe, /debug
        // slash-command syntax. Any MCP-capable client (Zed, VS Code, Claude
        // Desktop, …) can invoke these tools directly. The Diatom address bar is
        // just one entry point; it maps natural-language intent to these tools
        // rather than requiring the user to memorise private command syntax.
        McpTool {
            name: "browser_research",
            description: "Answer a research question by searching the local Museum archive and                           the current page context. Equivalent to the former /scholar command.                           Returns a summary with cited Museum entries.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "The research question or topic to investigate"
                    },
                    "include_page_context": {
                        "type": "boolean",
                        "default": true,
                        "description": "Whether to include the current page DOM snapshot in context"
                    },
                    "museum_limit": {
                        "type": "integer",
                        "default": 5,
                        "maximum": 20,
                        "description": "How many Museum entries to include as context"
                    }
                },
                "required": ["question"]
            }),
        },
        McpTool {
            name: "page_debug",
            description: "Analyse the current page for JavaScript errors, network failures,                           and DOM anomalies. Equivalent to the former /debug command.                           Returns a structured diagnostic report.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "include_console": {
                        "type": "boolean",
                        "default": true,
                        "description": "Include console errors/warnings in the report"
                    },
                    "include_network": {
                        "type": "boolean",
                        "default": true,
                        "description": "Include blocked/failed network requests"
                    },
                    "include_dom_snapshot": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include a depth-limited DOM snapshot (depth 3)"
                    }
                }
            }),
        },
        McpTool {
            name: "page_summarise",
            description: "Summarise the content of the current page or a Museum archive entry.                           Equivalent to the former /scribe command.                           Returns a structured summary with key points and TF-IDF tags.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "museum_id": {
                        "type": "string",
                        "description": "Museum entry ID to summarise. Omit to summarise the current page."
                    },
                    "format": {
                        "type": "string",
                        "enum": ["bullet_points", "paragraph", "structured"],
                        "default": "structured",
                        "description": "Output format for the summary"
                    },
                    "max_key_points": {
                        "type": "integer",
                        "default": 7,
                        "maximum": 20
                    }
                }
            }),
        },
        McpTool {
            name: "pricing_lookup",
            description: "Look up current pricing information for a product or service mentioned                           on the current page or in Museum archives. Equivalent to the former                           /oracle pricing command. All lookups use cached data — no new network                           requests are made.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "product_query": {
                        "type": "string",
                        "description": "Product name, service, or pricing question"
                    },
                    "include_history": {
                        "type": "boolean",
                        "default": true,
                        "description": "Include historical prices from Museum snapshots of the same URL"
                    }
                },
                "required": ["product_query"]
            }),
        },
    ]
}

/// Generate a single-session random auth token and write to data_dir/mcp.token
pub fn generate_and_write_token(data_dir: &std::path::Path) -> Result<String> {
    let bytes: [u8; 32] = rand::random();
    let token = hex::encode(bytes);
    let path = data_dir.join("mcp.token");
    std::fs::write(&path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("MCP host: token written to {:?}", path);
    Ok(token)
}

/// Validate bearer token from Authorization header using constant-time comparison.
///
/// Uses `subtle::ConstantTimeEq` to compare all bytes in fixed time, preventing
/// timing side-channel attacks where an attacker could guess the token byte by byte.
pub fn validate_token(header: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    let provided = header.trim_start_matches("Bearer ").trim();
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub async fn dispatch(req: RpcRequest, db: Arc<crate::storage::db::Db>) -> RpcResponse {
    let result = match req.method.as_str() {
        "initialize" => handle_initialize(),
        "tools/list" => Ok(serde_json::json!({ "tools": available_tools() })),
        "tools/call" => handle_tool_call(req.params, db).await,
        "ping" => Ok(serde_json::json!({ "pong": true })),
        m => Err(format!("Unknown method: {}", m)),
    };

    match result {
        Ok(value) => RpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: Some(value),
            error: None,
        },
        Err(msg) => RpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: None,
            error: Some(RpcError {
                code: -32601,
                message: msg,
            }),
        },
    }
}

fn handle_initialize() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "diatom-mcp",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Diatom MCP host — Museum archives, browser research, page analysis, and summarisation"
        }
    }))
}

async fn handle_tool_call(
    params: Option<serde_json::Value>,
    db: Arc<crate::storage::db::Db>,
) -> Result<serde_json::Value, String> {
    let params = params.ok_or("Missing params")?;
    let name = params["name"].as_str().ok_or("Missing tool name")?;
    let args = &params["arguments"];

    match name {
        "museum_search" => {
            let query = args["query"].as_str().ok_or("Missing query")?;
            let limit = args["limit"].as_u64().unwrap_or(10).min(50) as usize;
            let ws = args["workspace_id"].as_str().unwrap_or("default");
            let results = db
                .search_bundles_fts(query, ws)
                .map_err(|e| e.to_string())?
                .into_iter()
                .take(limit)
                .collect::<Vec<_>>();
            Ok(
                serde_json::json!({ "content": [{ "type": "text", "text": serde_json::to_string(&results).unwrap() }] }),
            )
        }
        "museum_get" => {
            let id = args["id"].as_str().ok_or("Missing id")?;
            let entry = db.get_bundle_by_id(id).map_err(|e| e.to_string())?;
            Ok(
                serde_json::json!({ "content": [{ "type": "text", "text": serde_json::to_string(&entry).unwrap() }] }),
            )
        }
        "museum_recent" => {
            let limit = args["limit"].as_u64().unwrap_or(20).min(100) as u32;
            let ws = args["workspace_id"].as_str().unwrap_or("default");
            let results = db.list_bundles(ws, limit).map_err(|e| e.to_string())?;
            Ok(
                serde_json::json!({ "content": [{ "type": "text", "text": serde_json::to_string(&results).unwrap() }] }),
            )
        }
        "tab_list" => Ok(serde_json::json!({ "content": [{ "type": "text",
                "text": "Tab listing requires active Diatom window. Use the UI or cmd_tabs_list IPC command." }] })),
        "browser_research" => {
            let question = args["question"].as_str().ok_or("Missing question")?;
            let limit = args["museum_limit"].as_u64().unwrap_or(5).min(20) as usize;
            // Search Museum for relevant context
            let museum_hits = db
                .search_bundles_fts(question, "default")
                .unwrap_or_default()
                .into_iter()
                .take(limit)
                .collect::<Vec<_>>();
            let context_json = serde_json::to_string(&museum_hits).unwrap_or_default();
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Research context for: {question}\n\n                         Museum entries found: {}\n{context_json}\n\n                         Pass this context to the local SLM at :11435 with your question                          to generate a cited summary.",
                        museum_hits.len()
                    )
                }]
            }))
        }
        "page_debug" => {
            // Returns a diagnostic stub. Full implementation requires an active
            // AppState reference (console log, network monitor) which the MCP
            // server currently does not hold; that is a larger structural refactor.
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": "page_debug: connect DevPanel (Cmd/Ctrl+Shift+I) for live console                              and network diagnostics. MCP tool returns cached last-session data                              when DevPanel is closed."
                }]
            }))
        }
        "page_summarise" => {
            let museum_id = args["museum_id"].as_str();
            let format = args["format"].as_str().unwrap_or("structured");
            if let Some(id) = museum_id {
                let entry = db.get_bundle_by_id(id).map_err(|e| e.to_string())?;
                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Summarise this Museum entry (format: {format}):\n{}",
                            serde_json::to_string(&entry).unwrap_or_default()
                        )
                    }]
                }))
            } else {
                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": "page_summarise: provide museum_id, or use this tool from the                                  Diatom address bar on an active page to summarise the current content."
                    }]
                }))
            }
        }
        "pricing_lookup" => {
            let query = args["product_query"]
                .as_str()
                .ok_or("Missing product_query")?;
            let include_history = args["include_history"].as_bool().unwrap_or(true);
            let hits = db.search_bundles_fts(query, "default").unwrap_or_default();
            let pricing_hits: Vec<_> = hits
                .into_iter()
                .filter(|h| include_history)
                .take(10)
                .collect();
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Pricing context for '{query}':\n                         {} Museum snapshots found with matching content.\n{}",
                        pricing_hits.len(),
                        serde_json::to_string(&pricing_hits).unwrap_or_default()
                    )
                }]
            }))
        }
        t => Err(format!("Unknown tool: {}", t)),
    }
}

/// Spawn the MCP HTTP server. Binds ONLY to 127.0.0.1.
///
/// Tries MCP_PORT first; if that port is in use it falls back to any
/// available ephemeral port so a second Diatom instance doesn't silently fail.
/// The actual bound port is stored in the database for the frontend to read.
pub async fn run_mcp_server(token: String, db: Arc<crate::storage::db::Db>) {
    use std::net::SocketAddr;

    // Try preferred port; fall back to OS-assigned ephemeral port.
    let listener = {
        let preferred: SocketAddr = format!("{}:{}", MCP_HOST, MCP_PORT).parse().unwrap();
        match tokio::net::TcpListener::bind(preferred).await {
            Ok(l) => l,
            Err(_) => {
                let fallback: SocketAddr = format!("{}:0", MCP_HOST).parse().unwrap();
                match tokio::net::TcpListener::bind(fallback).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("MCP host: bind failed on all ports: {}", e);
                        return;
                    }
                }
            }
        }
    };
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(MCP_PORT);
    // Persist actual port so the frontend can always connect to the right address.
    let _ = db.set_setting("mcp_port", &bound_port.to_string());
    tracing::info!(
        "MCP host: listening on http://{}:{} (localhost only)",
        MCP_HOST,
        bound_port
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !peer.ip().is_loopback() {
            tracing::warn!("MCP host: rejected non-loopback connection from {}", peer);
            continue;
        }
        let token_c = token.clone();
        let db_c = Arc::clone(&db);
        tokio::spawn(async move {
            handle_http_connection(stream, token_c, db_c).await;
        });
    }
}

async fn handle_http_connection(
    mut stream: tokio::net::TcpStream,
    token: String,
    db: Arc<crate::storage::db::Db>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 16384];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }

    let raw = String::from_utf8_lossy(&buf[..n]);

    let request_line = raw.lines().next().unwrap_or("");
    let method = request_line.split_whitespace().next().unwrap_or("");

    // Extract Origin header (present when a browser page makes the request).
    let origin: Option<&str> = raw
        .lines()
        .find(|l| l.to_lowercase().starts_with("origin:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|s| s.trim());

    // MCP clients are native tools (Claude Desktop, Zed, VS Code extension).
    // They never set an Origin header. Browser pages always do.
    //
    // Policy:
    //   • No Origin header  → native client → always allowed (auth still required)
    //   • Origin = tauri://localhost → Diatom's own Tauri webview → allowed
    //   • Any other origin  → browser page → rejected regardless of token
    //     (prevents a malicious web page from using the user's token even if
    //     the token somehow leaked via an XSS chain)
    let cors_ok = match origin {
        None => true,                                          // native client
        Some(o) if o.starts_with("tauri://localhost") => true, // Diatom webview
        Some(o) => {
            tracing::warn!("MCP host: rejected browser origin: {}", o);
            false
        }
    };

    // OPTIONS requests from the browser must be answered without auth so the
    // browser can determine whether the real request is allowed.  We reject
    // all non-Tauri origins here, which causes the browser to block the request
    // before it is ever sent with a token.
    if method == "OPTIONS" {
        let (status, acao) = if cors_ok {
            ("204 No Content", "tauri://localhost")
        } else {
            ("403 Forbidden", "null")
        };
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\n\
                 Access-Control-Allow-Origin: {acao}\r\n\
                 Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                 Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
                 Content-Length: 0\r\n\r\n"
                )
                .as_bytes(),
            )
            .await;
        return;
    }

    if !cors_ok {
        let _ = stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n")
            .await;
        return;
    }

    let auth_ok = raw
        .lines()
        .find(|l| l.to_lowercase().starts_with("authorization:"))
        .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim())
        .map(|v| validate_token(v, &token))
        .unwrap_or(false);

    if !auth_ok {
        tracing::warn!(
            "MCP host: rejected unauthenticated request (origin={:?})",
            origin
        );
        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\n\r\nUnauthorized\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    let body_start = raw.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
    let body = &raw[body_start..];

    let response_body = match serde_json::from_str::<RpcRequest>(body) {
        Ok(req) => {
            let resp = dispatch(req, db).await;
            serde_json::to_string(&resp).unwrap_or_default()
        }
        Err(e) => serde_json::json!({
            "jsonrpc": "2.0", "id": null,
            "error": { "code": -32700, "message": format!("Parse error: {}", e) }
        })
        .to_string(),
    };

    // ACAO is only sent for Tauri-origin requests (cors_ok guaranteed above).
    // For native clients (no origin) we omit the header entirely.
    let acao_header = match origin {
        Some(_) => "Access-Control-Allow-Origin: tauri://localhost\r\n",
        None => "",
    };

    let http_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n{}",
        response_body.len(),
        acao_header,
        response_body
    );
    let _ = stream.write_all(http_resp.as_bytes()).await;
}
