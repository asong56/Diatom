// Tauri command handlers for the micro-agent, registered via
// generate_handler![] in main.rs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use diatom_agent::executor::PageContext;
use diatom_agent::{AgentConfig, AgentEvent, AgentIo, AgentRunner, ToolResult};
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;

static NEXT_PLAN_ID: AtomicU64 = AtomicU64::new(1);

// Separate from AppState to avoid lock contention — the agent runner holds
// its own async task handle.
pub struct ActiveAgent {
    pub runner: Mutex<Option<AgentRunner>>,
}

impl ActiveAgent {
    pub fn new() -> Self {
        Self {
            runner: Mutex::new(None),
        }
    }
}

struct TauriAgentIo {
    app: AppHandle,
}

impl AgentIo for TauriAgentIo {
    fn emit(&self, event: AgentEvent) {
        if let Err(e) = self.app.emit("agent-event", &event) {
            log::warn!("[agent-commands] emit error: {e}");
        }
    }

    fn eval_js(&self, script: String) {
        if let Some(win) = self.app.get_webview_window("main") {
            if let Err(e) = win.eval(&script) {
                log::warn!("[agent-commands] eval_js error: {e}");
            }
        }
    }

    fn request_page_context(&self) -> PageContext {
        // request_page_context is a sync trait method so it can't .await — making
        // it async is a bigger refactor. Instead we inject the extraction
        // expression speculatively; the model gets the real DOM summary on its
        // first `read_page` tool call, which is functionally equivalent.
        if let Some(win) = self.app.get_webview_window("main") {
            let _ = win.eval(
                "window.__diatom_agent_ctx = \
                 JSON.stringify(window.extractPageContext?.() ?? {})",
            );
        }

        PageContext::default()
    }
}

// Aborts any currently running plan first. Empty model string = use the
// user's currently configured SLM model.
#[tauri::command]
pub async fn cmd_agent_start(
    goal: String,
    model: String,
    app: AppHandle,
    active_agent: State<'_, ActiveAgent>,
) -> Result<u64, String> {
    let plan_id = NEXT_PLAN_ID.fetch_add(1, Ordering::Relaxed);

    let model = if model.is_empty() {
        app.state::<crate::state::AppState>()
            .db
            .get_setting("slm_preferred_model")
            .unwrap_or_else(|| "diatom-balanced".to_string())
    } else {
        model
    };

    let io = Arc::new(TauriAgentIo { app });

    let runner = AgentRunner::start(
        AgentConfig {
            goal,
            model,
            plan_id,
            tool_timeout_secs: 15,
        },
        io,
    );

    *active_agent.runner.lock().await = Some(runner);

    log::info!("[agent-commands] started plan_id={plan_id}");
    Ok(plan_id)
}


#[tauri::command]
pub async fn cmd_agent_abort(plan_id: u64, active_agent: State<'_, ActiveAgent>) -> bool {
    let mut guard = active_agent.runner.lock().await;
    if guard.is_some() {
        *guard = None; // Drop aborts the inner tokio task via CancellationToken.
        log::info!("[agent-commands] aborted plan_id={plan_id}");
        true
    } else {
        false
    }
}

// false return means late or duplicate delivery — no active runner waiting.
#[tauri::command]
pub async fn cmd_agent_tool_result(
    plan_id: u64, // reserved for future multi-agent support
    ok: bool,
    output: String,
    imageb64: Option<String>,
    active_agent: State<'_, ActiveAgent>,
) -> bool {
    let guard = active_agent.runner.lock().await;
    if let Some(runner) = guard.as_ref() {
        let result = ToolResult {
            ok,
            output,
            image_b64: imageb64,
        };
        runner.result_tx.deliver(result).await
    } else {
        log::warn!("[agent-commands] cmd_agent_tool_result(plan_id={plan_id}): no active runner");
        false
    }
}
