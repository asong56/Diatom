//! `agent_commands.rs` — Tauri command handlers for the micro-agent.
//!
//! Registered in `main.rs`:
//!
//! ```rust
//! .manage(agent_commands::ActiveAgent::new())
//! .invoke_handler(tauri::generate_handler![
//!     // … existing commands …
//!     agent_commands::cmd_agent_start,
//!     agent_commands::cmd_agent_abort,
//!     agent_commands::cmd_agent_tool_result,
//! ])
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use diatom_agent::executor::PageContext;
use diatom_agent::{AgentConfig, AgentEvent, AgentIo, AgentRunner, ToolResult};
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;

static NEXT_PLAN_ID: AtomicU64 = AtomicU64::new(1);

/// Stored in Tauri's managed state (separate from `AppState` to avoid lock
/// contention; the agent runner holds its own async task handle).
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

/// Bridges `diatom_agent::AgentIo` to Tauri's event system and webview eval.
struct TauriAgentIo {
    app: AppHandle,
}

impl AgentIo for TauriAgentIo {
    fn emit(&self, event: AgentEvent) {
        // Emit on the Tauri global event bus.  JS listens via:
        //   window.__TAURI__.event.listen('agent-event', handler)
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
        // `AgentIo::request_page_context` is a synchronous trait method, so we
        // cannot `.await` here. The async read-back pattern requires making this
        // method async, which is a larger structural refactor.
        //
        // We inject the extraction expression speculatively. The model calls the
        // `read_page` tool on its first turn to obtain the actual DOM summary,
        // which is functionally equivalent and does not block the Tokio runtime.
        if let Some(win) = self.app.get_webview_window("main") {
            let _ = win.eval(
                "window.__diatom_agent_ctx = \
                 JSON.stringify(window.extractPageContext?.() ?? {})",
            );
        }

        // Model discovers actual DOM state via `read_page` tool call.
        PageContext::default()
    }
}

/// Start a new agent run.  Aborts any currently running plan first.
///
/// ```
/// invoke('cmd_agent_start', { goal: 'Book cheapest flight BJ→SH', model: '' })
///   .then(planId => console.log('started plan', planId))
/// ```
///
/// Pass `model: ""` to use the user's currently configured SLM model.
#[tauri::command]
pub async fn cmd_agent_start(
    goal: String,
    model: String,
    app: AppHandle,
    active_agent: State<'_, ActiveAgent>,
) -> Result<u64, String> {
    let plan_id = NEXT_PLAN_ID.fetch_add(1, Ordering::Relaxed);

    // Resolve the model name: explicit argument wins; otherwise fall back to
    // the DB setting written by `cmd_slm_set_model`.
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

/// Cancel the currently running agent plan.
///
/// Returns `true` if a plan was running and was cancelled, `false` otherwise.
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

/// Called by the JS bridge after executing a tool call in the page.
///
/// Returns `true` when the result was accepted by the waiting runner,
/// `false` when there was no active runner (late or duplicate delivery).
///
/// ```
/// invoke('cmd_agent_tool_result', {
///   planId: 7, ok: true, output: 'Clicked Submit', imageb64: null
/// })
/// ```
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
