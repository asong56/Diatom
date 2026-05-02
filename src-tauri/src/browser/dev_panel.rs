use crate::state::AppState;
use anyhow::{Context, Result};
use diatom_bridge::protocol::ResonanceContext;
use diatom_bridge::{
    BridgeClient, BrowserMessage, RequestId, ZedContextServer,
    transport::socket_path,
};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::Mutex;

/// Held in `tauri::State<DevPanelState>`.
pub struct DevPanelState {
    inner: Mutex<Option<DevPanelHandle>>,
    /// Resonance ↔ Zed context bridge (started once, lives for the process).
    resonance: Mutex<Option<ZedContextServer>>,
}

struct DevPanelHandle {
    #[allow(dead_code)]
    child: Child,
    client: BridgeClient,
}

impl DevPanelState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            resonance: Mutex::new(None),
        }
    }
}

/// Open (or focus) the DevPanel window.
/// Called from JS: `invoke("dev_panel_open", { projectRoot })`

#[tauri::command]
pub async fn dev_panel_open<R: Runtime>(
    app: AppHandle<R>,
    state: tauri::State<'_, DevPanelState>,
    project_root: Option<String>,
) -> Result<(), String> {
    let mut guard = state.inner.lock().await;

    if let Some(handle) = guard.as_ref() {
        let root = project_root.unwrap_or_default();
        handle
            .client
            .send(BrowserMessage::Open {
                id: next_id(),
                project_root: root,
            })
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    let auth_token = app
        .try_state::<AppState>()
        .map(|st| st.devpanel_auth_token.clone())
        .unwrap_or_else(|| {
            log::warn!("[dev-panel] AppState unavailable — generating ephemeral token");
            diatom_bridge::protocol::generate_auth_token()
        });

    let handle = spawn_devpanel(&app, project_root, &auth_token)
        .await
        .map_err(|e| e.to_string())?;

    if let Err(e) = start_inbound_pump(app.clone(), &handle, &state).await {
        log::warn!("[dev-panel] {e}");
    }

    ensure_resonance_server(&state).await;

    *guard = Some(handle);
    Ok(())
}

/// Close the DevPanel.
#[tauri::command]
pub async fn dev_panel_close(state: tauri::State<'_, DevPanelState>) -> Result<(), String> {
    let mut guard = state.inner.lock().await;
    if let Some(mut handle) = guard.take() {
        handle.client.send(BrowserMessage::Shutdown).await.ok();
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        handle.child.kill().ok();
    }
    Ok(())
}

/// Forward a console log entry from the WebView JS to the DevPanel.
#[tauri::command]
pub async fn dev_panel_console_entry(
    state: tauri::State<'_, DevPanelState>,
    level: String,
    text: String,
    source_file: Option<String>,
    source_line: Option<u32>,
) -> Result<(), String> {
    use diatom_bridge::protocol::ConsoleLevel;
    let level = match level.as_str() {
        "warn" => ConsoleLevel::Warn,
        "error" => ConsoleLevel::Error,
        "info" => ConsoleLevel::Info,
        "debug" => ConsoleLevel::Debug,
        _ => ConsoleLevel::Log,
    };
    send_if_open(
        &state,
        BrowserMessage::ConsoleEntry {
            level,
            text,
            source_file,
            source_line,
        },
    )
    .await
    .map_err(|e| e.to_string())
}

/// Notify the DevPanel of a page navigation.
#[tauri::command]
pub async fn dev_panel_navigate(
    state: tauri::State<'_, DevPanelState>,
    url: String,
    title: String,
) -> Result<(), String> {
    push_resonance_context(
        &state,
        ResonanceContext {
            page_url: url.clone(),
            page_title: title.clone(),
            console_errors: vec![],
            dom_root: None,
            active_source: None,
        },
    )
    .await;

    send_if_open(
        &state,
        BrowserMessage::PageNavigated {
            url,
            title,
            dom_snapshot: None,
        },
    )
    .await
    .map_err(|e| e.to_string())
}

async fn spawn_devpanel<R: Runtime>(
    app: &AppHandle<R>,
    project_root: Option<String>,
    auth_token: &str,
) -> Result<DevPanelHandle> {
    let pid = std::process::id();
    let sock = socket_path(pid);
    let bin = devpanel_bin_path(app)?;

    let child = Command::new(&bin)
        .arg("--diatom-pid")
        .arg(pid.to_string())
        // Pass the auth token as a CLI argument so the DevPanel can validate
        // the connecting backend (HandshakeMessage::Challenge/Response protocol).
        // NOTE: this is visible in /proc/<pid>/cmdline to same-user processes.
        // A 0600 tmpfile would be a stronger alternative for a future hardening pass.
        .arg("--auth-token")
        .arg(auth_token)
        .env("DIATOM_DEVPANEL", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn diatom-devpanel")?;

    let client = BridgeClient::connect(&sock, auth_token, 20)
        .await
        .context("connect to DevPanel")?;

    if let Some(root) = project_root {
        client
            .send(BrowserMessage::Open {
                id: next_id(),
                project_root: root,
            })
            .await
            .ok();
    }

    Ok(DevPanelHandle { child, client })
}

fn devpanel_bin_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf> {
    let mut path = app.path().resource_dir().context("resource_dir")?;
    #[cfg(target_os = "windows")]
    path.push("diatom-devpanel.exe");
    #[cfg(not(target_os = "windows"))]
    path.push("diatom-devpanel");
    Ok(path)
}

/// Start the inbound message pump and route DevPanelMessages to Diatom subsystems.
///
/// NOT YET IMPLEMENTED — returns Err so callers know the DevPanel receive path
/// is unavailable. Messages sent from the DevPanel to Diatom will be dropped
/// until this pump is wired.
///
/// TODO: wire DevPanelMessage variants:
///   EvalJs            → WebView.eval()
///   SlmRequest        → ai::slm proxy
///   FetchSourceFile   → read resource + reply
///   RequestNetworkLog → engine::monitor snapshot
///   OpenInZedIde      → open_in_zed()
async fn start_inbound_pump<R: Runtime>(
    _app: AppHandle<R>,
    _handle: &DevPanelHandle,
    _state: &DevPanelState,
) -> Result<(), String> {
    Err("inbound pump not yet implemented — DevPanel→Diatom messages will be dropped".into())
}

/// Attempt to open a local file in the external Zed IDE.
///
/// Resolution: `project_root + url_path_component → absolute path`.
/// Falls back to a notification if `zed` is not in PATH or no local file found.
pub fn open_in_zed(url: &str, project_root: Option<&str>, line: Option<u32>) {
    let path = resolve_local_path(url, project_root);
    let Some(path) = path else {
        log::info!("[open-in-zed] no local file resolved for {url}");
        return;
    };

    let arg = match line {
        Some(l) => format!("{path}:{l}", path = path.display()),
        None => path.display().to_string(),
    };

    match std::process::Command::new("zed").arg(&arg).spawn() {
        Ok(_) => log::info!("[open-in-zed] opened {arg}"),
        Err(e) => log::warn!("[open-in-zed] could not spawn zed: {e}"),
    }
}

/// Heuristic: map a resource URL to a local filesystem path.
///
/// Rules (in order):
///  1. `file://` URLs → strip scheme directly.
///  2. HTTP/HTTPS URLs relative to project_root → `project_root + path`.
///  3. Returns None if no project_root is set or the resulting path does not exist.
fn resolve_local_path(url: &str, project_root: Option<&str>) -> Option<PathBuf> {
    if let Some(file_path) = url.strip_prefix("file://") {
        let p = PathBuf::from(file_path);
        return p.exists().then_some(p);
    }

    let root = project_root?;
    let url_path = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/').map(|(_, path)| path))
        .unwrap_or("");

    let candidate = PathBuf::from(root).join(url_path);
    candidate.exists().then_some(candidate)
}

async fn ensure_resonance_server(state: &DevPanelState) {
    let mut guard = state.resonance.lock().await;
    if guard.is_none() {
        match ZedContextServer::start().await {
            Ok(srv) => {
                log::info!("[dev-panel] Resonance context server started");
                *guard = Some(srv);
            }
            Err(e) => {
                log::warn!("[dev-panel] could not start Resonance server: {e}");
            }
        }
    }
}

async fn push_resonance_context(state: &DevPanelState, ctx: ResonanceContext) {
    let guard = state.resonance.lock().await;
    if let Some(srv) = guard.as_ref() {
        srv.push(ctx);
    }
}

async fn send_if_open(state: &tauri::State<'_, DevPanelState>, msg: BrowserMessage) -> Result<()> {
    let guard = state.inner.lock().await;
    if let Some(handle) = guard.as_ref() {
        handle.client.send(msg).await?;
    }
    Ok(())
}

fn next_id() -> RequestId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Called from JS `window.__diatom_open_in_zed(url, line)`.
///
/// Resolves `url` to a local filesystem path using `resolve_local_path`,
/// then spawns `zed <path>:<line>`.
///
/// Returns `Ok(true)` if zed was spawned, `Ok(false)` if no local file
/// was found (the frontend can show a "file not found locally" hint).
#[tauri::command]
pub async fn dev_panel_open_in_zed(
    state: tauri::State<'_, DevPanelState>,
    url: String,
    line: Option<u32>,
) -> Result<bool, String> {
    let project_root: Option<String> = {
        let guard = state.inner.lock().await;
        drop(guard);
        std::env::var("DIATOM_PROJECT_ROOT").ok()
    };

    let path = resolve_local_path(&url, project_root.as_deref());
    match path {
        None => {
            log::info!("[open-in-zed] no local file for {url}");
            Ok(false)
        }
        Some(p) => {
            let arg = match line {
                Some(l) => format!("{path}:{l}", path = p.display()),
                None => p.display().to_string(),
            };
            match std::process::Command::new("zed").arg(&arg).spawn() {
                Ok(_) => log::info!("[open-in-zed] opened {arg}"),
                Err(e) => log::warn!("[open-in-zed] could not spawn zed: {e}"),
            }
            Ok(true)
        }
    }
}
