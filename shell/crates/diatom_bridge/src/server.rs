//! DevPanel-side bridge server.
//!
//! `BridgeServer` is used by the `diatom-devpanel` process. It binds the Unix
//! socket, accepts exactly one connection from the Diatom backend, completes
//! the authentication handshake, and then forwards messages in both directions.

use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::protocol::{BrowserMessage, DevPanelMessage, HANDSHAKE_TIMEOUT_MS, HandshakeMessage};
use crate::transport;

/// Capacity of the inbound message channel.
const CHAN_CAP: usize = 256;

/// Handle returned by [`BridgeServer::start`].
pub struct BridgeServer {
    /// Receive BrowserMessages arriving from the Diatom backend.
    pub inbound: mpsc::Receiver<BrowserMessage>,
    /// Send DevPanelMessages back to the Diatom backend.
    pub outbound: mpsc::Sender<DevPanelMessage>,
}

impl BridgeServer {
    /// Bind to `socket_path` and begin accepting exactly one connection
    /// (Diatom and DevPanel are always 1:1).
    ///
    /// `auth_token` must match the value passed to this DevPanel process via
    /// `--auth-token`. Any connecting client that cannot present the correct
    /// token is rejected and disconnected before any messages are processed.
    ///
    /// Returns immediately; the actual I/O runs on background tokio tasks.
    #[cfg(unix)]
    pub async fn start(socket_path: impl AsRef<Path>, auth_token: String) -> Result<Self> {
        use tokio::net::UnixListener;

        let path = socket_path.as_ref();

        if path.exists() {
            std::fs::remove_file(path).context("remove stale socket")?;
        }

        let listener = UnixListener::bind(path).context("bind Unix socket")?;

        // Restrict socket to owner only (belt-and-suspenders on top of the
        // token handshake — an attacker can't even connect from another user).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .context("set socket permissions")?;
        }

        let (inbound_tx, inbound_rx) = mpsc::channel::<BrowserMessage>(CHAN_CAP);
        let (outbound_tx, outbound_rx) = mpsc::channel::<DevPanelMessage>(CHAN_CAP);

        tokio::spawn(accept_unix(listener, auth_token, inbound_tx, outbound_rx));

        Ok(Self {
            inbound: inbound_rx,
            outbound: outbound_tx,
        })
    }

    #[cfg(windows)]
    pub async fn start(pipe_name: impl AsRef<str>, auth_token: String) -> Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = pipe_name.as_ref();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(name)
            .context("create named pipe")?;

        let (inbound_tx, inbound_rx) = mpsc::channel::<BrowserMessage>(CHAN_CAP);
        let (outbound_tx, outbound_rx) = mpsc::channel::<DevPanelMessage>(CHAN_CAP);

        tokio::spawn(accept_windows(server, auth_token, inbound_tx, outbound_rx));

        Ok(Self {
            inbound: inbound_rx,
            outbound: outbound_tx,
        })
    }
}

// ── Handshake helper ──────────────────────────────────────────────────────────

/// Perform the server side of the authentication handshake on `writer`/`reader`.
///
/// 1. Sends `HandshakeMessage::Challenge`.
/// 2. Waits up to `HANDSHAKE_TIMEOUT_MS` for a `Response { token }`.
/// 3. Validates the token in constant time.
/// 4. Sends `Accepted` or `Rejected` and returns `Ok(true)` / `Ok(false)`.
///
/// All I/O errors are surfaced as `Err`.
async fn perform_handshake<R, W>(reader: &mut R, writer: &mut W, auth_token: &str) -> Result<bool>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = Duration::from_millis(HANDSHAKE_TIMEOUT_MS);

    // Step 1 — send Challenge.
    transport::send(writer, &HandshakeMessage::Challenge)
        .await
        .context("handshake: send Challenge")?;

    // Step 2 — wait for Response.
    let frame = timeout(deadline, transport::recv::<_, HandshakeMessage>(reader))
        .await
        .context("handshake: timeout waiting for Response")?
        .context("handshake: recv Response")?;

    let Some(msg) = frame else {
        bail!("handshake: peer closed connection before sending Response");
    };

    // Step 3 — validate token in constant time to prevent timing side-channels.
    let token_ok = match msg {
        HandshakeMessage::Response { token } => {
            constant_time_eq(token.as_bytes(), auth_token.as_bytes())
        }
        other => {
            log::warn!("[bridge-server] unexpected handshake frame: {other:?}");
            false
        }
    };

    // Step 4 — send verdict.
    if token_ok {
        transport::send(writer, &HandshakeMessage::Accepted)
            .await
            .context("handshake: send Accepted")?;
        Ok(true)
    } else {
        let _ = transport::send(
            writer,
            &HandshakeMessage::Rejected {
                reason: "invalid token".to_owned(),
            },
        )
        .await;
        log::warn!("[bridge-server] authentication failed — connection rejected");
        Ok(false)
    }
}

/// Constant-time byte-slice comparison to prevent timing-based token oracle.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Unix accept loop ──────────────────────────────────────────────────────────

#[cfg(unix)]
async fn accept_unix(
    listener: tokio::net::UnixListener,
    auth_token: String,
    inbound_tx: mpsc::Sender<BrowserMessage>,
    outbound_rx: mpsc::Receiver<DevPanelMessage>,
) {
    let (stream, _addr) = match listener.accept().await {
        Ok(x) => x,
        Err(e) => {
            log::error!("[bridge-server] accept failed: {e}");
            return;
        }
    };

    let (mut reader, mut writer) = tokio::io::split(stream);

    // --- Handshake must succeed before normal I/O begins ---
    match perform_handshake(&mut reader, &mut writer, &auth_token).await {
        Ok(true) => log::info!("[bridge-server] handshake accepted"),
        Ok(false) => {
            log::warn!("[bridge-server] handshake rejected — dropping connection");
            return;
        }
        Err(e) => {
            log::error!("[bridge-server] handshake error: {e}");
            return;
        }
    }

    run_io_loop(reader, writer, inbound_tx, outbound_rx).await;
}

// ── Windows accept loop ───────────────────────────────────────────────────────

#[cfg(windows)]
async fn accept_windows(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    auth_token: String,
    inbound_tx: mpsc::Sender<BrowserMessage>,
    outbound_rx: mpsc::Receiver<DevPanelMessage>,
) {
    if let Err(e) = server.connect().await {
        log::error!("[bridge-server] pipe connect failed: {e}");
        return;
    }

    use std::sync::Arc;
    use tokio::sync::Mutex;
    let pipe = Arc::new(Mutex::new(server));

    // Handshake: borrow the pipe exclusively for the synchronous HS phase.
    {
        let mut guard = pipe.lock().await;
        let (mut r, mut w) = tokio::io::split(&mut *guard);
        match perform_handshake(&mut r, &mut w, &auth_token).await {
            Ok(true) => log::info!("[bridge-server] handshake accepted"),
            Ok(false) => {
                log::warn!("[bridge-server] handshake rejected — dropping connection");
                return;
            }
            Err(e) => {
                log::error!("[bridge-server] handshake error: {e}");
                return;
            }
        }
    }

    // Post-handshake I/O (Windows uses Arc<Mutex<_>> to share the pipe).
    let read_pipe = Arc::clone(&pipe);
    let write_pipe = Arc::clone(&pipe);

    let read_task = tokio::spawn(async move {
        loop {
            let mut guard = read_pipe.lock().await;
            match transport::recv::<_, BrowserMessage>(&mut *guard).await {
                Ok(Some(msg)) => {
                    drop(guard);
                    if inbound_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    log::error!("[bridge-server] recv: {e}");
                    break;
                }
            }
        }
    });

    let mut outbound_rx = outbound_rx;
    let write_task = tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            let mut guard = write_pipe.lock().await;
            if let Err(e) = transport::send(&mut *guard, &msg).await {
                log::error!("[bridge-server] send: {e}");
                break;
            }
        }
    });

    tokio::select! {
        _ = read_task  => {},
        _ = write_task => {},
    }
}

// ── Shared post-handshake I/O loop (Unix) ────────────────────────────────────

#[cfg(unix)]
async fn run_io_loop<R, W>(
    reader: R,
    writer: W,
    inbound_tx: mpsc::Sender<BrowserMessage>,
    mut outbound_rx: mpsc::Receiver<DevPanelMessage>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = reader;
    let mut writer = writer;

    let read_task = {
        let tx = inbound_tx;
        tokio::spawn(async move {
            loop {
                match transport::recv::<_, BrowserMessage>(&mut reader).await {
                    Ok(Some(msg)) => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        log::info!("[bridge-server] peer closed connection");
                        break;
                    }
                    Err(e) => {
                        log::error!("[bridge-server] recv error: {e}");
                        break;
                    }
                }
            }
        })
    };

    let write_task = tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            if let Err(e) = transport::send(&mut writer, &msg).await {
                log::error!("[bridge-server] send error: {e}");
                break;
            }
        }
    });

    tokio::select! {
        _ = read_task  => {},
        _ = write_task => {},
    }
}
