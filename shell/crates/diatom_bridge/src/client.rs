//! Diatom-backend-side bridge client.
//!
//! `BridgeClient` is used by the main `diatom` (Tauri) process. It connects
//! to the DevPanel's Unix socket, completes the authentication handshake, and
//! then forwards messages in both directions.

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::protocol::{BrowserMessage, DevPanelMessage, HANDSHAKE_TIMEOUT_MS, HandshakeMessage};
use crate::transport;

const CHAN_CAP: usize = 256;

/// Handle returned by [`BridgeClient::connect`].
pub struct BridgeClient {
    /// Messages arriving from the DevPanel (e.g. `EvalJs`, `SlmRequest`).
    pub inbound: mpsc::Receiver<DevPanelMessage>,
    /// Queue a message to be sent to the DevPanel.
    pub outbound: mpsc::Sender<BrowserMessage>,
}

impl BridgeClient {
    /// Connect to a DevPanel listening at `socket_path`.
    ///
    /// `auth_token` must be the same value that was passed to the DevPanel
    /// process via `--auth-token`. It is sent during the handshake and never
    /// transmitted again after the connection is established.
    ///
    /// Retries up to `retries` times with 100 ms back-off (the DevPanel may
    /// still be starting its GPUI event loop when Diatom calls connect).
    #[cfg(unix)]
    pub async fn connect(socket_path: &str, auth_token: &str, retries: u8) -> Result<Self> {
        use tokio::net::UnixStream;
        use tokio::time::sleep;

        let mut stream = None;
        for attempt in 0..=retries {
            match UnixStream::connect(socket_path).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) if attempt < retries => {
                    log::debug!("[bridge-client] connect attempt {attempt} failed ({e}), retrying");
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => return Err(e).context("connect to DevPanel socket"),
            }
        }
        let stream = stream.expect("loop exited only on success or error");
        let (mut reader, mut writer) = tokio::io::split(stream);

        // --- Handshake before any message traffic ---
        perform_handshake(&mut reader, &mut writer, auth_token).await?;

        let (inbound_tx, inbound_rx) = mpsc::channel::<DevPanelMessage>(CHAN_CAP);
        let (outbound_tx, outbound_rx) = mpsc::channel::<BrowserMessage>(CHAN_CAP);

        // Read task: forward DevPanelMessages from the socket to `inbound`.
        tokio::spawn(async move {
            loop {
                match transport::recv::<_, DevPanelMessage>(&mut reader).await {
                    Ok(Some(msg)) => {
                        if inbound_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        log::info!("[bridge-client] DevPanel disconnected");
                        break;
                    }
                    Err(e) => {
                        log::error!("[bridge-client] recv: {e}");
                        break;
                    }
                }
            }
        });

        // Write task: drain `outbound` and send BrowserMessages to the DevPanel.
        tokio::spawn(async move {
            let mut rx = outbound_rx;
            while let Some(msg) = rx.recv().await {
                if let Err(e) = transport::send(&mut writer, &msg).await {
                    log::error!("[bridge-client] send: {e}");
                    break;
                }
            }
        });

        Ok(Self {
            inbound: inbound_rx,
            outbound: outbound_tx,
        })
    }

    #[cfg(windows)]
    pub async fn connect(pipe_name: &str, auth_token: &str, retries: u8) -> Result<Self> {
        use tokio::net::windows::named_pipe::ClientOptions;
        use tokio::time::sleep;

        let mut pipe = None;
        for attempt in 0..=retries {
            match ClientOptions::new().open(pipe_name) {
                Ok(p) => {
                    pipe = Some(p);
                    break;
                }
                Err(e) if attempt < retries => {
                    sleep(Duration::from_millis(100)).await;
                    let _ = e;
                }
                Err(e) => return Err(e).context("connect to DevPanel pipe"),
            }
        }
        let pipe = pipe.expect("loop exits on success or early return");

        use std::sync::Arc;
        use tokio::sync::Mutex;
        let pipe = Arc::new(Mutex::new(pipe));

        // Handshake — borrow exclusively for HS phase.
        {
            let mut guard = pipe.lock().await;
            let (mut r, mut w) = tokio::io::split(&mut *guard);
            perform_handshake(&mut r, &mut w, auth_token).await?;
        }

        let (inbound_tx, inbound_rx) = mpsc::channel::<DevPanelMessage>(CHAN_CAP);
        let (outbound_tx, outbound_rx) = mpsc::channel::<BrowserMessage>(CHAN_CAP);

        let read_pipe = Arc::clone(&pipe);
        tokio::spawn(async move {
            loop {
                let mut guard = read_pipe.lock().await;
                match transport::recv::<_, DevPanelMessage>(&mut *guard).await {
                    Ok(Some(msg)) => {
                        drop(guard);
                        if inbound_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        log::error!("[bridge-client] recv: {e}");
                        break;
                    }
                }
            }
        });

        let write_pipe = Arc::clone(&pipe);
        tokio::spawn(async move {
            let mut rx = outbound_rx;
            while let Some(msg) = rx.recv().await {
                let mut guard = write_pipe.lock().await;
                if let Err(e) = transport::send(&mut *guard, &msg).await {
                    log::error!("[bridge-client] send: {e}");
                    break;
                }
            }
        });

        Ok(Self {
            inbound: inbound_rx,
            outbound: outbound_tx,
        })
    }

    /// Convenience wrapper — fire-and-forget a message to the DevPanel.
    pub async fn send(&self, msg: BrowserMessage) -> Result<()> {
        self.outbound
            .send(msg)
            .await
            .context("DevPanel outbound channel closed")
    }
}

// ── Handshake helper (client side) ───────────────────────────────────────────

/// Complete the client side of the authentication handshake.
///
/// 1. Waits for `HandshakeMessage::Challenge` from the server.
/// 2. Sends `HandshakeMessage::Response { token: auth_token }`.
/// 3. Waits for `HandshakeMessage::Accepted`.
/// 4. Returns `Ok(())` on success, `Err` on any failure.
async fn perform_handshake<R, W>(reader: &mut R, writer: &mut W, auth_token: &str) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = Duration::from_millis(HANDSHAKE_TIMEOUT_MS);

    // Step 1 — wait for Challenge.
    let frame = timeout(deadline, transport::recv::<_, HandshakeMessage>(reader))
        .await
        .context("handshake: timeout waiting for Challenge")?
        .context("handshake: recv Challenge")?;

    match frame {
        Some(HandshakeMessage::Challenge) => {}
        Some(other) => bail!("handshake: expected Challenge, got {other:?}"),
        None => bail!("handshake: server closed connection before Challenge"),
    }

    // Step 2 — send Response.
    transport::send(
        writer,
        &HandshakeMessage::Response {
            token: auth_token.to_owned(),
        },
    )
    .await
    .context("handshake: send Response")?;

    // Step 3 — wait for verdict.
    let frame = timeout(deadline, transport::recv::<_, HandshakeMessage>(reader))
        .await
        .context("handshake: timeout waiting for verdict")?
        .context("handshake: recv verdict")?;

    match frame {
        Some(HandshakeMessage::Accepted) => {
            log::debug!("[bridge-client] handshake accepted");
            Ok(())
        }
        Some(HandshakeMessage::Rejected { reason }) => {
            bail!("handshake rejected by server: {reason}")
        }
        Some(other) => bail!("handshake: unexpected verdict frame: {other:?}"),
        None => bail!("handshake: server closed connection before verdict"),
    }
}
