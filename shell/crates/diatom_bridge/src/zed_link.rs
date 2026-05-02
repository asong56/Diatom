use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::net::UnixListener;
use tokio::sync::broadcast;

use crate::protocol::ResonanceContext;
use crate::transport;

/// Capacity of the broadcast channel (snapshots, not a stream).
/// Old values are dropped when no Zed client is connected.
const BROADCAST_CAP: usize = 4;

/// Resolves the UDS socket path: `~/.diatom/resonance.sock`.
pub fn resonance_sock_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".diatom").join("resonance.sock")
}

/// Handle returned by [`ZedContextServer::start`].
///
/// Call `push(ctx)` whenever the browser context changes.
/// The server runs on background tasks for its entire lifetime.
pub struct ZedContextServer {
    tx: broadcast::Sender<ResonanceContext>,
}

impl ZedContextServer {
    /// Bind the UDS and start accepting Zed connections.
    /// Returns immediately; I/O runs on background tokio tasks.
    pub async fn start() -> Result<Self> {
        let path = resonance_sock_path();

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("create ~/.diatom/")?;
        }

        if path.exists() {
            std::fs::remove_file(&path).context("remove stale resonance.sock")?;
        }

        let listener = UnixListener::bind(&path).context("bind resonance.sock")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .context("set resonance.sock permissions")?;
        }

        let (tx, _) = broadcast::channel::<ResonanceContext>(BROADCAST_CAP);
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            accept_loop(listener, tx_clone).await;
        });

        log::info!(
            "[zed-link] Resonance context server listening at {:?}",
            path
        );
        Ok(Self { tx })
    }

    /// Push a new context snapshot to all connected Zed clients.
    /// If no clients are connected the snapshot is silently discarded.
    pub fn push(&self, ctx: ResonanceContext) {
        let _ = self.tx.send(ctx);
    }
}

async fn accept_loop(listener: UnixListener, tx: broadcast::Sender<ResonanceContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let rx = tx.subscribe();
                tokio::spawn(serve_zed_client(stream, rx));
            }
            Err(e) => {
                log::error!("[zed-link] accept error: {e}");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }
}

/// Serve one connected Zed client: forward every context snapshot until the
/// client disconnects or an I/O error occurs.
async fn serve_zed_client(
    stream: tokio::net::UnixStream,
    mut rx: broadcast::Receiver<ResonanceContext>,
) {
    let (_, mut writer) = tokio::io::split(stream);

    loop {
        match rx.recv().await {
            Ok(ctx) => {
                if let Err(e) = transport::send(&mut writer, &ctx).await {
                    log::debug!("[zed-link] client write error: {e}");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                log::debug!("[zed-link] client lagged, {n} snapshot(s) dropped");
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}
