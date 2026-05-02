mod ai;
mod auth;
/// Tauri command handlers, split by subsystem.
///
/// Each file owns one domain of commands.  `main.rs` registers them all via
/// `tauri::generate_handler![commands::cmd_X, ...]`; the flat re-exports below
/// keep that call-site unchanged.
///
/// Files:
///   browser.rs  — tabs, boosts, DOM crusher
///   data.rs     — history, bookmarks, settings, zen aphorism
///   storage.rs  — museum/archive, vault, storage budget
///   privacy.rs  — privacy config, OHTTP, onion, Wi-Fi trust, threat, fp-norm
///   engine.rs   — network monitor, bandwidth limiter, plugins
///   auth.rs     — TOTP/2FA, biometric, domain trust, Noise fingerprint
///   ai.rs       — SLM server, shadow-index search, MCP, rename suggester
///   sync.rs     — Nostr bookmark sync
///   features.rs — Zen, RSS, Panic Button, Breach monitor, Search, ToS, Labs
///   system.rs   — window lifecycle, Home Base, Peek Fetch, power budget, compliance
mod browser;
mod data;
mod engine;
mod features;
mod privacy;
mod storage;
mod sync;
mod system;

pub use ai::*;
pub use auth::*;
pub use browser::*;
pub use data::*;
pub use engine::*;
pub use features::*;
pub use privacy::*;
pub use storage::*;
pub use sync::*;
pub use system::*;

use crate::state::AppState;

/// Short type alias — removes the 33-char `tauri::State<'_, AppState>` noise
/// from every command signature.  `pub(super)` so sub-modules can use it with
/// `use super::St;`.
pub(super) type St<'r> = tauri::State<'r, AppState>;

/// Convert any `Display` error to `String` for Tauri command returns.
#[inline(always)]
pub(super) fn es<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}