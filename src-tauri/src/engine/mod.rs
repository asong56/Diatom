// diatom/src-tauri/src/engine
// Network request pipeline: blocking, bandwidth, caching, monitoring, tunnelling.
pub mod bandwidth;
pub mod blocker;
pub mod cache;
pub mod compat;
pub mod ghostpipe;
pub mod monitor;
pub mod plugins;
pub mod url_stripper;

// Convenience re-exports used by state.rs and commands.rs
pub use bandwidth::{BandwidthLimiter, BandwidthRule};
pub use compat::CompatStore;
pub use ghostpipe::GhostPipeConfig;
pub use monitor::NetMonitor;
pub use plugins::{PluginManifest, PluginRegistry, WasmPlugin};
pub use url_stripper::strip as strip_tracking_params;
