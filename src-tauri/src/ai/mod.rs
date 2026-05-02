// Local AI: SLM microkernel, download renamer, shadow index, MCP host.
pub mod mcp;
pub mod renamer;
pub mod shadow_index;
pub mod slm;

pub use renamer::{DownloadContext, RenameResult};
pub use slm::SlmServer;
