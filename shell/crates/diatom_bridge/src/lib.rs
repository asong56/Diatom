pub mod client;
pub mod protocol;
pub mod server;
pub mod slm_adapter;
pub mod transport;
pub mod zed_link;

pub use client::BridgeClient;
pub use protocol::{
    ActiveSource,
    BackendToShell,
    BrowserMessage,
    ConsoleLevel,
    DevPanelMessage,
    DomNode,
    NetworkEventPayload,
    RequestId,
    ResonanceContext,
    ShellMessage,
    ShellTab, // Shell ↔ Backend direction
    SlmMessage,
};
pub use server::BridgeServer;
pub use zed_link::ZedContextServer;
