// diatom/src-tauri/src/browser
// Browser UI: tabs, budget, proxy, DOM tools, accessibility, and DevPanel bridge.
pub mod a11y;
pub mod boosts;
pub mod budget;
pub mod dev_panel;
pub mod dom_crusher;
pub mod proxy;
pub mod tabs;

pub use boosts::BoostRule;
pub use budget::{DEFAULT_TAB_LIMIT, TabBudgetConfig};
pub use proxy::{ProxyConfig, TabProxyRegistry};
pub use tabs::TabStore;
