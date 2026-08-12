//! Library target for `diatom`.
//!
//! Exists so integration tests under `tests/` (e.g. `tests/privacy_behaviour.rs`,
//! which does `use diatom::engine::url_stripper::...`) can link against the
//! crate. Without a `[lib]` target, `cargo test --all-features` cannot resolve
//! that import at all and fails before any test runs.
//!
//! Declares the same modules as `main.rs` against the same source files;
//! Cargo compiles the bin and lib as two separate crate instances from
//! shared source, which is the standard pattern for a binary crate that
//! also needs to be integration-testable.

pub mod agent_commands;
pub mod ai;
pub mod auth;
pub mod browser;
pub mod commands;
pub mod engine;
pub mod features;
pub mod privacy;
pub mod state;
pub mod storage;
pub mod sync;
pub mod utils;
