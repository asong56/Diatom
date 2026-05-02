//! SQLite persistence layer, split into domain modules.
//!
//! | Module      | Contents                                               |
//! |-------------|--------------------------------------------------------|
//! | core        | Db handle, migrations, open(), get/set_setting, helpers|
//! | types       | All row and raw data structs                           |
//! | history     | History, privacy stats, reading events                 |
//! | museum      | Museum bundles, DOM Crusher blocks                     |
//! | auth        | TOTP, trust, RSS, filter subs, knowledge packs, Zen,   |
//! |             | onboarding, Nostr relays                               |
//! | vault       | Encrypted vault logins, cards, notes                   |
//! | tabs        | Tab groups                                             |

mod auth;
mod core;
mod history;
mod museum;
mod tabs;
mod types;
mod vault;

// Re-export everything callers need from one flat path: `crate::storage::db::*`
pub use core::{Db, new_id, unix_now, week_start};
pub use types::*;
