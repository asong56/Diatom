// Persistence: SQLite, encrypted vault, E-WBN archiving, storage budget.
pub mod db;
pub mod export_markdown;
pub mod freeze;
pub mod guard;
pub mod vault;

pub use db::Db;
pub use freeze::get_or_init_master_key;
pub use guard::{StorageBudget, StorageReport};
pub use vault::VaultStore;
