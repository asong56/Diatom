// Persistence: SQLite, encrypted vault, E-WBN archiving, storage budget.
pub mod db;
pub mod freeze;
pub mod guard;
pub mod vault;
pub mod versioning;

pub use db::Db;
pub use freeze::get_or_init_master_key;
pub use guard::{StorageBudget, StorageReport};
pub use vault::VaultStore;
pub mod warc_export;
