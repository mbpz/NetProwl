pub mod db;
pub mod types;

pub use db::{init_db, insert_cves, query, hot_update};
pub use types::{CveRule, CveResult};