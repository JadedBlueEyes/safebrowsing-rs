#![allow(unused)]
//! Re-export database types from the safebrowsing-db crate.

pub use safebrowsing_db::{ConcurrentDatabase, Database, DatabaseStats, InMemoryDatabase};

// Re-export RedbDatabase when the feature is enabled
#[cfg(feature = "redb")]
pub use safebrowsing_db_redb::RedbDatabase;
