#![allow(unused)]
//! Re-export database types from the safebrowsing-db crate.

pub use safebrowsing_db::{
    concurrent_db::ConcurrentDatabase, memory_db::InMemoryDatabase, Database, DatabaseStats,
};

// Re-export RedbDatabase when the feature is enabled
#[cfg(feature = "redb")]
pub use safebrowsing_db::redb::RedbDatabase;
