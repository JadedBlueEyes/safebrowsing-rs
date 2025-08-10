//! Database interface and implementations for Google Safe Browsing API
//!
//! This crate provides the database abstraction layer for the Safe Browsing API.
//! It defines a common `Database` trait and provides implementations for
//! in-memory storage and persistent disk storage.

#[cfg(feature = "concurrent-db")]
pub mod concurrent_db;
#[cfg(feature = "memory-db")]
pub mod memory_db;
#[cfg(feature = "redb")]
pub mod redb;

use async_trait::async_trait;

use safebrowsing_api::{SafeBrowsingApi, ThreatDescriptor};

use safebrowsing_hash::{HashPrefix, HashPrefixSet};
use safebrowsing_proto::{CompressionType, RawHashes, RawIndices, RiceDeltaEncoding};
use std::collections::{HashMap, HashSet as StdHashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

use tracing::{debug, error, info, warn};

/// Error and Result types should be imported from a shared error module or defined here
type Result<T> = std::result::Result<T, DatabaseError>;

/// Default maximum database age before it's considered stale
pub const DEFAULT_MAX_DATABASE_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum retry delay for database updates
const MAX_RETRY_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Base retry delay for database updates
const BASE_RETRY_DELAY: Duration = Duration::from_secs(15 * 60);

/// Error types for database operations
#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    /// Database is not ready
    #[error("Database not ready")]
    NotReady,

    /// Database is stale (not updated recently enough)
    #[error("Database is stale, last updated {0:?} ago")]
    Stale(Duration),

    /// Error decoding data
    #[error("Error decoding data: {0}")]
    DecodeError(String),

    /// API error
    #[error("API error: {0}")]
    ApiError(#[from] safebrowsing_api::Error),
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Rice decoder error
    #[error("Rice decoder error: {0}")]
    RiceDecodeError(String),

    /// Invalid indices
    #[error("Invalid indices: {0}")]
    InvalidIndices(String),
    /// Invalid checksum
    #[error("Invalid checksum: expected {expected}, got {actual}")]
    InvalidChecksum { expected: String, actual: String },
    /// Hash error
    #[error("Hash error: {0}")]
    HashError(#[from] safebrowsing_hash::HashError),
}

/// Database statistics
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// Total number of hash prefixes in the database
    pub total_hashes: usize,

    /// Number of threat lists
    pub threat_lists: usize,

    /// Estimated memory usage in bytes
    pub memory_usage: usize,

    /// Last update time
    pub last_update: Option<Instant>,

    /// Whether the database is stale
    pub is_stale: bool,
}

impl fmt::Display for DatabaseStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last_update = match self.last_update {
            Some(time) => format!("{:?} ago", time.elapsed()),
            None => "never".to_string(),
        };

        write!(
            f,
            "Database stats: {} hashes in {} lists, ~{} bytes, last update: {}, {}",
            self.total_hashes,
            self.threat_lists,
            self.memory_usage,
            last_update,
            if self.is_stale { "STALE" } else { "up-to-date" }
        )
    }
}

/// Database interface for Safe Browsing
///
/// This trait defines the methods required for a Safe Browsing database
/// implementation. It provides methods for looking up hash prefixes and
/// updating the database from the Safe Browsing API.
#[async_trait]
pub trait Database {
    /// Check if the database is ready for queries
    async fn is_ready(&self) -> Result<bool>;

    /// Get the current database status
    async fn status(&self) -> Result<()>;

    /// Update the database with the latest threat lists
    async fn update(&self, api: &SafeBrowsingApi, threat_lists: &[ThreatDescriptor]) -> Result<()>;

    /// Look up a hash prefix in the database
    ///
    /// If found, returns the matching hash prefix and the list of
    /// threat descriptors that contain it
    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>>;

    /// Get the time since the last successful update
    async fn time_since_last_update(&self) -> Option<Duration>;

    /// Get database statistics
    async fn stats(&self) -> DatabaseStats;
}

/// Entry in a threat list
struct ThreatListEntry {
    /// Set of hash prefixes
    hash_set: HashPrefixSet,

    /// Client state for this list
    client_state: Vec<u8>,

    /// Checksum of this list
    checksum: Vec<u8>,

    /// Last update time
    last_update: Instant,
}

impl ThreatListEntry {
    /// Create a new threat list entry
    fn new(hash_set: HashPrefixSet, client_state: Vec<u8>, checksum: Vec<u8>) -> Self {
        Self {
            hash_set,
            client_state,
            checksum,
            last_update: Instant::now(),
        }
    }

    /// Check if this entry is stale
    fn is_stale(&self, max_age: Duration) -> bool {
        self.last_update.elapsed() > max_age
    }
}
