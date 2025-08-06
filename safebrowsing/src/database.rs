//! Database abstraction and implementations for Safe Browsing threat lists
//!
//! This module provides a pluggable database interface for storing and querying
//! Safe Browsing threat lists, along with a basic in-memory implementation.

use crate::api::SafeBrowsingApi;
use crate::error::{DatabaseError, Error, Result};
use crate::hash::{decode_hashes, HashPrefix, HashSet};
use crate::types::ThreatDescriptor;
use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Database interface for Safe Browsing threat lists
#[async_trait]
pub trait Database {
    /// Check if the database is ready for queries
    async fn is_ready(&self) -> Result<bool>;

    /// Get the current database status
    async fn status(&self) -> Result<()>;

    /// Update the database with the latest threat lists
    async fn update(
        &mut self,
        api: &SafeBrowsingApi,
        threat_lists: &[ThreatDescriptor],
    ) -> Result<()>;

    /// Look up a hash prefix in the database
    /// Returns (partial_hash, threat_descriptors) if found, None if not found
    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>>;

    /// Get the time since the last successful update
    async fn time_since_last_update(&self) -> Option<Duration>;

    /// Get database statistics
    async fn stats(&self) -> DatabaseStats;
}

/// Database statistics
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// Total number of hash prefixes stored
    pub total_hashes: usize,
    /// Number of threat lists tracked
    pub threat_lists: usize,
    /// Size of database in memory (approximate)
    pub memory_usage: usize,
    /// Time of last successful update
    pub last_update: Option<Instant>,
    /// Whether the database is considered stale
    pub is_stale: bool,
}

/// Threat list entry containing hashes and metadata
#[derive(Debug, Clone)]
struct ThreatListEntry {
    /// Hash set for fast lookups
    hash_set: HashSet,
    /// Client state for API synchronization
    client_state: Vec<u8>,
    /// SHA256 checksum of the hash list
    checksum: Vec<u8>,
    /// Last update time
    last_update: Instant,
}

impl ThreatListEntry {
    fn new() -> Self {
        Self {
            hash_set: HashSet::new(),
            client_state: Vec::new(),
            checksum: Vec::new(),
            last_update: Instant::now(),
        }
    }

    fn is_stale(&self, max_age: Duration) -> bool {
        self.last_update.elapsed() > max_age
    }
}

/// In-memory database implementation
pub struct InMemoryDatabase {
    /// Map from threat descriptor to threat list data
    threat_lists: Arc<RwLock<HashMap<ThreatDescriptor, ThreatListEntry>>>,
    /// Database initialization state
    initialized: Arc<RwLock<bool>>,
    /// Last update time
    last_update: Arc<RwLock<Option<Instant>>>,
    /// Maximum age before database is considered stale
    max_age: Duration,
    /// Total number of hash prefixes (cached for performance)
    hash_count: Arc<RwLock<usize>>,
}

impl InMemoryDatabase {
    /// Create a new in-memory database
    pub fn new() -> Self {
        Self {
            threat_lists: Arc::new(RwLock::new(HashMap::new())),
            initialized: Arc::new(RwLock::new(false)),
            last_update: Arc::new(RwLock::new(None)),
            max_age: Duration::from_secs(2 * 60 * 60), // 2 hours
            hash_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Create a database with custom staleness threshold
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            threat_lists: Arc::new(RwLock::new(HashMap::new())),
            initialized: Arc::new(RwLock::new(false)),
            last_update: Arc::new(RwLock::new(None)),
            max_age,
            hash_count: Arc::new(RwLock::new(0)),
        }
    }

    async fn update_threat_list(
        &self,
        threat_descriptor: &ThreatDescriptor,
        api: &SafeBrowsingApi,
    ) -> Result<()> {
        let mut threat_lists = self.threat_lists.write().await;
        let entry = threat_lists.get(threat_descriptor);
        let client_state = entry.map(|e| e.client_state.clone()).unwrap_or_default();

        // Request update from API
        let response = api
            .fetch_threat_list_update(threat_descriptor, &client_state)
            .await?;

        for list_response in response.list_update_responses {
            let response_threat_descriptor = ThreatDescriptor {
                threat_type: list_response.threat_type().into(),
                platform_type: list_response.platform_type().into(),
                threat_entry_type: list_response.threat_entry_type().into(),
            };

            if response_threat_descriptor != *threat_descriptor {
                continue;
            }

            let mut entry = threat_lists
                .entry(threat_descriptor.clone())
                .or_insert_with(ThreatListEntry::new);

            // Handle response type
            use crate::proto::safebrowsing_proto::fetch_threat_list_updates_response::list_update_response::ResponseType;
            match list_response.response_type() {
                ResponseType::FullUpdate => {
                    // Replace entire list
                    entry.hash_set = HashSet::new();
                }
                ResponseType::PartialUpdate => {
                    // Apply incremental changes
                }
                _ => {
                    return Err(Error::Database(DatabaseError::UpdateFailed(
                        "Unknown response type".to_string(),
                    )));
                }
            }

            // Process removals
            for removal in &list_response.removals {
                let indices = self.decode_removal_indices(removal)?;
                // TODO: Apply removals to hash set
            }

            // Process additions
            let mut all_hashes = entry.hash_set.export();
            for addition in &list_response.additions {
                let new_hashes = decode_hashes(addition)?;
                for hash in new_hashes {
                    all_hashes.push(hash);
                }
            }

            // Sort and validate hashes
            all_hashes.sort();
            all_hashes.validate()?;

            // Verify checksum if provided
            if let Some(checksum) = &list_response.checksum {
                let computed_checksum = all_hashes.sha256();
                if computed_checksum != checksum.sha256 {
                    return Err(Error::Database(DatabaseError::ChecksumMismatch {
                        expected: u64::from_be_bytes(
                            checksum.sha256[..8].try_into().unwrap_or_default(),
                        ),
                        found: u64::from_be_bytes(
                            computed_checksum[..8].try_into().unwrap_or_default(),
                        ),
                    }));
                }
                entry.checksum = checksum.sha256.clone();
            }

            // Update entry
            entry.hash_set.import(all_hashes);
            entry.client_state = list_response.new_client_state;
            entry.last_update = Instant::now();
        }

        Ok(())
    }

    fn decode_removal_indices(
        &self,
        threat_entry_set: &crate::proto::safebrowsing_proto::ThreatEntrySet,
    ) -> Result<Vec<i32>> {
        use crate::proto::safebrowsing_proto::CompressionType;

        match threat_entry_set.compression_type() {
            CompressionType::Raw => {
                if let Some(raw_indices) = &threat_entry_set.raw_indices {
                    Ok(raw_indices.indices.clone())
                } else {
                    Err(Error::Encoding("Missing raw indices".to_string()))
                }
            }
            CompressionType::Rice => {
                if let Some(rice_indices) = &threat_entry_set.rice_indices {
                    let values = crate::hash::decode_rice_integers(rice_indices)?;
                    Ok(values.into_iter().map(|v| v as i32).collect())
                } else {
                    Err(Error::Encoding("Missing rice indices".to_string()))
                }
            }
            _ => Err(Error::Encoding("Unknown compression type".to_string())),
        }
    }

    async fn update_hash_count(&self) {
        let threat_lists = self.threat_lists.read().await;
        let total = threat_lists
            .values()
            .map(|entry| entry.hash_set.len())
            .sum();
        *self.hash_count.write().await = total;
    }
}

impl Default for InMemoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Database for InMemoryDatabase {
    async fn is_ready(&self) -> Result<bool> {
        let initialized = *self.initialized.read().await;
        if !initialized {
            return Ok(false);
        }

        let threat_lists = self.threat_lists.read().await;
        if threat_lists.is_empty() {
            return Ok(false);
        }

        // Check if any threat list is stale
        let is_stale = threat_lists
            .values()
            .any(|entry| entry.is_stale(self.max_age));

        Ok(!is_stale)
    }

    async fn status(&self) -> Result<()> {
        let is_ready = self.is_ready().await?;
        if !is_ready {
            let last_update = *self.last_update.read().await;
            return Err(Error::Database(DatabaseError::Stale { last_update }));
        }
        Ok(())
    }

    async fn update(
        &mut self,
        api: &SafeBrowsingApi,
        threat_lists: &[ThreatDescriptor],
    ) -> Result<()> {
        // Update each threat list
        for threat_descriptor in threat_lists {
            self.update_threat_list(threat_descriptor, api).await?;
        }

        // Mark as initialized and update timestamp
        *self.initialized.write().await = true;
        *self.last_update.write().await = Some(Instant::now());
        self.update_hash_count().await;

        Ok(())
    }

    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>> {
        if !hash.is_full() {
            return Err(Error::Hash("Hash must be full for lookup".to_string()));
        }

        let threat_lists = self.threat_lists.read().await;
        let mut matching_descriptors = Vec::new();
        let mut best_match_length = 0;
        let mut best_match_hash = None;

        for (threat_descriptor, entry) in threat_lists.iter() {
            let match_length = entry.hash_set.lookup(hash);
            if match_length > 0 {
                if match_length > best_match_length {
                    best_match_length = match_length;
                    best_match_hash = Some(hash.truncate(match_length)?);
                    matching_descriptors.clear();
                    matching_descriptors.push(threat_descriptor.clone());
                } else if match_length == best_match_length {
                    matching_descriptors.push(threat_descriptor.clone());
                }
            }
        }

        if let Some(partial_hash) = best_match_hash {
            Ok(Some((partial_hash, matching_descriptors)))
        } else {
            Ok(None)
        }
    }

    async fn time_since_last_update(&self) -> Option<Duration> {
        self.last_update
            .read()
            .await
            .map(|instant| instant.elapsed())
    }

    async fn stats(&self) -> DatabaseStats {
        let threat_lists = self.threat_lists.read().await;
        let last_update = *self.last_update.read().await;
        let total_hashes = *self.hash_count.read().await;

        let is_stale = if let Some(last_update_time) = last_update {
            last_update_time.elapsed() > self.max_age
        } else {
            true
        };

        DatabaseStats {
            total_hashes,
            threat_lists: threat_lists.len(),
            memory_usage: total_hashes * 32, // Rough estimate
            last_update,
            is_stale,
        }
    }
}

/// Thread-safe database wrapper using DashMap for concurrent access
pub struct ConcurrentDatabase {
    /// Map from threat descriptor to threat list data
    threat_lists: DashMap<ThreatDescriptor, ThreatListEntry>,
    /// Database initialization state
    initialized: Arc<RwLock<bool>>,
    /// Last update time
    last_update: Arc<RwLock<Option<Instant>>>,
    /// Maximum age before database is considered stale
    max_age: Duration,
}

impl ConcurrentDatabase {
    /// Create a new concurrent database
    pub fn new() -> Self {
        Self {
            threat_lists: DashMap::new(),
            initialized: Arc::new(RwLock::new(false)),
            last_update: Arc::new(RwLock::new(None)),
            max_age: Duration::from_secs(2 * 60 * 60), // 2 hours
        }
    }

    /// Create a database with custom staleness threshold
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            threat_lists: DashMap::new(),
            initialized: Arc::new(RwLock::new(false)),
            last_update: Arc::new(RwLock::new(None)),
            max_age,
        }
    }
}

#[async_trait]
impl Database for ConcurrentDatabase {
    async fn is_ready(&self) -> Result<bool> {
        let initialized = *self.initialized.read().await;
        if !initialized {
            return Ok(false);
        }

        if self.threat_lists.is_empty() {
            return Ok(false);
        }

        // Check if any threat list is stale
        let is_stale = self
            .threat_lists
            .iter()
            .any(|entry| entry.value().is_stale(self.max_age));

        Ok(!is_stale)
    }

    async fn status(&self) -> Result<()> {
        let is_ready = self.is_ready().await?;
        if !is_ready {
            let last_update = *self.last_update.read().await;
            return Err(Error::Database(DatabaseError::Stale { last_update }));
        }
        Ok(())
    }

    async fn update(
        &mut self,
        api: &SafeBrowsingApi,
        threat_lists: &[ThreatDescriptor],
    ) -> Result<()> {
        // Implementation similar to InMemoryDatabase but using DashMap
        // This is a simplified version - full implementation would be similar
        // to InMemoryDatabase::update but using DashMap operations

        for threat_descriptor in threat_lists {
            let mut entry = self
                .threat_lists
                .entry(threat_descriptor.clone())
                .or_insert_with(ThreatListEntry::new);
            entry.last_update = Instant::now();
        }

        *self.initialized.write().await = true;
        *self.last_update.write().await = Some(Instant::now());

        Ok(())
    }

    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>> {
        if !hash.is_full() {
            return Err(Error::Hash("Hash must be full for lookup".to_string()));
        }

        let mut matching_descriptors = Vec::new();
        let mut best_match_length = 0;
        let mut best_match_hash = None;

        for entry in self.threat_lists.iter() {
            let match_length = entry.value().hash_set.lookup(hash);
            if match_length > 0 {
                if match_length > best_match_length {
                    best_match_length = match_length;
                    best_match_hash = Some(hash.truncate(match_length)?);
                    matching_descriptors.clear();
                    matching_descriptors.push(entry.key().clone());
                } else if match_length == best_match_length {
                    matching_descriptors.push(entry.key().clone());
                }
            }
        }

        if let Some(partial_hash) = best_match_hash {
            Ok(Some((partial_hash, matching_descriptors)))
        } else {
            Ok(None)
        }
    }

    async fn time_since_last_update(&self) -> Option<Duration> {
        self.last_update
            .read()
            .await
            .map(|instant| instant.elapsed())
    }

    async fn stats(&self) -> DatabaseStats {
        let last_update = *self.last_update.read().await;
        let total_hashes: usize = self
            .threat_lists
            .iter()
            .map(|entry| entry.value().hash_set.len())
            .sum();

        let is_stale = if let Some(last_update_time) = last_update {
            last_update_time.elapsed() > self.max_age
        } else {
            true
        };

        DatabaseStats {
            total_hashes,
            threat_lists: self.threat_lists.len(),
            memory_usage: total_hashes * 32, // Rough estimate
            last_update,
            is_stale,
        }
    }
}

impl Default for ConcurrentDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PlatformType, ThreatEntryType, ThreatType};

    fn create_test_threat_descriptor() -> ThreatDescriptor {
        ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        }
    }

    #[tokio::test]
    async fn test_database_initialization() {
        let db = InMemoryDatabase::new();
        assert!(!db.is_ready().await.unwrap());

        let stats = db.stats().await;
        assert_eq!(stats.total_hashes, 0);
        assert_eq!(stats.threat_lists, 0);
        assert!(stats.is_stale);
    }

    #[tokio::test]
    async fn test_database_status() {
        let db = InMemoryDatabase::new();
        let status = db.status().await;
        assert!(status.is_err());
        assert!(matches!(
            status.unwrap_err(),
            Error::Database(DatabaseError::Stale { .. })
        ));
    }

    #[tokio::test]
    async fn test_lookup_with_invalid_hash() {
        let db = InMemoryDatabase::new();
        let short_hash = HashPrefix::new(vec![1, 2, 3, 4]).unwrap();
        let result = db.lookup(&short_hash).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_lookup_empty_database() {
        let db = InMemoryDatabase::new();
        let hash = HashPrefix::from_pattern("test.example.com");
        let result = db.lookup(&hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_time_since_last_update() {
        let db = InMemoryDatabase::new();
        assert!(db.time_since_last_update().await.is_none());
    }

    #[tokio::test]
    async fn test_concurrent_database() {
        let db = ConcurrentDatabase::new();
        assert!(!db.is_ready().await.unwrap());

        let stats = db.stats().await;
        assert_eq!(stats.total_hashes, 0);
        assert_eq!(stats.threat_lists, 0);
        assert!(stats.is_stale);
    }

    #[tokio::test]
    async fn test_database_stats_display() {
        let stats = DatabaseStats {
            total_hashes: 1000,
            threat_lists: 3,
            memory_usage: 32000,
            last_update: Some(Instant::now()),
            is_stale: false,
        };

        // Test that stats can be formatted
        let _ = format!("{:?}", stats);
    }
}
