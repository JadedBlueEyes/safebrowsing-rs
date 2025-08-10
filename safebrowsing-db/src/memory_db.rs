use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use safebrowsing_api::{SafeBrowsingApi, ThreatDescriptor};
use safebrowsing_hash::{HashPrefix, HashPrefixSet};
use safebrowsing_proto::{CompressionType, RawHashes, RawIndices, RiceDeltaEncoding};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::{Database, DatabaseError, DatabaseStats, Result, ThreatListEntry};

/// In-memory database implementation
///
/// This is a simple database that keeps all threat lists in memory.
/// It's suitable for applications with moderate memory usage requirements.
pub struct InMemoryDatabase {
    /// Inner data protected by RwLock for concurrent access
    inner: Arc<RwLock<InMemoryDatabaseInner>>,
}

struct InMemoryDatabaseInner {
    /// Threat lists indexed by ThreatDescriptor
    threat_lists: HashMap<ThreatDescriptor, ThreatListEntry>,

    /// Whether the database has been initialized
    initialized: bool,

    /// Last update time
    last_update: Option<Instant>,

    /// Maximum database age before it's considered stale
    max_age: Duration,

    /// Total hash count for statistics
    hash_count: usize,
}

impl InMemoryDatabase {
    /// Create a new in-memory database
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(InMemoryDatabaseInner {
                threat_lists: HashMap::new(),
                initialized: false,
                last_update: None,
                max_age: Duration::from_secs(2 * 60 * 60),
                hash_count: 0,
            })),
        }
    }

    /// Create a new in-memory database with a specific maximum age
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InMemoryDatabaseInner {
                threat_lists: HashMap::new(),
                initialized: false,
                last_update: None,
                max_age,
                hash_count: 0,
            })),
        }
    }

    /// Update a single threat list from the API
    async fn update_threat_list(
        &self,
        api: &SafeBrowsingApi,
        threat_descriptor: &ThreatDescriptor,
    ) -> Result<()> {
        let client_state = {
            let inner = self.inner.read().await;
            inner
                .threat_lists
                .get(threat_descriptor)
                .map(|entry| entry.client_state.clone())
                .unwrap_or_default()
        };

        debug!(
            "Updating threat list: {} (state len: {})",
            threat_descriptor,
            client_state.len()
        );

        let response = api
            .fetch_threat_list_update(threat_descriptor, &client_state)
            .await?;

        if response.list_update_responses.is_empty() {
            warn!("Empty list update response for {}", threat_descriptor);
            return Ok(());
        }

        let list_update = &response.list_update_responses[0];
        let response_type = list_update.response_type;

        debug!(
            "Received response for {}: type={}, additions={}, removals={}",
            threat_descriptor,
            response_type,
            list_update.additions.len(),
            list_update.removals.len()
        );

        // Process based on response type
        {
            let mut inner = self.inner.write().await;
            match response_type {
                0 | 1 => {
                    // Unspecified or partial update
                    // If we have an existing entry, apply incremental updates
                    if let Some(entry) = inner.threat_lists.get_mut(threat_descriptor) {
                        // Create a local mutable borrow of hash_set
                        let hash_set = &mut entry.hash_set;

                        // Collect removal and addition sets
                        let removals: Vec<safebrowsing_proto::ThreatEntrySet> =
                            list_update.removals.clone();
                        let additions: Vec<safebrowsing_proto::ThreatEntrySet> =
                            list_update.additions.clone();

                        // Apply removals first
                        for removal_set in &removals {
                            Self::process_raw_hashes_removal(hash_set, removal_set)?;
                        }

                        // Then apply additions
                        for addition_set in &additions {
                            Self::process_raw_hashes_addition(hash_set, addition_set)?;
                        }

                        // Update state and checksum
                        if !list_update.new_client_state.is_empty() {
                            entry.client_state = list_update.new_client_state.clone().to_vec();
                        }

                        if let Some(checksum) = &list_update.checksum {
                            entry.checksum = checksum.sha256.clone().to_vec();

                            // Verify the checksum
                            let computed_checksum = entry.hash_set.compute_checksum();
                            if computed_checksum.as_bytes() != &checksum.sha256[..] {
                                return Err(DatabaseError::InvalidChecksum {
                                    expected: hex::encode(&checksum.sha256),
                                    actual: hex::encode(computed_checksum.as_bytes()),
                                });
                            }
                        }

                        entry.last_update = Instant::now();
                    } else if response_type == 0 {
                        // Unspecified response but no existing entry, treat as full update
                        Self::process_full_update_inner(
                            &mut inner,
                            threat_descriptor,
                            list_update,
                        )?;
                    } else {
                        // Partial update but no existing entry, error
                        warn!(
                            "Received partial update for non-existent threat list: {}",
                            threat_descriptor
                        );
                        // We'll request a full update next time
                    }
                }
                2 => {
                    // Full update - replace entire list
                    Self::process_full_update_inner(&mut inner, threat_descriptor, list_update)?;
                }
                _ => {
                    warn!("Unknown response type: {}", response_type);
                }
            }

            Self::update_hash_count_inner(&mut inner).await;
        }
        Ok(())
    }

    /// Update hash count metadata
    async fn update_hash_count_inner(inner: &mut InMemoryDatabaseInner) {
        inner.hash_count = inner
            .threat_lists
            .values()
            .map(|entry| entry.hash_set.len())
            .sum();
    }

    /// Process a full update for a threat list
    fn process_full_update_inner(
        inner: &mut InMemoryDatabaseInner,
        threat_descriptor: &ThreatDescriptor,
        list_update: &safebrowsing_proto::fetch_threat_list_updates_response::ListUpdateResponse,
    ) -> Result<()> {
        let mut hash_set = HashPrefixSet::new();

        // Process additions only for full updates
        for addition_set in &list_update.additions {
            Self::process_raw_hashes_addition(&mut hash_set, addition_set)?;
        }

        // Create new entry
        let entry = ThreatListEntry::new(
            hash_set,
            list_update.new_client_state.clone().to_vec(),
            list_update
                .checksum
                .as_ref()
                .map_or_else(Vec::new, |c| c.sha256.clone().to_vec()),
        );

        // Verify checksum if present
        if let Some(checksum) = &list_update.checksum {
            let computed_checksum = entry.hash_set.compute_checksum();
            if computed_checksum.as_bytes() != &checksum.sha256[..] {
                return Err(DatabaseError::InvalidChecksum {
                    expected: hex::encode(&checksum.sha256),
                    actual: hex::encode(computed_checksum.as_bytes()),
                });
            }
        }

        // Add to threat lists
        inner.threat_lists.insert(threat_descriptor.clone(), entry);

        Ok(())
    }

    /// Process a threat entry addition set (free function)
    fn process_raw_hashes_addition(
        hash_set: &mut HashPrefixSet,
        addition: &safebrowsing_proto::ThreatEntrySet,
    ) -> Result<()> {
        match addition.compression_type {
            x if x == CompressionType::Raw as i32 => {
                // Raw hashes
                if let Some(raw_hashes) = &addition.raw_hashes {
                    Self::process_raw_hashes(hash_set, raw_hashes)?;
                }
            }
            x if x == CompressionType::Rice as i32 => {
                // Rice-encoded hashes
                if let Some(rice_hashes) = &addition.rice_hashes {
                    Self::process_rice_hashes(hash_set, rice_hashes)?;
                }
            }
            _ => {
                warn!(
                    "Unsupported compression type: {}",
                    addition.compression_type
                );
            }
        }

        Ok(())
    }

    /// Process a threat entry removal set (free function)
    fn process_raw_hashes_removal(
        hash_set: &mut HashPrefixSet,
        removal: &safebrowsing_proto::ThreatEntrySet,
    ) -> Result<()> {
        match removal.compression_type {
            x if x == CompressionType::Raw as i32 => {
                // Raw indices
                if let Some(raw_indices) = &removal.raw_indices {
                    Self::process_raw_indices(hash_set, raw_indices)?;
                }
            }
            x if x == CompressionType::Rice as i32 => {
                // Rice-encoded indices
                if let Some(rice_indices) = &removal.rice_indices {
                    Self::process_rice_indices(hash_set, rice_indices)?;
                }
            }
            _ => {
                warn!(
                    "Unsupported compression type for removal: {}",
                    removal.compression_type
                );
            }
        }

        Ok(())
    }

    // Move these helper functions outside the impl block

    /// Process raw hash additions
    fn process_raw_hashes(hash_set: &mut HashPrefixSet, raw_hashes: &RawHashes) -> Result<()> {
        let prefix_size = raw_hashes.prefix_size as usize;
        if !(4..=32).contains(&prefix_size) {
            return Err(DatabaseError::DecodeError(format!(
                "Invalid prefix size: {prefix_size}"
            )));
        }

        let hashes = &raw_hashes.raw_hashes;
        if hashes.len() % prefix_size != 0 {
            return Err(DatabaseError::DecodeError(format!(
                "Raw hashes length {} is not a multiple of prefix size {}",
                hashes.len(),
                prefix_size
            )));
        }

        for i in (0..hashes.len()).step_by(prefix_size) {
            let end = i + prefix_size;
            if end > hashes.len() {
                break;
            }

            // Convert to a Vec<u8> to avoid lifetime issues
            let hash_vec = hashes[i..end].to_vec();
            match HashPrefix::new(hash_vec) {
                Ok(hash) => {
                    hash_set.insert(hash);
                }
                Err(e) => {
                    warn!("Skipping invalid hash: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Process Rice-encoded hash additions
    /// Process Rice-encoded hashes and add them to the hash set.
    ///
    /// IMPORTANT: This uses little-endian byte order to match the Go implementation.
    /// The Safe Browsing API's Go reference implementation uses `binary.LittleEndian.PutUint32`
    /// when converting Rice-decoded integers to hash bytes. Using big-endian would result
    /// in completely different hash values and checksum mismatches.
    ///
    /// See: https://github.com/google/safebrowsing/blob/master/hash.go#L183
    fn process_rice_hashes(
        hash_set: &mut HashPrefixSet,
        rice_hashes: &RiceDeltaEncoding,
    ) -> Result<()> {
        let decoded_hashes = Self::decode_rice_delta_encoding(rice_hashes)?;

        for hash_value in decoded_hashes {
            // Rice encoding is for 4-byte hashes
            // CRITICAL: Use little-endian to match Go implementation
            // Go code: binary.LittleEndian.PutUint32(buf[:], h)
            let hash_vec = hash_value.to_le_bytes().to_vec();
            match HashPrefix::new(hash_vec) {
                Ok(hash) => {
                    hash_set.insert(hash);
                }
                Err(e) => {
                    warn!("Skipping invalid hash: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Process raw indices for removals
    fn process_raw_indices(hash_set: &mut HashPrefixSet, raw_indices: &RawIndices) -> Result<()> {
        // Need to sort the hashes and remove by index
        let sorted_hashes = hash_set.to_sorted_vec();

        // Build a set of indices to remove
        let mut indices_to_remove = crate::StdHashSet::new();
        for &index in &raw_indices.indices {
            if index >= 0 && (index as usize) < sorted_hashes.len() {
                indices_to_remove.insert(index as usize);
            } else {
                return Err(DatabaseError::InvalidIndices(format!(
                    "Index out of bounds: {} (max: {})",
                    index,
                    sorted_hashes.len()
                )));
            }
        }

        // Remove the hashes at the specified indices
        for (i, hash) in sorted_hashes.iter().enumerate() {
            if indices_to_remove.contains(&i) {
                hash_set.remove(hash);
            }
        }

        Ok(())
    }

    /// Process Rice-encoded indices for removals
    fn process_rice_indices(
        hash_set: &mut HashPrefixSet,
        rice_indices: &RiceDeltaEncoding,
    ) -> Result<()> {
        let decoded_indices = Self::decode_rice_delta_encoding(rice_indices)?;

        // Convert hash set to sorted vector for indexed removal
        let sorted_hashes: Vec<HashPrefix> = hash_set.to_sorted_vec();

        // Build a set of hashes to remove based on indices
        let mut hashes_to_remove = crate::StdHashSet::new();
        for index in decoded_indices {
            let index = index as usize;
            if index < sorted_hashes.len() {
                hashes_to_remove.insert(sorted_hashes[index].clone());
            } else {
                return Err(DatabaseError::InvalidIndices(format!(
                    "Rice-encoded index out of bounds: {} (max: {})",
                    index,
                    sorted_hashes.len()
                )));
            }
        }

        // Remove all identified hashes
        for hash in hashes_to_remove {
            hash_set.remove(&hash);
        }

        Ok(())
    }

    /// Decode a Rice-delta encoded value using proper Rice-Golomb decoding
    fn decode_rice_delta_encoding(rice: &RiceDeltaEncoding) -> Result<Vec<u32>> {
        use safebrowsing_hash::rice::decode_rice_integers;

        decode_rice_integers(
            rice.rice_parameter,
            rice.first_value,
            rice.num_entries,
            &rice.encoded_data,
        )
        .map_err(|e| DatabaseError::RiceDecodeError(e.to_string()))
    }

    /// Update the total hash count for statistics
    async fn update_hash_count(&self) {
        let mut inner = self.inner.write().await;
        Self::update_hash_count_inner(&mut inner).await;
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
        let inner = self.inner.read().await;
        if !inner.initialized {
            return Ok(false);
        }

        // Check if any list is stale
        for (descriptor, entry) in &inner.threat_lists {
            if entry.is_stale(inner.max_age) {
                warn!(
                    "Threat list {} is stale (last updated {:?} ago)",
                    descriptor,
                    entry.last_update.elapsed()
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn status(&self) -> Result<()> {
        let inner = self.inner.read().await;
        if !inner.initialized {
            return Err(DatabaseError::NotReady);
        }

        if let Some(last_update) = inner.last_update {
            let elapsed = last_update.elapsed();
            if elapsed > inner.max_age {
                return Err(DatabaseError::Stale(elapsed));
            }
        } else {
            return Err(DatabaseError::NotReady);
        }

        Ok(())
    }

    async fn update(&self, api: &SafeBrowsingApi, threat_lists: &[ThreatDescriptor]) -> Result<()> {
        info!("Updating database with {} threat lists", threat_lists.len());

        for threat_descriptor in threat_lists {
            if let Err(e) = self.update_threat_list(api, threat_descriptor).await {
                error!("Failed to update threat list {}: {}", threat_descriptor, e);
                // Continue with other lists
            }
        }

        {
            let mut inner = self.inner.write().await;
            inner.initialized = !inner.threat_lists.is_empty();
            inner.last_update = Some(Instant::now());
        }

        Ok(())
    }

    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>> {
        let inner = self.inner.read().await;
        if !inner.initialized {
            return Err(DatabaseError::NotReady);
        }

        let mut matching_descriptors = Vec::new();
        let mut matching_prefix = None;

        for (descriptor, entry) in &inner.threat_lists {
            if let Some(prefix) = entry.hash_set.find_prefix(hash) {
                matching_descriptors.push(descriptor.clone());

                // We'll use the first matching prefix we find
                if matching_prefix.is_none() {
                    matching_prefix = Some(prefix.clone());
                }
            }
        }

        if let Some(prefix) = matching_prefix {
            Ok(Some((prefix, matching_descriptors)))
        } else {
            Ok(None)
        }
    }

    async fn time_since_last_update(&self) -> Option<Duration> {
        let inner = self.inner.read().await;
        inner.last_update.map(|time| time.elapsed())
    }

    async fn stats(&self) -> DatabaseStats {
        let inner = self.inner.read().await;
        let is_stale = if let Some(last_update) = inner.last_update {
            last_update.elapsed() > inner.max_age
        } else {
            true
        };

        // Estimate memory usage (very rough approximation)
        let mut memory_usage = 0;
        for entry in inner.threat_lists.values() {
            // Each hash is approximately its length + overhead
            memory_usage += entry.hash_set.len() * 8; // ~8 bytes per hash with overhead
            memory_usage += entry.client_state.len();
            memory_usage += entry.checksum.len();
            memory_usage += 32; // Struct overhead
        }

        // Map overhead
        memory_usage += inner.threat_lists.len() * 32;

        DatabaseStats {
            total_hashes: inner.hash_count,
            threat_lists: inner.threat_lists.len(),
            memory_usage,
            last_update: inner.last_update,
            is_stale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_db::*;
    use safebrowsing_api::{PlatformType, ThreatDescriptor, ThreatEntryType, ThreatType};
    use safebrowsing_hash::HashPrefix;

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

        // New database should not be ready
        assert!(!db.is_ready().await.unwrap());

        // Status should return an error
        assert!(matches!(db.status().await, Err(DatabaseError::NotReady)));

        // Last update time should be None
        assert!(db.time_since_last_update().await.is_none());
    }

    #[tokio::test]
    async fn test_database_stats() {
        let db = InMemoryDatabase::new();

        let stats = db.stats().await;
        assert_eq!(stats.total_hashes, 0);
        assert_eq!(stats.threat_lists, 0);
        assert!(stats.last_update.is_none());
        assert!(stats.is_stale);
    }

    #[tokio::test]
    async fn test_lookup_with_invalid_hash() {
        let db = InMemoryDatabase::new();
        let hash = HashPrefix::from_pattern("test");

        // Lookup should fail on uninitialized database
        assert!(matches!(
            db.lookup(&hash).await,
            Err(DatabaseError::NotReady)
        ));
    }

    #[tokio::test]
    async fn test_lookup_empty_database() {
        let db = InMemoryDatabase::new();
        let hash = HashPrefix::from_pattern("test");

        // Manually set initialized to simulate a database with no entries
        {
            let mut inner = db.inner.write().await;
            inner.initialized = true;
            inner.last_update = Some(Instant::now());
        }

        // Lookup should return None for an empty database
        assert!(matches!(db.lookup(&hash).await, Ok(None)));
    }

    #[tokio::test]
    async fn test_time_since_last_update() {
        let db = InMemoryDatabase::new();

        // Initially, there should be no update time
        assert!(db.time_since_last_update().await.is_none());

        // Set an update time
        {
            let mut inner = db.inner.write().await;
            inner.last_update = Some(Instant::now());
        }
        assert!(db.time_since_last_update().await.is_some());
    }

    #[tokio::test]
    async fn test_database_stats_display() {
        let db = InMemoryDatabase::new();

        // Without update time
        let stats = db.stats().await;
        let display = format!("{stats}");
        assert!(display.contains("never"));
        assert!(display.contains("STALE"));

        // With update time
        {
            let mut inner = db.inner.write().await;
            inner.last_update = Some(Instant::now());
        }
        let stats = db.stats().await;
        let display = format!("{stats}");
        assert!(display.contains("ago"));
        assert!(display.contains("up-to-date"));
    }
}
