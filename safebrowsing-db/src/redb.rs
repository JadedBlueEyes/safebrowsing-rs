//! Redb-based persistent database backend for Google Safe Browsing API
//!
//! This crate provides a persistent database implementation using redb that implements
//! the Database trait from safebrowsing-db. It stores threat lists on disk and provides
//! thread-safe access with ACID transactions.

use crate::{Database, DatabaseError, DatabaseStats};
use async_trait::async_trait;
use redb::{Database as RedbDb, ReadableDatabase, ReadableTable, TableDefinition};
use safebrowsing_api::{SafeBrowsingApi, ThreatDescriptor};
use safebrowsing_hash::{HashPrefix, HashPrefixSet};
use safebrowsing_proto::{CompressionType, RiceDeltaEncoding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

type Result<T> = std::result::Result<T, DatabaseError>;

/// Table definitions for redb storage
const THREAT_LISTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("threat_lists");
const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const HASH_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("hashes");

/// Metadata keys
const LAST_UPDATE_KEY: &str = "last_update";
const INITIALIZED_KEY: &str = "initialized";
const HASH_COUNT_KEY: &str = "hash_count";

/// Serializable threat list entry for storage
#[derive(Serialize, Deserialize, Clone)]
struct StoredThreatListEntry {
    /// Hash prefixes as bytes
    hash_prefixes: Vec<Vec<u8>>,
    /// Client state for this list
    client_state: Vec<u8>,
    /// Checksum of this list
    checksum: Vec<u8>,
    /// Last update timestamp (seconds since epoch)
    last_update: u64,
}

impl StoredThreatListEntry {
    fn from_hash_set(hash_set: &HashPrefixSet, client_state: Vec<u8>, checksum: Vec<u8>) -> Self {
        let hash_prefixes = hash_set
            .iter()
            .map(|prefix| prefix.as_bytes().to_vec())
            .collect();

        Self {
            hash_prefixes,
            client_state,
            checksum,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn to_hash_set(&self) -> Result<HashPrefixSet> {
        let mut hash_set = HashPrefixSet::new();
        for prefix_bytes in &self.hash_prefixes {
            let prefix = HashPrefix::new(prefix_bytes.clone())
                .map_err(|e| DatabaseError::DecodeError(format!("Invalid hash prefix: {e}")))?;
            hash_set.insert(prefix);
        }
        Ok(hash_set)
    }
}

/// Redb-based persistent database for Safe Browsing
pub struct RedbDatabase {
    /// Redb database instance
    db: Arc<RedbDb>,
    /// In-memory cache of threat lists for fast access
    cache: Arc<RwLock<HashMap<ThreatDescriptor, StoredThreatListEntry>>>,
    /// Maximum database age before it's considered stale
    max_age: Duration,
    /// Database file path
    path: PathBuf,
}

impl RedbDatabase {
    /// Create a new redb database at the specified path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        info!("Creating RedbDatabase at {:?}", path);

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(DatabaseError::IoError)?;
        }

        let db = if path.exists() {
            info!("Opening existing database at {:?}", path);
            RedbDb::open(&path).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to open existing database: {e}"))
            })?
        } else {
            info!("Creating new database at {:?}", path);
            RedbDb::create(&path).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to create new database: {e}"))
            })?
        };

        // Initialize tables
        {
            let write_txn = db.begin_write().map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to begin write transaction: {e}"))
            })?;

            write_txn.open_table(THREAT_LISTS_TABLE).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to create threat_lists table: {e}"))
            })?;
            write_txn.open_table(METADATA_TABLE).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to create metadata table: {e}"))
            })?;
            write_txn.open_table(HASH_TABLE).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to create hash table: {e}"))
            })?;

            write_txn.commit().map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to commit transaction: {e}"))
            })?;
        }

        let instance = Self {
            db: Arc::new(db),
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_age: crate::DEFAULT_MAX_DATABASE_AGE,
            path,
        };

        Ok(instance)
    }

    /// Initialize the database and load cache
    pub async fn init(&self) -> Result<()> {
        info!("Initializing RedbDatabase at {:?}", self.path);
        self.load_cache().await?;
        info!("RedbDatabase initialization completed");
        Ok(())
    }

    /// Create a new redb database with a custom maximum age
    pub async fn with_max_age<P: AsRef<Path>>(path: P, max_age: Duration) -> Result<Self> {
        let mut db = Self::new(path)?;
        db.max_age = max_age;
        db.init().await?;
        Ok(db)
    }

    /// Get the default database path in the system cache directory
    pub fn default_path() -> Result<PathBuf> {
        let cache_dir = dirs::cache_dir().ok_or_else(|| {
            DatabaseError::DecodeError("Failed to get cache directory".to_string())
        })?;

        let safebrowsing_dir = cache_dir.join("safebrowsing");
        Ok(safebrowsing_dir.join("database.redb"))
    }

    /// Load threat lists from disk into memory cache
    async fn load_cache(&self) -> Result<()> {
        debug!("Loading cache from database");
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to begin read transaction: {e}"))
        })?;

        let table = read_txn.open_table(THREAT_LISTS_TABLE).map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to open threat_lists table: {e}"))
        })?;

        let mut cache = HashMap::new();
        let mut loaded_count = 0;

        for item in table
            .iter()
            .map_err(|e| DatabaseError::DecodeError(format!("Failed to iterate table: {e}")))?
        {
            let (key, value) = item.map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to read table item: {e}"))
            })?;

            let threat_descriptor: ThreatDescriptor =
                serde_json::from_str(key.value()).map_err(|e| {
                    DatabaseError::DecodeError(format!("Failed to decode threat descriptor: {e}"))
                })?;

            let entry: StoredThreatListEntry =
                serde_json::from_slice(value.value()).map_err(|e| {
                    DatabaseError::DecodeError(format!("Failed to decode threat list entry: {e}"))
                })?;

            debug!(
                "Loaded threat list {:?} with {} hashes",
                threat_descriptor,
                entry.hash_prefixes.len()
            );
            cache.insert(threat_descriptor, entry);
            loaded_count += 1;
        }

        debug!(
            "Loaded {} threat lists from database into cache",
            loaded_count
        );
        let mut cache_guard = self.cache.write().await;
        *cache_guard = cache;

        Ok(())
    }

    /// Store a threat list entry both in cache and on disk
    async fn store_threat_list(
        &self,
        threat_descriptor: &ThreatDescriptor,
        entry: StoredThreatListEntry,
    ) -> Result<()> {
        debug!(
            "Storing threat list {:?} with {} hashes",
            threat_descriptor,
            entry.hash_prefixes.len()
        );

        // Update cache first
        {
            let mut cache = self.cache.write().await;
            cache.insert(threat_descriptor.clone(), entry.clone());
        }

        // Then persist to disk
        let threat_descriptor_key = serde_json::to_string(threat_descriptor).map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to serialize threat descriptor: {e}"))
        })?;

        let entry_value = serde_json::to_vec(&entry).map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to serialize threat list entry: {e}"))
        })?;

        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to begin write transaction: {e}"))
        })?;

        {
            let mut table = write_txn.open_table(THREAT_LISTS_TABLE).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to open threat_lists table: {e}"))
            })?;

            table
                .insert(threat_descriptor_key.as_str(), entry_value.as_slice())
                .map_err(|e| {
                    DatabaseError::DecodeError(format!("Failed to insert threat list: {e}"))
                })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to commit transaction: {e}"))
        })?;

        debug!(
            "Successfully stored threat list {:?} to database",
            threat_descriptor
        );
        Ok(())
    }

    /// Store metadata value
    fn store_metadata(&self, key: &str, value: &[u8]) -> Result<()> {
        debug!("Storing metadata key: {}", key);
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to begin write transaction: {e}"))
        })?;

        {
            let mut table = write_txn.open_table(METADATA_TABLE).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to open metadata table: {e}"))
            })?;

            table.insert(key, value).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to insert metadata: {e}"))
            })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to commit transaction: {e}"))
        })?;

        debug!("Successfully stored metadata key: {}", key);
        Ok(())
    }

    /// Get metadata value
    fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>> {
        debug!("Getting metadata key: {}", key);
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to begin read transaction: {e}"))
        })?;

        let table = read_txn.open_table(METADATA_TABLE).map_err(|e| {
            DatabaseError::DecodeError(format!("Failed to open metadata table: {e}"))
        })?;

        match table.get(key) {
            Ok(Some(value)) => {
                debug!(
                    "Found metadata key: {} with {} bytes",
                    key,
                    value.value().len()
                );
                Ok(Some(value.value().to_vec()))
            }
            Ok(None) => {
                debug!("Metadata key not found: {}", key);
                Ok(None)
            }
            Err(e) => Err(DatabaseError::DecodeError(format!(
                "Failed to get metadata: {e}"
            ))),
        }
    }

    /// Update hash count metadata
    async fn update_hash_count(&self) -> Result<()> {
        let cache = self.cache.read().await;
        let total_count: usize = cache.values().map(|entry| entry.hash_prefixes.len()).sum();

        let count_bytes = total_count.to_le_bytes();
        self.store_metadata(HASH_COUNT_KEY, &count_bytes)?;

        Ok(())
    }

    /// Process full update for a threat list
    async fn process_full_update(
        &self,
        threat_descriptor: &ThreatDescriptor,
        list_update: &safebrowsing_proto::fetch_threat_list_updates_response::ListUpdateResponse,
    ) -> Result<()> {
        debug!("Processing full update for {:?}", threat_descriptor);

        let mut hash_set = HashPrefixSet::new();

        // Process additions only for full updates
        for addition_set in &list_update.additions {
            self.process_raw_hashes_addition(&mut hash_set, addition_set)?;
        }

        // Create and store the new entry
        let entry = StoredThreatListEntry::from_hash_set(
            &hash_set,
            list_update.new_client_state.clone().to_vec(),
            list_update
                .checksum
                .as_ref()
                .map_or_else(Vec::new, |c| c.sha256.clone().to_vec()),
        );
        self.store_threat_list(threat_descriptor, entry).await?;

        Ok(())
    }

    /// Process partial update by applying additions to existing data
    async fn process_partial_update(
        &self,
        threat_descriptor: &ThreatDescriptor,
        list_update: &safebrowsing_proto::fetch_threat_list_updates_response::ListUpdateResponse,
    ) -> Result<()> {
        debug!("Processing partial update for {:?}", threat_descriptor);

        // Get existing hash set
        let mut hash_set = {
            let cache = self.cache.read().await;
            match cache.get(threat_descriptor) {
                Some(entry) => entry.to_hash_set()?,
                None => {
                    debug!("No existing data found, treating as full update");
                    return self
                        .process_full_update(threat_descriptor, list_update)
                        .await;
                }
            }
        };

        // Process removals first (order matters for correct indexing)
        for removal_set in &list_update.removals {
            debug!(
                "Processing removal set with {} indices",
                removal_set
                    .raw_indices
                    .as_ref()
                    .map_or(0, |r| r.indices.len())
                    + removal_set.rice_indices.as_ref().map_or(0, |_| 1)
            ); // Rice indices contain multiple values
            self.process_raw_hashes_removal(&mut hash_set, removal_set)?;
        }

        // Then process additions
        for addition_set in &list_update.additions {
            debug!("Processing addition set");
            self.process_raw_hashes_addition(&mut hash_set, addition_set)?;
        }

        debug!(
            "Partial update complete. Hash set now contains {} entries",
            hash_set.len()
        );

        // Create and store the updated entry
        let entry = StoredThreatListEntry::from_hash_set(
            &hash_set,
            list_update.new_client_state.clone().to_vec(),
            list_update
                .checksum
                .as_ref()
                .map_or_else(Vec::new, |c| c.sha256.clone().to_vec()),
        );
        self.store_threat_list(threat_descriptor, entry).await?;

        Ok(())
    }

    /// Process raw hashes addition
    fn process_raw_hashes_addition(
        &self,
        hash_set: &mut HashPrefixSet,
        addition_set: &safebrowsing_proto::ThreatEntrySet,
    ) -> Result<()> {
        match addition_set.compression_type {
            x if x == CompressionType::Raw as i32 => {
                // Raw hashes
                if let Some(raw_hashes) = &addition_set.raw_hashes {
                    self.process_raw_hashes(hash_set, raw_hashes)?;
                }
            }
            x if x == CompressionType::Rice as i32 => {
                // Rice-encoded hashes
                if let Some(rice_hashes) = &addition_set.rice_hashes {
                    self.process_rice_hashes(hash_set, rice_hashes)?;
                }
            }
            _ => {
                debug!(
                    "Unsupported compression type: {}",
                    addition_set.compression_type
                );
            }
        }

        Ok(())
    }

    /// Process raw hashes and add them to the hash set
    fn process_raw_hashes(
        &self,
        hash_set: &mut HashPrefixSet,
        raw_hashes: &safebrowsing_proto::RawHashes,
    ) -> Result<()> {
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
                    debug!("Skipping invalid hash: {}", e);
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
        &self,
        hash_set: &mut HashPrefixSet,
        rice_hashes: &RiceDeltaEncoding,
    ) -> Result<()> {
        let decoded_hashes = self.decode_rice_delta_encoding(rice_hashes)?;

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
                    debug!("Skipping invalid hash: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Decode Rice delta encoding
    fn decode_rice_delta_encoding(&self, rice: &RiceDeltaEncoding) -> Result<Vec<u32>> {
        use safebrowsing_hash::rice::decode_rice_integers;

        decode_rice_integers(
            rice.rice_parameter,
            rice.first_value,
            rice.num_entries,
            &rice.encoded_data,
        )
        .map_err(|e| DatabaseError::RiceDecodeError(e.to_string()))
    }

    /// Process hash removals from a threat entry set
    fn process_raw_hashes_removal(
        &self,
        hash_set: &mut HashPrefixSet,
        removal_set: &safebrowsing_proto::ThreatEntrySet,
    ) -> Result<()> {
        match removal_set.compression_type {
            x if x == CompressionType::Raw as i32 => {
                // Raw indices
                if let Some(raw_indices) = &removal_set.raw_indices {
                    self.process_raw_indices(hash_set, raw_indices)?;
                }
            }
            x if x == CompressionType::Rice as i32 => {
                // Rice-encoded indices
                if let Some(rice_indices) = &removal_set.rice_indices {
                    self.process_rice_indices(hash_set, rice_indices)?;
                }
            }
            _ => {
                debug!(
                    "Unsupported compression type for removal: {}",
                    removal_set.compression_type
                );
            }
        }

        Ok(())
    }

    /// Process raw indices for hash removal
    fn process_raw_indices(
        &self,
        hash_set: &mut HashPrefixSet,
        raw_indices: &safebrowsing_proto::RawIndices,
    ) -> Result<()> {
        // Need to sort the hashes and remove by index
        let sorted_hashes = hash_set.to_sorted_vec();

        // Build a set of indices to remove
        let mut indices_to_remove = std::collections::HashSet::new();
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

    /// Process Rice-encoded indices for hash removal
    fn process_rice_indices(
        &self,
        hash_set: &mut HashPrefixSet,
        rice_indices: &RiceDeltaEncoding,
    ) -> Result<()> {
        let decoded_indices = self.decode_rice_delta_encoding(rice_indices)?;

        // Need to sort the hashes and remove by index
        let sorted_hashes = hash_set.to_sorted_vec();

        // Build a set of indices to remove
        let mut indices_to_remove = std::collections::HashSet::new();
        for index in decoded_indices {
            if (index as usize) < sorted_hashes.len() {
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

    /// Update threat list from API response
    async fn update_threat_list(
        &self,
        api: &SafeBrowsingApi,
        threat_descriptor: &ThreatDescriptor,
    ) -> Result<()> {
        info!("Updating threat list: {:?}", threat_descriptor);

        // Get current client state
        let client_state = {
            let cache = self.cache.read().await;
            cache
                .get(threat_descriptor)
                .map(|entry| entry.client_state.clone())
                .unwrap_or_default()
        };

        // Fetch updates from API
        let response = api
            .fetch_threat_list_update(threat_descriptor, &client_state)
            .await
            .map_err(DatabaseError::ApiError)?;

        if response.list_update_responses.is_empty() {
            return Ok(());
        }

        let list_update = &response.list_update_responses[0];
        let response_type = list_update.response_type;

        // Process based on response type
        match response_type {
            0 => {
                // Unspecified - check if this is actually a full update
                debug!("Unspecified update type, checking for additions/removals");
                if list_update.additions.is_empty() && list_update.removals.is_empty() {
                    debug!("No additions or removals, skipping update");
                    return Ok(());
                }
                // If we have additions/removals, process as partial update
                self.process_partial_update(threat_descriptor, list_update)
                    .await?;
            }
            1 => {
                // Partial update - apply changes to existing data
                debug!("Processing partial update");
                self.process_partial_update(threat_descriptor, list_update)
                    .await?;
            }
            2 => {
                // Full update - replace entire list
                debug!("Processing full update");
                self.process_full_update(threat_descriptor, list_update)
                    .await?;
            }
            _ => {
                return Err(DatabaseError::DecodeError(format!(
                    "Unknown response type: {response_type}"
                )));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Database for RedbDatabase {
    async fn is_ready(&self) -> Result<bool> {
        // Check if we have metadata indicating initialization
        let has_metadata = match self.get_metadata(INITIALIZED_KEY) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false,
        };

        if !has_metadata {
            return Ok(false);
        }

        // Also check if cache has actual data
        let cache = self.cache.read().await;
        let has_data =
            !cache.is_empty() && cache.values().any(|entry| !entry.hash_prefixes.is_empty());

        if !has_data {
            warn!("Database metadata indicates initialization but cache is empty - forcing update");
            return Ok(false);
        }

        Ok(true)
    }

    async fn status(&self) -> Result<()> {
        // Check if database is stale
        if let Some(duration) = self.time_since_last_update().await {
            if duration > self.max_age {
                return Err(DatabaseError::Stale(duration));
            }
        }

        // Check if database is ready
        if !Database::is_ready(self).await? {
            return Err(DatabaseError::NotReady);
        }

        Ok(())
    }

    async fn update(&self, api: &SafeBrowsingApi, threat_lists: &[ThreatDescriptor]) -> Result<()> {
        for threat_descriptor in threat_lists {
            // Get current client state
            let client_state = {
                let cache = self.cache.read().await;
                cache
                    .get(threat_descriptor)
                    .map(|entry| entry.client_state.clone())
                    .unwrap_or_default()
            };

            // Fetch updates from API
            let response = api
                .fetch_threat_list_update(threat_descriptor, &client_state)
                .await
                .map_err(DatabaseError::ApiError)?;

            if response.list_update_responses.is_empty() {
                continue;
            }

            let list_update = &response.list_update_responses[0];
            let response_type = list_update.response_type;

            // Get the current hash set
            let mut hash_set = {
                let cache = self.cache.read().await;
                match cache.get(threat_descriptor) {
                    Some(entry) => entry.to_hash_set()?,
                    None => HashPrefixSet::new(),
                }
            };

            // Process based on response type
            match response_type {
                0 => {
                    // Unspecified - check if this is actually a full update
                    if list_update.additions.is_empty() && list_update.removals.is_empty() {
                        continue;
                    }
                    // If we have additions/removals, process as partial update
                    for removal_set in &list_update.removals {
                        self.process_raw_hashes_removal(&mut hash_set, removal_set)?;
                    }
                    for addition_set in &list_update.additions {
                        self.process_raw_hashes_addition(&mut hash_set, addition_set)?;
                    }
                }
                1 => {
                    // Partial update - apply changes to existing data
                    for removal_set in &list_update.removals {
                        self.process_raw_hashes_removal(&mut hash_set, removal_set)?;
                    }
                    for addition_set in &list_update.additions {
                        self.process_raw_hashes_addition(&mut hash_set, addition_set)?;
                    }
                }
                2 => {
                    // Full update - replace entire list
                    hash_set = HashPrefixSet::new();
                    for addition_set in &list_update.additions {
                        self.process_raw_hashes_addition(&mut hash_set, addition_set)?;
                    }
                }
                _ => {
                    return Err(DatabaseError::DecodeError(format!(
                        "Unknown response type: {response_type}"
                    )));
                }
            }

            // Create new entry
            let entry = StoredThreatListEntry::from_hash_set(
                &hash_set,
                list_update.new_client_state.clone().to_vec(),
                list_update
                    .checksum
                    .as_ref()
                    .map_or_else(Vec::new, |c| c.sha256.clone().to_vec()),
            );

            // Store in a single transaction
            let threat_descriptor_key = serde_json::to_string(threat_descriptor).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to serialize threat descriptor: {e}"))
            })?;

            let entry_value = serde_json::to_vec(&entry).map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to serialize threat list entry: {e}"))
            })?;

            let write_txn = self.db.begin_write().map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to begin write transaction: {e}"))
            })?;

            {
                let mut table = write_txn.open_table(THREAT_LISTS_TABLE).map_err(|e| {
                    DatabaseError::DecodeError(format!("Failed to open threat_lists table: {e}"))
                })?;

                table
                    .insert(threat_descriptor_key.as_str(), entry_value.as_slice())
                    .map_err(|e| {
                        DatabaseError::DecodeError(format!("Failed to insert threat list: {e}"))
                    })?;
            }

            write_txn.commit().map_err(|e| {
                DatabaseError::DecodeError(format!("Failed to commit transaction: {e}"))
            })?;

            // Update cache
            {
                let mut cache = self.cache.write().await;
                cache.insert(threat_descriptor.clone(), entry);
            }
        }

        // Update metadata in separate transactions
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.store_metadata(LAST_UPDATE_KEY, &now.to_le_bytes())?;
        self.store_metadata(INITIALIZED_KEY, &[1u8])?;
        self.update_hash_count().await?;

        Ok(())
    }

    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>> {
        let cache = self.cache.read().await;
        let mut matching_threats = Vec::new();

        // Search through all threat lists
        for (threat_descriptor, entry) in cache.iter() {
            let hash_set = entry.to_hash_set()?;
            if hash_set.contains(hash) {
                matching_threats.push(threat_descriptor.clone());
            }
        }

        if matching_threats.is_empty() {
            Ok(None)
        } else {
            Ok(Some((hash.clone(), matching_threats)))
        }
    }

    async fn time_since_last_update(&self) -> Option<Duration> {
        match self.get_metadata(LAST_UPDATE_KEY) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let timestamp = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                Some(Duration::from_secs(now.saturating_sub(timestamp)))
            }
            _ => None,
        }
    }

    async fn stats(&self) -> DatabaseStats {
        let cache = self.cache.read().await;

        let total_hashes = cache.values().map(|entry| entry.hash_prefixes.len()).sum();

        let threat_lists = cache.len();

        let memory_usage = std::mem::size_of::<RedbDatabase>()
            + cache
                .iter()
                .map(|(k, v)| {
                    std::mem::size_of_val(k)
                        + std::mem::size_of_val(v)
                        + v.hash_prefixes.iter().map(|h| h.len()).sum::<usize>()
                        + v.client_state.len()
                        + v.checksum.len()
                })
                .sum::<usize>();

        let is_stale = self
            .time_since_last_update()
            .await
            .map(|duration| duration > self.max_age)
            .unwrap_or(true);

        let last_update = match self.get_metadata(LAST_UPDATE_KEY) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let timestamp = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);

                Some(std::time::UNIX_EPOCH + Duration::from_secs(timestamp))
                    .and_then(|t| t.elapsed().ok())
                    .map(|elapsed| std::time::Instant::now() - elapsed)
            }
            _ => None,
        };

        DatabaseStats {
            total_hashes,
            threat_lists,
            memory_usage,
            last_update,
            is_stale,
        }
    }
}

impl Default for RedbDatabase {
    fn default() -> Self {
        // Note: Default implementation doesn't load cache automatically
        // Call init() separately for async initialization
        Self::new(Self::default_path().unwrap_or_else(|_| PathBuf::from("safebrowsing.redb")))
            .expect("Failed to create default RedbDatabase")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safebrowsing_api::{PlatformType, ThreatEntryType, ThreatType};
    use tempfile::tempdir;

    fn create_test_threat_descriptor() -> ThreatDescriptor {
        ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        }
    }

    #[tokio::test]
    async fn test_database_creation() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let db = RedbDatabase::new(&db_path).unwrap();
        db.init().await.unwrap();
        assert!(db_path.exists());
    }

    #[tokio::test]
    async fn test_database_stats() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let db = RedbDatabase::new(&db_path).unwrap();
        db.init().await.unwrap();
        let stats = db.stats().await;

        assert_eq!(stats.total_hashes, 0);
        assert_eq!(stats.threat_lists, 0);
        assert!(stats.is_stale);
    }

    #[tokio::test]
    async fn test_metadata_storage() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let db = RedbDatabase::new(&db_path).unwrap();
        db.init().await.unwrap();

        // Test storing and retrieving metadata
        db.store_metadata("test_key", b"test_value").unwrap();
        let value = db.get_metadata("test_key").unwrap();

        assert_eq!(value, Some(b"test_value".to_vec()));
    }

    #[tokio::test]
    async fn test_default_path() {
        let path = RedbDatabase::default_path().unwrap();
        assert!(path.to_string_lossy().contains("safebrowsing"));
        assert!(path.extension().map(|s| s == "redb").unwrap_or(false));
    }

    #[tokio::test]
    async fn test_hash_processing() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let db = RedbDatabase::new(&db_path).unwrap();
        db.init().await.unwrap();

        // Test raw hash processing
        let mut hash_set = HashPrefixSet::new();

        // Create mock raw hashes (4-byte prefixes)
        let raw_hashes = safebrowsing_proto::RawHashes {
            prefix_size: 4,
            raw_hashes: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].into(),
        };

        db.process_raw_hashes(&mut hash_set, &raw_hashes).unwrap();

        // Should have 2 hash prefixes (8 bytes / 4 bytes per prefix)
        assert_eq!(hash_set.len(), 2);

        // Test that we can find the hashes
        let prefix1 = HashPrefix::new(vec![0x01, 0x02, 0x03, 0x04]).unwrap();
        let prefix2 = HashPrefix::new(vec![0x05, 0x06, 0x07, 0x08]).unwrap();

        assert!(hash_set.contains(&prefix1));
        assert!(hash_set.contains(&prefix2));
    }

    #[tokio::test]
    async fn test_threat_entry_processing() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let db = RedbDatabase::new(&db_path).unwrap();
        db.init().await.unwrap();

        // Test processing a threat entry set with raw compression
        let mut hash_set = HashPrefixSet::new();

        let threat_entry_set = safebrowsing_proto::ThreatEntrySet {
            compression_type: safebrowsing_proto::CompressionType::Raw as i32,
            raw_hashes: Some(safebrowsing_proto::RawHashes {
                prefix_size: 4,
                raw_hashes: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11].into(),
            }),
            rice_hashes: None,
            raw_indices: None,
            rice_indices: None,
        };

        db.process_raw_hashes_addition(&mut hash_set, &threat_entry_set)
            .unwrap();

        // Should have processed 2 hash prefixes
        assert_eq!(hash_set.len(), 2);

        // Verify the specific hashes are present
        let prefix1 = HashPrefix::new(vec![0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let prefix2 = HashPrefix::new(vec![0xEE, 0xFF, 0x00, 0x11]).unwrap();

        assert!(hash_set.contains(&prefix1));
        assert!(hash_set.contains(&prefix2));
    }

    #[tokio::test]
    async fn test_full_update_and_lookup() {
        use safebrowsing_api::{PlatformType, ThreatEntryType, ThreatType};

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let db = RedbDatabase::new(&db_path).unwrap();
        db.init().await.unwrap();

        // Create a threat descriptor
        let threat_descriptor = ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        };

        // Create a mock list update response
        let list_update =
            safebrowsing_proto::fetch_threat_list_updates_response::ListUpdateResponse {
                threat_type: ThreatType::Malware as i32,
                threat_entry_type: ThreatEntryType::Url as i32,
                platform_type: PlatformType::AnyPlatform as i32,
                response_type: 2, // Full update
                additions: vec![safebrowsing_proto::ThreatEntrySet {
                    compression_type: safebrowsing_proto::CompressionType::Raw as i32,
                    raw_hashes: Some(safebrowsing_proto::RawHashes {
                        prefix_size: 4,
                        raw_hashes: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0].into(),
                    }),
                    rice_hashes: None,
                    raw_indices: None,
                    rice_indices: None,
                }],
                removals: vec![],
                new_client_state: vec![0x01, 0x02, 0x03].into(),
                checksum: Some(safebrowsing_proto::Checksum {
                    sha256: vec![0xAA, 0xBB, 0xCC, 0xDD].into(),
                }),
            };

        // Process the update
        db.process_full_update(&threat_descriptor, &list_update)
            .await
            .unwrap();

        // Verify the database now has hashes
        let stats = db.stats().await;
        assert_eq!(stats.threat_lists, 1);
        assert_eq!(stats.total_hashes, 2); // 8 bytes / 4 bytes per hash = 2 hashes

        // Test lookup - should find matching hash
        let test_hash = HashPrefix::new(vec![0x12, 0x34, 0x56, 0x78]).unwrap();
        let result = db.lookup(&test_hash).await.unwrap();
        assert!(result.is_some());
        let (found_hash, threats) = result.unwrap();
        assert_eq!(found_hash, test_hash);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0], threat_descriptor);

        // Test lookup - should not find non-matching hash
        let non_matching_hash = HashPrefix::new(vec![0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        let result = db.lookup(&non_matching_hash).await.unwrap();
        assert!(result.is_none());

        // Verify persistence - create new instance and check data survives
        drop(db);
        let db2 = RedbDatabase::new(&db_path).unwrap();
        db2.init().await.unwrap();

        let stats2 = db2.stats().await;
        assert_eq!(stats2.threat_lists, 1);
        assert_eq!(stats2.total_hashes, 2);

        // Verify lookups still work after reload
        let result2 = db2.lookup(&test_hash).await.unwrap();
        assert!(result2.is_some());
    }
}
