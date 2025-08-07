//! Hash generation and prefix matching for Google Safe Browsing API
//!
//! This crate provides the hash generation and prefix matching functionality
//! used in the Safe Browsing API. The API works with SHA256 hashes of canonicalized
//! URLs, typically using the first 4 bytes (32 bits) of the hash as a prefix
//! for efficient lookups.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashSet as StdHashSet;
use std::fmt;
use std::hash::Hash;
use std::ops::Deref;
use thiserror::Error;

pub mod rice;

/// Error type for hash operations
#[derive(Debug, Error)]
pub enum HashError {
    /// Invalid hash prefix length
    #[error("Invalid hash prefix length: {0}, must be between 4 and 32")]
    InvalidLength(usize),

    /// Invalid hash format
    #[error("Invalid hash format: {0}")]
    InvalidFormat(String),

    /// Input/Output error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for hash operations
pub type Result<T> = std::result::Result<T, HashError>;

/// A hash prefix used in the Safe Browsing API
///
/// Hash prefixes are the first N bytes of a SHA256 hash of a canonicalized URL.
/// The Safe Browsing API typically uses 4-byte prefixes for efficient lookups.
use std::collections::HashMap;

/// The minimum allowed hash prefix length (4 bytes)
pub const MIN_HASH_PREFIX_LENGTH: usize = 4;
/// The maximum allowed hash prefix length (32 bytes)
pub const MAX_HASH_PREFIX_LENGTH: usize = 32;

/// A collection of hash prefixes
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HashPrefixes(Vec<HashPrefix>);

impl HashPrefixes {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn from_vec(vec: Vec<HashPrefix>) -> Self {
        Self(vec)
    }

    pub fn push(&mut self, prefix: HashPrefix) {
        self.0.push(prefix)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if there are no hash prefixes in the collection.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl IntoIterator for HashPrefixes {
    type Item = HashPrefix;
    type IntoIter = std::vec::IntoIter<HashPrefix>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a HashPrefixes {
    type Item = &'a HashPrefix;
    type IntoIter = std::slice::Iter<'a, HashPrefix>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// HashSet for fast hash prefix lookups
pub struct HashSet {
    // Map from 4-byte prefix to maximum length available
    h4: HashMap<[u8; 4], u8>,
    // Map for longer prefixes
    hx: HashMap<HashPrefix, ()>,
    count: usize,
}

impl Default for HashSet {
    fn default() -> Self {
        Self::new()
    }
}

impl HashSet {
    /// Create a new empty hash set
    pub fn new() -> Self {
        Self {
            h4: HashMap::new(),
            hx: HashMap::new(),
            count: 0,
        }
    }

    /// Get the number of hash prefixes in the set
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Import hash prefixes from a collection
    pub fn import(&mut self, hashes: HashPrefixes) {
        self.h4.clear();
        self.hx.clear();
        self.count = hashes.len();

        for hash in hashes {
            if hash.len() == MIN_HASH_PREFIX_LENGTH {
                let mut key = [0u8; 4];
                key.copy_from_slice(hash.as_bytes());
                self.h4.insert(key, MIN_HASH_PREFIX_LENGTH as u8);
            } else {
                // Update the 4-byte prefix map with the maximum length
                let mut key = [0u8; 4];
                key.copy_from_slice(&hash.as_bytes()[..4]);
                let current_max = self.h4.get(&key).copied().unwrap_or(0);
                if hash.len() as u8 > current_max {
                    self.h4.insert(key, hash.len() as u8);
                }

                // Store longer prefixes separately
                if hash.len() > MIN_HASH_PREFIX_LENGTH {
                    self.hx.insert(hash, ());
                }
            }
        }
    }

    /// Export hash prefixes to a collection
    pub fn export(&self) -> HashPrefixes {
        let mut hashes = Vec::new();

        // Add 4-byte prefixes
        for (key, len) in &self.h4 {
            if *len == MIN_HASH_PREFIX_LENGTH as u8 {
                hashes.push(HashPrefix::from_bytes_unchecked(key.to_vec()));
            }
        }

        // Add longer prefixes
        for hash in self.hx.keys() {
            hashes.push(hash.clone());
        }

        HashPrefixes::from_vec(hashes)
    }

    /// Look up a hash prefix and return the length of the match (0 if no match)
    pub fn lookup(&self, hash: &HashPrefix) -> usize {
        if hash.len() < MIN_HASH_PREFIX_LENGTH {
            return 0;
        }

        let mut key = [0u8; 4];
        key.copy_from_slice(&hash.as_bytes()[..4]);

        let max_len = match self.h4.get(&key) {
            Some(len) => *len as usize,
            None => return 0,
        };

        if max_len <= MIN_HASH_PREFIX_LENGTH {
            return max_len;
        }

        // Check longer prefixes
        let check_len = std::cmp::min(max_len, hash.len());
        for i in MIN_HASH_PREFIX_LENGTH..=check_len {
            if let Ok(prefix) = hash.truncate(i) {
                if self.hx.contains_key(&prefix) {
                    return i;
                }
            }
        }

        0
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct HashPrefix {
    bytes: Bytes,
}

impl HashPrefix {
    /// Create a HashPrefix from bytes without checking length (internal use)
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::from(bytes),
        }
    }
}

impl Serialize for HashPrefix {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for HashPrefix {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Ok(Self {
            bytes: Bytes::from(bytes),
        })
    }
}

impl HashPrefix {
    /// Create a new HashPrefix from bytes
    ///
    /// Hash prefixes should be between 4 and 32 bytes in length.
    pub fn new(bytes: impl Into<Bytes>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() < 4 || bytes.len() > 32 {
            return Err(HashError::InvalidLength(bytes.len()));
        }
        Ok(Self { bytes })
    }

    /// Create a HashPrefix from a pattern string
    ///
    /// This computes the SHA256 hash of the input pattern and takes
    /// the first 4 bytes as the hash prefix.
    pub fn from_pattern(pattern: &str) -> Self {
        let hash = Sha256::digest(pattern.as_bytes());
        let bytes = Bytes::copy_from_slice(&hash[0..4]);
        Self { bytes }
    }

    /// Create a full HashPrefix from a pattern string
    ///
    /// This computes the complete SHA256 hash of the input pattern.
    pub fn full_hash(pattern: &str) -> Self {
        let hash = Sha256::digest(pattern.as_bytes());
        let bytes = Bytes::copy_from_slice(&hash);
        Self { bytes }
    }

    /// Get the raw hash bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the hash prefix in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the hash prefix contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check if this is a full hash (32 bytes)
    pub fn is_full_hash(&self) -> bool {
        self.bytes.len() == 32
    }

    /// Check if this hash is a prefix of another hash
    pub fn is_prefix_of(&self, other: &HashPrefix) -> bool {
        if self.bytes.len() > other.bytes.len() {
            return false;
        }
        other.bytes[..self.bytes.len()] == self.bytes[..]
    }

    /// Truncate this hash to a given length
    pub fn truncate(&self, len: usize) -> Result<Self> {
        if len < 4 || len > self.bytes.len() {
            return Err(HashError::InvalidLength(len));
        }
        Ok(Self {
            bytes: self.bytes.slice(0..len),
        })
    }

    /// Convert the hash to a hexadecimal string
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Create a HashPrefix from a hexadecimal string
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() % 2 != 0 {
            return Err(HashError::InvalidFormat(
                "Hex string must have even length".to_string(),
            ));
        }

        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte_str = &hex[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16)
                .map_err(|_| HashError::InvalidFormat(format!("Invalid hex: {byte_str}")))?;
            bytes.push(byte);
        }

        Self::new(bytes)
    }
}

impl Deref for HashPrefix {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for HashPrefix {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for HashPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashPrefix({})", self.to_hex())
    }
}

impl fmt::Display for HashPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Ord for HashPrefix {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl PartialOrd for HashPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A set of hash prefixes for efficient lookups
///
/// This is an optimized data structure for storing and querying
/// hash prefixes, which is a core operation in the Safe Browsing API.
#[derive(Clone, Default, Debug)]
pub struct HashPrefixSet {
    // We use a standard library HashSet for fast lookups
    // In the future, this could be optimized with a more specialized
    // data structure like a prefix tree
    hashes: StdHashSet<HashPrefix>,
}

impl HashPrefixSet {
    /// Create a new empty HashSet
    pub fn new() -> Self {
        Self {
            hashes: StdHashSet::new(),
        }
    }

    /// Create a HashSet with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            hashes: StdHashSet::with_capacity(capacity),
        }
    }

    /// Add a hash prefix to the set
    pub fn insert(&mut self, hash: HashPrefix) -> bool {
        self.hashes.insert(hash)
    }

    /// Remove a hash prefix from the set
    pub fn remove(&mut self, hash: &HashPrefix) -> bool {
        self.hashes.remove(hash)
    }

    /// Check if the set contains a hash prefix
    pub fn contains(&self, hash: &HashPrefix) -> bool {
        self.hashes.contains(hash)
    }
    /// Add a hash prefix to the set
    pub fn get(&mut self, hash: &HashPrefix) -> Option<&HashPrefix> {
        self.hashes.get(hash)
    }

    /// Find a prefix of the given hash
    ///
    /// This is a core operation in Safe Browsing. If the set contains
    /// a hash that is a prefix of the given hash, it returns that prefix.
    pub fn find_prefix(&self, hash: &HashPrefix) -> Option<&HashPrefix> {
        // This is a naive implementation that could be optimized
        // In the real implementation, we'd use a prefix tree or
        // group hashes by length for more efficient lookups
        self.hashes.iter().find(|h| h.is_prefix_of(hash))
    }

    /// Get the number of hash prefixes in the set
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Clear all hash prefixes from the set
    pub fn clear(&mut self) {
        self.hashes.clear();
    }

    /// Get an iterator over the hash prefixes
    pub fn iter(&self) -> impl Iterator<Item = &HashPrefix> {
        self.hashes.iter()
    }

    /// Convert the set to a sorted vector
    pub fn to_sorted_vec(&self) -> Vec<HashPrefix> {
        let mut vec: Vec<_> = self.hashes.iter().cloned().collect();
        vec.sort();
        vec
    }

    /// Compute the SHA256 checksum of all hash prefixes
    ///
    /// This is used to verify database integrity in the Safe Browsing API.
    pub fn compute_checksum(&self) -> HashPrefix {
        let mut hasher = Sha256::new();

        // Add hashes in sorted order to ensure consistent checksums
        let sorted_hashes = self.to_sorted_vec();
        for hash in sorted_hashes {
            hasher.update(hash.as_bytes());
        }

        let result = hasher.finalize();
        HashPrefix {
            bytes: Bytes::copy_from_slice(&result),
        }
    }
}

impl Extend<HashPrefix> for HashPrefixSet {
    fn extend<T: IntoIterator<Item = HashPrefix>>(&mut self, iter: T) {
        self.hashes.extend(iter);
    }
}

impl FromIterator<HashPrefix> for HashPrefixSet {
    fn from_iter<T: IntoIterator<Item = HashPrefix>>(iter: T) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_prefix_creation() {
        let hash = HashPrefix::new(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(hash.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(hash.len(), 4);
    }

    #[test]
    fn test_hash_prefix_from_pattern() {
        let hash = HashPrefix::from_pattern("test");
        assert_eq!(hash.len(), 4);
    }

    #[test]
    fn test_hash_prefix_full_hash() {
        let hash = HashPrefix::full_hash("test");
        assert_eq!(hash.len(), 32);
        assert!(hash.is_full_hash());
    }

    #[test]
    fn test_hash_prefix_is_prefix_of() {
        let prefix = HashPrefix::new(vec![1, 2, 3, 4]).unwrap();
        let full = HashPrefix::new(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        assert!(prefix.is_prefix_of(&full));
        assert!(!full.is_prefix_of(&prefix));

        let different = HashPrefix::new(vec![2, 2, 3, 4]).unwrap();
        assert!(!different.is_prefix_of(&full));
    }

    #[test]
    fn test_hash_prefix_truncate() {
        let hash = HashPrefix::new(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let truncated = hash.truncate(4).unwrap();
        assert_eq!(truncated.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_hash_prefix_hex() {
        let hash = HashPrefix::new(vec![0x12, 0x34, 0xab, 0xcd]).unwrap();
        assert_eq!(hash.to_hex(), "1234abcd");

        let from_hex = HashPrefix::from_hex("1234abcd").unwrap();
        assert_eq!(from_hex.as_bytes(), &[0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_hash_set_basic_operations() {
        let mut set = HashPrefixSet::new();
        let hash1 = HashPrefix::new(vec![1, 2, 3, 4]).unwrap();
        let hash2 = HashPrefix::new(vec![2, 3, 4, 5]).unwrap();

        assert!(set.is_empty());

        set.insert(hash1.clone());
        assert_eq!(set.len(), 1);
        assert!(set.contains(&hash1));
        assert!(!set.contains(&hash2));

        set.insert(hash2.clone());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&hash2));

        set.remove(&hash1);
        assert_eq!(set.len(), 1);
        assert!(!set.contains(&hash1));
        assert!(set.contains(&hash2));

        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn test_hash_set_find_prefix() {
        let mut set = HashPrefixSet::new();
        let prefix1 = HashPrefix::new(vec![1, 2, 3, 4]).unwrap();
        let prefix2 = HashPrefix::new(vec![5, 6, 7, 8]).unwrap();

        set.insert(prefix1.clone());
        set.insert(prefix2.clone());

        let full = HashPrefix::new(vec![1, 2, 3, 4, 5, 6]).unwrap();
        let found = set.find_prefix(&full);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &prefix1);

        let not_matching = HashPrefix::new(vec![9, 9, 9, 9]).unwrap();
        let not_found = set.find_prefix(&not_matching);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_hash_set_checksum() {
        let mut set1 = HashPrefixSet::new();
        let mut set2 = HashPrefixSet::new();

        // Add hashes in different order, checksum should be the same
        set1.insert(HashPrefix::new(vec![1, 2, 3, 4]).unwrap());
        set1.insert(HashPrefix::new(vec![5, 6, 7, 8]).unwrap());

        set2.insert(HashPrefix::new(vec![5, 6, 7, 8]).unwrap());
        set2.insert(HashPrefix::new(vec![1, 2, 3, 4]).unwrap());

        let checksum1 = set1.compute_checksum();
        let checksum2 = set2.compute_checksum();

        assert_eq!(checksum1, checksum2);
    }
}
