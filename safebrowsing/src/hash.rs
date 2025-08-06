//! Hash operations for Safe Browsing
//!
//! This module handles hash prefixes, hash sets, and various encoding/decoding operations
//! for Safe Browsing threat lists.

use crate::error::{Error, Result};
use crate::proto::safebrowsing_proto;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

/// Minimum hash prefix length (4 bytes)
pub const MIN_HASH_PREFIX_LENGTH: usize = 4;

/// Maximum hash prefix length (32 bytes - full SHA256)
pub const MAX_HASH_PREFIX_LENGTH: usize = 32;

/// Represents a SHA256 hash prefix
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HashPrefix {
    bytes: Vec<u8>,
}

impl HashPrefix {
    /// Create a new hash prefix from bytes
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < MIN_HASH_PREFIX_LENGTH || bytes.len() > MAX_HASH_PREFIX_LENGTH {
            return Err(Error::Hash(format!(
                "Invalid hash prefix length: {}, must be between {} and {}",
                bytes.len(),
                MIN_HASH_PREFIX_LENGTH,
                MAX_HASH_PREFIX_LENGTH
            )));
        }
        Ok(Self { bytes })
    }

    /// Create a hash prefix from a URL pattern
    pub fn from_pattern(pattern: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pattern.as_bytes());
        let hash = hasher.finalize();
        Self {
            bytes: hash.to_vec(),
        }
    }

    /// Create a hash prefix from raw bytes without validation (for internal use)
    pub(crate) fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the raw bytes of the hash prefix
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the hash prefix
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if this is a full SHA256 hash (32 bytes)
    pub fn is_full(&self) -> bool {
        self.bytes.len() == MAX_HASH_PREFIX_LENGTH
    }

    /// Check if this hash prefix is valid
    pub fn is_valid(&self) -> bool {
        self.len() >= MIN_HASH_PREFIX_LENGTH && self.len() <= MAX_HASH_PREFIX_LENGTH
    }

    /// Check if this hash has the given prefix
    pub fn has_prefix(&self, prefix: &HashPrefix) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        self.bytes.starts_with(&prefix.bytes)
    }

    /// Get a truncated version of this hash prefix
    pub fn truncate(&self, len: usize) -> Result<Self> {
        if len > self.len() {
            return Err(Error::Hash(
                "Cannot truncate to length greater than current length".to_string(),
            ));
        }
        if len < MIN_HASH_PREFIX_LENGTH {
            return Err(Error::Hash(format!(
                "Cannot truncate to length less than {}",
                MIN_HASH_PREFIX_LENGTH
            )));
        }
        Ok(Self {
            bytes: self.bytes[..len].to_vec(),
        })
    }

    /// Convert to hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Create from hexadecimal string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| Error::Hash(format!("Invalid hex: {}", e)))?;
        Self::new(bytes)
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

impl From<Vec<u8>> for HashPrefix {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes_unchecked(bytes)
    }
}

impl From<&[u8]> for HashPrefix {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes_unchecked(bytes.to_vec())
    }
}

/// A collection of hash prefixes
#[derive(Debug, Clone)]
pub struct HashPrefixes(Vec<HashPrefix>);

impl HashPrefixes {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Create from a vector of hash prefixes
    pub fn from_vec(hashes: Vec<HashPrefix>) -> Self {
        Self(hashes)
    }

    /// Add a hash prefix to the collection
    pub fn push(&mut self, hash: HashPrefix) {
        self.0.push(hash);
    }

    /// Get the number of hash prefixes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get an iterator over the hash prefixes
    pub fn iter(&self) -> std::slice::Iter<HashPrefix> {
        self.0.iter()
    }

    /// Sort the hash prefixes
    pub fn sort(&mut self) {
        self.0.sort();
    }

    /// Validate that all hash prefixes are valid and sorted
    pub fn validate(&self) -> Result<()> {
        let mut prev: Option<&HashPrefix> = None;

        for hash in &self.0 {
            if !hash.is_valid() {
                return Err(Error::Hash("Invalid hash prefix in collection".to_string()));
            }

            if let Some(p) = prev {
                if p >= hash {
                    return Err(Error::Hash("Hash prefixes are not sorted".to_string()));
                }
                if hash.has_prefix(p) {
                    return Err(Error::Hash("Duplicate hash prefix detected".to_string()));
                }
            }
            prev = Some(hash);
        }

        Ok(())
    }

    /// Compute SHA256 of all hash prefixes concatenated
    pub fn sha256(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for hash in &self.0 {
            hasher.update(hash.as_bytes());
        }
        hasher.finalize().to_vec()
    }
}

impl IntoIterator for HashPrefixes {
    type Item = HashPrefix;
    type IntoIter = std::vec::IntoIter<HashPrefix>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Optimized hash set for fast lookups
#[derive(Debug, Clone)]
pub struct HashSet {
    // Map from 4-byte prefix to maximum length available
    h4: HashMap<[u8; 4], u8>,
    // Map for longer prefixes
    hx: HashMap<HashPrefix, ()>,
    count: usize,
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

/// Decode hash prefixes from Safe Browsing API format
pub fn decode_hashes(
    threat_entry_set: &safebrowsing_proto::ThreatEntrySet,
) -> Result<Vec<HashPrefix>> {
    use safebrowsing_proto::CompressionType;

    match threat_entry_set.compression_type() {
        CompressionType::Raw => {
            let raw_hashes = threat_entry_set
                .raw_hashes
                .as_ref()
                .ok_or_else(|| Error::Encoding("Missing raw hashes".to_string()))?;

            decode_raw_hashes(raw_hashes)
        }
        CompressionType::Rice => {
            let rice_hashes = threat_entry_set
                .rice_hashes
                .as_ref()
                .ok_or_else(|| Error::Encoding("Missing rice hashes".to_string()))?;

            decode_rice_hashes(rice_hashes)
        }
        _ => Err(Error::Encoding("Unknown compression type".to_string())),
    }
}

/// Decode raw hash format
fn decode_raw_hashes(raw_hashes: &safebrowsing_proto::RawHashes) -> Result<Vec<HashPrefix>> {
    let prefix_size = raw_hashes.prefix_size as usize;

    if prefix_size < MIN_HASH_PREFIX_LENGTH || prefix_size > MAX_HASH_PREFIX_LENGTH {
        return Err(Error::Encoding(format!(
            "Invalid prefix size: {}",
            prefix_size
        )));
    }

    if raw_hashes.raw_hashes.len() % prefix_size != 0 {
        return Err(Error::Encoding("Invalid raw hashes length".to_string()));
    }

    let mut hashes = Vec::new();
    let chunks = raw_hashes.raw_hashes.chunks(prefix_size);

    for chunk in chunks {
        hashes.push(HashPrefix::from_bytes_unchecked(chunk.to_vec()));
    }

    Ok(hashes)
}

/// Decode Rice-Golomb encoded hashes
fn decode_rice_hashes(
    rice_encoding: &safebrowsing_proto::RiceDeltaEncoding,
) -> Result<Vec<HashPrefix>> {
    let values = decode_rice_integers(rice_encoding)?;

    let mut hashes = Vec::new();
    for value in values {
        let bytes = value.to_le_bytes().to_vec();
        hashes.push(HashPrefix::from_bytes_unchecked(bytes));
    }

    Ok(hashes)
}

/// Decode Rice-Golomb encoded integers
pub fn decode_rice_integers(rice: &safebrowsing_proto::RiceDeltaEncoding) -> Result<Vec<u32>> {
    if rice.rice_parameter < 0 || rice.rice_parameter > 32 {
        return Err(Error::Encoding(format!(
            "Invalid rice parameter: {}",
            rice.rice_parameter
        )));
    }

    if rice.num_entries == 0 {
        return Ok(vec![rice.first_value as u32]);
    }

    let mut values = vec![rice.first_value as u32];
    let mut bit_reader = BitReader::new(&rice.encoded_data);

    let rice_decoder = RiceDecoder::new(rice.rice_parameter as u32);

    for i in 0..rice.num_entries {
        let delta = rice_decoder.read_value(&mut bit_reader)?;
        values.push(values[i as usize] + delta);
    }

    if bit_reader.bits_remaining() >= 8 {
        return Err(Error::Encoding("Unconsumed rice encoded data".to_string()));
    }

    Ok(values)
}

/// Bit reader for Rice-Golomb decoding
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bits(&mut self, num_bits: u32) -> Result<u32> {
        if num_bits > 32 {
            return Err(Error::Encoding("Cannot read more than 32 bits".to_string()));
        }

        let mut result = 0u32;
        let mut bits_read = 0u32;

        while bits_read < num_bits {
            if self.byte_pos >= self.data.len() {
                return Err(Error::Encoding("Unexpected end of data".to_string()));
            }

            let current_byte = self.data[self.byte_pos];
            let bit_mask = 1u8 << self.bit_pos;

            if (current_byte & bit_mask) != 0 {
                result |= 1u32 << bits_read;
            }

            bits_read += 1;
            self.bit_pos += 1;

            if self.bit_pos >= 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }

        Ok(result)
    }

    fn bits_remaining(&self) -> usize {
        if self.byte_pos >= self.data.len() {
            0
        } else {
            (self.data.len() - self.byte_pos) * 8 - self.bit_pos as usize
        }
    }
}

/// Rice-Golomb decoder
struct RiceDecoder {
    k: u32,
}

impl RiceDecoder {
    fn new(k: u32) -> Self {
        Self { k }
    }

    fn read_value(&self, bit_reader: &mut BitReader) -> Result<u32> {
        // Read quotient (unary encoding)
        let mut quotient = 0u32;
        loop {
            let bit = bit_reader.read_bits(1)?;
            if bit == 0 {
                break;
            }
            quotient += 1;
        }

        // Read remainder (k bits)
        let remainder = if self.k > 0 {
            bit_reader.read_bits(self.k)?
        } else {
            0
        };

        Ok((quotient << self.k) + remainder)
    }
}

// Add hex module for encoding/decoding
mod hex {
    use super::*;

    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    pub fn decode(hex_str: &str) -> std::result::Result<Vec<u8>, String> {
        if hex_str.len() % 2 != 0 {
            return Err("Hex string length must be even".to_string());
        }

        let mut result = Vec::with_capacity(hex_str.len() / 2);
        for chunk in hex_str.as_bytes().chunks(2) {
            let hex_byte = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8 in hex string")?;
            let byte = u8::from_str_radix(hex_byte, 16).map_err(|_| "Invalid hex character")?;
            result.push(byte);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_prefix_creation() {
        let bytes = vec![1, 2, 3, 4];
        let hash = HashPrefix::new(bytes.clone()).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
        assert_eq!(hash.len(), 4);
        assert!(!hash.is_full());
        assert!(hash.is_valid());
    }

    #[test]
    fn test_hash_prefix_from_pattern() {
        let pattern = "example.com/path";
        let hash = HashPrefix::from_pattern(pattern);
        assert_eq!(hash.len(), 32);
        assert!(hash.is_full());
        assert!(hash.is_valid());
    }

    #[test]
    fn test_hash_prefix_validation() {
        // Too short
        let result = HashPrefix::new(vec![1, 2, 3]);
        assert!(result.is_err());

        // Too long
        let result = HashPrefix::new(vec![0; 33]);
        assert!(result.is_err());

        // Just right
        let result = HashPrefix::new(vec![0; 4]);
        assert!(result.is_ok());

        let result = HashPrefix::new(vec![0; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_prefix_operations() {
        let hash1 = HashPrefix::new(vec![1, 2, 3, 4, 5, 6]).unwrap();
        let hash2 = HashPrefix::new(vec![1, 2, 3, 4]).unwrap();

        assert!(hash1.has_prefix(&hash2));
        assert!(!hash2.has_prefix(&hash1));

        let truncated = hash1.truncate(4).unwrap();
        assert_eq!(truncated.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_hash_set_operations() {
        let mut hash_set = HashSet::new();
        assert_eq!(hash_set.len(), 0);
        assert!(hash_set.is_empty());

        let mut hashes = HashPrefixes::new();
        hashes.push(HashPrefix::new(vec![1, 2, 3, 4]).unwrap());
        hashes.push(HashPrefix::new(vec![5, 6, 7, 8]).unwrap());

        hash_set.import(hashes);
        assert_eq!(hash_set.len(), 2);
        assert!(!hash_set.is_empty());

        let lookup_hash = HashPrefix::new(vec![1, 2, 3, 4, 9, 10]).unwrap();
        let match_len = hash_set.lookup(&lookup_hash);
        assert_eq!(match_len, 4);

        let no_match = HashPrefix::new(vec![9, 8, 7, 6]).unwrap();
        let match_len = hash_set.lookup(&no_match);
        assert_eq!(match_len, 0);
    }

    #[test]
    fn test_hex_encoding() {
        let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex_str = hex::encode(&data);
        assert_eq!(hex_str, "0123456789abcdef");

        let decoded = hex::decode(&hex_str).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hash_prefixes_validation() {
        let mut hashes = HashPrefixes::new();
        hashes.push(HashPrefix::new(vec![1, 2, 3, 4]).unwrap());
        hashes.push(HashPrefix::new(vec![5, 6, 7, 8]).unwrap());

        // Should be valid when sorted
        assert!(hashes.validate().is_ok());

        // Test with unsorted hashes
        let mut unsorted = HashPrefixes::new();
        unsorted.push(HashPrefix::new(vec![5, 6, 7, 8]).unwrap());
        unsorted.push(HashPrefix::new(vec![1, 2, 3, 4]).unwrap());

        assert!(unsorted.validate().is_err());
    }

    #[test]
    fn test_bit_reader() {
        let data = vec![0b10110100, 0b11010011];
        let mut reader = BitReader::new(&data);

        assert_eq!(reader.read_bits(1).unwrap(), 0);
        assert_eq!(reader.read_bits(2).unwrap(), 2); // 10
        assert_eq!(reader.read_bits(3).unwrap(), 5); // 101
        assert_eq!(reader.read_bits(8).unwrap(), 0b11001011); // Crosses byte boundary
    }
}
