//! Caching for Safe Browsing API responses
//!
//! This module provides TTL-based caching for API responses to reduce network calls
//! and improve performance.

use safebrowsing_api::{ThreatDescriptor, URLThreat};
use safebrowsing_hash::HashPrefix;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cache result types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CacheResult {
    /// Found a positive match in cache
    PositiveHit,
    /// Found a negative cache entry (known safe)
    NegativeHit,
    /// No cache entry found
    Miss,
}

/// Cache entry for threat matches
#[derive(Debug, Clone)]
struct ThreatCacheEntry {
    threats: HashMap<ThreatDescriptor, Instant>,
}

impl ThreatCacheEntry {
    fn new() -> Self {
        Self {
            threats: HashMap::new(),
        }
    }

    fn insert(&mut self, threat: ThreatDescriptor, expiry: Instant) {
        self.threats.insert(threat, expiry);
    }

    fn get_valid_threats(&self, now: Instant) -> Vec<ThreatDescriptor> {
        self.threats
            .iter()
            .filter(|(_, &expiry)| expiry > now)
            .map(|(threat, _)| threat.clone())
            .collect()
    }

    fn cleanup_expired(&mut self, now: Instant) {
        self.threats.retain(|_, &mut expiry| expiry > now);
    }

    fn is_empty(&self) -> bool {
        self.threats.is_empty()
    }
}

/// TTL-based cache for Safe Browsing responses
pub struct Cache {
    // Positive cache: full hash -> threat descriptors with TTL
    positive_cache: HashMap<HashPrefix, ThreatCacheEntry>,

    // Negative cache: hash prefix -> expiry time
    negative_cache: HashMap<HashPrefix, Instant>,

    // Statistics
    hits: u64,
    misses: u64,

    // Last cleanup time
    last_cleanup: Instant,

    // Cleanup interval
    cleanup_interval: Duration,
}

impl Cache {
    /// Create a new cache
    pub fn new() -> Self {
        Self {
            positive_cache: HashMap::new(),
            negative_cache: HashMap::new(),
            hits: 0,
            misses: 0,
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a cache with custom cleanup interval
    pub fn with_cleanup_interval(cleanup_interval: Duration) -> Self {
        Self {
            positive_cache: HashMap::new(),
            negative_cache: HashMap::new(),
            hits: 0,
            misses: 0,
            last_cleanup: Instant::now(),
            cleanup_interval,
        }
    }

    /// Look up a hash in the cache
    pub fn lookup(&mut self, hash: &HashPrefix) -> Option<Vec<URLThreat>> {
        if !hash.is_full_hash() {
            return None;
        }

        let now = Instant::now();
        self.maybe_cleanup(now);

        // Check positive cache first
        if let Some(entry) = self.positive_cache.get_mut(hash) {
            let valid_threats = entry.get_valid_threats(now);
            if !valid_threats.is_empty() {
                self.hits += 1;
                let url_threats = valid_threats
                    .into_iter()
                    .map(|threat| URLThreat {
                        pattern: String::new(),
                        threat_descriptor: threat,
                    })
                    .collect();
                return Some(url_threats);
            }

            // Clean up expired entries
            entry.cleanup_expired(now);
            if entry.is_empty() {
                self.positive_cache.remove(hash);
            }
        }

        // Check negative cache for all possible prefixes
        for prefix_len in 4..=hash.len() {
            if let Ok(prefix) = hash.truncate(prefix_len) {
                if let Some(&expiry) = self.negative_cache.get(&prefix) {
                    if expiry > now {
                        self.hits += 1;
                        return Some(Vec::new()); // Empty = safe
                    } else {
                        // Remove expired entry
                        self.negative_cache.remove(&prefix);
                    }
                }
            }
        }

        self.misses += 1;
        None
    }

    /// Insert positive cache entries (threats found)
    pub fn insert_positive(
        &mut self,
        hash: HashPrefix,
        threats: Vec<ThreatDescriptor>,
        ttl: Duration,
    ) {
        if !hash.is_full_hash() {
            return;
        }

        let expiry = Instant::now() + ttl;
        let entry = self
            .positive_cache
            .entry(hash)
            .or_insert_with(ThreatCacheEntry::new);

        for threat in threats {
            entry.insert(threat, expiry);
        }
    }

    /// Insert negative cache entry (no threats found)
    pub fn insert_negative(&mut self, hash_prefix: HashPrefix, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.negative_cache.insert(hash_prefix, expiry);
    }

    /// Insert a generic cache entry with threats
    pub fn insert(&mut self, hash: HashPrefix, threats: Vec<URLThreat>) {
        let default_ttl = Duration::from_secs(300); // 5 minutes default

        if threats.is_empty() {
            // Negative cache entry
            self.insert_negative(hash, default_ttl);
        } else {
            // Positive cache entry
            let threat_descriptors: Vec<ThreatDescriptor> =
                threats.into_iter().map(|t| t.threat_descriptor).collect();
            self.insert_positive(hash, threat_descriptors, default_ttl);
        }
    }

    /// Update cache with API response
    pub fn update_with_response(
        &mut self,
        request_hashes: &[HashPrefix],
        response: &safebrowsing_proto::FindFullHashesResponse,
    ) {
        let _now = Instant::now();

        // Insert positive cache entries for matches
        for threat_match in &response.matches {
            if let Some(threat_entry) = &threat_match.threat {
                let full_hash = HashPrefix::new(threat_entry.hash.clone()).unwrap();

                let ttl = if let Some(cache_duration) = &threat_match.cache_duration {
                    Duration::from_secs(cache_duration.seconds as u64)
                        + Duration::from_nanos(cache_duration.nanos as u64)
                } else {
                    Duration::from_secs(300) // Default 5 minutes
                };

                let threat_descriptor = ThreatDescriptor {
                    threat_type: threat_match.threat_type.into(),
                    platform_type: threat_match.platform_type.into(),
                    threat_entry_type: threat_match.threat_entry_type.into(),
                };

                self.insert_positive(full_hash, vec![threat_descriptor], ttl);
            }
        }

        // Insert negative cache entries for prefixes that didn't match
        if let Some(negative_duration) = &response.negative_cache_duration {
            let negative_ttl = Duration::from_secs(negative_duration.seconds as u64)
                + Duration::from_nanos(negative_duration.nanos as u64);

            for hash_prefix in request_hashes {
                // Only add negative entry if no positive match exists
                let has_positive_match = response.matches.iter().any(|m| {
                    if let Some(threat_entry) = &m.threat {
                        let match_hash = HashPrefix::new(threat_entry.hash.clone()).unwrap();
                        hash_prefix.is_prefix_of(&match_hash)
                    } else {
                        false
                    }
                });

                if !has_positive_match {
                    self.insert_negative(hash_prefix.clone(), negative_ttl);
                }
            }
        }
    }

    /// Purge expired entries from the cache
    pub fn purge(&mut self) {
        let now = Instant::now();

        // Clean positive cache
        self.positive_cache.retain(|_, entry| {
            entry.cleanup_expired(now);
            !entry.is_empty()
        });

        // Clean negative cache
        self.negative_cache.retain(|_, &mut expiry| expiry > now);

        self.last_cleanup = now;
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits,
            misses: self.misses,
            positive_entries: self.positive_cache.len(),
            negative_entries: self.negative_cache.len(),
            hit_rate: if self.hits + self.misses > 0 {
                self.hits as f64 / (self.hits + self.misses) as f64
            } else {
                0.0
            },
        }
    }

    /// Clear all cache entries
    pub fn clear(&mut self) {
        self.positive_cache.clear();
        self.negative_cache.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Get the total number of cache entries
    pub fn entry_count(&self) -> usize {
        self.positive_cache.len() + self.negative_cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.positive_cache.is_empty() && self.negative_cache.is_empty()
    }

    /// Maybe perform cleanup if enough time has passed
    fn maybe_cleanup(&mut self, now: Instant) {
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            self.purge();
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Number of positive cache entries
    pub positive_entries: usize,
    /// Number of negative cache entries
    pub negative_entries: usize,
    /// Cache hit rate (0.0 to 1.0)
    pub hit_rate: f64,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache Stats: {} hits, {} misses, {:.1}% hit rate, {} positive, {} negative entries",
            self.hits,
            self.misses,
            self.hit_rate * 100.0,
            self.positive_entries,
            self.negative_entries
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safebrowsing_api::{PlatformType, ThreatEntryType, ThreatType};

    fn create_test_hash() -> HashPrefix {
        HashPrefix::full_hash("test.example.com/path")
    }

    fn create_test_threat_descriptor() -> ThreatDescriptor {
        ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        }
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = Cache::new();
        let hash = create_test_hash();

        assert!(cache.lookup(&hash).is_none());
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);
    }

    #[test]
    fn test_positive_cache() {
        let mut cache = Cache::new();
        let hash = create_test_hash();
        let threat = create_test_threat_descriptor();

        cache.insert_positive(hash.clone(), vec![threat.clone()], Duration::from_secs(60));

        let result = cache.lookup(&hash).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].threat_descriptor, threat);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_negative_cache() {
        let mut cache = Cache::new();
        let hash = create_test_hash();
        let prefix = hash.truncate(4).unwrap();

        cache.insert_negative(prefix, Duration::from_secs(60));

        let result = cache.lookup(&hash).unwrap();
        assert!(result.is_empty());
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = Cache::new();
        let hash = create_test_hash();
        let threat = create_test_threat_descriptor();

        // Insert with very short TTL
        cache.insert_positive(hash.clone(), vec![threat], Duration::from_millis(1));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Should be cache miss now
        assert!(cache.lookup(&hash).is_none());
    }

    #[test]
    fn test_cache_purge() {
        let mut cache = Cache::new();
        let hash = create_test_hash();
        let threat = create_test_threat_descriptor();

        cache.insert_positive(hash.clone(), vec![threat], Duration::from_millis(1));
        cache.insert_negative(hash.truncate(4).unwrap(), Duration::from_millis(1));

        assert!(!cache.is_empty());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        cache.purge();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = Cache::new();
        let hash = create_test_hash();

        // Generate some hits and misses
        cache.lookup(&hash); // miss
        cache.insert_positive(
            hash.clone(),
            vec![create_test_threat_descriptor()],
            Duration::from_secs(60),
        );
        cache.lookup(&hash); // hit
        cache.lookup(&hash); // hit

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 2.0 / 3.0);
    }

    #[test]
    fn test_insert_generic() {
        let mut cache = Cache::new();
        let hash = create_test_hash();

        // Test empty threats (negative cache)
        cache.insert(hash.clone(), Vec::new());
        let result = cache.lookup(&hash).unwrap();
        assert!(result.is_empty());

        // Test with threats (positive cache)
        let threat = URLThreat {
            pattern: "test".to_string(),
            threat_descriptor: create_test_threat_descriptor(),
        };
        cache.insert(hash.clone(), vec![threat.clone()]);
        let result = cache.lookup(&hash).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].threat_descriptor, threat.threat_descriptor);
    }
}
