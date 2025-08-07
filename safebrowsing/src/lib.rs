//! # Safe Browsing API Client for Rust
//!
//! This crate provides a Rust implementation of the Google Safe Browsing Update API (v4).
//! It allows you to check URLs against Google's constantly updated lists of unsafe web resources.
//!
//! ## Features
//!
//! - Asynchronous API using tokio
//! - Pluggable database backends
//! - Built-in caching with TTL support
//! - URL canonicalization and pattern generation
//! - Support for all Safe Browsing threat types
//!
//! ## Example
//!
//! ```rust,no_run
//! use safebrowsing::{SafeBrowser, Config, ThreatDescriptor, ThreatType, PlatformType, ThreatEntryType};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config {
//!         api_key: "your-api-key".to_string(),
//!         client_id: "your-client-id".to_string(),
//!         client_version: "1.0.0".to_string(),
//!         update_period: Duration::from_secs(1800), // 30 minutes
//!         threat_lists: vec![
//!             ThreatDescriptor {
//!                 threat_type: ThreatType::Malware,
//!                 platform_type: PlatformType::AnyPlatform,
//!                 threat_entry_type: ThreatEntryType::Url,
//!             },
//!             ThreatDescriptor {
//!                 threat_type: ThreatType::SocialEngineering,
//!                 platform_type: PlatformType::AnyPlatform,
//!                 threat_entry_type: ThreatEntryType::Url,
//!             },
//!         ],
//!         ..Default::default()
//!     };
//!
//!     let mut sb = SafeBrowser::new(config).await?;
//!     sb.wait_until_ready().await?;
//!
//!     let urls = vec!["http://example.com/suspicious"];
//!     let threats = sb.lookup_urls(&urls).await?;
//!
//!     for (url, threat_matches) in urls.iter().zip(threats.iter()) {
//!         if !threat_matches.is_empty() {
//!             println!("⚠️  {} is unsafe: {:?}", url, threat_matches);
//!         } else {
//!             println!("✅ {} is safe", url);
//!         }
//!     }
//!
//!     sb.close().await?;
//!     Ok(())
//! }
//! ```

// Re-export crates from workspace
pub use safebrowsing_api;
pub use safebrowsing_db;
pub use safebrowsing_hash;
pub use safebrowsing_proto;
pub use safebrowsing_url;

// Internal modules
pub mod cache;
pub mod database;
pub mod error;
pub mod types;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

// Re-export commonly used types
pub use crate::cache::Cache;
pub use crate::error::{Error, Result};
pub use safebrowsing_api::{
    PlatformType, SafeBrowsingApi, ThreatDescriptor, ThreatEntryType, ThreatType, URLThreat,
};
pub use safebrowsing_db::{ConcurrentDatabase, Database, DatabaseStats, InMemoryDatabase};
pub use safebrowsing_hash::{HashPrefix, HashSet};
pub use safebrowsing_url::{canonicalize_url, generate_patterns, validate_url};

/// Default Safe Browsing API server URL
pub const DEFAULT_SERVER_URL: &str = "https://safebrowsing.googleapis.com";

/// Default update period for threat lists (30 minutes)
pub const DEFAULT_UPDATE_PERIOD: Duration = Duration::from_secs(30 * 60);

/// Default client ID
pub const DEFAULT_CLIENT_ID: &str = env!("CARGO_PKG_NAME");

/// Default client version
pub const DEFAULT_CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default request timeout
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for the Safe Browsing client
#[derive(Debug, Clone)]
pub struct Config {
    /// The Google Safe Browsing API key
    pub api_key: String,

    /// Client identifier for API requests
    pub client_id: String,

    /// Client version for API requests
    pub client_version: String,

    /// Safe Browsing API server URL
    pub server_url: String,

    /// HTTP proxy URL (optional)
    pub proxy_url: Option<String>,

    /// How often to update threat lists
    pub update_period: Duration,

    /// Request timeout for API calls
    pub request_timeout: Duration,

    /// List of threat descriptors to track
    pub threat_lists: Vec<ThreatDescriptor>,

    /// Database implementation to use
    /// If None, defaults to InMemoryDatabase
    pub database_type: Option<DatabaseType>,
}

/// Type of database to use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    /// In-memory database (fastest but uses more memory)
    InMemory,

    /// Thread-safe in-memory database
    Concurrent,

    /// Persistent redb-based database (requires "redb" feature)
    #[cfg(feature = "redb")]
    Redb,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_version: DEFAULT_CLIENT_VERSION.to_string(),
            server_url: DEFAULT_SERVER_URL.to_string(),
            proxy_url: None,
            update_period: DEFAULT_UPDATE_PERIOD,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            threat_lists: vec![
                ThreatDescriptor {
                    threat_type: ThreatType::Malware,
                    platform_type: PlatformType::AnyPlatform,
                    threat_entry_type: ThreatEntryType::Url,
                },
                ThreatDescriptor {
                    threat_type: ThreatType::SocialEngineering,
                    platform_type: PlatformType::AnyPlatform,
                    threat_entry_type: ThreatEntryType::Url,
                },
                ThreatDescriptor {
                    threat_type: ThreatType::UnwantedSoftware,
                    platform_type: PlatformType::AnyPlatform,
                    threat_entry_type: ThreatEntryType::Url,
                },
            ],
            database_type: None,
        }
    }
}

/// Statistics about Safe Browsing operations
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Number of queries served from local database
    pub queries_by_database: u64,

    /// Number of queries served from cache
    pub queries_by_cache: u64,

    /// Number of queries served by API
    pub queries_by_api: u64,

    /// Number of failed queries
    pub queries_fail: u64,

    /// Duration since last successful database update
    pub database_update_lag: Duration,
}

/// Main Safe Browsing client
pub struct SafeBrowser {
    config: Config,
    api: SafeBrowsingApi,
    database: Arc<dyn Database + Send + Sync>,
    cache: Arc<Mutex<Cache>>,
    stats: Arc<Mutex<Stats>>,
    last_update: Arc<RwLock<Option<Instant>>>,
    update_task: Option<tokio::task::JoinHandle<()>>,
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl SafeBrowser {
    /// Create a new Safe Browsing client with the given configuration
    pub async fn new(config: Config) -> Result<Self> {
        // Choose database implementation based on config
        let database = match config.database_type.unwrap_or(DatabaseType::InMemory) {
            DatabaseType::InMemory => {
                Arc::new(InMemoryDatabase::new()) as Arc<dyn Database + Send + Sync>
            }
            DatabaseType::Concurrent => {
                Arc::new(ConcurrentDatabase::new()) as Arc<dyn Database + Send + Sync>
            }
            #[cfg(feature = "redb")]
            DatabaseType::Redb => {
                use crate::database::RedbDatabase;
                let db_path = RedbDatabase::default_path().map_err(|e| {
                    Error::Configuration(format!("Failed to get default database path: {}", e))
                })?;
                let db = RedbDatabase::new(db_path).map_err(|e| {
                    Error::Configuration(format!("Failed to create redb database: {}", e))
                })?;
                db.init().await.map_err(|e| {
                    Error::Configuration(format!("Failed to initialize redb database: {}", e))
                })?;
                Arc::new(db) as Arc<dyn Database + Send + Sync>
            }
        };

        Self::with_database(config, database).await
    }

    /// Create a new Safe Browsing client with a custom database backend
    pub async fn with_database(
        config: Config,
        database: Arc<dyn Database + Send + Sync>,
    ) -> Result<Self> {
        if config.api_key.is_empty() {
            return Err(Error::Configuration("API key is required".to_string()));
        }

        // Create API client
        let api_config = safebrowsing_api::ApiConfig {
            api_key: config.api_key.clone(),
            client_id: config.client_id.clone(),
            client_version: config.client_version.clone(),
            base_url: config.server_url.clone(),
            proxy_url: config.proxy_url.clone(),
            request_timeout: config.request_timeout,
        };
        let api = SafeBrowsingApi::new(&api_config)?;

        let cache = Arc::new(Mutex::new(Cache::new()));
        let stats = Arc::new(Mutex::new(Stats::default()));
        let last_update = Arc::new(RwLock::new(None));

        let mut browser = Self {
            config,
            api,
            database,
            cache,
            stats,
            last_update,
            update_task: None,
            shutdown_sender: None,
        };

        // Start the update task
        browser.start_updater().await?;

        Ok(browser)
    }

    /// Wait until the database is ready (has been populated with threat lists)
    pub async fn wait_until_ready(&self) -> Result<()> {
        let timeout = Duration::from_secs(60);
        let start = Instant::now();

        while start.elapsed() < timeout {
            if self.database.is_ready().await? {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(Error::Timeout(
            "Database not ready within timeout".to_string(),
        ))
    }

    /// Check multiple URLs for threats
    pub async fn lookup_urls(&self, urls: &[impl AsRef<str>]) -> Result<Vec<Vec<URLThreat>>> {
        let mut results = Vec::with_capacity(urls.len());

        for url in urls {
            let url_str = url.as_ref();

            // Validate the URL first
            if !validate_url(url_str) {
                return Err(Error::InvalidUrl(url_str.to_string()));
            }

            // Canonicalize and generate patterns
            let canonical = canonicalize_url(url_str)?;
            let patterns = generate_patterns(&canonical)?;

            let mut url_threats = Vec::new();

            // Check each pattern
            for pattern in patterns {
                let threats = self.lookup_pattern(&pattern).await?;
                url_threats.extend(threats);
            }

            results.push(url_threats);
        }

        Ok(results)
    }

    /// Get current statistics
    pub async fn stats(&self) -> Stats {
        self.stats.lock().await.clone()
    }

    /// Check if the database is healthy and up-to-date
    pub async fn status(&self) -> Result<()> {
        match self.database.status().await {
            Ok(()) => Ok(()),
            Err(err) => Err(Error::Database(err)),
        }
    }

    /// Manually trigger a database update
    pub async fn update(&self) -> Result<()> {
        self.database
            .update(&self.api, &self.config.threat_lists)
            .await?;

        let mut last_update = self.last_update.write().await;
        *last_update = Some(Instant::now());

        Ok(())
    }

    /// Get database statistics
    pub async fn database_stats(&self) -> Result<DatabaseStats> {
        Ok(self.database.stats().await)
    }

    /// Shutdown the Safe Browsing client and cleanup resources
    pub async fn close(&mut self) -> Result<()> {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }

        if let Some(task) = self.update_task.take() {
            task.await
                .map_err(|e| Error::Internal(format!("Update task error: {e}")))?;
        }

        Ok(())
    }

    // Private helper methods

    async fn lookup_pattern(&self, pattern: &str) -> Result<Vec<URLThreat>> {
        // Instrumentation: start timing lookup_pattern
        let lookup_pattern_start = Instant::now();
        let hash = HashPrefix::from_pattern(pattern);

        // First check the cache
        {
            let mut cache = self.cache.lock().await;
            if let Some(result) = cache.lookup(&hash) {
                let mut stats = self.stats.lock().await;
                stats.queries_by_cache += 1;
                // Instrumentation: log lookup_pattern duration for cache-hit
                debug!(
                    "lookup_pattern (cache) for '{}' completed in {:?}",
                    pattern,
                    lookup_pattern_start.elapsed()
                );
                return Ok(result);
            }
        }

        // Then check the database
        if let Some((partial_hash, threat_descriptors)) = self.database.lookup(&hash).await? {
            // We have a partial match, need to query the API for full hashes
            let threats = self
                .query_full_hashes(&partial_hash, &threat_descriptors)
                .await?;
            // Instrumentation: log lookup_pattern duration for database-hit
            debug!(
                "lookup_pattern (db) for '{}' completed in {:?}",
                pattern,
                lookup_pattern_start.elapsed()
            );

            // Update cache with results
            {
                let mut cache = self.cache.lock().await;
                cache.insert(hash.clone(), threats.clone());
            }

            let mut stats = self.stats.lock().await;
            stats.queries_by_database += 1;
            return Ok(threats);
        }

        // No match found
        let mut stats = self.stats.lock().await;
        stats.queries_by_database += 1;
        // Instrumentation: log lookup_pattern duration for no-match
        debug!(
            "lookup_pattern for '{}' completed in {:?}",
            pattern,
            lookup_pattern_start.elapsed()
        );
        Ok(Vec::new())
    }

    async fn query_full_hashes(
        &self,
        hash_prefix: &HashPrefix,
        threat_descriptors: &[ThreatDescriptor],
    ) -> Result<Vec<URLThreat>> {
        let response = self
            .api
            .find_full_hashes(hash_prefix, threat_descriptors)
            .await?;

        let mut threats = Vec::new();
        for threat_match in response.matches {
            threats.push(URLThreat {
                pattern: String::new(), // Will be filled in by caller
                threat_descriptor: ThreatDescriptor {
                    threat_type: ThreatType::from(threat_match.threat_type),
                    platform_type: PlatformType::from(threat_match.platform_type),
                    threat_entry_type: ThreatEntryType::from(threat_match.threat_entry_type),
                },
            });
        }

        let mut stats = self.stats.lock().await;
        stats.queries_by_api += 1;

        Ok(threats)
    }

    async fn start_updater(&mut self) -> Result<()> {
        let (shutdown_sender, mut shutdown_receiver) = tokio::sync::oneshot::channel();
        self.shutdown_sender = Some(shutdown_sender);

        let api = self.api.clone();
        let database = Arc::clone(&self.database);
        let last_update = Arc::clone(&self.last_update);
        let stats = Arc::clone(&self.stats);
        let threat_lists = self.config.threat_lists.clone();
        let update_period = self.config.update_period;

        let update_task = tokio::spawn(async move {
            // First interval is immediate, for initial update
            let mut interval = interval(update_period);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::perform_update(&api, &database, &threat_lists, &last_update, &stats).await {
                            error!("Database update failed: {}", e);
                        }
                    }
                    _ = &mut shutdown_receiver => {
                        info!("Update task shutting down");
                        break;
                    }
                }
            }
        });

        self.update_task = Some(update_task);
        Ok(())
    }

    async fn perform_update(
        api: &SafeBrowsingApi,
        database: &Arc<dyn Database + Send + Sync>,
        threat_lists: &[ThreatDescriptor],
        last_update: &Arc<RwLock<Option<Instant>>>,
        stats: &Arc<Mutex<Stats>>,
    ) -> Result<()> {
        debug!("Starting database update");

        match database.update(api, threat_lists).await {
            Ok(()) => {
                let mut last_update_guard = last_update.write().await;
                *last_update_guard = Some(Instant::now());
                info!("Database update completed successfully");
            }
            Err(e) => {
                let mut stats_guard = stats.lock().await;
                stats_guard.queries_fail += 1;
                warn!("Database update failed: {}", e);
                return Err(Error::Database(e));
            }
        }

        Ok(())
    }
}

impl Drop for SafeBrowser {
    fn drop(&mut self) {
        if self.update_task.is_some() {
            warn!("SafeBrowser dropped without calling close()");
        }
    }
}

impl std::fmt::Debug for SafeBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeBrowser")
            .field("config", &self.config)
            .field("stats", &"<stats>")
            .field("last_update", &"<last_update>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
        assert_eq!(config.client_id, DEFAULT_CLIENT_ID);
        assert_eq!(config.update_period, DEFAULT_UPDATE_PERIOD);
        assert!(!config.threat_lists.is_empty());
    }

    #[tokio::test]
    async fn test_safebrowser_creation_without_api_key() {
        let config = Config::default(); // Empty API key
        let result = SafeBrowser::new(config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Configuration(_)));
    }
}
