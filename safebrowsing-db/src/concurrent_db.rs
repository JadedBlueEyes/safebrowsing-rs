use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use safebrowsing_api::{SafeBrowsingApi, ThreatDescriptor};
use safebrowsing_hash::HashPrefix;
use tokio::sync::Mutex;

use crate::{memory_db::InMemoryDatabase, Database, DatabaseStats, Result};

/// Thread-safe wrapper around an in-memory database
///
/// This provides a concurrent version of the InMemoryDatabase
/// that can be safely shared between threads.
pub struct ConcurrentDatabase {
    /// The inner database
    db: Arc<Mutex<InMemoryDatabase>>,
}

impl ConcurrentDatabase {
    /// Create a new concurrent database
    pub fn new() -> Self {
        Self {
            db: Arc::new(Mutex::new(InMemoryDatabase::new())),
        }
    }

    /// Create a new concurrent database with a specific maximum age
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            db: Arc::new(Mutex::new(InMemoryDatabase::with_max_age(max_age))),
        }
    }
}

#[async_trait]
impl Database for ConcurrentDatabase {
    async fn is_ready(&self) -> Result<bool> {
        let db = self.db.lock().await;
        db.is_ready().await
    }

    async fn status(&self) -> Result<()> {
        let db = self.db.lock().await;
        db.status().await
    }

    async fn update(&self, api: &SafeBrowsingApi, threat_lists: &[ThreatDescriptor]) -> Result<()> {
        let db = self.db.lock().await;
        db.update(api, threat_lists).await
    }

    async fn lookup(
        &self,
        hash: &HashPrefix,
    ) -> Result<Option<(HashPrefix, Vec<ThreatDescriptor>)>> {
        let db = self.db.lock().await;
        db.lookup(hash).await
    }

    async fn time_since_last_update(&self) -> Option<Duration> {
        let db = self.db.lock().await;
        db.time_since_last_update().await
    }

    async fn stats(&self) -> DatabaseStats {
        let db = self.db.lock().await;
        db.stats().await
    }
}

impl Default for ConcurrentDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::Database;
    use crate::{concurrent_db::ConcurrentDatabase, DatabaseError};

    #[tokio::test]
    async fn test_concurrent_database() {
        let db = ConcurrentDatabase::new();

        // New database should not be ready
        assert!(!db.is_ready().await.unwrap());

        // Status should return an error
        assert!(matches!(db.status().await, Err(DatabaseError::NotReady)));

        // Stats should be default values
        let stats = db.stats().await;
        assert_eq!(stats.total_hashes, 0);
    }
}
