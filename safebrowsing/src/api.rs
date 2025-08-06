//! HTTP API client for Google Safe Browsing API v4
//!
//! This module provides the HTTP client implementation for communicating with
//! the Google Safe Browsing API servers.

use crate::error::{ApiError, Error, Result};
use crate::hash::HashPrefix;
use crate::proto::safebrowsing_proto::{
    self, ClientInfo, CompressionType, FetchThreatListUpdatesRequest,
    FetchThreatListUpdatesResponse, FindFullHashesRequest, FindFullHashesResponse, ThreatEntry,
    ThreatInfo,
};
use crate::types::ThreatDescriptor;
use crate::Config;
use bytes::Bytes;
use prost::Message;
use reqwest::{Client, Proxy, Response};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default Safe Browsing API base URL
const API_BASE_URL: &str = "https://safebrowsing.googleapis.com";

/// API endpoint paths
const THREAT_LIST_UPDATES_PATH: &str = "/v4/threatListUpdates:fetch";
const FULL_HASHES_PATH: &str = "/v4/fullHashes:find";

/// Safe Browsing API client
#[derive(Clone)]
pub struct SafeBrowsingApi {
    client: Client,
    base_url: String,
    api_key: String,
    client_info: ClientInfo,
}

impl SafeBrowsingApi {
    /// Create a new API client
    pub fn new(config: &Config) -> Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(config.request_timeout)
            .user_agent(format!("{}/{}", config.client_id, config.client_version))
            .gzip(true);

        // Configure proxy if specified
        if let Some(proxy_url) = &config.proxy_url {
            let proxy = Proxy::all(proxy_url)
                .map_err(|e| Error::Configuration(format!("Invalid proxy URL: {}", e)))?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder
            .build()
            .map_err(|e| Error::Configuration(format!("Failed to create HTTP client: {}", e)))?;

        let client_info = ClientInfo {
            client_id: config.client_id.clone(),
            client_version: config.client_version.clone(),
        };

        Ok(Self {
            client,
            base_url: config.server_url.clone(),
            api_key: config.api_key.clone(),
            client_info,
        })
    }

    /// Fetch threat list updates from the API
    pub async fn fetch_threat_list_update(
        &self,
        threat_descriptor: &ThreatDescriptor,
        client_state: &[u8],
    ) -> Result<FetchThreatListUpdatesResponse> {
        let request = FetchThreatListUpdatesRequest {
            client: Some(self.client_info.clone()),
            list_update_requests: vec![
                safebrowsing_proto::fetch_threat_list_updates_request::ListUpdateRequest {
                    threat_type: threat_descriptor.threat_type.into(),
                    platform_type: threat_descriptor.platform_type.into(),
                    threat_entry_type: threat_descriptor.threat_entry_type.into(),
                    state: client_state.to_vec(),
                    constraints: Some(
                        safebrowsing_proto::fetch_threat_list_updates_request::list_update_request::Constraints {
                            max_update_entries: 0, // No limit
                            max_database_entries: 0, // No limit
                            region: String::new(),
                            supported_compressions: vec![
                                CompressionType::Raw.into(),
                                CompressionType::Rice.into(),
                            ],
                        },
                    ),
                },
            ],
        };

        self.post_protobuf(THREAT_LIST_UPDATES_PATH, &request).await
    }

    /// Find full hashes for the given hash prefixes
    pub async fn find_full_hashes(
        &self,
        hash_prefix: &HashPrefix,
        threat_descriptors: &[ThreatDescriptor],
    ) -> Result<FindFullHashesResponse> {
        let threat_entries = vec![ThreatEntry {
            hash: hash_prefix.as_bytes().to_vec(),
            url: String::new(),
        }];

        let threat_types: Vec<i32> = threat_descriptors
            .iter()
            .map(|td| td.threat_type.into())
            .collect();

        let platform_types: Vec<i32> = threat_descriptors
            .iter()
            .map(|td| td.platform_type.into())
            .collect();

        let threat_entry_types: Vec<i32> = threat_descriptors
            .iter()
            .map(|td| td.threat_entry_type.into())
            .collect();

        let request = FindFullHashesRequest {
            client: Some(self.client_info.clone()),
            client_states: Vec::new(),
            threat_info: Some(ThreatInfo {
                threat_types,
                platform_types,
                threat_entry_types,
                threat_entries,
            }),
        };

        self.post_protobuf(FULL_HASHES_PATH, &request).await
    }

    /// Make a POST request with protobuf payload
    async fn post_protobuf<T, R>(&self, path: &str, request: &T) -> Result<R>
    where
        T: Message,
        R: Message + Default,
    {
        let url = format!("{}{}?key={}&alt=proto", self.base_url, path, self.api_key);

        // Encode the request
        let mut buf = Vec::new();
        request
            .encode(&mut buf)
            .map_err(|e| Error::Protobuf(prost::DecodeError::new(e.to_string())))?;

        debug!("Making API request to: {}", url);
        debug!("Request size: {} bytes", buf.len());

        // Make the request
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-protobuf")
            .body(buf)
            .send()
            .await
            .map_err(Error::Http)?;

        self.handle_response(response).await
    }

    /// Handle HTTP response and decode protobuf
    async fn handle_response<R>(&self, response: Response) -> Result<R>
    where
        R: Message + Default,
    {
        let status = response.status();
        let headers = response.headers().clone();

        debug!("API response status: {}", status);

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read response body".to_string());

            let api_error = match status.as_u16() {
                400 => ApiError::BadRequest(body),
                401 => ApiError::Authentication("Invalid API key".to_string()),
                403 => ApiError::QuotaExceeded,
                429 => {
                    let retry_after = headers
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    ApiError::RateLimit { retry_after }
                }
                503 => ApiError::ServerUnavailable("Service temporarily unavailable".to_string()),
                _ => ApiError::HttpStatus {
                    status: status.as_u16(),
                    message: body,
                },
            };

            return Err(Error::Api(api_error));
        }

        // Read response body
        let body = response.bytes().await.map_err(Error::Http)?;
        debug!("Response size: {} bytes", body.len());

        // Decode protobuf
        R::decode(body).map_err(Error::Protobuf)
    }

    /// Get the API base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the client info
    pub fn client_info(&self) -> &ClientInfo {
        &self.client_info
    }
}

/// Builder for constructing API requests with batch operations
pub struct ApiRequestBuilder {
    api: SafeBrowsingApi,
    threat_descriptors: Vec<ThreatDescriptor>,
    hash_prefixes: Vec<HashPrefix>,
}

impl ApiRequestBuilder {
    /// Create a new request builder
    pub fn new(api: SafeBrowsingApi) -> Self {
        Self {
            api,
            threat_descriptors: Vec::new(),
            hash_prefixes: Vec::new(),
        }
    }

    /// Add threat descriptors to track
    pub fn with_threat_descriptors(mut self, descriptors: Vec<ThreatDescriptor>) -> Self {
        self.threat_descriptors = descriptors;
        self
    }

    /// Add hash prefixes to lookup
    pub fn with_hash_prefixes(mut self, prefixes: Vec<HashPrefix>) -> Self {
        self.hash_prefixes = prefixes;
        self
    }

    /// Execute a batch full hash lookup
    pub async fn find_full_hashes_batch(self) -> Result<FindFullHashesResponse> {
        if self.hash_prefixes.is_empty() {
            return Ok(FindFullHashesResponse::default());
        }

        let threat_entries: Vec<ThreatEntry> = self
            .hash_prefixes
            .iter()
            .map(|hash| ThreatEntry {
                hash: hash.as_bytes().to_vec(),
                url: String::new(),
            })
            .collect();

        let threat_types: Vec<i32> = self
            .threat_descriptors
            .iter()
            .map(|td| td.threat_type.into())
            .collect();

        let platform_types: Vec<i32> = self
            .threat_descriptors
            .iter()
            .map(|td| td.platform_type.into())
            .collect();

        let threat_entry_types: Vec<i32> = self
            .threat_descriptors
            .iter()
            .map(|td| td.threat_entry_type.into())
            .collect();

        let request = FindFullHashesRequest {
            client: Some(self.api.client_info.clone()),
            client_states: Vec::new(),
            threat_info: Some(ThreatInfo {
                threat_types,
                platform_types,
                threat_entry_types,
                threat_entries,
            }),
        };

        self.api.post_protobuf(FULL_HASHES_PATH, &request).await
    }
}

/// Retry configuration for API requests
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: usize,
    /// Base delay between retries
    pub base_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

/// API client with retry capabilities
pub struct RetryableApi {
    api: SafeBrowsingApi,
    retry_config: RetryConfig,
}

impl RetryableApi {
    /// Create a new retryable API client
    pub fn new(api: SafeBrowsingApi, retry_config: RetryConfig) -> Self {
        Self { api, retry_config }
    }

    /// Fetch threat list updates with retries
    pub async fn fetch_threat_list_update_with_retry(
        &self,
        threat_descriptor: &ThreatDescriptor,
        client_state: &[u8],
    ) -> Result<FetchThreatListUpdatesResponse> {
        let mut delay = self.retry_config.base_delay;

        for attempt in 0..self.retry_config.max_attempts {
            match self
                .api
                .fetch_threat_list_update(threat_descriptor, client_state)
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt == self.retry_config.max_attempts - 1 {
                        return Err(e);
                    }

                    if !e.is_retryable() {
                        return Err(e);
                    }

                    warn!(
                        "API request failed (attempt {}/{}): {}, retrying in {:?}",
                        attempt + 1,
                        self.retry_config.max_attempts,
                        e,
                        delay
                    );

                    tokio::time::sleep(delay).await;

                    // Exponential backoff
                    delay = std::cmp::min(
                        Duration::from_millis(
                            (delay.as_millis() as f64 * self.retry_config.backoff_multiplier)
                                as u64,
                        ),
                        self.retry_config.max_delay,
                    );
                }
            }
        }

        unreachable!()
    }

    /// Find full hashes with retries
    pub async fn find_full_hashes_with_retry(
        &self,
        hash_prefix: &HashPrefix,
        threat_descriptors: &[ThreatDescriptor],
    ) -> Result<FindFullHashesResponse> {
        let mut delay = self.retry_config.base_delay;

        for attempt in 0..self.retry_config.max_attempts {
            match self
                .api
                .find_full_hashes(hash_prefix, threat_descriptors)
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt == self.retry_config.max_attempts - 1 {
                        return Err(e);
                    }

                    if !e.is_retryable() {
                        return Err(e);
                    }

                    warn!(
                        "API request failed (attempt {}/{}): {}, retrying in {:?}",
                        attempt + 1,
                        self.retry_config.max_attempts,
                        e,
                        delay
                    );

                    tokio::time::sleep(delay).await;

                    // Exponential backoff
                    delay = std::cmp::min(
                        Duration::from_millis(
                            (delay.as_millis() as f64 * self.retry_config.backoff_multiplier)
                                as u64,
                        ),
                        self.retry_config.max_delay,
                    );
                }
            }
        }

        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PlatformType, ThreatEntryType, ThreatType};

    fn create_test_config() -> Config {
        Config {
            api_key: "test-api-key".to_string(),
            client_id: "test-client".to_string(),
            client_version: "1.0.0".to_string(),
            server_url: "https://test.example.com".to_string(),
            proxy_url: None,
            request_timeout: Duration::from_secs(30),
            ..Default::default()
        }
    }

    fn create_test_threat_descriptor() -> ThreatDescriptor {
        ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        }
    }

    #[tokio::test]
    async fn test_api_creation() {
        let config = create_test_config();
        let api = SafeBrowsingApi::new(&config).unwrap();

        assert_eq!(api.base_url(), "https://test.example.com");
        assert_eq!(api.client_info().client_id, "test-client");
        assert_eq!(api.client_info().client_version, "1.0.0");
    }

    #[tokio::test]
    async fn test_api_creation_with_proxy() {
        let mut config = create_test_config();
        config.proxy_url = Some("http://proxy.example.com:8080".to_string());

        let api = SafeBrowsingApi::new(&config).unwrap();
        assert_eq!(api.base_url(), "https://test.example.com");
    }

    #[tokio::test]
    async fn test_api_creation_with_invalid_proxy() {
        let mut config = create_test_config();
        config.proxy_url = Some("invalid-proxy-url".to_string());

        let result = SafeBrowsingApi::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.base_delay, Duration::from_millis(100));
        assert_eq!(config.max_delay, Duration::from_secs(30));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[tokio::test]
    async fn test_request_builder() {
        let config = create_test_config();
        let api = SafeBrowsingApi::new(&config).unwrap();
        let threat_descriptor = create_test_threat_descriptor();
        let hash = HashPrefix::from_pattern("test.example.com");

        let builder = ApiRequestBuilder::new(api)
            .with_threat_descriptors(vec![threat_descriptor])
            .with_hash_prefixes(vec![hash]);

        // Can't actually make the request without a real API server
        // but we can test that the builder constructs properly
        assert!(!builder.threat_descriptors.is_empty());
        assert!(!builder.hash_prefixes.is_empty());
    }

    #[test]
    fn test_api_error_classification() {
        let retryable_errors = vec![
            ApiError::HttpStatus {
                status: 500,
                message: "Internal Server Error".to_string(),
            },
            ApiError::RateLimit { retry_after: None },
            ApiError::ServerUnavailable("Unavailable".to_string()),
            ApiError::Network("Connection failed".to_string()),
        ];

        for error in retryable_errors {
            assert!(
                error.is_retryable(),
                "Error should be retryable: {:?}",
                error
            );
        }

        let non_retryable_errors = vec![
            ApiError::Authentication("Invalid key".to_string()),
            ApiError::BadRequest("Bad request".to_string()),
            ApiError::QuotaExceeded,
            ApiError::InvalidResponse("Invalid response".to_string()),
        ];

        for error in non_retryable_errors {
            assert!(
                !error.is_retryable(),
                "Error should not be retryable: {:?}",
                error
            );
        }
    }
}
