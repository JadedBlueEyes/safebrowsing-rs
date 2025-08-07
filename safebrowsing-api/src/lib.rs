//! HTTP API client for Google Safe Browsing API v4
//!
//! This crate provides the HTTP client implementation for communicating with
//! the Google Safe Browsing API servers. It handles request formation,
//! authorization, and response parsing.

use bytes::Bytes;
use prost::Message;
use reqwest::{Client, Proxy, Response};
use safebrowsing_hash::HashPrefix;
use safebrowsing_proto::{
    safebrowsing_proto, ClientInfo, FetchThreatListUpdatesRequest, FetchThreatListUpdatesResponse,
    FindFullHashesRequest, FindFullHashesResponse, ThreatEntry, ThreatInfo,
};
use safebrowsing_proto::{
    PlatformType as ProtoPlatformType, ThreatEntryType as ProtoThreatEntryType,
    ThreatType as ProtoThreatType,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error};

/// Default Safe Browsing API base URL
pub const API_BASE_URL: &str = "https://safebrowsing.googleapis.com";

/// API endpoint paths
const THREAT_LIST_UPDATES_PATH: &str = "/v4/threatListUpdates:fetch";
const FULL_HASHES_PATH: &str = "/v4/fullHashes:find";

/// Error types specific to the Safe Browsing API
#[derive(Error, Debug)]
pub enum ApiError {
    /// Bad request error (HTTP 400)
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Authentication error (HTTP 401)
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// API quota exceeded (HTTP 403)
    #[error("API quota exceeded")]
    QuotaExceeded,

    /// Rate limiting error (HTTP 429)
    #[error("Rate limited, retry after {retry_after:?}")]
    RateLimit { retry_after: Option<Duration> },

    /// Server unavailable (HTTP 503)
    #[error("Server unavailable: {0}")]
    ServerUnavailable(String),

    /// Other HTTP error
    #[error("HTTP error {status}: {message}")]
    HttpStatus { status: u16, message: String },
}

/// Error type for API operations
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP client error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Safe Browsing API error
    #[error("API error: {0}")]
    Api(#[from] ApiError),

    /// Protobuf encoding/decoding error
    #[error("Protobuf error: {0}")]
    Protobuf(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Result type for API operations
type Result<T> = std::result::Result<T, Error>;

/// Configuration for the Safe Browsing API client
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// The API key for authenticating with the Safe Browsing API
    pub api_key: String,

    /// Client ID to identify the client to the API
    pub client_id: String,

    /// Client version string
    pub client_version: String,

    /// Base URL for the Safe Browsing API
    pub base_url: String,

    /// Optional HTTP proxy URL
    pub proxy_url: Option<String>,

    /// Request timeout duration
    pub request_timeout: Duration,
}

/// A threat descriptor describes a specific threat list
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreatDescriptor {
    /// The type of threat (malware, phishing, etc)
    pub threat_type: ThreatType,

    /// The platform this threat applies to
    pub platform_type: PlatformType,

    /// The type of entries in the threat list
    pub threat_entry_type: ThreatEntryType,
}

impl fmt::Display for ThreatDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.threat_type, self.platform_type, self.threat_entry_type
        )
    }
}

/// Types of threats in the Safe Browsing API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    /// Unknown threat type
    Unspecified,
    /// Malware threat
    Malware,
    /// Social engineering/phishing
    SocialEngineering,
    /// Unwanted software
    UnwantedSoftware,
    /// Potentially harmful application
    PotentiallyHarmfulApplication,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "UNSPECIFIED"),
            Self::Malware => write!(f, "MALWARE"),
            Self::SocialEngineering => write!(f, "SOCIAL_ENGINEERING"),
            Self::UnwantedSoftware => write!(f, "UNWANTED_SOFTWARE"),
            Self::PotentiallyHarmfulApplication => write!(f, "POTENTIALLY_HARMFUL_APPLICATION"),
        }
    }
}

impl From<ThreatType> for i32 {
    fn from(tt: ThreatType) -> i32 {
        match tt {
            ThreatType::Unspecified => ProtoThreatType::Unspecified as i32,
            ThreatType::Malware => ProtoThreatType::Malware as i32,
            ThreatType::SocialEngineering => ProtoThreatType::SocialEngineering as i32,
            ThreatType::UnwantedSoftware => ProtoThreatType::UnwantedSoftware as i32,
            ThreatType::PotentiallyHarmfulApplication => {
                ProtoThreatType::PotentiallyHarmfulApplication as i32
            }
        }
    }
}

impl From<i32> for ThreatType {
    fn from(value: i32) -> Self {
        match value {
            x if x == ProtoThreatType::Malware as i32 => Self::Malware,
            x if x == ProtoThreatType::SocialEngineering as i32 => Self::SocialEngineering,
            x if x == ProtoThreatType::UnwantedSoftware as i32 => Self::UnwantedSoftware,
            x if x == ProtoThreatType::PotentiallyHarmfulApplication as i32 => {
                Self::PotentiallyHarmfulApplication
            }
            _ => Self::Unspecified,
        }
    }
}

/// Platform types in the Safe Browsing API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformType {
    /// Unknown platform
    Unspecified,
    /// Windows platform
    Windows,
    /// Linux platform
    Linux,
    /// Android platform
    Android,
    /// macOS platform
    OSX,
    /// iOS platform
    IOS,
    /// Any platform (at least one platform)
    AnyPlatform,
    /// All platforms
    AllPlatforms,
    /// Chrome browser
    Chrome,
}

impl fmt::Display for PlatformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "UNSPECIFIED"),
            Self::Windows => write!(f, "WINDOWS"),
            Self::Linux => write!(f, "LINUX"),
            Self::Android => write!(f, "ANDROID"),
            Self::OSX => write!(f, "OSX"),
            Self::IOS => write!(f, "IOS"),
            Self::AnyPlatform => write!(f, "ANY_PLATFORM"),
            Self::AllPlatforms => write!(f, "ALL_PLATFORMS"),
            Self::Chrome => write!(f, "CHROME"),
        }
    }
}

impl From<PlatformType> for i32 {
    fn from(pt: PlatformType) -> i32 {
        match pt {
            PlatformType::Unspecified => ProtoPlatformType::Unspecified as i32,
            PlatformType::Windows => ProtoPlatformType::Windows as i32,
            PlatformType::Linux => ProtoPlatformType::Linux as i32,
            PlatformType::Android => ProtoPlatformType::Android as i32,
            PlatformType::OSX => ProtoPlatformType::Osx as i32,
            PlatformType::IOS => ProtoPlatformType::Ios as i32,
            PlatformType::AnyPlatform => ProtoPlatformType::AnyPlatform as i32,
            PlatformType::AllPlatforms => ProtoPlatformType::AllPlatforms as i32,
            PlatformType::Chrome => ProtoPlatformType::Chrome as i32,
        }
    }
}

impl From<i32> for PlatformType {
    fn from(value: i32) -> Self {
        match value {
            x if x == ProtoPlatformType::Windows as i32 => Self::Windows,
            x if x == ProtoPlatformType::Linux as i32 => Self::Linux,
            x if x == ProtoPlatformType::Android as i32 => Self::Android,
            x if x == ProtoPlatformType::Osx as i32 => Self::OSX,
            x if x == ProtoPlatformType::Ios as i32 => Self::IOS,
            x if x == ProtoPlatformType::AnyPlatform as i32 => Self::AnyPlatform,
            x if x == ProtoPlatformType::AllPlatforms as i32 => Self::AllPlatforms,
            x if x == ProtoPlatformType::Chrome as i32 => Self::Chrome,
            _ => Self::Unspecified,
        }
    }
}

/// Types of threat entries in the Safe Browsing API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatEntryType {
    /// Unknown entry type
    Unspecified,
    /// URL entry
    Url,
    /// Executable file
    Executable,
    /// IP range
    IpRange,
}

impl fmt::Display for ThreatEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "UNSPECIFIED"),
            Self::Url => write!(f, "URL"),
            Self::Executable => write!(f, "EXECUTABLE"),
            Self::IpRange => write!(f, "IP_RANGE"),
        }
    }
}

impl From<ThreatEntryType> for i32 {
    fn from(tet: ThreatEntryType) -> i32 {
        match tet {
            ThreatEntryType::Unspecified => ProtoThreatEntryType::Unspecified as i32,
            ThreatEntryType::Url => ProtoThreatEntryType::Url as i32,
            ThreatEntryType::Executable => ProtoThreatEntryType::Executable as i32,
            ThreatEntryType::IpRange => ProtoThreatEntryType::IpRange as i32,
        }
    }
}

impl From<i32> for ThreatEntryType {
    fn from(value: i32) -> Self {
        match value {
            x if x == ProtoThreatEntryType::Url as i32 => Self::Url,
            x if x == ProtoThreatEntryType::Executable as i32 => Self::Executable,
            x if x == ProtoThreatEntryType::IpRange as i32 => Self::IpRange,
            _ => Self::Unspecified,
        }
    }
}

/// Information about a URL that matched a threat list
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct URLThreat {
    /// The URL pattern that matched
    pub pattern: String,

    /// The threat descriptor that matched
    pub threat_descriptor: ThreatDescriptor,
}

impl fmt::Display for URLThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pattern, self.threat_descriptor)
    }
}

/// Safe Browsing API client
#[derive(Clone)]
pub struct SafeBrowsingApi {
    client: Client,
    base_url: String,
    api_key: String,
    client_info: ClientInfo,
}

impl SafeBrowsingApi {
    /// Create a new API client with the provided configuration
    pub fn new(config: &ApiConfig) -> Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(config.request_timeout)
            .user_agent(format!("{}/{}", config.client_id, config.client_version))
            .gzip(true);

        // Configure proxy if specified
        if let Some(proxy_url) = &config.proxy_url {
            let proxy = Proxy::all(proxy_url)
                .map_err(|e| Error::Configuration(format!("Invalid proxy URL: {e}")))?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder
            .build()
            .map_err(|e| Error::Configuration(format!("Failed to create HTTP client: {e}")))?;

        let client_info = ClientInfo {
            client_id: config.client_id.clone(),
            client_version: config.client_version.clone(),
        };

        Ok(Self {
            client,
            base_url: config.base_url.clone(),
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
                    state: client_state.to_vec().into(),
                    constraints: Some(
                        safebrowsing_proto::fetch_threat_list_updates_request::list_update_request::Constraints {
                            max_update_entries: 0, // No limit
                            max_database_entries: 0, // No limit
                            region: String::new(),
                            supported_compressions: vec![
                                safebrowsing_proto::CompressionType::Raw as i32,
                                safebrowsing_proto::CompressionType::Rice as i32,
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
            hash: Bytes::copy_from_slice(hash_prefix.as_bytes()),
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
        prost::Message::encode(request, &mut buf).map_err(|e| Error::Protobuf(e.to_string()))?;

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
        prost::Message::decode(body).map_err(|e| Error::Protobuf(e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_descriptor_display() {
        let td = ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        };
        assert_eq!(format!("{td}"), "MALWARE/ANY_PLATFORM/URL");
    }

    #[test]
    fn test_threat_type_conversions() {
        assert_eq!(
            i32::from(ThreatType::Malware),
            safebrowsing_proto::ThreatType::Malware as i32
        );
        assert_eq!(
            ThreatType::from(safebrowsing_proto::ThreatType::Malware as i32),
            ThreatType::Malware
        );
    }

    #[test]
    fn test_platform_type_conversions() {
        assert_eq!(
            i32::from(PlatformType::AnyPlatform),
            safebrowsing_proto::PlatformType::AnyPlatform as i32
        );
        assert_eq!(
            PlatformType::from(safebrowsing_proto::PlatformType::AnyPlatform as i32),
            PlatformType::AnyPlatform
        );
    }

    #[test]
    fn test_threat_entry_type_conversions() {
        assert_eq!(
            i32::from(ThreatEntryType::Url),
            safebrowsing_proto::ThreatEntryType::Url as i32
        );
        assert_eq!(
            ThreatEntryType::from(safebrowsing_proto::ThreatEntryType::Url as i32),
            ThreatEntryType::Url
        );
    }
}
