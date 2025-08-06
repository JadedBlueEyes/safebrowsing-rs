//! Error types for the Safe Browsing library

use thiserror::Error;

/// Result type alias for Safe Browsing operations
pub type Result<T> = std::result::Result<T, Error>;

/// Comprehensive error type for Safe Browsing operations
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Network/API related errors
    #[error("API error: {0}")]
    Api(#[from] ApiError),

    /// Database operation errors
    #[error("Database error: {0}")]
    Database(#[from] safebrowsing_db::DatabaseError),

    /// URL parsing and validation errors
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Hash processing errors
    #[error("Hash error: {0}")]
    Hash(String),

    /// Timeout errors
    #[error("Timeout: {0}")]
    Timeout(String),

    /// HTTP client errors
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Protobuf encoding/decoding errors
    #[error("Protobuf error: {0}")]
    Protobuf(#[from] prost::DecodeError),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// URL parsing errors
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Internal library errors
    #[error("Internal error: {0}")]
    Internal(String),

    /// Cache-related errors
    #[error("Cache error: {0}")]
    Cache(String),

    /// Encoding errors (Rice, compression, etc.)
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),
}

/// API-specific error types
#[derive(Error, Debug)]
pub enum ApiError {
    /// HTTP status error with code and message
    #[error("HTTP {status}: {message}")]
    HttpStatus { status: u16, message: String },

    /// Invalid API response format
    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    /// API rate limiting
    #[error("Rate limited, retry after: {retry_after:?}")]
    RateLimit {
        retry_after: Option<std::time::Duration>,
    },

    /// API quota exceeded
    #[error("API quota exceeded")]
    QuotaExceeded,

    /// Authentication failure
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Server temporarily unavailable
    #[error("Server unavailable: {0}")]
    ServerUnavailable(String),

    /// Malformed request
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Network connectivity issues
    #[error("Network error: {0}")]
    Network(String),
}

/// Database-specific error types
#[derive(Error, Debug)]
pub enum DatabaseError {
    /// Database not initialized
    #[error("Database not initialized")]
    NotInitialized,

    /// Database is stale and needs updating
    #[error("Database is stale (last update: {last_update:?})")]
    Stale {
        last_update: Option<std::time::Instant>,
    },

    /// Database corruption detected
    #[error("Database corruption detected: {0}")]
    Corruption(String),

    /// Incompatible database version
    #[error("Incompatible database version: expected {expected}, found {found}")]
    VersionMismatch { expected: String, found: String },

    /// Database file operations
    #[error("File operation failed: {0}")]
    FileOperation(String),

    /// Checksum mismatch
    #[error("Checksum mismatch: expected {expected:x}, found {found:x}")]
    ChecksumMismatch { expected: u64, found: u64 },

    /// Missing required data
    #[error("Missing required data: {0}")]
    MissingData(String),

    /// Update operation failed
    #[error("Update failed: {0}")]
    UpdateFailed(String),

    /// Concurrent access violation
    #[error("Concurrent access error: {0}")]
    ConcurrentAccess(String),
}

impl From<safebrowsing_api::Error> for Error {
    fn from(err: safebrowsing_api::Error) -> Self {
        match err {
            safebrowsing_api::Error::Api(api_err) => Error::Api(ApiError::from(api_err)),
            safebrowsing_api::Error::Http(http_err) => Error::Http(http_err),
            safebrowsing_api::Error::Protobuf(msg) => Error::Protobuf(prost::DecodeError::new(msg)),
            safebrowsing_api::Error::Configuration(msg) => Error::Configuration(msg),
        }
    }
}

impl From<safebrowsing_url::UrlError> for Error {
    fn from(err: safebrowsing_url::UrlError) -> Self {
        match err {
            safebrowsing_url::UrlError::Parse(parse_err) => Error::UrlParse(parse_err),
            safebrowsing_url::UrlError::InvalidHost(msg) => Error::InvalidUrl(msg),
            safebrowsing_url::UrlError::Idna(msg) => {
                Error::InvalidUrl(format!("IDNA error: {msg}"))
            }
            safebrowsing_url::UrlError::InvalidFormat(msg) => Error::InvalidUrl(msg),
        }
    }
}

impl From<safebrowsing_api::ApiError> for ApiError {
    fn from(err: safebrowsing_api::ApiError) -> Self {
        match err {
            safebrowsing_api::ApiError::BadRequest(msg) => ApiError::BadRequest(msg),
            safebrowsing_api::ApiError::Authentication(msg) => ApiError::Authentication(msg),
            safebrowsing_api::ApiError::QuotaExceeded => ApiError::QuotaExceeded,
            safebrowsing_api::ApiError::RateLimit { retry_after } => {
                ApiError::RateLimit { retry_after }
            }
            safebrowsing_api::ApiError::ServerUnavailable(msg) => ApiError::ServerUnavailable(msg),
            safebrowsing_api::ApiError::HttpStatus { status, message } => {
                ApiError::HttpStatus { status, message }
            }
        }
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Error::Internal(msg.to_string())
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error::Internal(msg)
    }
}

/// Helper trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add context to an error
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;

    /// Add static context to an error
    fn context(self, msg: &'static str) -> Result<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: Into<Error>,
{
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let base_error = e.into();
            Error::Internal(format!("{}: {}", f(), base_error))
        })
    }

    fn context(self, msg: &'static str) -> Result<T> {
        self.with_context(|| msg.to_string())
    }
}

/// Check if an error is retryable
impl Error {
    /// Returns true if this error indicates a temporary condition that might succeed on retry
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Api(api_error) => api_error.is_retryable(),
            Error::Database(safebrowsing_db::DatabaseError::Stale(_)) => true,
            Error::Http(req_error) => {
                // Network timeouts and connection errors are retryable
                req_error.is_timeout() || req_error.is_connect()
            }
            Error::Timeout(_) => true,
            _ => false,
        }
    }

    /// Returns true if this is a permanent error that shouldn't be retried
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Error::Configuration(_)
                | Error::InvalidUrl(_)
                | Error::Api(ApiError::Authentication(_))
                | Error::Api(ApiError::BadRequest(_))
                | Error::Database(safebrowsing_db::DatabaseError::DecodeError(_))
                | Error::Database(safebrowsing_db::DatabaseError::InvalidChecksum { .. })
                | Error::Validation(_)
        )
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            Error::Configuration(_) => "Configuration issue detected".to_string(),
            Error::Api(ApiError::Authentication(_)) => {
                "Invalid API key or authentication failed".to_string()
            }
            Error::Api(ApiError::QuotaExceeded) => {
                "API quota exceeded, please try again later".to_string()
            }
            Error::Api(ApiError::RateLimit { .. }) => {
                "Rate limited by API, please wait before retrying".to_string()
            }
            Error::InvalidUrl(url) => format!("Invalid URL format: {url}"),
            Error::Database(safebrowsing_db::DatabaseError::Stale(_)) => {
                "Database needs updating".to_string()
            }
            Error::Database(safebrowsing_db::DatabaseError::DecodeError(_)) => {
                "Database corruption detected, please reset".to_string()
            }
            Error::Timeout(_) => "Operation timed out, please try again".to_string(),
            Error::Http(_) => "Network connection failed".to_string(),
            _ => "An unexpected error occurred".to_string(),
        }
    }
}

impl ApiError {
    /// Returns true if this API error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            ApiError::HttpStatus { status, .. } => {
                // 5xx errors are generally retryable, 4xx are not (except 429)
                *status >= 500 || *status == 429
            }
            ApiError::RateLimit { .. } => true,
            ApiError::ServerUnavailable(_) => true,
            ApiError::Network(_) => true,
            ApiError::Authentication(_) => false,
            ApiError::BadRequest(_) => false,
            ApiError::QuotaExceeded => false,
            ApiError::InvalidResponse(_) => false,
        }
    }

    /// Create an API error from HTTP status code and response body
    pub fn from_status(status: u16, body: &str) -> Self {
        match status {
            401 => ApiError::Authentication("Invalid API key".to_string()),
            403 => ApiError::QuotaExceeded,
            429 => ApiError::RateLimit { retry_after: None },
            400 => ApiError::BadRequest(body.to_string()),
            503 => ApiError::ServerUnavailable("Service temporarily unavailable".to_string()),
            _ => ApiError::HttpStatus {
                status,
                message: body.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context() {
        let result: std::result::Result<(), &str> = Err("test error");
        let error = result.context("operation failed").unwrap_err();

        assert!(matches!(error, Error::Internal(_)));
        assert!(error.to_string().contains("operation failed"));
        assert!(error.to_string().contains("test error"));
    }

    #[test]
    fn test_retryable_errors() {
        assert!(Error::Timeout("test".to_string()).is_retryable());
        assert!(Error::Api(ApiError::RateLimit { retry_after: None }).is_retryable());
        assert!(!Error::Configuration("test".to_string()).is_retryable());
        assert!(!Error::InvalidUrl("test".to_string()).is_retryable());
    }

    #[test]
    fn test_permanent_errors() {
        assert!(Error::Configuration("test".to_string()).is_permanent());
        assert!(Error::InvalidUrl("test".to_string()).is_permanent());
        assert!(Error::Api(ApiError::Authentication("test".to_string())).is_permanent());
        assert!(!Error::Timeout("test".to_string()).is_permanent());
    }

    #[test]
    fn test_api_error_from_status() {
        assert!(matches!(
            ApiError::from_status(401, "unauthorized"),
            ApiError::Authentication(_)
        ));
        assert!(matches!(
            ApiError::from_status(403, "forbidden"),
            ApiError::QuotaExceeded
        ));
        assert!(matches!(
            ApiError::from_status(429, "rate limit"),
            ApiError::RateLimit { .. }
        ));
        assert!(matches!(
            ApiError::from_status(500, "server error"),
            ApiError::HttpStatus { status: 500, .. }
        ));
    }

    #[test]
    fn test_user_messages() {
        let config_error = Error::Configuration("test".to_string());
        assert_eq!(config_error.user_message(), "Configuration issue detected");

        let auth_error = Error::Api(ApiError::Authentication("test".to_string()));
        assert_eq!(
            auth_error.user_message(),
            "Invalid API key or authentication failed"
        );

        let url_error = Error::InvalidUrl("invalid-url".to_string());
        assert_eq!(url_error.user_message(), "Invalid URL format: invalid-url");
    }
}
