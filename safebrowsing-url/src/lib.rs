//! URL processing and canonicalization for Google Safe Browsing API
//!
//! This crate provides URL processing and canonicalization functions used
//! by the Safe Browsing API. It handles URL normalization, host extraction,
//! and pattern generation for URL lookups.

use idna::domain_to_ascii;

use std::fmt;
use thiserror::Error;
use tracing::debug;
use url::{Host, Url};

/// Error type for URL operations
#[derive(Debug, Error)]
pub enum UrlError {
    /// Error parsing URL
    #[error("URL parse error: {0}")]
    Parse(#[from] url::ParseError),

    /// Invalid host in URL
    #[error("Invalid host in URL: {0}")]
    InvalidHost(String),

    /// IDNA encoding error
    #[error("IDNA encoding error: {0}")]
    Idna(String),

    /// Invalid URL format
    #[error("Invalid URL format: {0}")]
    InvalidFormat(String),
}

/// Result type for URL operations
pub type Result<T> = std::result::Result<T, UrlError>;

/// Information about a canonicalized URL
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalUrl {
    /// The original URL that was canonicalized
    pub original: String,

    /// The canonicalized URL
    pub url: String,

    /// The hostname from the URL
    pub host: String,

    /// The path component, including query parameters
    pub path: String,
}

impl fmt::Display for CanonicalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

/// Check if a URL string is potentially valid
pub fn validate_url(url_str: &str) -> bool {
    // Quick check for obviously invalid URLs
    if url_str.trim().is_empty() || url_str.starts_with("://") {
        return false;
    }

    // Quick check for protocol
    if !url_str.contains("://") && !url_str.starts_with("//") {
        // Try with http:// prefix for domain-like URLs
        return Url::parse(&format!("http://{url_str}")).is_ok();
    }

    // Try to parse it
    Url::parse(url_str).is_ok()
}

/// Canonicalize a URL according to the Safe Browsing specification
///
/// This function normalizes URLs in a way that matches the Safe Browsing
/// canonicalization algorithm. This includes:
/// - Converting to lowercase
/// - Removing fragments
/// - Converting IDNs to punycode
/// - Normalizing paths
/// - Removing default ports
pub fn canonicalize_url(url_str: &str) -> Result<CanonicalUrl> {
    // Add http:// prefix if no scheme is present
    let url_str = if !url_str.contains("://") && !url_str.starts_with("//") {
        format!("http://{url_str}")
    } else {
        url_str.to_string()
    };

    // Parse the URL
    let parsed_url = Url::parse(&url_str)?;

    // Extract the host
    let host = match parsed_url.host() {
        Some(Host::Domain(domain)) => {
            // Convert to IDNA/punycode
            domain_to_ascii(domain)
                .map_err(|e| UrlError::Idna(e.to_string()))?
                .to_lowercase()
        }
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => format!("[{ip}]"),
        None => return Err(UrlError::InvalidHost("No host in URL".to_string())),
    };

    // Extract the path (including query but not fragment)
    let mut path = parsed_url.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }

    if let Some(query) = parsed_url.query() {
        path = format!("{path}?{query}");
    }

    // Build the canonical URL
    let scheme = parsed_url.scheme();
    let port = match parsed_url.port() {
        // Don't include default ports
        Some(p) if (scheme == "http" && p == 80) || (scheme == "https" && p == 443) => None,
        p => p,
    };

    let canonical_url = if let Some(p) = port {
        format!("{scheme}://{host}:{p}{path}")
    } else {
        format!("{scheme}://{host}{path}")
    };

    Ok(CanonicalUrl {
        original: url_str,
        url: canonical_url,
        host,
        path,
    })
}

/// Generate URL patterns for lookup in the Safe Browsing database
///
/// The Safe Browsing API uses a set of URL patterns to check against the
/// database. This function generates all the patterns needed for a full
/// lookup according to the specification.
pub fn generate_patterns(url: &CanonicalUrl) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    let host = &url.host;
    let path = &url.path;

    // Extract host components
    let host_components: Vec<&str> = host.split('.').collect();

    // Generate host suffixes (from longest to shortest)
    let mut host_suffixes = Vec::new();
    // Always include the full host
    host_suffixes.push(host.clone());

    // Generate up to 4 hostnames by removing subdomains from the left
    for i in 0..(host_components.len() - 1).min(4) {
        let suffix = host_components[i + 1..].join(".");
        host_suffixes.push(suffix);
    }

    // URL paths to check
    let mut path_suffixes = Vec::new();
    path_suffixes.push(path.clone());

    // Generate path suffixes
    if path != "/" {
        let path_parts: Vec<&str> = path.split('/').collect();
        if path_parts.len() > 1 {
            // Add root path
            path_suffixes.push("/".to_string());

            // Add up to 4 path components
            for i in 1..path_parts.len().min(4) {
                let path_suffix = format!("/{}", path_parts[1..=i].join("/"));
                if &path_suffix != path {
                    path_suffixes.push(path_suffix);
                }
            }
        }
    }

    // Generate patterns combining hosts and paths
    for host_suffix in &host_suffixes {
        for path_suffix in &path_suffixes {
            patterns.push(format!("{host_suffix}{path_suffix}"));
        }
    }

    debug!("Generated {} patterns for URL: {}", patterns.len(), url.url);
    Ok(patterns)
}

/// Extract the domain from a URL
pub fn extract_domain(url_str: &str) -> Result<String> {
    let canonical = canonicalize_url(url_str)?;
    Ok(canonical.host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url() {
        assert!(validate_url("http://example.com"));
        assert!(validate_url("https://example.com/path?query=1"));
        assert!(validate_url("example.com"));
        assert!(!validate_url("not a url"));
    }

    #[test]
    fn test_canonicalize_url() {
        let canonical = canonicalize_url("http://Example.Com/path").unwrap();
        assert_eq!(canonical.url, "http://example.com/path");
        assert_eq!(canonical.host, "example.com");
        assert_eq!(canonical.path, "/path");

        // Test scheme-less URL
        let canonical = canonicalize_url("example.com").unwrap();
        assert_eq!(canonical.url, "http://example.com/");

        // Test query parameters
        let canonical = canonicalize_url("http://example.com/path?query=1").unwrap();
        assert_eq!(canonical.url, "http://example.com/path?query=1");
        assert_eq!(canonical.path, "/path?query=1");

        // Test default port removal
        let canonical = canonicalize_url("http://example.com:80/path").unwrap();
        assert_eq!(canonical.url, "http://example.com/path");

        // Test non-default port
        let canonical = canonicalize_url("http://example.com:8080/path").unwrap();
        assert_eq!(canonical.url, "http://example.com:8080/path");

        // Test fragment removal
        let canonical = canonicalize_url("http://example.com/path#fragment").unwrap();
        assert_eq!(canonical.url, "http://example.com/path");

        // Test IDN
        let canonical = canonicalize_url("http://例子.测试").unwrap();
        assert!(canonical.host.starts_with("xn--"));
    }

    #[test]
    fn test_generate_patterns() {
        let canonical = canonicalize_url("http://a.b.c.d.e.f/1/2.html?param=1").unwrap();
        let patterns = generate_patterns(&canonical).unwrap();

        // Check that the patterns include all expected combinations
        assert!(patterns.contains(&"d.e.f/1/2.html?param=1".to_string()));
        assert!(patterns.contains(&"c.d.e.f/1/2.html?param=1".to_string()));
        assert!(patterns.contains(&"b.c.d.e.f/1/2.html?param=1".to_string()));
        assert!(patterns.contains(&"a.b.c.d.e.f/1/2.html?param=1".to_string()));
        assert!(patterns.contains(&"d.e.f/".to_string()));
        assert!(patterns.contains(&"c.d.e.f/".to_string()));
        assert!(patterns.contains(&"b.c.d.e.f/".to_string()));
        assert!(patterns.contains(&"a.b.c.d.e.f/".to_string()));
        assert!(patterns.contains(&"d.e.f/1".to_string()));
        assert!(patterns.contains(&"c.d.e.f/1".to_string()));
        assert!(patterns.contains(&"b.c.d.e.f/1".to_string()));
        assert!(patterns.contains(&"a.b.c.d.e.f/1".to_string()));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("http://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            extract_domain("https://sub.example.co.uk").unwrap(),
            "sub.example.co.uk"
        );
    }
}
