//! URL processing and canonicalization for Safe Browsing
//!
//! This module handles URL canonicalization, pattern generation, and validation
//! according to Safe Browsing specifications.

use crate::error::{Error, Result};
use regex::Regex;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Maximum number of host components to consider for lookup hosts
const MAX_HOST_COMPONENTS: usize = 7;

/// Maximum number of path components to consider for lookup paths
const MAX_PATH_COMPONENTS: usize = 4;

/// Validate if a URL is compatible with Safe Browsing
pub fn validate_url(url_str: &str) -> bool {
    match parse_url(url_str) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Canonicalize a URL according to Safe Browsing rules
pub fn canonicalize_url(url_str: &str) -> Result<String> {
    let parsed = parse_url(url_str)?;

    // Rebuild the URL with canonical components
    let scheme = parsed.scheme().to_lowercase();
    let host = canonical_host(&parsed)?;
    let path = canonical_path(&parsed);

    let mut canonical = format!("{}://{}", scheme, host);
    if !path.is_empty() && path != "/" {
        canonical.push_str(&path);
    } else {
        canonical.push('/');
    }

    Ok(canonical)
}

/// Generate all URL patterns for Safe Browsing lookup
pub fn generate_patterns(url_str: &str) -> Result<Vec<String>> {
    let hosts = generate_lookup_hosts(url_str)?;
    let paths = generate_lookup_paths(url_str)?;

    let mut patterns = Vec::new();
    for host in hosts {
        for path in &paths {
            patterns.push(format!("{}{}", host, path));
        }
    }

    Ok(patterns)
}

/// Parse and validate a URL
fn parse_url(url_str: &str) -> Result<ParsedUrl> {
    let trimmed = url_str.trim();

    // Remove fragments and normalize whitespace
    let cleaned = remove_fragment(trimmed);
    let cleaned = normalize_whitespace(&cleaned);
    let cleaned = normalize_escapes(&cleaned)?;

    // Extract scheme and remaining parts
    let (scheme, rest) = extract_scheme(&cleaned);
    let scheme = if scheme.is_empty() {
        "http".to_string()
    } else {
        scheme
    };

    // Split into host and path parts
    let (host_part, path_part) = if rest.starts_with("//") {
        split_host_path(&rest[2..])
    } else if scheme == "http" || scheme == "https" {
        split_host_path(&rest)
    } else {
        return Err(Error::InvalidUrl("Invalid URL scheme".to_string()));
    };

    if host_part.is_empty() {
        return Err(Error::InvalidUrl("Missing hostname".to_string()));
    }

    let host = parse_host(&host_part)?;
    let path = if path_part.is_empty() {
        "/".to_string()
    } else {
        path_part
    };

    Ok(ParsedUrl { scheme, host, path })
}

/// Internal parsed URL representation
#[derive(Debug, Clone)]
struct ParsedUrl {
    scheme: String,
    host: String,
    path: String,
}

impl ParsedUrl {
    fn scheme(&self) -> &str {
        &self.scheme
    }
}

/// Remove URL fragment (everything after #)
fn remove_fragment(url: &str) -> String {
    if let Some(pos) = url.find('#') {
        url[..pos].to_string()
    } else {
        url.to_string()
    }
}

/// Normalize whitespace characters
fn normalize_whitespace(url: &str) -> String {
    url.chars()
        .filter(|&c| c != '\t' && c != '\r' && c != '\n')
        .collect()
}

/// Normalize percent-encoded characters
fn normalize_escapes(url: &str) -> Result<String> {
    recursive_unescape(url)
}

/// Recursively unescape percent-encoded characters
fn recursive_unescape(s: &str) -> Result<String> {
    const MAX_DEPTH: usize = 1024;
    let mut current = s.to_string();

    for _ in 0..MAX_DEPTH {
        let unescaped = unescape(&current);
        if unescaped == current {
            return Ok(escape(&unescaped));
        }
        current = unescaped;
    }

    Err(Error::InvalidUrl("Too many unescape levels".to_string()))
}

/// Unescape percent-encoded characters
fn unescape(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                    let byte = (d1 * 16 + d2) as u8;
                    result.push(byte as char);
                    continue;
                }
            }
            result.push(c);
        } else {
            result.push(c);
        }
    }

    result
}

/// Escape characters that need percent-encoding
fn escape(s: &str) -> String {
    let mut result = String::new();

    for byte in s.bytes() {
        if byte < 0x20 || byte >= 0x7f || byte == b' ' || byte == b'#' || byte == b'%' {
            result.push_str(&format!("%{:02x}", byte));
        } else {
            result.push(byte as char);
        }
    }

    result
}

/// Extract scheme from URL
fn extract_scheme(url: &str) -> (String, String) {
    for (i, c) in url.char_indices() {
        match c {
            'a'..='z' | 'A'..='Z' => continue,
            '0'..='9' | '+' | '-' | '.' if i > 0 => continue,
            ':' => return (url[..i].to_lowercase(), url[i + 1..].to_string()),
            _ => break,
        }
    }
    (String::new(), url.to_string())
}

/// Split host and path parts
fn split_host_path(rest: &str) -> (String, String) {
    if let Some(pos) = rest.find('/') {
        (rest[..pos].to_string(), rest[pos..].to_string())
    } else {
        (rest.to_string(), String::new())
    }
}

/// Parse and canonicalize host
fn parse_host(host_str: &str) -> Result<String> {
    let host = remove_userinfo(host_str);
    let host = remove_port(&host);
    let host = normalize_unicode(&host)?;
    let host = normalize_dots(&host);
    let host = canonicalize_ip(&host).unwrap_or_else(|| host.to_lowercase());

    Ok(host)
}

/// Remove userinfo (username:password@) from host
fn remove_userinfo(host: &str) -> String {
    if let Some(pos) = host.rfind('@') {
        host[pos + 1..].to_string()
    } else {
        host.to_string()
    }
}

/// Remove port number from host
fn remove_port(host: &str) -> String {
    // Handle IPv6 addresses
    if host.starts_with('[') {
        if let Some(bracket_pos) = host.find(']') {
            return host[..=bracket_pos].to_string();
        }
    }

    // Handle regular hosts
    if let Some(colon_pos) = host.rfind(':') {
        // Check if this looks like a port (digits only)
        if host[colon_pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            return host[..colon_pos].to_string();
        }
    }

    host.to_string()
}

/// Normalize Unicode characters in hostname
fn normalize_unicode(host: &str) -> Result<String> {
    // Check if host contains non-ASCII characters
    if host.chars().any(|c| !c.is_ascii()) {
        // Use IDNA encoding for internationalized domain names
        idna::domain_to_ascii(host)
            .map_err(|e| Error::InvalidUrl(format!("IDNA encoding failed: {}", e)))
    } else {
        Ok(host.to_string())
    }
}

/// Normalize consecutive dots in hostname
fn normalize_dots(host: &str) -> String {
    let re = Regex::new(r"\.+").unwrap();
    let normalized = re.replace_all(host, ".");
    normalized.trim_matches('.').to_string()
}

/// Canonicalize IP addresses
fn canonicalize_ip(host: &str) -> Option<String> {
    // Try parsing as IPv4 or IPv6
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    // Try parsing special IPv4 formats
    if let Some(ip) = parse_special_ipv4(host) {
        return Some(ip.to_string());
    }

    None
}

/// Parse special IPv4 formats (octal, hex, decimal)
fn parse_special_ipv4(host: &str) -> Option<Ipv4Addr> {
    // Handle space-terminated IP (Windows resolver quirk)
    let host = if host.len() <= 15 {
        host.split_whitespace().next().unwrap_or(host)
    } else {
        host
    };

    // Check if it could be an IP
    if !host
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == 'x' || c == 'X')
    {
        return None;
    }

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }

    let mut octets = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let remaining_parts = 4 - parts.len() + i;
        let num = parse_numeric_part(part, remaining_parts)?;

        if i == parts.len() - 1 {
            // Last part can represent multiple octets
            for j in 0..remaining_parts {
                octets.push(((num >> (8 * (remaining_parts - 1 - j))) & 0xff) as u8);
            }
        } else {
            if num > 255 {
                return None;
            }
            octets.push(num as u8);
        }
    }

    if octets.len() == 4 {
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    } else {
        None
    }
}

/// Parse numeric part (supports decimal, octal, hex)
fn parse_numeric_part(part: &str, bytes_needed: usize) -> Option<u64> {
    if part.is_empty() {
        return None;
    }

    let max_value = (1u64 << (8 * bytes_needed)) - 1;

    let num = if part.starts_with("0x") || part.starts_with("0X") {
        // Hexadecimal
        u64::from_str_radix(&part[2..], 16).ok()?
    } else if part.starts_with('0') && part.len() > 1 {
        // Octal
        u64::from_str_radix(part, 8).ok()?
    } else {
        // Decimal
        part.parse::<u64>().ok()?
    };

    if num <= max_value {
        Some(num)
    } else {
        None
    }
}

/// Canonicalize URL path
fn canonical_path(parsed: &ParsedUrl) -> String {
    let path = &parsed.path;

    // Handle query strings
    let (path_part, query_part) = if let Some(pos) = path.find('?') {
        (&path[..pos], Some(&path[pos..]))
    } else {
        (path.as_str(), None)
    };

    // Normalize path
    let normalized = normalize_path_segments(path_part);

    // Add query back if it existed and is not empty
    if let Some(query) = query_part {
        if query.len() > 1 {
            // More than just "?"
            normalized + query
        } else {
            normalized
        }
    } else {
        normalized
    }
}

/// Normalize path segments (handle . and ..)
fn normalize_path_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let mut result = Vec::new();

    for segment in segments {
        match segment {
            "" | "." => {
                // Skip empty and current directory segments
                if result.is_empty() {
                    result.push("");
                }
            }
            ".." => {
                // Parent directory
                if !result.is_empty() && result.last() != Some(&"..") {
                    result.pop();
                }
            }
            _ => {
                result.push(segment);
            }
        }
    }

    let normalized = result.join("/");

    // Ensure path starts with /
    if !normalized.starts_with('/') {
        format!("/{}", normalized)
    } else if path.ends_with('/') && !normalized.ends_with('/') && normalized != "/" {
        format!("{}/", normalized)
    } else {
        normalized
    }
}

/// Generate host suffixes for lookup
fn generate_lookup_hosts(url_str: &str) -> Result<Vec<String>> {
    let parsed = parse_url(url_str)?;
    let host = canonical_host(&parsed)?;

    // Handle IP addresses
    if host.parse::<IpAddr>().is_ok() || (host.starts_with('[') && host.ends_with(']')) {
        return Ok(vec![host]);
    }

    let parts: Vec<&str> = host.split('.').collect();
    let mut hosts = vec![host.clone()];

    // Generate host suffixes (up to MAX_HOST_COMPONENTS)
    let start_index = if parts.len() > MAX_HOST_COMPONENTS {
        parts.len() - MAX_HOST_COMPONENTS
    } else {
        1
    };

    for i in start_index..parts.len() - 1 {
        hosts.push(parts[i..].join("."));
    }

    Ok(hosts)
}

/// Generate path prefixes for lookup
fn generate_lookup_paths(url_str: &str) -> Result<Vec<String>> {
    let parsed = parse_url(url_str)?;
    let path = canonical_path(&parsed);

    // Split path and query
    let (path_part, query_part) = if let Some(pos) = path.find('?') {
        (&path[..pos], Some(&path[pos..]))
    } else {
        (path.as_str(), None)
    };

    let mut paths = vec!["/".to_string()];

    // Split path into components
    let components: Vec<&str> = path_part.split('/').filter(|s| !s.is_empty()).collect();

    // Generate path prefixes (up to MAX_PATH_COMPONENTS)
    let max_components = std::cmp::min(components.len(), MAX_PATH_COMPONENTS);

    for i in 1..max_components {
        let prefix = format!("/{}/", components[..i].join("/"));
        paths.push(prefix);
    }

    // Add the full path (without query)
    if path_part != "/" {
        paths.push(path_part.to_string());
    }

    // Add path with query if present
    if let Some(query) = query_part {
        if query.len() > 1 {
            // More than just "?"
            paths.push(format!("{}{}", path_part, query));
        }
    }

    // Remove duplicates while preserving order
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));

    Ok(paths)
}

/// Get canonical host from parsed URL
fn canonical_host(parsed: &ParsedUrl) -> Result<String> {
    Ok(parsed.host.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url() {
        assert!(validate_url("http://example.com"));
        assert!(validate_url("https://example.com/path"));
        assert!(validate_url("example.com"));
        assert!(!validate_url(""));
        assert!(!validate_url("://invalid"));
    }

    #[test]
    fn test_canonicalize_url() {
        assert_eq!(
            canonicalize_url("http://Example.COM/Path").unwrap(),
            "http://example.com/Path"
        );
        assert_eq!(
            canonicalize_url("example.com").unwrap(),
            "http://example.com/"
        );
        assert_eq!(
            canonicalize_url("http://example.com:80/").unwrap(),
            "http://example.com/"
        );
    }

    #[test]
    fn test_generate_patterns() {
        let patterns = generate_patterns("http://a.b.c/1/2.html").unwrap();
        assert!(patterns.contains(&"a.b.c/1/2.html".to_string()));
        assert!(patterns.contains(&"a.b.c/1/".to_string()));
        assert!(patterns.contains(&"a.b.c/".to_string()));
        assert!(patterns.contains(&"b.c/1/2.html".to_string()));
        assert!(patterns.contains(&"b.c/1/".to_string()));
        assert!(patterns.contains(&"b.c/".to_string()));
    }

    #[test]
    fn test_unescape() {
        assert_eq!(unescape("hello%20world"), "hello world");
        assert_eq!(unescape("test%2Bstring"), "test+string");
        assert_eq!(unescape("no%escape"), "no%escape");
    }

    #[test]
    fn test_escape() {
        assert_eq!(escape("hello world"), "hello%20world");
        assert_eq!(escape("test#hash"), "test%23hash");
        assert_eq!(escape("normal"), "normal");
    }

    #[test]
    fn test_parse_special_ipv4() {
        assert_eq!(
            parse_special_ipv4("192.168.1.1"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parse_special_ipv4("0x12.0x34.0x56.0x78"),
            Some(Ipv4Addr::new(18, 52, 86, 120))
        );
        assert_eq!(
            parse_special_ipv4("3232235777"), // 192.168.1.1 as decimal
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_normalize_path_segments() {
        assert_eq!(normalize_path_segments("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path_segments("/a/./b"), "/a/b");
        assert_eq!(normalize_path_segments("/a//b"), "/a/b");
        assert_eq!(normalize_path_segments("/a/b/"), "/a/b/");
    }

    #[test]
    fn test_generate_lookup_hosts() {
        let hosts = generate_lookup_hosts("http://a.b.c.d/path").unwrap();
        assert_eq!(hosts, vec!["a.b.c.d", "b.c.d", "c.d"]);

        let hosts = generate_lookup_hosts("http://192.168.1.1/path").unwrap();
        assert_eq!(hosts, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_generate_lookup_paths() {
        let paths = generate_lookup_paths("http://example.com/a/b/c.html?query=1").unwrap();
        assert!(paths.contains(&"/".to_string()));
        assert!(paths.contains(&"/a/".to_string()));
        assert!(paths.contains(&"/a/b/".to_string()));
        assert!(paths.contains(&"/a/b/c.html".to_string()));
        assert!(paths.contains(&"/a/b/c.html?query=1".to_string()));
    }

    #[test]
    fn test_remove_userinfo() {
        assert_eq!(remove_userinfo("user:pass@example.com"), "example.com");
        assert_eq!(remove_userinfo("example.com"), "example.com");
        assert_eq!(remove_userinfo("user@example.com"), "example.com");
    }

    #[test]
    fn test_remove_port() {
        assert_eq!(remove_port("example.com:8080"), "example.com");
        assert_eq!(remove_port("example.com"), "example.com");
        assert_eq!(remove_port("[::1]:8080"), "[::1]");
        assert_eq!(remove_port("[::1]"), "[::1]");
    }
}
