# Safe Browsing API Client for Rust

[![Build Status](https://github.com/your-org/safebrowsing-rs/workflows/CI/badge.svg)](https://github.com/your-org/safebrowsing-rs/actions)
[![Crates.io](https://img.shields.io/crates/v/safebrowsing.svg)](https://crates.io/crates/safebrowsing)
[![Documentation](https://docs.rs/safebrowsing/badge.svg)](https://docs.rs/safebrowsing)

A Rust implementation of the [Google Safe Browsing Update API (v4)](https://developers.google.com/safe-browsing/v4/). This library allows you to check URLs against Google's constantly updated lists of unsafe web resources.

## Features

- **Asynchronous API** using tokio for high performance
- **Pluggable database backends** for flexible storage options
- **Built-in caching** with TTL support to reduce API calls
- **URL canonicalization** and pattern generation according to Safe Browsing specs
- **Support for all threat types**: Malware, Social Engineering, Unwanted Software, and Potentially Harmful Applications
- **Comprehensive error handling** with retryable and permanent error classification
- **Command-line tools** for URL checking and proxy server

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
safebrowsing = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use safebrowsing::{SafeBrowser, Config, ThreatType, PlatformType, ThreatEntryType};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        api_key: "your-google-api-key".to_string(),
        client_id: "your-client-id".to_string(),
        client_version: "1.0.0".to_string(),
        update_period: Duration::from_secs(1800), // 30 minutes
        threat_lists: vec![
            (ThreatType::Malware, PlatformType::AnyPlatform, ThreatEntryType::Url),
            (ThreatType::SocialEngineering, PlatformType::AnyPlatform, ThreatEntryType::Url),
        ],
        ..Default::default()
    };

    let mut sb = SafeBrowser::new(config).await?;
    sb.wait_until_ready().await?;

    let urls = vec!["http://example.com/suspicious", "https://google.com"];
    let threats = sb.lookup_urls(&urls).await?;

    for (url, threat_matches) in urls.iter().zip(threats.iter()) {
        if !threat_matches.is_empty() {
            println!("⚠️  {} is unsafe: {:?}", url, threat_matches);
        } else {
            println!("✅ {} is safe", url);
        }
    }

    sb.close().await?;
    Ok(())
}
```

### Custom Database Backend

The library supports pluggable database backends:

```rust
use safebrowsing::{SafeBrowser, Config, InMemoryDatabase, ConcurrentDatabase};
use std::sync::Arc;
use tokio::sync::RwLock;

// Using the built-in concurrent database
let db = Arc::new(RwLock::new(ConcurrentDatabase::new()));
let sb = SafeBrowser::with_database(config, db).await?;
```

## Command Line Tools

### sblookup

A command-line tool for checking URLs from stdin:

```bash
cargo install safebrowsing --features=bin

echo "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/" | sblookup -apikey YOUR_API_KEY
```

### sbserver

A local proxy server that provides Safe Browsing API endpoints:

```bash
sbserver -apikey YOUR_API_KEY -addr 0.0.0.0:8080
```

The server provides:
- `POST /v4/threatMatches:find` - Safe Browsing API proxy
- `GET /r?url=<URL>` - URL redirector with interstitial warning pages

## Configuration

### API Key Setup

1. Visit the [Google Developer Console](https://console.developers.google.com/)
2. Create a new project or select an existing one
3. Enable the Safe Browsing API
4. Create credentials (API key)
5. Optionally restrict the API key to Safe Browsing API only

### Threat Lists

The library supports all Safe Browsing threat types:

```rust
use safebrowsing::types::{ThreatType, PlatformType, ThreatEntryType, ThreatDescriptor};

let threat_lists = vec![
    // Web threats (most common)
    ThreatDescriptor::new(ThreatType::Malware, PlatformType::AnyPlatform, ThreatEntryType::Url),
    ThreatDescriptor::new(ThreatType::SocialEngineering, PlatformType::AnyPlatform, ThreatEntryType::Url),
    ThreatDescriptor::new(ThreatType::UnwantedSoftware, PlatformType::AnyPlatform, ThreatEntryType::Url),
    
    // Android-specific threats
    ThreatDescriptor::new(ThreatType::PotentiallyHarmfulApplication, PlatformType::Android, ThreatEntryType::Url),
];
```

## Architecture

The library is built with modularity in mind:

- **SafeBrowser**: Main client that orchestrates all components
- **API Client**: HTTP client for communicating with Google's servers
- **Database**: Pluggable storage for threat lists (in-memory, file-based, etc.)
- **Cache**: TTL-based caching to reduce API calls
- **URL Processing**: Canonicalization and pattern generation
- **Hash Operations**: Efficient hash prefix storage and lookup

## Performance

- **Asynchronous**: Built on tokio for high concurrency
- **Efficient Storage**: Optimized hash set implementation for fast lookups
- **Smart Caching**: Reduces API calls while respecting TTL requirements
- **Batch Operations**: Support for bulk URL checking

## Error Handling

The library provides comprehensive error handling with classification:

```rust
use safebrowsing::Error;

match sb.lookup_urls(&urls).await {
    Ok(results) => { /* handle results */ },
    Err(e) => {
        if e.is_retryable() {
            // Temporary error, retry later
            eprintln!("Temporary error: {}", e);
        } else if e.is_permanent() {
            // Permanent error, don't retry
            eprintln!("Permanent error: {}", e);
        } else {
            eprintln!("Error: {}", e);
        }
    }
}
```

## Testing

Run the test suite:

```bash
cargo test
```

Run with nextest for better output:

```bash
cargo nextest run
```

Format code:

```bash
cargo fmt
```

Run clippy for linting:

```bash
cargo clippy
```

## Examples

See the `examples/` directory for more comprehensive examples:

- `examples/basic.rs` - Basic URL checking
- `examples/server.rs` - Running a Safe Browsing proxy server
- `examples/custom_db.rs` - Using custom database backends

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Clone the repository
2. Install Rust (latest stable)
3. Install protoc: `brew install protobuf` (macOS) or equivalent
4. Run tests: `cargo test`

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgments

This implementation is based on the reference Go implementation by Google and follows the Safe Browsing API v4 specification. Special thanks to the Google Safe Browsing team for providing comprehensive documentation and test cases.

## Safety and Disclaimer

This library is designed for legitimate security applications. Please use responsibly and in accordance with Google's Safe Browsing API terms of service. The authors are not responsible for any misuse of this software.