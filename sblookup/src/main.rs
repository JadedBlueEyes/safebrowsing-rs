//! Command-line Safe Browsing URL lookup tool
//!
//! This tool allows checking URLs for threats using the Safe Browsing API.

use clap::{Parser, ValueEnum};
use safebrowsing::{Config, DatabaseType, SafeBrowser};
use safebrowsing_api::{PlatformType, ThreatDescriptor, ThreatEntryType, ThreatType};
use std::io::{self, BufRead};
use std::time::Duration;
use tracing::{error, info, trace, warn};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "sblookup")]
struct Cli {
    /// Google Safe Browsing API key
    #[arg(long, env = "SAFEBROWSING_API_KEY")]
    api_key: String,

    /// Enable database statistics
    #[arg(short, long)]
    stats: bool,

    /// Database type to use
    #[arg(long, value_enum, default_value_t = DatabaseTypeArg::Redb)]
    database_type: DatabaseTypeArg,

    /// Update period in seconds
    #[arg(long, default_value_t = 300)]
    update_period: u64,

    /// Client ID for API requests
    #[arg(long, default_value = env!("CARGO_PKG_NAME"))]
    client_id: String,

    /// Client version for API requests
    #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
    client_version: String,

    /// URLs to check (if not provided, reads from stdin)
    urls: Vec<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum DatabaseTypeArg {
    /// Use in-memory database
    InMemory,
    /// Use thread-safe concurrent database
    Concurrent,
    /// Use persistent redb-based database
    Redb,
}

impl From<DatabaseTypeArg> for DatabaseType {
    fn from(arg: DatabaseTypeArg) -> Self {
        match arg {
            DatabaseTypeArg::InMemory => DatabaseType::InMemory,
            DatabaseTypeArg::Concurrent => DatabaseType::Concurrent,
            DatabaseTypeArg::Redb => DatabaseType::Redb,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Configure logging
    tracing_subscriber::fmt::init();

    // Configure Safe Browser
    let config = Config {
        api_key: cli.api_key,
        client_id: cli.client_id,
        client_version: cli.client_version,
        update_period: Duration::from_secs(cli.update_period),
        database_type: Some(cli.database_type.into()),
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
        ..Default::default()
    };

    info!("Initializing Safe Browser...");
    // Instrumentation: measure time for SafeBrowser::new
    let init_start = std::time::Instant::now();

    // Initialize Safe Browser
    // Instrumentation: start SafeBrowser::new
    let mut sb = SafeBrowser::new(config).await.map_err(|e| {
        error!("Failed to initialize Safe Browser: {}", e);
        e
    })?;

    // Instrumentation: log duration of initialization
    let init_elapsed = init_start.elapsed();
    info!("SafeBrowser::new completed in {:?}", init_elapsed);
    info!("Waiting for database to be ready...");
    // Instrumentation: measure time for wait_until_ready
    let ready_start = std::time::Instant::now();

    // Wait for database to be ready
    // Instrumentation: waiting for database readiness
    sb.wait_until_ready().await.map_err(|e| {
        error!("Database failed to become ready: {}", e);
        e
    })?;

    // Instrumentation: log duration of wait_until_ready
    let ready_elapsed = ready_start.elapsed();
    info!("wait_until_ready completed in {:?}", ready_elapsed);
    info!("Safe Browser ready, starting URL checks");

    // Check URLs from command line arguments or stdin
    if !cli.urls.is_empty() {
        // Check URLs provided as arguments
        check_url(&mut sb, &cli.urls).await;
    } else {
        // Read URLs from stdin
        info!("Reading URLs from stdin...");
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let url = match line {
                Ok(url) => url.trim().to_string(),
                Err(e) => {
                    error!("Error reading input: {}", e);
                    continue;
                }
            };

            if url.is_empty() {
                continue;
            }

            check_url(&mut sb, &[url]).await;
        }
    }

    // Show database statistics
    if cli.stats {
        match sb.database_stats().await {
            Ok(stats) => info!("Database stats: {}", stats),
            Err(e) => warn!("Error getting database stats: {}", e),
        }
        info!("{:?}", sb.stats().await);
    }

    // Clean up
    if let Err(e) = sb.close().await {
        warn!("Error closing Safe Browser: {}", e);
    }

    Ok(())
}

async fn check_url(sb: &mut SafeBrowser, urls: &[impl AsRef<str> + std::fmt::Debug]) {
    // Instrumentation: measure time for lookup_urls
    let lookup_start = std::time::Instant::now();
    // Instrumentation: start lookup_urls
    match sb.lookup_urls(urls).await {
        Ok(results) => {
            for (url, threats) in urls.iter().zip(results) {
                if !threats.is_empty() {
                    info!("⚠️ UNSAFE: {} {}", url.as_ref(), format_threats(&threats));
                } else {
                    info!("✅ SAFE: {}", url.as_ref());
                }
            }
        }
        Err(e) => {
            // Instrumentation: log duration even on error
            let lookup_elapsed = lookup_start.elapsed();
            warn!(
                "lookup_urls for {:?} failed after {:?}",
                urls, lookup_elapsed
            );
            error!(
                "Error checking URLs {}: {}",
                urls.iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<_>>()
                    .join(", "),
                e
            );
            error!(
                "❌ ERROR: {} ({e})",
                urls.iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    // Instrumentation: on success, log duration
    let lookup_elapsed = lookup_start.elapsed();
    trace!(
        "lookup_urls for {:?} completed in {:?}",
        urls,
        lookup_elapsed
    );
}

fn format_threats(threats: &[safebrowsing_api::URLThreat]) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    for (i, threat) in threats.iter().enumerate() {
        if i > 0 {
            let _ = write!(&mut result, ", ");
        }
        let _ = write!(
            &mut result,
            "{} ({})",
            threat.threat_descriptor.threat_type, threat.threat_descriptor.platform_type
        );
    }
    result
}
