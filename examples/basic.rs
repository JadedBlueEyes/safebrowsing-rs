//! Basic usage example for the Safe Browsing API client
//!
//! This example demonstrates how to:
//! - Initialize the Safe Browsing client
//! - Check URLs for threats
//! - Handle different types of results
//!
//! Usage:
//!   cargo run --example basic -- YOUR_API_KEY

use safebrowsing::{
    Config, SafeBrowser, ThreatDescriptor, ThreatEntryType, ThreatType, PlatformType,
};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::init();

    // Get API key from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <API_KEY>", args[0]);
        eprintln!("Example: {} your-google-api-key", args[0]);
        std::process::exit(1);
    }
    let api_key = &args[1];

    println!("🔧 Initializing Safe Browsing client...");

    // Configure the Safe Browsing client
    let config = Config {
        api_key: api_key.clone(),
        client_id: env!("CARGO_PKG_NAME").to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        update_period: Duration::from_secs(30 * 60), // 30 minutes
        threat_lists: vec![
            ThreatDescriptor::new(
                ThreatType::Malware,
                PlatformType::AnyPlatform,
                ThreatEntryType::Url,
            ),
            ThreatDescriptor::new(
                ThreatType::SocialEngineering,
                PlatformType::AnyPlatform,
                ThreatEntryType::Url,
            ),
            ThreatDescriptor::new(
                ThreatType::UnwantedSoftware,
                PlatformType::AnyPlatform,
                ThreatEntryType::Url,
            ),
            ThreatDescriptor::new(
                ThreatType::PotentiallyHarmfulApplication,
                PlatformType::Android,
                ThreatEntryType::Url,
            ),
        ],
        ..Default::default()
    };

    // Initialize the Safe Browser
    let mut sb = SafeBrowser::new(config).await?;

    println!("⏳ Waiting for database to be ready...");
    sb.wait_until_ready().await?;

    println!("✅ Safe Browsing client is ready!");

    // Test URLs - mix of safe and unsafe
    let test_urls = vec![
        "https://www.google.com",
        "https://github.com",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/UNWANTED_SOFTWARE/URL/",
        "https://example.com",
        "https://rust-lang.org",
    ];

    println!("\n🔍 Checking URLs for threats...");
    println!("{}", "=".repeat(60));

    // Check each URL
    for url in &test_urls {
        print!("Checking: {} ... ", url);

        match sb.lookup_urls(&[url]).await {
            Ok(results) => {
                if let Some(threats) = results.get(0) {
                    if threats.is_empty() {
                        println!("✅ SAFE");
                    } else {
                        println!("⚠️ UNSAFE");
                        for threat in threats {
                            println!("  └─ Threat: {}", threat.threat_descriptor);
                        }
                    }
                } else {
                    println!("❓ NO RESULT");
                }
            }
            Err(e) => {
                println!("❌ ERROR: {}", e);

                // Demonstrate error handling
                if e.is_retryable() {
                    println!("  └─ This error is retryable");
                } else if e.is_permanent() {
                    println!("  └─ This error is permanent - don't retry");
                } else {
                    println!("  └─ Unknown error type");
                }
            }
        }
    }

    // Batch lookup example
    println!("\n📊 Performing batch lookup...");
    let batch_urls = vec![
        "https://www.google.com",
        "https://github.com",
        "https://stackoverflow.com",
    ];

    match sb.lookup_urls(&batch_urls).await {
        Ok(results) => {
            println!("Batch results:");
            for (url, threats) in batch_urls.iter().zip(results.iter()) {
                let status = if threats.is_empty() { "SAFE" } else { "UNSAFE" };
                println!("  {} -> {}", url, status);
            }
        }
        Err(e) => {
            eprintln!("Batch lookup failed: {}", e);
        }
    }

    // Show statistics
    let stats = sb.stats().await;
    println!("\n📈 Statistics:");
    println!("  Database queries: {}", stats.queries_by_database);
    println!("  Cache queries: {}", stats.queries_by_cache);
    println!("  API queries: {}", stats.queries_by_api);
    println!("  Failed queries: {}", stats.queries_fail);
    println!("  Database update lag: {:?}", stats.database_update_lag);

    // Check database status
    match sb.status().await {
        Ok(()) => println!("  Database status: ✅ Healthy"),
        Err(e) => println!("  Database status: ⚠️  {}", e),
    }

    println!("\n🔧 Shutting down...");
    sb.close().await?;

    println!("✅ Example completed successfully!");
    Ok(())
}
