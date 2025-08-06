//! Command-line Safe Browsing URL lookup tool
//!
//! This tool allows checking URLs for threats using the Safe Browsing API.

use safebrowsing::{Config, SafeBrowser};
use std::env;
use std::io::{self, BufRead};
use std::time::Duration;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let mut api_key = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-apikey" => {
                if i + 1 < args.len() {
                    api_key = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: -apikey requires a value");
                    std::process::exit(1);
                }
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                return Ok(());
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_usage(&args[0]);
                std::process::exit(1);
            }
        }
    }

    if api_key.is_empty() {
        eprintln!("Error: API key is required. Use -apikey <key>");
        print_usage(&args[0]);
        std::process::exit(1);
    }

    // Configure Safe Browser
    let config = Config {
        api_key,
        client_id: "GoSafeBrowserSystemTest".to_string(),
        client_version: "1.0.0".to_string(),
        update_period: Duration::from_secs(10),
        ..Default::default()
    };

    // Initialize Safe Browser
    let mut sb = match SafeBrowser::new(config).await {
        Ok(sb) => sb,
        Err(e) => {
            eprintln!("Error initializing Safe Browser: {}", e);
            std::process::exit(1);
        }
    };

    // Wait for database to be ready
    if let Err(e) = sb.wait_until_ready().await {
        eprintln!("Error waiting for database: {}", e);
        std::process::exit(1);
    }

    // Read URLs from stdin and check them
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let url = match line {
            Ok(url) => url.trim().to_string(),
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                continue;
            }
        };

        if url.is_empty() {
            continue;
        }

        match sb.lookup_urls(&[url.clone()]).await {
            Ok(results) => {
                if let Some(threats) = results.get(0) {
                    if !threats.is_empty() {
                        println!("Unsafe URL found: {} {:?}", url, threats);
                    } else {
                        println!("Safe: {}", url);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error checking URL {}: {}", url, e);
            }
        }
    }

    // Clean up
    if let Err(e) = sb.close().await {
        eprintln!("Error closing Safe Browser: {}", e);
    }

    Ok(())
}

fn print_usage(program_name: &str) {
    println!("Usage: {} -apikey <API_KEY>", program_name);
    println!();
    println!("Options:");
    println!("  -apikey <key>    Google Safe Browsing API key (required)");
    println!("  -h, --help       Show this help message");
    println!();
    println!("Example:");
    println!(
        "  echo 'http://example.com' | {} -apikey YOUR_API_KEY",
        program_name
    );
}
