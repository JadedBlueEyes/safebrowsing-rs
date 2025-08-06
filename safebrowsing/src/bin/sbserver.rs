//! Safe Browsing proxy server
//!
//! This server provides a local proxy for Safe Browsing API lookups and includes
//! an URL redirector with interstitial warning pages.

use safebrowsing::{Config, SafeBrowser};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let mut api_key = String::new();
    let mut bind_addr = "127.0.0.1:8080".to_string();

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
            "-addr" => {
                if i + 1 < args.len() {
                    bind_addr = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: -addr requires a value");
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
        client_id: "SafeBrowsingServer".to_string(),
        client_version: "1.0.0".to_string(),
        update_period: Duration::from_secs(30 * 60), // 30 minutes
        ..Default::default()
    };

    // Initialize Safe Browser
    let sb = match SafeBrowser::new(config).await {
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

    let safe_browser = Arc::new(RwLock::new(sb));

    // Parse bind address
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Error parsing bind address {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };

    // Start TCP listener
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Error binding to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    println!("Safe Browsing server listening on {}", addr);
    println!("API endpoint: http://{}/v4/threatMatches:find", addr);
    println!("Redirector endpoint: http://{}/r?url=<URL>", addr);

    // Simple HTTP server loop (placeholder implementation)
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from: {}", addr);
                let sb_clone = Arc::clone(&safe_browser);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, sb_clone).await {
                        eprintln!("Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    _stream: tokio::net::TcpStream,
    _safe_browser: Arc<RwLock<SafeBrowser>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Placeholder HTTP request handling
    // In a real implementation, this would:
    // 1. Parse HTTP requests
    // 2. Handle /v4/threatMatches:find POST requests with JSON
    // 3. Handle /r redirector requests with URL parameter
    // 4. Serve static interstitial warning pages
    // 5. Return appropriate HTTP responses

    println!("Connection handled (placeholder)");
    Ok(())
}

fn print_usage(program_name: &str) {
    println!("Usage: {} -apikey <API_KEY> [options]", program_name);
    println!();
    println!("Options:");
    println!("  -apikey <key>    Google Safe Browsing API key (required)");
    println!("  -addr <address>  Server bind address (default: 127.0.0.1:8080)");
    println!("  -h, --help       Show this help message");
    println!();
    println!("Endpoints:");
    println!("  POST /v4/threatMatches:find  - Safe Browsing API proxy");
    println!("  GET  /r?url=<URL>           - URL redirector with warnings");
    println!();
    println!("Example:");
    println!("  {} -apikey YOUR_API_KEY -addr 0.0.0.0:8080", program_name);
}
