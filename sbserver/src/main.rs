//! Safe Browsing proxy server
//!
//! This server provides a local proxy for Safe Browsing API lookups and includes
//! an URL redirector with interstitial warning pages.

use clap::{Parser, ValueEnum};
use safebrowsing::{Config, DatabaseType, SafeBrowser};
use safebrowsing_api::{PlatformType, ThreatDescriptor, ThreatEntryType, ThreatType};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "sbserver")]
struct Cli {
    /// Google Safe Browsing API key
    #[arg(long, env = "SAFEBROWSING_API_KEY")]
    api_key: String,

    /// Server bind address
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind_addr: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Database type to use
    #[arg(long, value_enum, default_value_t = DatabaseTypeArg::Redb)]
    database_type: DatabaseTypeArg,

    /// Update period in seconds for threat lists
    #[arg(long, default_value_t = 1800)]
    update_period: u64,

    /// Client ID for API requests
    #[arg(long, default_value = env!("CARGO_PKG_NAME"))]
    client_id: String,

    /// Client version for API requests
    #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
    client_version: String,
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

/// Request body for threat matches API
#[derive(Debug, Deserialize, Serialize)]
struct ThreatMatchesRequest {
    threat_info: ThreatInfo,
}

/// Threat info for API requests
#[derive(Debug, Deserialize, Serialize)]
struct ThreatInfo {
    threat_types: Vec<String>,
    platform_types: Vec<String>,
    threat_entry_types: Vec<String>,
    threat_entries: Vec<ThreatEntry>,
}

/// Threat entry for API requests
#[derive(Debug, Deserialize, Serialize)]
struct ThreatEntry {
    url: String,
}

/// Response for threat matches API
#[derive(Debug, Serialize)]
struct ThreatMatchesResponse {
    matches: Vec<Match>,
}

/// Match in threat matches response
#[derive(Debug, Serialize)]
struct Match {
    threat_type: String,
    platform_type: String,
    threat_entry_type: String,
    threat: ThreatEntry,
    cache_duration: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Configure logging
    if cli.verbose {
        tracing_subscriber::fmt::init();
        info!("Verbose logging enabled");
    } else {
        tracing_subscriber::fmt::init();
    }

    // Configure Safe Browser
    let config = Config {
        api_key: cli.api_key,
        client_id: cli.client_id,
        client_version: cli.client_version,
        database_type: Some(cli.database_type.into()),
        update_period: Duration::from_secs(cli.update_period),
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

    // Initialize Safe Browser
    let sb = SafeBrowser::new(config).await.map_err(|e| {
        error!("Failed to initialize Safe Browser: {}", e);
        e
    })?;

    info!("Waiting for database to be ready...");

    // Wait for database to be ready
    sb.wait_until_ready().await.map_err(|e| {
        error!("Database failed to become ready: {}", e);
        e
    })?;

    let safe_browser = Arc::new(RwLock::new(sb));

    // Parse bind address
    let addr: SocketAddr = cli.bind_addr.parse().map_err(|e| {
        error!("Invalid bind address {}: {}", cli.bind_addr, e);
        e
    })?;

    // Start TCP listener
    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        error!("Failed to bind to {}: {}", addr, e);
        e
    })?;

    info!("Safe Browsing server listening on {}", addr);
    info!("API endpoint: http://{}/v4/threatMatches:find", addr);
    info!("Redirector endpoint: http://{}/r?url=<URL>", addr);

    // Simple HTTP server loop
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                info!("New connection from: {}", client_addr);
                let sb_clone = Arc::clone(&safe_browser);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, sb_clone).await {
                        error!("Error handling connection from {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    safe_browser: Arc<RwLock<SafeBrowser>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Buffer to read the request
    let mut buffer = [0; 8192];
    let mut request_data = Vec::new();

    // Read HTTP request
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        request_data.extend_from_slice(&buffer[..n]);

        // Check if we've read the entire HTTP request
        if request_data.len() >= 4 && &request_data[request_data.len() - 4..] == b"\r\n\r\n" {
            break;
        }

        // Safety check to prevent buffer overflow
        if request_data.len() > 1024 * 1024 {
            // 1MB limit
            return Err("Request too large".into());
        }
    }

    // Convert request data to string
    let request_str = String::from_utf8_lossy(&request_data);
    let request_lines: Vec<&str> = request_str.split("\r\n").collect();

    if request_lines.is_empty() {
        return Err("Empty request".into());
    }

    // Parse the request line
    let request_parts: Vec<&str> = request_lines[0].split_whitespace().collect();
    if request_parts.len() < 3 {
        return Err("Invalid request line".into());
    }

    let method = request_parts[0];
    let path = request_parts[1];

    // Extract request content
    let mut content_length = 0;
    let mut content_type = "";
    for line in &request_lines[1..] {
        if let Some(cl) = line.strip_prefix("Content-Length: ") {
            content_length = cl.parse::<usize>().unwrap_or(0);
        } else if let Some(ct) = line.strip_prefix("Content-Type: ") {
            content_type = ct;
        }
    }

    // Read body if necessary
    let mut body = Vec::new();
    if content_length > 0 {
        // We might have already read part of the body
        let header_end = request_data
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .unwrap_or(request_data.len());

        if header_end < request_data.len() {
            // We already have part of the body
            body.extend_from_slice(&request_data[header_end..]);
        }

        // Read remaining body
        while body.len() < content_length {
            let mut buf = [0; 8192];
            let bytes_to_read = std::cmp::min(8192, content_length - body.len());
            let n = stream.read(&mut buf[..bytes_to_read]).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
    }

    // Handle different endpoints
    match (method, path) {
        ("GET", "/") => {
            let response = "HTTP/1.1 200 OK\r\n\
                          Content-Type: text/html\r\n\
                          Connection: close\r\n\
                          \r\n\
                          <html><body>\
                          <h1>Safe Browsing Server</h1>\
                          <p>Server is running! Try the following endpoints:</p>\
                          <ul>\
                          <li>POST /v4/threatMatches:find - Check URLs</li>\
                          <li>GET /r?url=URL - URL redirector with warning</li>\
                          </ul>\
                          </body></html>";
            stream.write_all(response.as_bytes()).await?;
        }

        ("GET", path) if path.starts_with("/r?") => {
            // URL redirector
            if let Some(url_param) = path.strip_prefix("/r?url=") {
                let url = url_param.split('&').next().unwrap_or("");
                let decoded_url = urlencoding::decode(url).unwrap_or_else(|_| url.into());

                let sb = safe_browser.read().await;
                let result = sb.lookup_urls(&[decoded_url.to_string()]).await?;

                if let Some(threats) = result.first() {
                    if threats.is_empty() {
                        // Safe URL, redirect
                        let response = format!(
                            "HTTP/1.1 302 Found\r\n\
                             Location: {decoded_url}\r\n\
                             Connection: close\r\n\
                             \r\n"
                        );
                        stream.write_all(response.as_bytes()).await?;
                    } else {
                        // Unsafe URL, show warning
                        let threat_types = threats
                            .iter()
                            .map(|t| format!("{}", t.threat_descriptor.threat_type))
                            .collect::<Vec<_>>()
                            .join(", ");

                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/html\r\n\
                             Connection: close\r\n\
                             \r\n\
                             <html><body>\
                             <h1>⚠️ Warning: Unsafe Site Detected</h1>\
                             <p>The site you are trying to visit may be dangerous:</p>\
                             <p><strong>{decoded_url}</strong></p>\
                             <p>Threat types: {threat_types}</p>\
                             <p>This site may harm your computer or attempt to steal personal information.</p>\
                             <form action=\"{decoded_url}\" method=\"get\">\
                             <p><button type=\"submit\">Proceed anyway (not recommended)</button></p>\
                             </form>\
                             <p><a href=\"/\">Return to safety</a></p>\
                             </body></html>"
                        );
                        stream.write_all(response.as_bytes()).await?;
                    }
                } else {
                    // Error checking URL
                    let response = "HTTP/1.1 400 Bad Request\r\n\
                                  Content-Type: text/html\r\n\
                                  Connection: close\r\n\
                                  \r\n\
                                  <html><body>\
                                  <h1>Error</h1>\
                                  <p>Could not check URL safety.</p>\
                                  </body></html>";
                    stream.write_all(response.as_bytes()).await?;
                }
            } else {
                // Missing URL parameter
                let response = "HTTP/1.1 400 Bad Request\r\n\
                              Content-Type: text/html\r\n\
                              Connection: close\r\n\
                              \r\n\
                              <html><body>\
                              <h1>Error</h1>\
                              <p>Missing URL parameter. Use /r?url=http://example.com</p>\
                              </body></html>";
                stream.write_all(response.as_bytes()).await?;
            }
        }

        ("POST", "/v4/threatMatches:find") => {
            // API endpoint for checking URLs
            if content_type.contains("application/json") {
                let body_str = String::from_utf8_lossy(&body);
                match serde_json::from_str::<ThreatMatchesRequest>(&body_str) {
                    Ok(request) => {
                        let urls: Vec<String> = request
                            .threat_info
                            .threat_entries
                            .iter()
                            .map(|entry| entry.url.clone())
                            .collect();

                        let sb = safe_browser.read().await;
                        let results = sb.lookup_urls(&urls).await?;

                        // Build response
                        let mut matches = Vec::new();
                        for (url, threats) in urls.iter().zip(results.iter()) {
                            for threat in threats {
                                matches.push(Match {
                                    threat_type: format!(
                                        "{}",
                                        threat.threat_descriptor.threat_type
                                    ),
                                    platform_type: format!(
                                        "{}",
                                        threat.threat_descriptor.platform_type
                                    ),
                                    threat_entry_type: format!(
                                        "{}",
                                        threat.threat_descriptor.threat_entry_type
                                    ),
                                    threat: ThreatEntry { url: url.clone() },
                                    cache_duration: "300s".to_string(),
                                });
                            }
                        }

                        let response_body = ThreatMatchesResponse { matches };
                        let json_response = serde_json::to_string(&response_body)?;

                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            json_response.len(),
                            json_response
                        );
                        stream.write_all(response.as_bytes()).await?;
                    }
                    Err(e) => {
                        // Invalid JSON
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\n\
                             Content-Type: application/json\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {{\"error\": \"Invalid request format: {e}\"}}"
                        );
                        stream.write_all(response.as_bytes()).await?;
                    }
                }
            } else {
                // Unsupported content type
                let response = "HTTP/1.1 415 Unsupported Media Type\r\n\
                              Content-Type: application/json\r\n\
                              Connection: close\r\n\
                              \r\n\
                              {\"error\": \"Content-Type must be application/json\"}";
                stream.write_all(response.as_bytes()).await?;
            }
        }

        _ => {
            // Not found
            let response = "HTTP/1.1 404 Not Found\r\n\
                          Content-Type: text/html\r\n\
                          Connection: close\r\n\
                          \r\n\
                          <html><body>\
                          <h1>404 Not Found</h1>\
                          <p>The requested resource was not found.</p>\
                          </body></html>";
            stream.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}
