//! Basic usage example for RedbDatabase
//!
//! This example demonstrates how to create and use a RedbDatabase
//! for storing Safe Browsing threat lists persistently.
//!
//! To run this example:
//! ```bash
//! cargo run --example basic_usage
//! ```

use safebrowsing_db::redb::RedbDatabase;
use safebrowsing_db::{Database, DatabaseStats};
use tempfile::tempdir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🗃️  RedbDatabase Basic Usage Example");
    println!("====================================\n");

    // Create a temporary directory for this example
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("example.redb");

    println!("📁 Creating database at: {}", db_path.display());

    // Create a new RedbDatabase
    let db = RedbDatabase::new(&db_path)?;

    // Initialize the database (loads existing data if any)
    db.init().await?;

    println!("✅ Database created and initialized");

    // Check if the database is ready
    let is_ready = db.is_ready().await?;
    println!("🔍 Database ready: {is_ready}");

    // Get initial statistics
    let stats = db.stats().await;
    print_stats("Initial", &stats);

    // Check database status
    match db.status().await {
        Ok(()) => println!("✅ Database status: OK"),
        Err(e) => println!("⚠️  Database status: {e}"),
    }

    // Get time since last update
    if let Some(duration) = db.time_since_last_update().await {
        println!("⏰ Time since last update: {duration:?}");
    } else {
        println!("⏰ No previous updates found");
    }

    // Example of how to use with the Safe Browsing API
    // (This part would require an API key and network access)
    println!("\n📚 Usage Notes:");
    println!("• To actually populate the database, you would need:");
    println!("  - A Google Safe Browsing API key");
    println!("  - Network connectivity");
    println!("  - Call db.update(api, threat_lists) with real API client");

    println!("\n• The database file persists between runs");
    println!("• Location: {}", db_path.display());
    println!("• Real usage stores in system cache directory");

    // Example of default path
    if let Ok(default_path) = RedbDatabase::default_path() {
        println!("• Default system path would be: {}", default_path.display());
    }

    println!("\n🎯 Next Steps:");
    println!("• Set SAFEBROWSING_API_KEY environment variable");
    println!("• Use with sblookup: cargo run --bin sblookup -- --database-type redb --help");
    println!("• Integrate into your application using the Database trait");

    Ok(())
}

fn print_stats(label: &str, stats: &DatabaseStats) {
    println!("\n📊 {label} Database Statistics:");
    println!("   • Total hashes: {}", stats.total_hashes);
    println!("   • Threat lists: {}", stats.threat_lists);
    println!("   • Memory usage: {} bytes", stats.memory_usage);
    println!("   • Is stale: {}", stats.is_stale);
    if let Some(last_update) = stats.last_update {
        println!("   • Last update: {:?} ago", last_update.elapsed());
    } else {
        println!("   • Last update: Never");
    }
}
