# safebrowsing-db-redb

A persistent database backend for the Safe Browsing API using [redb](https://github.com/cberner/redb).

## Overview

This crate provides a `RedbDatabase` implementation that stores Google Safe Browsing threat lists persistently on disk using the redb embedded database. Unlike the in-memory databases, this implementation:

- **Persists data between restarts** - No need to re-download threat lists every time
- **Stores data in system cache directory** - Uses platform-appropriate cache locations
- **Thread-safe with ACID transactions** - Safe for concurrent access
- **Efficient storage** - Compressed binary format with fast lookups

## Features

- Implements the `Database` trait from `safebrowsing-db`
- Automatic cache directory management
- Efficient hash prefix storage and lookup
- Metadata tracking (last update time, initialization status, etc.)
- Compatible with all Safe Browsing threat list types

## Usage

### Basic Usage

```rust
use safebrowsing_db_redb::RedbDatabase;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create database in default system cache location
    let mut db = RedbDatabase::default();

    // Or specify a custom path
    let mut db = RedbDatabase::new("/path/to/database.redb")?;

    // Use with Safe Browsing API
    // (Database trait methods available)
    Ok(())
}
```

### With SafeBrowser

```rust
use safebrowsing::{Config, DatabaseType, SafeBrowser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        api_key: "your-api-key".to_string(),
        database_type: Some(DatabaseType::Redb),
        ..Default::default()
    };

    let mut sb = SafeBrowser::new(config).await?;
    // Database will be automatically stored in system cache
    Ok(())
}
```

### Command Line Tool

The `sblookup` tool supports the redb backend:

```bash
# Use persistent redb database
sblookup --database-type redb --api-key YOUR_API_KEY example.com

# Database will be stored in:
# - Linux: ~/.cache/safebrowsing/database.redb
# - macOS: ~/Library/Caches/safebrowsing/database.redb
# - Windows: %LOCALAPPDATA%/safebrowsing/database.redb
```

## Storage Location

By default, the database is stored in the system cache directory:

- **Linux**: `~/.cache/safebrowsing/database.redb`
- **macOS**: `~/Library/Caches/safebrowsing/database.redb`
- **Windows**: `%LOCALAPPDATA%\safebrowsing\database.redb`

You can override this by providing a custom path to `RedbDatabase::new()`.

## Database Schema

The redb database uses three tables:

- **`threat_lists`**: Stores serialized threat list entries with hash prefixes
- **`metadata`**: Stores database metadata (last update time, initialization status, etc.)
- **`hashes`**: Reserved for future use (direct hash lookups)

## Performance

- **First run**: Downloads and stores threat lists (may take a few minutes)
- **Subsequent runs**: Fast startup using cached data
- **Updates**: Incremental updates from Google's API
- **Lookups**: Fast hash prefix lookups with in-memory caching

## Thread Safety

The `RedbDatabase` is thread-safe and supports concurrent reads and writes through redb's ACID transaction system. Multiple processes can safely access the same database file.

## Error Handling

The implementation maps redb errors to `DatabaseError` types:

- `DatabaseError::IoError` - File system or permission errors
- `DatabaseError::DecodeError` - Serialization/deserialization errors
- `DatabaseError::Stale` - Database needs updating
- `DatabaseError::NotReady` - Database not initialized

## Requirements

- Rust 1.70+
- Tokio async runtime
- Read/write access to cache directory

## Dependencies

- `redb` - Embedded database engine
- `dirs` - System directory detection
- `serde` - Serialization framework
- `tokio` - Async runtime
- `safebrowsing-*` - Safe Browsing API components

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
