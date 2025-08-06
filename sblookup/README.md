# sblookup

A command-line Safe Browsing URL lookup tool that allows checking URLs for threats using the Google Safe Browsing API.

## Installation

From the workspace root:

```bash
cargo build --bin sblookup
```

## Usage

### Basic Usage

Check URLs from command line arguments:

```bash
sblookup --api-key YOUR_API_KEY http://example.com https://malware.example.com
```

Check URLs from stdin:

```bash
echo "http://example.com" | sblookup --api-key YOUR_API_KEY
```

### Options

- `--api-key <API_KEY>`: Google Safe Browsing API key (required)
- `-s, --stats`: Output statistics
- `--database-type <TYPE>`: Database type to use (`in-memory` or `concurrent`)
- `--update-period <SECONDS>`: Update period in seconds (default: 10)
- `--client-id <ID>`: Client ID for API requests
- `--client-version <VERSION>`: Client version for API requests

### Environment Variables

You can also set the API key via environment variable:

```bash
export SAFEBROWSING_API_KEY=your_api_key_here
sblookup http://example.com
```

### Examples

Check a single URL:
```bash
sblookup --api-key YOUR_API_KEY https://example.com
```

Check multiple URLs with verbose output:
```bash
sblookup --api-key YOUR_API_KEY --verbose \
  https://example.com \
  https://malware.example.com \
  https://phishing.example.com
```

Check URLs from a file:
```bash
cat urls.txt | sblookup --api-key YOUR_API_KEY
```


## API Key

You need a Google Safe Browsing API key to use this tool. You can get one from the [Google Cloud Console](https://console.cloud.google.com/) by enabling the Safe Browsing API.
