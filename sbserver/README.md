# sbserver

A Safe Browsing proxy server that provides a local HTTP API for Safe Browsing URL lookups and includes a URL redirector with interstitial warning pages.

## Installation

From the workspace root:

```bash
cargo build --bin sbserver
```

## Usage

### Basic Usage

Start the server with your API key:

```bash
sbserver --api-key YOUR_API_KEY
```

Start the server on a specific address:

```bash
sbserver --api-key YOUR_API_KEY --bind-addr 0.0.0.0:8080
```

### Options

- `--api-key <API_KEY>`: Google Safe Browsing API key (required)
- `--bind-addr <BIND_ADDR>`: Server bind address (default: 127.0.0.1:8080)
- `-v, --verbose`: Enable verbose logging
- `--update-period <SECONDS>`: Update period in seconds for threat lists (default: 1800)
- `--client-id <ID>`: Client ID for API requests
- `--client-version <VERSION>`: Client version for API requests

### Environment Variables

You can set the API key via environment variable:

```bash
export SAFEBROWSING_API_KEY=your_api_key_here
sbserver --bind-addr 0.0.0.0:8080
```

## API Endpoints

### 1. Health Check

**GET /** - Returns a simple HTML page confirming the server is running.

### 2. Safe Browsing API Proxy

**POST /v4/threatMatches:find** - Compatible with Google Safe Browsing API format.

Request body:
```json
{
  "threatInfo": {
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
      {"url": "http://example.com"},
      {"url": "https://malware.example.com"}
    ]
  }
}
```

Response:
```json
{
  "matches": [
    {
      "threatType": "MALWARE",
      "platformType": "ANY_PLATFORM",
      "threatEntryType": "URL",
      "threat": {"url": "https://malware.example.com"},
      "cacheDuration": "300s"
    }
  ]
}
```

### 3. URL Redirector with Warnings

**GET /r?url=<URL>** - Checks URL safety and either redirects or shows warning page.

Examples:
- `GET /r?url=http%3A//example.com` - Safe URL, redirects immediately
- `GET /r?url=http%3A//malware.example.com` - Unsafe URL, shows warning page

## Examples

### Start Server

```bash
# Start on default address (127.0.0.1:8080)
sbserver --api-key YOUR_API_KEY

# Start on all interfaces
sbserver --api-key YOUR_API_KEY --bind-addr 0.0.0.0:8080

# Start with verbose logging
sbserver --api-key YOUR_API_KEY --verbose
```

### Test API Endpoint

```bash
curl -X POST http://localhost:8080/v4/threatMatches:find \
  -H "Content-Type: application/json" \
  -d '{
    "threatInfo": {
      "threatTypes": ["MALWARE"],
      "platformTypes": ["ANY_PLATFORM"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [{"url": "http://example.com"}]
    }
  }'
```

### Test URL Redirector

```bash
# Safe URL - will redirect
curl -i "http://localhost:8080/r?url=http%3A//example.com"

# Unsafe URL - will show warning page
curl -i "http://localhost:8080/r?url=http%3A//malware.example.com"
```

## Use Cases

### 1. Proxy for Applications

Use as a local proxy to reduce direct API calls to Google Safe Browsing:

```python
import requests

response = requests.post('http://localhost:8080/v4/threatMatches:find', json={
    'threatInfo': {
        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
        'platformTypes': ['ANY_PLATFORM'],
        'threatEntryTypes': ['URL'],
        'threatEntries': [{'url': 'http://example.com'}]
    }
})

matches = response.json().get('matches', [])
if matches:
    print("⚠️  Unsafe URL detected!")
else:
    print("✅ URL is safe")
```

### 2. Browser Integration

Use the redirector endpoint to add Safe Browsing protection to web browsers or proxies:

```html
<!-- Replace direct links with redirector -->
<a href="http://localhost:8080/r?url=http%3A//example.com">Visit Example</a>
```

### 3. Network Gateway

Deploy as a network gateway service to check URLs before allowing access.

## Security Considerations

- The server performs no authentication - secure it appropriately for your environment
- Consider running behind a reverse proxy (nginx, Caddy, etc.) for production use

## Performance

- The server maintains an in-memory threat database that updates every 30 minutes by default
- Adjust `--update-period` to control update frequency vs. API usage
- The server handles concurrent requests efficiently
- Consider horizontal scaling for high-traffic scenarios

## API Key

You need a Google Safe Browsing API key to use this server. You can get one from the [Google Cloud Console](https://console.cloud.google.com/) by enabling the Safe Browsing API.
