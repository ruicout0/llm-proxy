# llm-proxy

Lightweight Rust proxy that injects authentication headers (`Authorization: Bearer` + `x-apikey`) and auto-refreshes bearer tokens via OAuth client_credentials grant (M2M). **No upstream proxy required** — connects directly to the LLM provider.

## Quick Start

### Build
```bash
cargo build --release
cp target/release/llm-proxy ~/.local/bin/
```

### Configuration File
Create `~/.config/llm-proxy/config.toml`:

```toml
# Required
llm_host = "api.your-llm-provider.com"
api_key = "your-x-api-key"

# Optional (default: 3128)
listen_port = 3128

# llm_host can include a path prefix for all upstream requests:
# llm_host = "api.example.com/llmapi"

# Option 1: M2M OAuth auto-refresh (recommended)
m2m_oauth_url = "https://auth.example.com/oauth/token"
client_id = "your-client-id"
client_secret = "your-client-secret"
oauth_scope = "machine2machine"        # optional OAuth scope

# Option 2: Static bearer token (alternative to OAuth)
# bearer_token = "your-static-bearer-token"

# Optional: skip TLS certificate verification for upstream (internal CAs)
# insecure_skip_tls_verify = true

# Optional: custom CA certificate for upstream TLS
# ca_cert_path = "/path/to/ca-cert.pem"
```

### Run (foreground)
```bash
llm-proxy run   # reads ~/.config/llm-proxy/config.toml
```

### Test
```bash
# No auth needed — the proxy handles Bearer + x-apikey injection
curl http://localhost:3128/v1/models
curl -X POST http://localhost:3128/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## Service Management (macOS launchd)

### Install as service

```bash
# M2M OAuth auto-refresh (recommended)
llm-proxy install \
  --host api.your-llm-provider.com \
  --api-key YOUR_X_API_KEY \
  --m2m-oauth-url https://auth.example.com/oauth/token \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET

# Or with static bearer token
llm-proxy install \
  --host api.your-llm-provider.com \
  --api-key YOUR_X_API_KEY \
  --bearer-token YOUR_BEARER_TOKEN
```

### Control service
```bash
llm-proxy start     # Start service
llm-proxy stop      # Stop service
llm-proxy restart   # Restart service
llm-proxy status    # Show status
llm-proxy logs      # Follow logs
llm-proxy usage     # Show accumulated usage/cost totals
llm-proxy usage --reset  # Reset usage store
llm-proxy uninstall # Remove service (also removes config & keychain entries)
```

## Configuration

### Config File (`~/.config/llm-proxy/config.toml`)

| Field | Required | Description |
|-------|----------|-------------|
| `llm_host` | Yes | Target LLM provider hostname (can include path prefix, e.g. `api.example.com/llmapi`) |
| `api_key` | Yes | Value for `x-apikey` header |
| `listen_port` | No | Listen port (default: 3128) |
| `m2m_oauth_url` | No* | M2M OAuth token endpoint URL |
| `client_id` | No* | OAuth client ID |
| `client_secret` | No* | OAuth client secret |
| `oauth_scope` | No | OAuth scope parameter (e.g. `machine2machine`) |
| `bearer_token` | No* | Static bearer token (alternative to OAuth) |
| `insecure_skip_tls_verify` | No | Skip upstream TLS certificate verification (for internal CAs) |
| `ca_cert_path` | No | Path to custom CA certificate PEM file for upstream TLS |
| `usage_store_path` | No | Path to usage/cost JSON store (default: `~/.config/llm-proxy/usage.json`) |

*Either `bearer_token` OR all three of `m2m_oauth_url`, `client_id`, `client_secret` must be provided.

### CLI Options
```bash
llm-proxy [OPTIONS] <COMMAND>

Options:
  -c, --config <PATH>    Path to config file (default: ~/.config/llm-proxy/config.toml)

Commands:
  run        Run proxy in foreground
  install    Install as macOS launchd service
  start      Start the service
  stop       Stop the service
  restart    Restart the service
  status     Show service status
  logs       Follow service logs
  usage      Show accumulated usage/cost totals
  uninstall  Uninstall the service

Install Options:
  -h, --host <HOST>              Target LLM provider hostname
  -x, --api-key <KEY>            X-API-Key header value
  -b, --bearer-token <TOKEN>     Static bearer token (alternative to OAuth)
  -t, --m2m-oauth-url <URL>      M2M OAuth token endpoint URL
  -i, --client-id <ID>           OAuth client ID
  -s, --client-secret <SECRET>   OAuth client secret
  -p, --port <PORT>              Listen port [default: 3128]
      --use-keychain             Store secrets in macOS Keychain [default: true]
```

## Keychain Integration

Secrets can be stored in macOS Keychain instead of plaintext config files. The proxy reads from keychain at runtime, falling back to config file values if keychain entries are missing.

### Keychain entries

| Account           | Config field    | Description              |
|-------------------|-----------------|--------------------------|
| `x-api-key`       | `api_key`       | X-API-Key header value   |
| `bearer-token`    | `bearer_token`  | Static bearer token      |
| `client-secret`   | `client_secret` | OAuth client secret      |

All entries share the **service name** `llm-proxy`.

### Automatic setup (install)

`llm-proxy install --use-keychain` (default) stores secrets in keychain and strips them from the written config file.

### Manual setup

If you already have a config file with secrets, or want to pre-populate keychain before running:

```bash
security add-generic-password -s "llm-proxy" -a "x-api-key" -w "your-api-key"
security add-generic-password -s "llm-proxy" -a "bearer-token" -w "your-bearer-token"
security add-generic-password -s "llm-proxy" -a "client-secret" -w "your-client-secret"
```

To verify entries were created:

```bash
security find-generic-password -s "llm-proxy"
```

The proxy resolves secrets at startup in this order: **keychain → config file → error**. Entries in keychain take precedence but are optional — you can mix keychain and config file secrets as needed.

## Architecture

```
Client (curl, IDE, SDK)
    │
    ▼ HTTP (no auth required)
localhost:{port} (llm-proxy)
    ├─ Acquires OAuth bearer token (client_credentials grant)
    ├─ Injects: Authorization: Bearer <token>
    ├─ Injects: x-apikey: <key>
    ├─ Adds: Cache-Control: no-cache, no-store, must-revalidate
    ├─ Sets: Host header (hostname only, path prefix stripped)
    ├─ Auto-refreshes bearer token 60s before expiry
    ├─ On 401: forces token refresh and retries once
    ▼ HTTPS (with auth headers)
LLM Provider API
```

## Development

```bash
# Run in debug mode with logging
RUST_LOG=debug cargo run -- run

# Test with curl
curl http://localhost:3128/v1/models
curl -X POST http://localhost:3128/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## Usage Cost Tracking

The proxy records usage and cost from upstream responses automatically. Every successful LLM request updates a local JSON store with:

- Global request count and totals
- Per-group breakdown (group is resolved from `x-usage-group` → `Authorization` hash → `x-apikey` hash → `default`)
- Per-model cost and token totals within each group

Query usage via the local endpoints:

```bash
curl http://localhost:3128/llm-proxy/usage
```

A pretty HTML dashboard is also available while the proxy is running:

```bash
open http://localhost:3128/llm-proxy/usage/dashboard
```

Or via CLI:

```bash
llm-proxy usage
llm-proxy usage --reset
```

The store path defaults to `~/.config/llm-proxy/usage.json` and can be overridden with the `usage_store_path` config option.

### Streaming requests

Clients like GitHub Copilot Chat send `"stream": true`, so the upstream replies with a
Server-Sent Events (SSE) stream instead of a single JSON object. The proxy handles this
transparently:

- Streaming responses are **forwarded chunk by chunk** and never buffered, so clients
  render tokens in real time and requests do not stall.
- For streaming requests the proxy injects `stream_options: {"include_usage": true}` into
  the request body. Without it, OpenAI-compatible upstreams never emit token usage for
  streams, and cost cannot be attributed.
- Usage and cost are parsed from the final SSE chunk (the one carrying `usage`) once the
  stream completes, and recorded under the same group/model as non-streaming requests.

If an upstream ignores `stream_options.include_usage`, no usage chunk is emitted and the
request is forwarded normally without cost attribution (a debug log line is emitted).

## Requirements

- Rust 1.70+
- macOS (for launchd service) or Linux (systemd — TODO)
- Direct network access to LLM provider and OAuth endpoint