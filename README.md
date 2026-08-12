# llm-proxy

Lightweight Rust proxy for gh copilot that injects authentication headers (`Authorization: Bearer` + `x-apikey`) and optionally auto-refreshes Bearer tokens via OAuth client_credentials flow (M2M). **No upstream proxy required** - connects directly to the LLM provider.

## Quick Start

### Build & Install Binary
```bash
cargo build --release
mkdir -p ~/.local/bin
cp target/release/llm-proxy ~/.local/bin/
# Ensure ~/.local/bin is in your PATH (add to .zshrc/.bashrc)
export PATH="$HOME/.local/bin:$PATH"
```

### Configuration File
Create `~/.config/llm-proxy/config.toml`:

```toml
# Required
llm_host = "api.your-llm-provider.com"
api_key = "your-x-api-key"

# Optional (default: 3128)
listen_port = 3128

# Option 1: M2M OAuth auto-refresh (recommended)
m2m_oauth_url = "https://auth.example.com/oauth/token"
client_id = "your-client-id"
client_secret = "your-client-secret"

# Option 2: Static Bearer token (alternative to OAuth)
# bearer_token = "your-static-bearer-token"
```

### Run (foreground)
```bash
llm-proxy run
```

### Configure gh copilot
```bash
# Point gh copilot to this proxy (add to .zshrc/.bashrc)
export HTTP_PROXY=http://localhost:3128
export HTTPS_PROXY=http://localhost:3128
gh copilot chat
```

## Service Management (macOS launchd)

### Install as service

First, copy the binary to a permanent location:
```bash
mkdir -p ~/.local/bin
cp target/release/llm-proxy ~/.local/bin/
```

Then install the launchd service (creates config file + keychain entries):
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
llm-proxy uninstall # Remove service (also removes config & keychain entries)
```

## Configuration

### Config File (`~/.config/llm-proxy/config.toml`)
| Field | Required | Description |
|-------|----------|-------------|
| `llm_host` | Yes | Target LLM provider hostname |
| `api_key` | Yes | Value for `x-apikey` header |
| `listen_port` | No | Listen port (default: 3128) |
| `m2m_oauth_url` | No* | M2M OAuth token endpoint URL |
| `client_id` | No* | OAuth client ID |
| `client_secret` | No* | OAuth client secret |
| `bearer_token` | No* | Static Bearer token (alternative to OAuth) |

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
  uninstall  Uninstall the service

Install Options:
  -h, --host <HOST>              Target LLM provider hostname
  -x, --api-key <KEY>            X-API-Key header value
  -b, --bearer-token <TOKEN>     Static Bearer token (alternative to OAuth)
  -t, --m2m-oauth-url <URL>      M2M OAuth token endpoint URL
  -i, --client-id <ID>           OAuth client ID
  -s, --client-secret <SECRET>   OAuth client secret
  -p, --port <PORT>              Listen port [default: 3128]
      --use-keychain             Store secrets in macOS Keychain [default: true]
```

## Keychain Integration

When installing as a service with `--use-keychain` (default), secrets are stored in macOS Keychain:

- **Service name**: `llm-proxy`
- **Accounts**: `x-api-key`, `bearer-token`, `client-secret` (separate entries)
- **Retrieved at runtime** by the service (launchd runs as your user)

This keeps secrets out of plist files and process listings. The config file only contains non-secret values.

### Manual Keychain Operations
```bash
# Store manually
security add-generic-password -s "llm-proxy" -a "x-api-key" -w "YOUR_KEY"
security add-generic-password -s "llm-proxy" -a "client-secret" -w "YOUR_SECRET"

# Retrieve
security find-generic-password -s "llm-proxy" -a "x-api-key" -w

# Delete
security delete-generic-password -s "llm-proxy" -a "x-api-key"
```

## Architecture

```
gh copilot
    │
    ▼ HTTP/HTTPS
localhost:3128 (llm-proxy)
    ├─ Injects: Authorization: Bearer <token>
    ├─ Injects: x-apikey: <key>
    ├─ Adds: Cache-Control: no-cache, no-store, must-revalidate
    ├─ Auto-refreshes Bearer via M2M OAuth (60s before expiry)
    ├─ On 401: invalidates cache → forces refresh
    ▼
Direct connection to LLM Provider (no upstream proxy)
    ├─ OAuth token endpoint (for M2M refresh)
    ▼
LLM Provider API
```

## Development

```bash
# Run in debug mode with logging
RUST_LOG=debug cargo run -- run

# Test with curl
curl -x http://localhost:3128 https://api.your-llm-provider.com/v1/models \
  -H "Authorization: Bearer test"  # Will be replaced by proxy
```

## Requirements

- Rust 1.70+
- macOS (for launchd service) or Linux (systemd - TODO)
- Direct network access to LLM provider and OAuth endpoint
