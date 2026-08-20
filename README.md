# llm-proxy

Lightweight, high-performance local multi-provider LLM reverse proxy written in Rust. It serves an OpenAI-compatible API (`/v1/chat/completions`, `/v1/models`), orchestrates upstream routing across multi-cloud and enterprise endpoints, handles automatic authentication/token refresh, converts dialects transparently (e.g., AWS Bedrock Converse API), and tracks detailed token and cost usage.

---

## Key Features

* **Multi-Provider Architecture**: Configure multiple upstream providers simultaneously (OpenAI-compatible APIs, Google Gemini, AWS Bedrock Converse, Azure OpenAI, PCAI, etc.).
* **Dialect Translation**:
  * Seamlessly translates standard OpenAI chat completion payloads and SSE streams to/from AWS Bedrock Converse API (`converse` & `converse-stream`).
  * Automatic AWS Cross-Region Inference Profile ID mapping (e.g., `eu.anthropic.claude...`, `us.anthropic.claude...`).
* **Flexible Authentication Styles**:
  * **AWS SigV4 (`aws_sigv4`)**: Automatic SigV4 request signing using short-lived credentials exported dynamically from `aws configure export-credentials` (SSO session awareness with macOS browser login prompt alerts), environment variables, or macOS Keychain.
  * **M2M OAuth (`oauth_m2m`)**: Automated client credentials grant flow with preemptive token refresh before expiry.
  * **Bearer API Key (`bearer_api_key`)**: Custom bearer key header injection (e.g. Google Gemini `/openai` endpoint).
  * **Static Bearer (`static_bearer`)**: Pre-configured long-lived bearer tokens.
  * **Custom Header (`custom_header`)**: Pass custom API keys like `x-api-key`.
* **Dynamic Model Discovery & Caching**:
  * Auto-discovers upstream models at startup and periodically refreshes them (`/v1/models` aggregates all available providers).
  * Fast namespace resolution with configurable separators (e.g., `google_test/gemini-3.7-flash`, `aws-bedrock/eu.amazon.nova-pro-v1:0`, `bmw_llm_api/gpt-4o`).
* **Pricing & Usage Tracking**:
  * Real-time SSE streaming cost estimation and token accounting.
  * Syncs with LiteLLM's live model pricing catalog with offline disk caching (`~/.config/llm-proxy/prices_cache.json`).
  * Web Dashboard (`/llm-proxy/usage/dashboard`) and JSON metrics (`/llm-proxy/usage`).
* **Traffic Classification**:
  * Automatic traffic segregation between billable chat completions, zero-cost probe requests (`x-llm-probe: true`), model discovery, and internal endpoints.
* **Corporate Outbound Proxy & Egress Filtering**:
  * Built-in HTTP `CONNECT` tunneling activated automatically via standard environment variables (`HTTPS_PROXY`, `ALL_PROXY`, `HTTP_PROXY`).
  * Comprehensive `NO_PROXY` / `no_proxy` bypass filtering for local and internal enterprise hostnames.
  * Custom CA certificate loading (`ca_cert_path`) and optional insecure TLS skip (`insecure_skip_tls_verify`).
* **macOS Keychain Integration & Keyring Migration**:
  * Encrypt and store API keys, OAuth client secrets, and AWS tokens securely inside the system keyring.
  * Built-in migration command (`llm-proxy migrate-keychain`) to namespace legacy flat keychain keys.

---

## Outbound Proxy & Network Configuration

`llm-proxy` connects to upstream providers either directly or through an outbound forward proxy (e.g. corporate proxies or local egress forwarders on port 3128).

### Activation Rules
The proxy automatically activates outbound HTTP `CONNECT` tunneling if any of the standard environment variables are defined:
1. `HTTPS_PROXY` / `https_proxy`
2. `ALL_PROXY` / `all_proxy`
3. `HTTP_PROXY` / `http_proxy`

Example proxy URL: `http://localhost:3128` or `http://proxy.corp.example.com:8080`

### Proxy Bypass (`NO_PROXY`)
Traffic bypasses the outbound proxy and connects directly when the target host matches rules defined in `NO_PROXY` / `no_proxy`:
* Localhost/Loopback: `localhost`, `127.0.0.1`, `::1` are always bypassed by default.
* Wildcard bypass: `NO_PROXY=*` forces all connections to be direct.
* Comma-separated domain/host suffixes: e.g. `NO_PROXY=localhost,127.0.0.1,.bmwgroup.net,.cloud.bmw` will route `.cloud.bmw` and `.bmwgroup.net` directly while routing public endpoints (like `generativelanguage.googleapis.com` or AWS endpoints) through the proxy tunnel.

---

## Quick Start

### 1. Build & Install

For local development:

```bash
cargo build --release
cp target/release/llm-proxy ~/.local/bin/
```

#### Prebuilt binaries

Tagged releases publish checksummed archives for Linux (`x86_64`), macOS (`x86_64` and `aarch64`), and Windows (`x86_64`). Download the archive matching your platform from the [Releases](https://github.com/ruicout0/llm-proxy/releases) page, extract it, and place `llm-proxy` (or `llm-proxy.exe`) on your `PATH`.

Verify downloads before installing:

```bash
sha256sum -c SHA256SUMS.txt       # Linux
shasum -a 256 -c SHA256SUMS.txt   # macOS
```

On Windows PowerShell, use `Get-FileHash .\\llm-proxy-windows-x86_64.exe -Algorithm SHA256` and compare the result with `SHA256SUMS.txt`.

### 2. Configuration Reference (`~/.config/llm-proxy/config.toml`)

#### Global Settings

| Field | Default | Description |
|---|---|---|
| `listen_port` | `3128` | Local port the proxy server listens on. |
| `default_provider` | `"bmw"` | Default provider ID used when requests omit a provider prefix. |
| `model_separator` | `"/"` | Separator character used between provider ID and model ID (e.g. `/` or `:`). |
| `discovery_ttl_secs` | `300` | Discovery model cache time-to-live in seconds (5 min). |
| `discovery_timeout_ms` | `2500` | Timeout per provider model discovery request in milliseconds. |
| `usage_store_path` | `~/.config/llm-proxy/usage.json` | Path to the persistent usage and cost JSON store. |
| `pricing_cache_path` | `~/.config/llm-proxy/prices_cache.json` | Path to the cached LiteLLM pricing catalog file. |
| `ca_cert_path` | `None` | Path to custom CA root certificate PEM file for enterprise TLS interception. |
| `insecure_skip_tls_verify` | `false` | Skip upstream TLS certificate verification (useful for self-signed CAs). |

#### Provider Settings (`[[providers]]`)

| Field | Type | Description |
|---|---|---|
| `id` | `String` (Required) | Unique identifier for the provider (e.g. `"aws-bedrock"`, `"google_test"`, `"bmw_llm_api"`). |
| `base_url` | `String` (Required) | Upstream hostname and path prefix (e.g. `"api.int.gcp.cloud.bmw/llmapi"`). |
| `scheme` | `String` | `"https"` (default) or `"http"`. |
| `dialect` | `String` | `"openai_compatible"` (default) or `"bedrock_converse"`. |
| `auth_style` | `String` | `"oauth_m2m"`, `"bearer_api_key"`, `"static_bearer"`, `"custom_header"`, `"aws_sigv4"`, or `"none"`. |
| `m2m_oauth_url` | `String` | OAuth 2.0 token endpoint for `oauth_m2m`. |
| `client_id` | `String` | OAuth 2.0 client ID for `oauth_m2m`. |
| `client_secret` / `client_secret_ref` | `String` | Inline secret or Keychain reference `keychain:<provider>:client_secret`. |
| `oauth_scope` | `String` | Optional OAuth scope parameter. |
| `api_key` / `api_key_ref` | `String` | API key or Keychain reference `keychain:<provider>:api_key`. |
| `bearer_token` / `bearer_token_ref` | `String` | Static token or Keychain reference `keychain:<provider>:bearer_token`. |
| `header_name` | `String` | Custom header name for `custom_header` (e.g. `"x-api-key"`). |
| `header_value` / `header_value_ref` | `String` | Header value or Keychain reference `keychain:<provider>:header_val`. |
| `aws_region` | `String` | AWS region for SigV4 signing (e.g. `"eu-central-1"` or `"us-east-1"`). |
| `aws_profile` | `String` | AWS CLI SSO profile name for `aws configure export-credentials`. |
| `aws_access_key_id` / `_ref` | `String` | Static AWS access key or `keychain:<provider>:aws_access_key_id`. |
| `aws_secret_access_key` / `_ref` | `String` | Static AWS secret key or `keychain:<provider>:aws_secret_access_key`. |
| `aws_session_token` / `_ref` | `String` | Optional AWS STS session token or `keychain:<provider>:aws_session_token`. |
| `insecure_skip_tls_verify` | `bool` | Provider-specific TLS verification override. |
| `ca_cert_path` | `String` | Provider-specific custom CA certificate path. |
| `models` | `Vec<ModelSpec>` | Optional manual model definitions, aliases, or cost overrides. |

#### Model Specification Overrides (`[[providers.models]]`)

```toml
[[providers.models]]
id = "gpt-4o"
alias = "fast"                     # Creates route alias: fast -> provider/gpt-4o
context_window = 128000
max_output_tokens = 4096
input_cost_per_1m = 2.50           # Manual pricing override (per 1M input tokens)
output_cost_per_1m = 10.00         # Manual pricing override (per 1M output tokens)
currency = "USD"
hidden = false                     # Set true to hide from /v1/models listing
```

---

## Example `config.toml`

```toml
listen_port = 14142
default_provider = "bmw_llm_api"
model_separator = "/"
usage_store_path = "~/.config/llm-proxy/usage.json"
ca_cert_path = "~/.config/llm-proxy/BMW_Trusted_Certificates_Latest.pem"

# -------------------------------------------------------------
# 1. AWS Bedrock Provider (SigV4 Authentication)
# -------------------------------------------------------------
[[providers]]
id = "aws-bedrock"
base_url = "bedrock-runtime.eu-central-1.amazonaws.com"
scheme = "https"
dialect = "bedrock_converse"
auth_style = "aws_sigv4"
aws_region = "eu-central-1"
# Optional: specify an AWS CLI SSO profile (default is used if omitted)
# aws_profile = "default"
# Or store static credentials in Keychain (keychain:aws-bedrock:aws_access_key_id)
# aws_access_key_id_ref = "keychain:aws-bedrock:aws_access_key_id"
# aws_secret_access_key_ref = "keychain:aws-bedrock:aws_secret_access_key"
models = []

# -------------------------------------------------------------
# 2. Google Gemini (OpenAI-compatible Endpoint)
# -------------------------------------------------------------
[[providers]]
id = "google_test"
base_url = "generativelanguage.googleapis.com/v1beta/openai"
scheme = "https"
auth_style = "bearer_api_key"
api_key_ref = "keychain:google_test:api_key"
models = []

# -------------------------------------------------------------
# 3. Enterprise LLM API (OAuth M2M)
# -------------------------------------------------------------
[[providers]]
id = "bmw_llm_api"
base_url = "api.int.gcp.cloud.bmw/llmapi"
scheme = "https"
auth_style = "oauth_m2m"
m2m_oauth_url = "https://auth.int.gcp.cloud.bmw/oauth/token"
client_id = "your-client-id"
client_secret_ref = "keychain:bmw_llm_api:client_secret"
api_key_ref = "keychain:bmw_llm_api:api_key"
insecure_skip_tls_verify = true
models = []
```

---

## Keychain Secret Storage & Management

Secrets can be stored securely in the system keyring instead of plaintext configuration files.

### 1. Store Secrets
Save credentials using `keychain:<provider_id>:<secret_type>` identifiers:

```bash
# Google Gemini API Key
security add-generic-password -s "llm-proxy" -a "google_test:api_key" -w "YOUR_GEMINI_API_KEY"

# BMW LLM API Credentials
security add-generic-password -s "llm-proxy" -a "bmw_llm_api:client_secret" -w "YOUR_CLIENT_SECRET"
security add-generic-password -s "llm-proxy" -a "bmw_llm_api:api_key" -w "YOUR_BMW_GATEWAY_KEY"

# AWS Static Credentials (if not using AWS SSO)
security add-generic-password -s "llm-proxy" -a "aws-bedrock:aws_access_key_id" -w "AKIAIOSFODNN7EXAMPLE"
security add-generic-password -s "llm-proxy" -a "aws-bedrock:aws_secret_access_key" -w "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### 2. Migrate Legacy Flat Keychain Keys
If you previously used single-provider `llm-proxy` versions that stored credentials under flat account names (`api_key`, `client_secret`, `bearer_token`), run:

```bash
# Preview migration without touching Keychain
llm-proxy migrate-keychain --dry-run

# Perform migration to <default_provider>:<secret>
llm-proxy migrate-keychain
```

---

## AWS Bedrock Provider & Authentication

The AWS Bedrock provider translates standard OpenAI JSON payloads to Bedrock's `Converse` format and signs requests with AWS SigV4.

### Authentication Precedence
`llm-proxy` resolves AWS credentials dynamically at runtime:

1. **AWS CLI SSO Session (`aws configure export-credentials`)**:
   * If logged in via AWS IAM Identity Center / SSO (`aws sso login --profile <profile>`), the proxy automatically obtains temporary STS credentials.
   * **Automatic Expiry Alert (macOS)**: When your AWS SSO session expires, `llm-proxy` displays a native macOS system dialog alerting you that credentials need renewal, with a 1-click button to launch your SSO portal directly in the browser.
2. **macOS Keychain / Config**:
   * Stored under `keychain:<provider_id>:aws_access_key_id`, `keychain:<provider_id>:aws_secret_access_key`, and optionally `keychain:<provider_id>:aws_session_token`.
3. **Environment Variables**:
   * `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`.

### Bedrock Cross-Region Inference Profiles
Bedrock requires Regional or Cross-Region System-Defined profile IDs for certain foundation models (e.g. Anthropic Claude 3.5 Sonnet). `llm-proxy` automatically detects un-prefixed IDs and prepends the region tag (e.g. converting `anthropic.claude-3-5-sonnet-20241022-v2:0` to `eu.anthropic.claude-3-5-sonnet-20241022-v2:0` when `aws_region = "eu-central-1"`).

---

## Routing & Request Handling

### Resolution Rules
When a client sends a request with `"model": "<name>"`, `llm-proxy` resolves the target provider in order:

1. **Prefixed Name**: Matches `<provider_id><separator><upstream_model>` (e.g. `google_test/gemini-3.7-flash` or `aws-bedrock/eu.amazon.nova-pro-v1:0`).
2. **Model Alias**: Matches configured aliases in `[[providers.models]]` (e.g. `model: "fast"`).
3. **Header Override (`x-llm-provider`)**: Routes the bare model name explicitly to the specified provider.
4. **Unique Bare Model Lookup**: If the bare model name is unambiguously hosted by only one provider in the discovery index, it routes to that provider automatically.
5. **Fallback to Default Provider**: Routes to `default_provider`.

---

## CLI & Service Management Commands

```bash
llm-proxy [OPTIONS] <COMMAND>

Commands:
  run                Run proxy in foreground (reads ~/.config/llm-proxy/config.toml)
  setup              Interactive CLI wizard to configure providers and settings
  install            Install as macOS launchd service
  start              Start the background service
  stop               Stop the background service
  restart            Restart the background service
  status             Show background service status
  logs               Follow service stdout/stderr logs
  providers list     List all configured providers and models
  usage              Show accumulated usage and cost statistics
  migrate-keychain   Migrate legacy flat keychain accounts to namespaced format
  uninstall          Uninstall background service
```

### Usage CLI Options
```bash
llm-proxy usage                           # Show summary across all groups
llm-proxy usage --by-provider             # Detailed provider and model breakdown
llm-proxy usage --provider google_test    # Filter by specific provider
llm-proxy usage --reset                   # Reset usage store
```

---

## Local Endpoints

* **OpenAI Chat Completions**: `POST http://localhost:14142/v1/chat/completions`
* **OpenAI Models Discovery**: `GET http://localhost:14142/v1/models`
* **Provider Health Status**: `GET http://localhost:14142/llm-proxy/health`
* **Usage JSON Store**: `GET http://localhost:14142/llm-proxy/usage`
* **Web Cost Dashboard**: `GET http://localhost:14142/llm-proxy/usage/dashboard`
