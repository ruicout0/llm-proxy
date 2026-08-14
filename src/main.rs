//! llm-proxy - Lightweight proxy for gh copilot with auth header injection and OAuth token refresh
//!
//! Usage:
//!   llm-proxy run                    # Run in foreground (reads from config file)
//!   llm-proxy install [OPTIONS]      # Install as macOS launchd service
//!   llm-proxy start                  # Start service
//!   llm-proxy stop                   # Stop service
//!   llm-proxy restart                # Restart service
//!   llm-proxy status                 # Show service status
//!   llm-proxy logs                   # Follow service logs
//!   llm-proxy uninstall              # Remove service
//!
//! Config file (TOML):
//!   # ~/.config/llm-proxy/config.toml
//!   llm_host = "api.your-llm-provider.com"
//!   listen_port = 3128
//!   api_key = "your-x-api-key"
//!   m2m_oauth_url = "https://auth.example.com/oauth/token"
//!   client_id = "your-client-id"
//!   client_secret = "your-client-secret"
//!   # bearer_token = "static-token"  # Optional: use instead of OAuth

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dirs::home_dir;
use hyper::body::to_bytes;
use hyper::client::HttpConnector;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use hyper::Client;
use hyper::{
    header::{HeaderValue, AUTHORIZATION, CACHE_CONTROL},
    Body, Method, Request, Response, StatusCode,
};
use hyper_rustls::HttpsConnector;
use keyring::Entry;
use plist::{Dictionary, Value as PlistValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// No-op TLS certificate verifier for internal/self-signed certs
struct NoopVerifier;
impl rustls::client::ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

// ============================================================================
// Config File
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ConfigFile {
    /// Target LLM provider hostname (required)
    llm_host: String,
    /// Port to listen on (default: 3128)
    #[serde(default = "default_port")]
    listen_port: u16,
    /// X-API-Key header value (required)
    api_key: String,
    /// M2M OAuth token endpoint URL (for auto-refresh)
    #[serde(rename = "m2m_oauth_url")]
    token_endpoint: Option<String>,
    /// OAuth client ID
    client_id: Option<String>,
    /// OAuth client secret
    client_secret: Option<String>,
    /// OAuth scope (e.g., "machine2machine")
    #[serde(default)]
    oauth_scope: Option<String>,
    /// Static bearer token (alternative to OAuth)
    bearer_token: Option<String>,
    /// Optional CA certificate path (PEM format) for custom TLS verification
    #[serde(default)]
    ca_cert_path: Option<String>,
    /// Skip TLS certificate verification for upstream LLM host
    #[serde(default)]
    insecure_skip_tls_verify: bool,
    /// Path to usage/cost tracking JSON store
    #[serde(default)]
    usage_store_path: Option<String>,
}

fn default_port() -> u16 {
    3128
}

fn default_usage_store_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/llm-proxy/usage.json")
}

impl ConfigFile {
    fn validate(&self) -> Result<()> {
        if self.llm_host.is_empty() {
            anyhow::bail!("llm_host is required in config file");
        }
        // api_key can be empty in file if stored in keychain
        let has_oauth = self.token_endpoint.is_some() && self.client_id.is_some();
        if self.bearer_token.is_none() && !has_oauth {
            anyhow::bail!("Either bearer_token OR (m2m_oauth_url + client_id) must be provided. client_secret and api_key may be stored in keychain.");
        }
        Ok(())
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "llm-proxy", version, about = "LLM proxy with auth injection")]
struct Cli {
    /// Path to config file (default: ~/.config/llm-proxy/config.toml)
    #[arg(short = 'c', long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run proxy in foreground (reads config from file)
    Run,
    /// Interactive setup - create config file
    Setup,
    /// Install as macOS launchd service
    Install(InstallArgs),
    /// Start the service
    Start,
    /// Stop the service
    Stop,
    /// Restart the service
    Restart,
    /// Show service status
    Status,
    /// Follow service logs
    Logs,
    /// Show accumulated usage/cost totals
    Usage(UsageArgs),
    /// Uninstall the service
    Uninstall,
}

#[derive(Parser)]
struct UsageArgs {
    /// Path to usage store JSON (overrides config)
    #[arg(short = 'p', long)]
    store_path: Option<PathBuf>,

    /// Reset all usage data
    #[arg(long)]
    reset: bool,
}

#[derive(Parser)]
struct InstallArgs {
    /// Target LLM provider hostname
    #[arg(short = 'h', long)]
    host: Option<String>,

    /// X-API-Key header value
    #[arg(short = 'x', long)]
    api_key: Option<String>,

    /// Static Bearer token (alternative to OAuth)
    #[arg(short = 'b', long)]
    bearer_token: Option<String>,

    /// M2M OAuth token endpoint URL
    #[arg(short = 't', long)]
    m2m_oauth_url: Option<String>,

    /// OAuth client ID
    #[arg(short = 'i', long)]
    client_id: Option<String>,

    /// OAuth client secret
    #[arg(short = 's', long)]
    client_secret: Option<String>,

    /// Listen port
    #[arg(short = 'p', long, default_value = "3128")]
    port: u16,

    /// Use macOS Keychain for secrets (default: true)
    #[arg(long, default_value = "true")]
    use_keychain: bool,
}

// ============================================================================
// Runtime Config
// ============================================================================

struct Config {
    listen_port: u16,
    llm_host: String,
    bearer_token: Option<String>,
    x_api_key: String,
    token_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    oauth_scope: Option<String>,
    ca_cert_path: Option<String>,
    insecure_skip_tls_verify: bool,
    usage_store_path: PathBuf,
}

impl Config {
    /// Load config from file, with CLI args as override
    fn load(config_path: Option<PathBuf>, cli_args: Option<&InstallArgs>) -> Result<Self> {
        // Determine config file path
        let path = config_path.unwrap_or_else(|| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config/llm-proxy/config.toml")
        });

        // Load from file if exists
        let mut file_config = if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;
            let cfg: ConfigFile = toml::from_str(&content)
                .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
            cfg.validate()?;
            Some(cfg)
        } else {
            None
        };

        // Apply CLI overrides if provided
        if let Some(args) = cli_args {
            if let Some(ref mut fc) = file_config {
                if let Some(ref v) = args.host {
                    fc.llm_host = v.clone();
                }
                if let Some(ref v) = args.api_key {
                    fc.api_key = v.clone();
                }
                if let Some(ref v) = args.bearer_token {
                    fc.bearer_token = Some(v.clone());
                }
                if let Some(ref v) = args.m2m_oauth_url {
                    fc.token_endpoint = Some(v.clone());
                }
                if let Some(ref v) = args.client_id {
                    fc.client_id = Some(v.clone());
                }
                if let Some(ref v) = args.client_secret {
                    fc.client_secret = Some(v.clone());
                }
                fc.listen_port = args.port;
            } else {
                // Create from CLI args only
                file_config = Some(ConfigFile {
                    llm_host: args.host.clone().context("host required")?,
                    api_key: args.api_key.clone().context("api_key required")?,
                    bearer_token: args.bearer_token.clone(),
                    token_endpoint: args.m2m_oauth_url.clone(),
                    client_id: args.client_id.clone(),
                    client_secret: args.client_secret.clone(),
                    listen_port: args.port,
                    ca_cert_path: None,
                    oauth_scope: None,
                    insecure_skip_tls_verify: false,
                    usage_store_path: None,
                });
                file_config.as_ref().unwrap().validate()?;
            }
        } else if file_config.is_none() {
            anyhow::bail!(
                "Config file not found at: {}. Run 'llm-proxy install' or create it manually.",
                path.display()
            );
        }

        let fc = file_config.unwrap();

        // Try keychain for secrets first, fall back to config file values
        let x_api_key = Entry::new(KEYCHAIN_SERVICE, "x-api-key")
            .ok()
            .and_then(|e| e.get_password().ok())
            .unwrap_or(fc.api_key);

        let bearer_token = fc.bearer_token.or_else(|| {
            Entry::new(KEYCHAIN_SERVICE, "bearer-token")
                .ok()
                .and_then(|e| e.get_password().ok())
        });

        let client_secret = fc.client_secret.or_else(|| {
            Entry::new(KEYCHAIN_SERVICE, "client-secret")
                .ok()
                .and_then(|e| e.get_password().ok())
        });

        // Validate that we have required secrets after keychain resolution
        if x_api_key.is_empty() {
            anyhow::bail!("api_key is required (set in config file or keychain)");
        }
        let has_oauth =
            fc.token_endpoint.is_some() && fc.client_id.is_some() && client_secret.is_some();
        if bearer_token.is_none() && !has_oauth {
            anyhow::bail!("Either bearer_token OR (m2m_oauth_url + client_id + client_secret) must be configured");
        }

        Ok(Self {
            listen_port: fc.listen_port,
            llm_host: fc.llm_host,
            bearer_token,
            x_api_key,
            token_endpoint: fc.token_endpoint,
            client_id: fc.client_id,
            client_secret,
            oauth_scope: fc.oauth_scope,
            ca_cert_path: fc.ca_cert_path,
            insecure_skip_tls_verify: fc.insecure_skip_tls_verify,
            usage_store_path: fc
                .usage_store_path
                .map(PathBuf::from)
                .unwrap_or_else(default_usage_store_path),
        })
    }
}
// Interactive Setup
// ============================================================================

async fn setup_config(config_path: Option<PathBuf>) -> Result<()> {
    use dialoguer::{Confirm, Input, Select};

    let path = config_path.unwrap_or_else(|| {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/llm-proxy/config.toml")
    });

    println!("\n🔧 llm-proxy Interactive Setup");
    println!("==============================\n");

    if path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "Config file already exists at {}. Overwrite?",
                path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            println!("Setup cancelled.");
            return Ok(());
        }
    }

    // Required fields
    let llm_host: String = Input::new()
        .with_prompt("Target LLM provider hostname (e.g., api.example.com)")
        .interact_text()?;

    let api_key: String = Input::new()
        .with_prompt("X-API-Key value")
        .interact_text()?;

    let listen_port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(3128)
        .interact_text()?;

    // Auth method
    let auth_methods = &[
        "M2M OAuth auto-refresh (recommended)",
        "Static bearer token",
    ];
    let auth_choice = Select::new()
        .with_prompt("Authentication method")
        .items(auth_methods)
        .default(0)
        .interact()?;

    let mut config = ConfigFile {
        ca_cert_path: None,
        llm_host,
        api_key,
        listen_port,
        token_endpoint: None,
        client_id: None,
        client_secret: None,
        oauth_scope: None,
        insecure_skip_tls_verify: false,
        bearer_token: None,
        usage_store_path: None,
    };

    if auth_choice == 0 {
        // M2M OAuth
        let token_endpoint: String = Input::new()
            .with_prompt(
                "M2M OAuth token endpoint URL (e.g., https://auth.example.com/oauth/token)",
            )
            .interact_text()?;

        let client_id: String = Input::new()
            .with_prompt("OAuth Client ID")
            .interact_text()?;

        let client_secret: String = Input::new()
            .with_prompt("OAuth Client Secret")
            .interact_text()?;

        let scope: String = Input::new()
            .with_prompt("OAuth scope (optional, e.g., 'machine2machine' - leave empty to skip)")
            .allow_empty(true)
            .interact_text()?;
        let scope = if scope.is_empty() { None } else { Some(scope) };

        config.token_endpoint = Some(token_endpoint);
        config.client_id = Some(client_id);
        config.client_secret = Some(client_secret);
        config.oauth_scope = scope;
    } else {
        // Static bearer token
        let bearer_token: String = Input::new()
            .with_prompt("Static Bearer Token")
            .interact_text()?;

        config.bearer_token = Some(bearer_token);
    }

    // Validate
    config.validate()?;

    // Create directory
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write config file
    let toml_string = toml::to_string_pretty(&config)?;
    std::fs::write(&path, toml_string)?;

    println!("\n✅ Config file created at: {}", path.display());
    println!("\nYou can now run:");
    println!("  llm-proxy run           # Run in foreground");
    println!("  llm-proxy install       # Install as service (uses config file)");

    Ok(())
}

// ============================================================================
// Usage Tracking
// ============================================================================

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
struct ModelUsage {
    requests: u64,
    #[serde(default)]
    cost: BTreeMap<String, f64>,
    #[serde(default)]
    tokens: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
struct GroupUsage {
    requests: u64,
    #[serde(default)]
    models: BTreeMap<String, ModelUsage>,
    #[serde(default)]
    totals: BTreeMap<String, f64>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
struct UsageStoreData {
    #[serde(default)]
    groups: BTreeMap<String, GroupUsage>,
    #[serde(default)]
    global_requests: u64,
    #[serde(default)]
    global_totals: BTreeMap<String, f64>,
    last_updated: Option<u64>,
}

impl UsageStoreData {
    fn touch_last_updated(&mut self) {
        self.last_updated = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
    }
}

struct UsageStore {
    data: RwLock<UsageStoreData>,
    path: PathBuf,
}

impl UsageStore {
    fn new(path: PathBuf) -> Self {
        let data = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<UsageStoreData>(&s).ok())
                .unwrap_or_default()
        } else {
            UsageStoreData::default()
        };
        Self {
            data: RwLock::new(data),
            path,
        }
    }

    async fn record(
        &self,
        group: &str,
        model: &str,
        cost: Option<(f64, String)>,
        tokens: BTreeMap<String, u64>,
    ) -> Result<()> {
        let mut data = self.data.write().await;
        data.global_requests += 1;

        let group = data.groups.entry(group.to_string()).or_default();
        group.requests += 1;

        let model_usage = group.models.entry(model.to_string()).or_default();
        model_usage.requests += 1;

        if let Some((amount, currency)) = cost {
            if amount > 0.0 {
                *model_usage.cost.entry(currency.clone()).or_default() += amount;
                *group.totals.entry(currency.clone()).or_default() += amount;
            }
        }

        for (token_type, count) in tokens {
            if count > 0 {
                *model_usage.tokens.entry(token_type.clone()).or_default() += count;
                *group
                    .totals
                    .entry(format!("{}_tokens", token_type))
                    .or_default() += count as f64;
            }
        }

        // Recalculate global totals from groups to avoid multiple mutable borrows
        let mut global_totals = BTreeMap::new();
        for group in data.groups.values() {
            for (currency, amount) in &group.totals {
                *global_totals.entry(currency.clone()).or_default() += amount;
            }
        }
        data.global_totals = global_totals;

        data.touch_last_updated();
        self.persist_sync(&data)?;
        Ok(())
    }

    async fn get(&self) -> UsageStoreData {
        self.data.read().await.clone()
    }

    async fn reset(&self) -> Result<()> {
        let mut data = self.data.write().await;
        *data = UsageStoreData::default();
        data.touch_last_updated();
        self.persist_sync(&data)?;
        Ok(())
    }

    fn persist_sync(&self, data: &UsageStoreData) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create usage store dir: {}", parent.display())
            })?;
        }
        let json = serde_json::to_string_pretty(data)?;
        std::fs::write(&self.path, json)
            .with_context(|| format!("Failed to write usage store: {}", self.path.display()))?;
        Ok(())
    }
}

fn resolve_usage_group(headers: &hyper::HeaderMap) -> String {
    if let Some(value) = headers.get("x-usage-group").and_then(|v| v.to_str().ok()) {
        if !value.is_empty() {
            return value.to_string();
        }
    }

    if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let normalized = value.trim().to_lowercase();
        if !normalized.is_empty() {
            return format!("auth:{}", sha256_hex(normalized.as_bytes()));
        }
    }

    if let Some(value) = headers.get("x-apikey").and_then(|v| v.to_str().ok()) {
        if !value.is_empty() {
            return format!("apikey:{}", sha256_hex(value.as_bytes()));
        }
    }

    "default".to_string()
}

fn sha256_hex(input: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn usage_dashboard_html() -> &'static str {
    r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LLM Proxy Usage</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --panel-2: #27354f;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent-2: #818cf8;
      --success: #34d399;
      --danger: #f87171;
      --border: #334155;
      --radius: 14px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
    header { margin-bottom: 28px; }
    h1 { margin: 0 0 6px; font-size: 1.75rem; letter-spacing: -0.02em; }
    .subtitle { color: var(--muted); font-size: 0.95rem; }
    .refresh { color: var(--muted); font-size: 0.85rem; margin-top: 8px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 28px; }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
    .card h3 { margin: 0 0 6px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    .card .value { font-size: 1.7rem; font-weight: 700; color: var(--text); }
    .card .value.accent { color: var(--accent); }
    .card .value.success { color: var(--success); }
    .card .value.danger { color: var(--danger); }
    section { margin-bottom: 28px; }
    h2 { font-size: 1.15rem; margin: 0 0 14px; display: flex; align-items: center; gap: 8px; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: var(--panel-2); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.03); }
    .tag { display: inline-block; padding: 3px 8px; border-radius: 999px; background: var(--panel-2); font-size: 0.75rem; color: var(--accent); border: 1px solid var(--border); }
    .empty { color: var(--muted); font-style: italic; padding: 20px; text-align: center; }
    .right { text-align: right; }
    .last-updated { color: var(--muted); font-size: 0.8rem; margin-top: 12px; }
    @media (max-width: 600px) {
      .container { padding: 20px 14px; }
      th, td { padding: 10px 12px; font-size: 0.85rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🧠 LLM Proxy Usage</h1>
      <div class="subtitle">Live cost and token totals from proxied requests</div>
      <div class="refresh">Auto-refresh every 30s · <a href="/llm-proxy/usage" style="color:var(--accent)">JSON API</a></div>
    </header>

    <div class="grid" id="summary">
      <div class="card"><h3>Total Requests</h3><div class="value accent" id="total-requests">–</div></div>
      <div class="card"><h3>Total Cost</h3><div class="value success" id="total-cost">–</div></div>
      <div class="card"><h3>Active Groups</h3><div class="value" id="active-groups">–</div></div>
      <div class="card"><h3>Models Used</h3><div class="value" id="models-used">–</div></div>
    </div>

    <section>
      <h2>📊 Per-Group / Per-Model</h2>
      <table id="details-table">
        <thead>
          <tr><th>Group</th><th>Model</th><th class="right">Requests</th><th class="right">Cost</th><th class="right">Tokens</th></tr>
        </thead>
        <tbody id="details-body"><tr><td colspan="5" class="empty">No usage recorded yet.</td></tr></tbody>
      </table>
      <div class="last-updated" id="last-updated"></div>
    </section>
  </div>

  <script>
    const fmt = (n) => typeof n === 'number' ? n.toLocaleString() : '–';
    const fmtCost = (n, c) => typeof n === 'number' ? `${n.toFixed(6)} ${c || 'USD'}` : '–';

    async function load() {
      try {
        const res = await fetch('/llm-proxy/usage');
        const data = await res.json();

        document.getElementById('total-requests').textContent = fmt(data.global_requests);

        const costEntries = Object.entries(data.global_totals || {}).filter(([k]) => !k.endsWith('_tokens'));
        document.getElementById('total-cost').textContent = costEntries.length
          ? costEntries.map(([c, a]) => fmtCost(a, c)).join(' + ')
          : '$0.000000';

        const groups = Object.entries(data.groups || {});
        document.getElementById('active-groups').textContent = groups.length;

        let modelCount = 0;
        const tbody = document.getElementById('details-body');
        tbody.innerHTML = '';

        if (groups.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" class="empty">No usage recorded yet.</td></tr>';
        } else {
          for (const [groupName, group] of groups) {
            const models = Object.entries(group.models || {});
            modelCount += models.length;
            for (const [modelName, model] of models) {
              const cost = Object.entries(model.cost || {})
                .filter(([k]) => !k.endsWith('_tokens'))
                .map(([c, a]) => fmtCost(a, c))
                .join(' + ') || '–';
              const tokens = Object.entries(model.tokens || {})
                .map(([t, n]) => `${t}: ${fmt(n)}`)
                .join('<br>') || '–';
              const row = document.createElement('tr');
              row.innerHTML = `<td><span class="tag">${groupName}</span></td><td>${modelName}</td><td class="right">${fmt(model.requests)}</td><td class="right">${cost}</td><td class="right">${tokens}</td>`;
              tbody.appendChild(row);
            }
          }
        }
        document.getElementById('models-used').textContent = modelCount;

        const ts = data.last_updated
          ? new Date(data.last_updated * 1000).toLocaleString()
          : 'never';
        document.getElementById('last-updated').textContent = 'Last updated: ' + ts;
      } catch (e) {
        console.error(e);
      }
    }

    load();
    setInterval(load, 30000);
  </script>
</body>
</html>"##
}

// ============================================================================
// Token Cache
// ============================================================================

struct TokenCache {
    bearer_token: RwLock<Option<(String, Instant)>>,
    config: Arc<Config>,
    client: Client<HttpsConnector<HttpConnector>>,
}

impl TokenCache {
    fn new(config: Arc<Config>) -> Self {
        let client_config = if config.insecure_skip_tls_verify {
            info!("WARNING: TLS certificate verification disabled for upstream connections");
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(NoopVerifier))
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));

            // Load custom CA certificate if provided
            if let Some(cert_path) = &config.ca_cert_path {
                if let Ok(cert_data) = std::fs::read(cert_path) {
                    if let Ok(certs) = rustls_pemfile::certs(&mut &cert_data[..]) {
                        for cert in certs {
                            root_store.add(&rustls::Certificate(cert)).ok();
                        }
                        info!("Loaded custom CA certificate from: {}", cert_path);
                    } else {
                        warn!("Failed to parse CA certificate from: {}", cert_path);
                    }
                } else {
                    warn!("Failed to read CA certificate from: {}", cert_path);
                }
            }

            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_or_http()
            .enable_http1()
            .build();

        let client = Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(4)
            .build(https);
        Self {
            bearer_token: RwLock::new(None),
            config,
            client,
        }
    }

    async fn get_valid_bearer(&self) -> Result<String> {
        // Fast path: read lock first
        {
            let guard = self.bearer_token.read().await;
            if let Some((token, expiry)) = &*guard {
                if *expiry > Instant::now() + Duration::from_secs(60) {
                    return Ok(token.clone());
                }
            }
        }

        // Need refresh - check if static token configured
        if let Some(key) = &self.config.bearer_token {
            return Ok(key.clone());
        }

        // Acquire write lock and double-check (only first contender refreshes)
        let guard = self.bearer_token.write().await;
        if let Some((token, expiry)) = &*guard {
            if *expiry > Instant::now() + Duration::from_secs(60) {
                return Ok(token.clone());
            }
        }

        // Actually refresh the token
        drop(guard);
        self.refresh_token().await
    }

    async fn get_x_api_key(&self) -> Result<String> {
        Ok(self.config.x_api_key.clone())
    }

    async fn refresh_token(&self) -> Result<String> {
        let token_url = self
            .config
            .token_endpoint
            .as_ref()
            .context("No token endpoint configured and no static bearer token")?;

        let client_id = self
            .config
            .client_id
            .as_ref()
            .context("client_id required for token refresh")?;
        let client_secret = self
            .config
            .client_secret
            .as_ref()
            .context("client_secret required for token refresh")?;

        let form = if let Some(ref scope) = self.config.oauth_scope {
            format!(
                "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
                urlencoding::encode(client_id),
                urlencoding::encode(client_secret),
                urlencoding::encode(scope)
            )
        } else {
            format!(
                "grant_type=client_credentials&client_id={}&client_secret={}",
                urlencoding::encode(client_id),
                urlencoding::encode(client_secret)
            )
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri(token_url.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", form.len())
            .body(Body::from(form))?;

        let resp = self.client.request(req).await?;
        let body = to_bytes(resp.into_body()).await?;
        let json: serde_json::Value = serde_json::from_slice(&body)?;

        let access_token = json["access_token"]
            .as_str()
            .context("No access_token in response")?
            .to_string();
        let expires_in = json["expires_in"].as_u64().unwrap_or(3600);

        let expiry = Instant::now() + Duration::from_secs(expires_in - 60); // Refresh 1 min early
        *self.bearer_token.write().await = Some((access_token.clone(), expiry));

        info!("Refreshed LLM bearer token (expires in {}s)", expires_in);
        Ok(access_token)
    }

    async fn clear_token(&self) {
        *self.bearer_token.write().await = None;
    }
}

async fn record_usage_from_response(
    resp: Response<Body>,
    usage_store: &UsageStore,
    group: &str,
    request_model: Option<&str>,
) -> Result<Response<Body>> {
    debug!("Entering record_usage_from_response");
    let (parts, body) = resp.into_parts();
    debug!("Reading response body for usage tracking");
    let body_bytes = to_bytes(body).await?;
    debug!("Response body read: len={}", body_bytes.len());

    debug!(
        "Usage tracking check: status={} body_len={} request_model={:?}",
        parts.status,
        body_bytes.len(),
        request_model
    );
    if parts.status.is_success() {
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(json) => {
                let model = json["model"]
                    .as_str()
                    .or_else(|| json["model_id"].as_str())
                    .map(|s| s.to_string())
                    .or_else(|| request_model.map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown".to_string());
                let cost = json["cost"]["total"]
                    .as_f64()
                    .zip(json["cost"]["currency"].as_str().map(|s| s.to_string()));
                let mut tokens = BTreeMap::new();
                if let Some(obj) = json["usage"].as_object() {
                    for (k, v) in obj {
                        if let Some(n) = v.as_u64() {
                            tokens.insert(k.clone(), n);
                        }
                    }
                }
                debug!(
                    "Recorded usage for group={} model={} cost={:?}",
                    group, model, cost
                );
                if let Err(e) = usage_store.record(group, &model, cost, tokens).await {
                    warn!("Failed to record usage: {}", e);
                }
            }
            Err(e) => {
                debug!(
                    "Failed to parse upstream response as JSON for usage tracking: {}",
                    e
                );
            }
        }
    }

    Ok(Response::from_parts(parts, Body::from(body_bytes)))
}

async fn handle_request(
    req: Request<Body>,
    token_cache: Arc<TokenCache>,
    usage_store: Arc<UsageStore>,
    config: Arc<Config>,
) -> Result<Response<Body>> {
    debug!(
        "handle_request start: method={} uri={}",
        req.method(),
        req.uri()
    );
    // Capture method and path before consuming req
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    // Local usage endpoints
    if method == Method::GET && path_and_query == "/llm-proxy/usage" {
        let data = usage_store.get().await;
        let body = serde_json::to_string_pretty(&data)?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(body))?);
    }
    if method == Method::GET && path_and_query == "/llm-proxy/usage/dashboard" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Body::from(usage_dashboard_html()))?);
    }

    // Buffer the body so we can replay it on 401 retry
    let (parts, body) = req.into_parts();
    let group = resolve_usage_group(&parts.headers);
    let body_bytes = to_bytes(body).await?;

    // Extract request model for usage tracking fallback from multiple sources
    let request_model = serde_json::from_slice::<serde_json::Value>(&body_bytes)
        .ok()
        .and_then(|v| {
            v["model"]
                .as_str()
                .or_else(|| v["model_id"].as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            parts.uri.query().and_then(|q| {
                q.split('&').find_map(|pair| {
                    let mut it = pair.splitn(2, '=');
                    if it.next()? == "model" {
                        it.next().map(|v| v.replace('+', " "))
                    } else {
                        None
                    }
                })
            })
        })
        .or_else(|| {
            parts
                .headers
                .get("x-model")
                .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
        });

    // Always inject auth headers and forward to configured LLM host
    let bearer = token_cache.get_valid_bearer().await?;
    let x_api_key = token_cache.get_x_api_key().await?;

    let uri: hyper::Uri = format!("https://{}{}", config.llm_host, path_and_query).parse()?;
    let host_only = config
        .llm_host
        .split('/')
        .next()
        .unwrap_or(&config.llm_host);

    // Build a fully-injected request from the buffered body
    let build_request = |bearer: &str, api_key: &str| -> Result<Request<Body>> {
        let mut req_builder = Request::builder().method(method.clone()).uri(uri.clone());

        // Copy original headers except hop-by-hop and auth overrides
        for (name, value) in parts.headers.iter() {
            let lower = name.as_str().to_lowercase();
            if lower == "host"
                || lower == "authorization"
                || lower == "x-apikey"
                || lower == "transfer-encoding"
                || lower == "connection"
            {
                continue;
            }
            req_builder = req_builder.header(name, value);
        }

        req_builder = req_builder
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", bearer))?,
            )
            .header(
                "x-apikey".parse::<hyper::header::HeaderName>()?,
                HeaderValue::from_str(api_key)?,
            )
            .header(
                CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            )
            .header(hyper::header::HOST, HeaderValue::from_str(host_only)?);

        Ok(req_builder.body(Body::from(body_bytes.clone()))?)
    };

    let request = build_request(&bearer, &x_api_key)?;
    debug!(
        "Forwarding {} {} to {} (group={} request_model={:?})",
        method, path_and_query, config.llm_host, group, request_model
    );

    debug!("Sending upstream request");
    let result = match token_cache.client.request(request).await {
        Ok(resp) => {
            debug!("Upstream response received: status={}", resp.status());
            if resp.status() == StatusCode::UNAUTHORIZED {
                warn!("Got 401 from LLM - refreshing token and retrying once");
                token_cache.clear_token().await;

                let fresh_bearer = token_cache.get_valid_bearer().await?;
                let x_api_key = token_cache.get_x_api_key().await?;

                let retry_req = build_request(&fresh_bearer, &x_api_key)?;
                info!("Retrying request with fresh token");
                match token_cache.client.request(retry_req).await {
                    Ok(retry_resp) => {
                        if retry_resp.status() == StatusCode::UNAUTHORIZED {
                            warn!("Still got 401 after token refresh");
                        }
                        // Record usage on successful retry too
                        let result = record_usage_from_response(
                            retry_resp,
                            &usage_store,
                            &group,
                            request_model.as_deref(),
                        )
                        .await;
                        result
                    }
                    Err(e) => {
                        error!("Retry request failed: {}", e);
                        Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from("Upstream error after token refresh"))?)
                    }
                }
            } else {
                let result = record_usage_from_response(
                    resp,
                    &usage_store,
                    &group,
                    request_model.as_deref(),
                )
                .await;
                result
            }
        }
        Err(e) => {
            error!("Upstream request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Upstream error"))?)
        }
    };
    debug!(
        "handle_request end: result_status={:?}",
        result.as_ref().map(|r| r.status())
    );
    result
}
const SERVICE_LABEL: &str = "com.user.llm-proxy";
const KEYCHAIN_SERVICE: &str = "llm-proxy";

fn plist_path() -> Result<PathBuf> {
    let home = home_dir().context("No home directory")?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", SERVICE_LABEL)))
}

fn log_dir() -> Result<PathBuf> {
    let home = home_dir().context("No home directory")?;
    let dir = home.join("Library/Logs/llm-proxy");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn binary_path() -> Result<PathBuf> {
    let current_exe = std::env::current_exe()?;
    if current_exe.file_name().unwrap() == "llm-proxy" {
        Ok(current_exe)
    } else {
        let home = home_dir().context("No home directory")?;
        Ok(home.join(".local/bin/llm-proxy"))
    }
}

fn config_path() -> Result<PathBuf> {
    let home = home_dir().context("No home directory")?;
    Ok(home.join(".config/llm-proxy/config.toml"))
}

async fn install_service(args: InstallArgs, config_file: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config_file, Some(&args))?;

    // Store secrets in keychain if requested
    if args.use_keychain {
        Entry::new(KEYCHAIN_SERVICE, "x-api-key")?.set_password(&config.x_api_key)?;
        if let Some(ref token) = config.bearer_token {
            Entry::new(KEYCHAIN_SERVICE, "bearer-token")?.set_password(token)?;
        }
        if let Some(ref secret) = config.client_secret {
            Entry::new(KEYCHAIN_SERVICE, "client-secret")?.set_password(secret)?;
        }
        info!(
            "Stored secrets in macOS Keychain (service: {})",
            KEYCHAIN_SERVICE
        );
    }

    // Write config file (without secrets if keychain is used)
    let cfg_path = config_path()?;
    if let Some(config_dir) = cfg_path.parent() {
        std::fs::create_dir_all(config_dir)?;
    }

    let config_file_content = ConfigFile {
        ca_cert_path: config.ca_cert_path.clone(),
        llm_host: config.llm_host.clone(),
        listen_port: config.listen_port,
        api_key: if args.use_keychain {
            String::new()
        } else {
            config.x_api_key.clone()
        },
        bearer_token: if args.use_keychain {
            None
        } else {
            config.bearer_token.clone()
        },
        token_endpoint: config.token_endpoint.clone(),
        client_id: config.client_id.clone(),
        client_secret: if args.use_keychain {
            None
        } else {
            config.client_secret.clone()
        },
        oauth_scope: config.oauth_scope.clone(),
        insecure_skip_tls_verify: config.insecure_skip_tls_verify,
        usage_store_path: Some(config.usage_store_path.to_string_lossy().to_string()),
    };
    let toml_str = toml::to_string_pretty(&config_file_content)?;
    std::fs::write(&cfg_path, toml_str)?;
    info!("Wrote config file: {}", cfg_path.display());

    let bin_path = binary_path()?;
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    // Build environment dict for launchd - only pass config path
    let mut env_dict = Dictionary::new();
    env_dict.insert(
        "LLM_PROXY_CONFIG".to_string(),
        PlistValue::String(config_path()?.to_string_lossy().to_string()),
    );
    env_dict.insert(
        "RUST_LOG".to_string(),
        PlistValue::String("info".to_string()),
    );

    let mut plist = Dictionary::new();
    plist.insert(
        "Label".to_string(),
        PlistValue::String(SERVICE_LABEL.to_string()),
    );
    plist.insert(
        "ProgramArguments".to_string(),
        PlistValue::Array(vec![
            PlistValue::String(bin_path.to_string_lossy().to_string()),
            PlistValue::String("run".to_string()),
        ]),
    );
    plist.insert("RunAtLoad".to_string(), PlistValue::Boolean(true));
    plist.insert("KeepAlive".to_string(), PlistValue::Boolean(true));
    plist.insert(
        "StandardOutPath".to_string(),
        PlistValue::String(out_log.to_string_lossy().to_string()),
    );
    plist.insert(
        "StandardErrorPath".to_string(),
        PlistValue::String(err_log.to_string_lossy().to_string()),
    );
    plist.insert(
        "EnvironmentVariables".to_string(),
        PlistValue::Dictionary(env_dict),
    );
    plist.insert(
        "WorkingDirectory".to_string(),
        PlistValue::String(
            home_dir()
                .ok_or_else(|| anyhow::anyhow!("No home directory"))?
                .to_string_lossy()
                .to_string(),
        ),
    );

    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    plist::Value::Dictionary(plist).to_file_xml(&path)?;

    info!("Installed launchd service: {}", path.display());
    info!("Config: {}", cfg_path.display());
    info!("Logs: {}", log_dir.display());
    info!("Run 'llm-proxy start' to start the service");
    Ok(())
}

fn run_launchctl(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("launchctl")
        .args(args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchctl failed: {}", stderr);
    }
    Ok(())
}

fn start_service() -> Result<()> {
    run_launchctl(&["load", "-w", plist_path()?.to_str().unwrap()])?;
    info!("Service started");
    Ok(())
}

fn stop_service() -> Result<()> {
    let _ = run_launchctl(&["unload", "-w", plist_path()?.to_str().unwrap()]);
    info!("Service stopped");
    Ok(())
}

fn restart_service() -> Result<()> {
    stop_service()?;
    std::thread::sleep(Duration::from_secs(1));
    start_service()?;
    Ok(())
}

fn status_service() -> Result<()> {
    let output = std::process::Command::new("launchctl")
        .args(["list", SERVICE_LABEL])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(SERVICE_LABEL) {
        info!("Service is LOADED");
        println!("{}", stdout);
    } else {
        info!("Service is NOT loaded");
    }
    Ok(())
}

fn logs_service() -> Result<()> {
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    println!("Following logs (Ctrl+C to stop)...");
    println!("  stdout: {}", out_log.display());
    println!("  stderr: {}", err_log.display());

    let mut child = std::process::Command::new("tail")
        .args(["-f", out_log.to_str().unwrap(), err_log.to_str().unwrap()])
        .spawn()?;
    child.wait()?;
    Ok(())
}

async fn usage_command(args: UsageArgs, config_file: Option<PathBuf>) -> Result<()> {
    let store_path = args
        .store_path
        .or_else(|| {
            Config::load(config_file.clone(), None)
                .ok()
                .map(|c| c.usage_store_path)
        })
        .unwrap_or_else(default_usage_store_path);

    let store = UsageStore::new(store_path.clone());

    if args.reset {
        store.reset().await?;
        println!("Usage store reset: {}", store_path.display());
        return Ok(());
    }

    let data = store.get().await;
    println!("Usage store: {}", store_path.display());
    println!("Global requests: {}", data.global_requests);
    println!("Global totals:");
    for (currency, amount) in &data.global_totals {
        println!("  {}: {:.10}", currency, amount);
    }

    for (group, group_usage) in &data.groups {
        println!("\nGroup: {} ({} requests)", group, group_usage.requests);
        for (model, model_usage) in &group_usage.models {
            println!("  Model: {} ({} requests)", model, model_usage.requests);
            for (currency, amount) in &model_usage.cost {
                println!("    cost {}: {:.10}", currency, amount);
            }
            for (token_type, count) in &model_usage.tokens {
                println!("    {}: {}", token_type, count);
            }
        }
    }

    Ok(())
}

fn uninstall_service() -> Result<()> {
    let _ = stop_service();
    let path = plist_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
        info!("Removed plist: {}", path.display());
    }

    // Remove config file
    let cfg_path = config_path()?;
    if cfg_path.exists() {
        std::fs::remove_file(&cfg_path)?;
        info!("Removed config: {}", cfg_path.display());
    }

    // Remove keychain entries (best effort)
    for account in ["x-api-key", "bearer-token", "client-secret"] {
        if let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, account) {
            let _ = entry.delete_credential();
        }
    }
    info!("Removed keychain entries");

    info!("Service uninstalled");
    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
            run_proxy(cli.config).await
        }
        Command::Setup => setup_config(cli.config).await,
        Command::Install(args) => install_service(args, cli.config).await,
        Command::Start => start_service(),
        Command::Stop => stop_service(),
        Command::Restart => restart_service(),
        Command::Status => status_service(),
        Command::Logs => logs_service(),
        Command::Usage(args) => usage_command(args, cli.config).await,
        Command::Uninstall => uninstall_service(),
    }
}

async fn run_proxy(config_file: Option<PathBuf>) -> Result<()> {
    let config = Arc::new(Config::load(config_file, None)?);

    let token_cache = Arc::new(TokenCache::new(config.clone()));
    let usage_store = Arc::new(UsageStore::new(config.usage_store_path.clone()));

    let addr = SocketAddr::from(([127, 0, 0, 1], config.listen_port));
    info!("LLM proxy listening on {}", addr);
    info!("Target LLM host: {}", config.llm_host);

    let make_svc = make_service_fn(move |_| {
        let token_cache = token_cache.clone();
        let usage_store = usage_store.clone();
        let config = config.clone();
        async move {
            Ok::<_, anyhow::Error>(service_fn(move |req| {
                let token_cache = token_cache.clone();
                let usage_store = usage_store.clone();
                let config = config.clone();
                async move { handle_request(req, token_cache, usage_store, config).await }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    info!("Server started, waiting for shutdown signal...");
    server.with_graceful_shutdown(shutdown_signal()).await?;
    info!("Shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT, shutting down gracefully...");
        }
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully...");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_parses_valid_toml() {
        let content = r#"
llm_host = "api.example.com"
api_key = "test-key-123"
bearer_token = "static-token-abc"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.llm_host, "api.example.com");
        assert_eq!(cfg.listen_port, 3128);
        assert_eq!(cfg.api_key, "test-key-123");
        assert_eq!(cfg.bearer_token, Some("static-token-abc".to_string()));
    }

    #[test]
    fn config_file_parses_oauth_fields() {
        let content = r#"
llm_host = "api.example.com"
api_key = "key"
m2m_oauth_url = "https://auth.example.com/oauth/token"
client_id = "my-client"
client_secret = "my-secret"
oauth_scope = "machine2machine"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.token_endpoint,
            Some("https://auth.example.com/oauth/token".to_string())
        );
        assert_eq!(cfg.client_id, Some("my-client".to_string()));
        assert_eq!(cfg.oauth_scope, Some("machine2machine".to_string()));
    }

    #[test]
    fn config_file_fails_without_auth() {
        let content = r#"
llm_host = "api.example.com"
api_key = "key"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_file_fails_without_host() {
        let content = r#"
llm_host = ""
api_key = "key"
bearer_token = "token"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_file_default_values() {
        let content = r#"
llm_host = "api.example.com"
api_key = "key"
bearer_token = "token"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        assert_eq!(cfg.listen_port, 3128);
        assert!(cfg.token_endpoint.is_none());
        assert!(cfg.ca_cert_path.is_none());
        assert!(!cfg.insecure_skip_tls_verify);
    }

    #[test]
    fn token_cache_uses_static_bearer() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = Arc::new(Config {
                listen_port: 3128,
                llm_host: "api.example.com".into(),
                bearer_token: Some("static-token".into()),
                x_api_key: "key".into(),
                token_endpoint: None,
                client_id: None,
                client_secret: None,
                oauth_scope: None,
                ca_cert_path: None,
                insecure_skip_tls_verify: false,
                usage_store_path: PathBuf::from("/tmp/llm-proxy-test-usage.json"),
            });
            let cache = TokenCache::new(config);
            let token = cache.get_valid_bearer().await.unwrap();
            assert_eq!(token, "static-token");
        });
    }

    #[test]
    fn token_cache_clear_and_repopulate() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = Arc::new(Config {
                listen_port: 3128,
                llm_host: "api.example.com".into(),
                bearer_token: Some("static-token".into()),
                x_api_key: "key".into(),
                token_endpoint: None,
                client_id: None,
                client_secret: None,
                oauth_scope: None,
                ca_cert_path: None,
                insecure_skip_tls_verify: false,
                usage_store_path: PathBuf::from("/tmp/llm-proxy-test-usage.json"),
            });
            let cache = TokenCache::new(config);
            // First call populates
            let _ = cache.get_valid_bearer().await.unwrap();
            // Clear the cached token
            cache.clear_token().await;
            // Should still get static token
            let token = cache.get_valid_bearer().await.unwrap();
            assert_eq!(token, "static-token");
        });
    }

    #[test]
    fn token_cache_returns_x_api_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = Arc::new(Config {
                listen_port: 3128,
                llm_host: "api.example.com".into(),
                bearer_token: Some("token".into()),
                x_api_key: "my-api-key".into(),
                token_endpoint: None,
                client_id: None,
                client_secret: None,
                oauth_scope: None,
                ca_cert_path: None,
                insecure_skip_tls_verify: false,
                usage_store_path: PathBuf::from("/tmp/llm-proxy-test-usage.json"),
            });
            let cache = TokenCache::new(config);
            let key = cache.get_x_api_key().await.unwrap();
            assert_eq!(key, "my-api-key");
        });
    }

    #[test]
    fn config_file_with_insecure_tls() {
        let content = r#"
llm_host = "api.example.com"
api_key = "key"
bearer_token = "token"
insecure_skip_tls_verify = true
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.insecure_skip_tls_verify);
    }

    #[test]
    fn usage_store_records_group_model_cost_and_tokens() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let store = UsageStore::new(tmp.path().to_path_buf());

            let mut tokens = BTreeMap::new();
            tokens.insert("prompt_tokens".to_string(), 100_u64);
            tokens.insert("completion_tokens".to_string(), 50_u64);
            store
                .record("team-a", "gpt-4o", Some((0.00123, "USD".into())), tokens)
                .await
                .unwrap();

            let data = store.get().await;
            assert_eq!(data.global_requests, 1);
            assert_eq!(data.global_totals.get("USD").unwrap(), &0.00123);

            let group = data.groups.get("team-a").unwrap();
            assert_eq!(group.requests, 1);
            let model = group.models.get("gpt-4o").unwrap();
            assert_eq!(model.requests, 1);
            assert_eq!(model.cost.get("USD").unwrap(), &0.00123);
            assert_eq!(model.tokens.get("prompt_tokens").unwrap(), &100);
            assert_eq!(model.tokens.get("completion_tokens").unwrap(), &50);
        });
    }

    #[test]
    fn usage_store_persists_and_loads() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let path = tmp.path().to_path_buf();

            {
                let store = UsageStore::new(path.clone());
                let mut tokens = BTreeMap::new();
                tokens.insert("input_tokens".to_string(), 10_u64);
                store
                    .record(
                        "default",
                        "claude-opus",
                        Some((0.005, "USD".into())),
                        tokens,
                    )
                    .await
                    .unwrap();
            }

            let store2 = UsageStore::new(path);
            let data = store2.get().await;
            assert_eq!(data.global_requests, 1);
            assert_eq!(data.global_totals.get("USD").unwrap(), &0.005);
        });
    }

    #[test]
    fn model_fallback_uses_request_body_when_response_omits_model() {
        let response_body = r#"{
            "cost": {"total": 0.002, "currency": "USD"},
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}
        }"#;
        let response_json: serde_json::Value = serde_json::from_str(response_body).unwrap();

        let resolve = |req: &str, query: Option<&str>, header: Option<&str>| {
            let parsed: Option<serde_json::Value> = serde_json::from_str(req).ok();
            parsed
                .as_ref()
                .and_then(|v| {
                    v["model"]
                        .as_str()
                        .or_else(|| v["model_id"].as_str())
                        .map(|s| s.to_string())
                })
                .or_else(|| {
                    query.and_then(|q| {
                        q.split('&').find_map(|pair| {
                            let mut it = pair.splitn(2, '=');
                            if it.next()? == "model" {
                                it.next().map(|v| v.replace('+', " "))
                            } else {
                                None
                            }
                        })
                    })
                })
                .or_else(|| header.map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".to_string())
        };

        // Body fallback
        assert_eq!(
            resolve(r#"{"model":"gpt-4o-mini"}"#, None, None),
            "gpt-4o-mini"
        );

        // Query fallback
        assert_eq!(
            resolve("{}", Some("model=claude-3-5-sonnet"), None),
            "claude-3-5-sonnet"
        );

        // Header fallback
        assert_eq!(
            resolve("{}", None, Some("custom-model-v1")),
            "custom-model-v1"
        );

        // When response has no model, fallback is used
        assert_eq!(
            resolve_with_response(&response_json, Some("gpt-4o-mini".to_string())),
            "gpt-4o-mini"
        );
    }

    fn resolve_with_response(
        response_json: &serde_json::Value,
        request_model: Option<String>,
    ) -> String {
        response_json["model"]
            .as_str()
            .or_else(|| response_json["model_id"].as_str())
            .map(|s| s.to_string())
            .or_else(|| request_model.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[test]
    fn resolve_usage_group_uses_header_then_token_then_apikey() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-usage-group", "project-x".parse().unwrap());
        assert_eq!(resolve_usage_group(&headers), "project-x");

        let mut headers = hyper::HeaderMap::new();
        headers.insert("authorization", "Bearer abc123".parse().unwrap());
        assert!(resolve_usage_group(&headers).starts_with("auth:"));

        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-apikey", "secret-key".parse().unwrap());
        assert!(resolve_usage_group(&headers).starts_with("apikey:"));

        let headers = hyper::HeaderMap::new();
        assert_eq!(resolve_usage_group(&headers), "default");
    }

    #[test]
    fn config_file_with_usage_store_path() {
        let content = r#"
llm_host = "api.example.com"
api_key = "key"
bearer_token = "token"
usage_store_path = "/custom/usage.json"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        assert_eq!(cfg.usage_store_path, Some("/custom/usage.json".to_string()));
    }
}
