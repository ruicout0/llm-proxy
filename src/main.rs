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
use hyper::{
    header::{HeaderValue, AUTHORIZATION, CACHE_CONTROL},
    Method, Request, Response, StatusCode, Body
};
use hyper::service::{make_service_fn, service_fn};
use hyper::server::Server;
use hyper::client::HttpConnector;
use rustls_pemfile;
use hyper_rustls::HttpsConnector;
use hyper::Client;
use keyring::Entry;
use plist::{Dictionary, Value as PlistValue};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use hyper::body::to_bytes;

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
}

fn default_port() -> u16 { 3128 }

impl ConfigFile {
    fn validate(&self) -> Result<()> {
        if self.llm_host.is_empty() {
            anyhow::bail!("llm_host is required in config file");
        }
        if self.api_key.is_empty() {
            anyhow::bail!("api_key is required in config file");
        }
        let has_static = self.bearer_token.is_some();
        let has_oauth = self.token_endpoint.is_some() && self.client_id.is_some() && self.client_secret.is_some();
        if !has_static && !has_oauth {
            anyhow::bail!("Either bearer_token OR (m2m_oauth_url + client_id + client_secret) must be provided");
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
    /// Uninstall the service
    Uninstall,
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
}

impl Config {
    /// Load config from file, with CLI args as override
    fn load(config_path: Option<PathBuf>, cli_args: Option<&InstallArgs>) -> Result<Self> {
        // Determine config file path
        let path = config_path.unwrap_or_else(|| {
            home_dir().unwrap().join(".config/llm-proxy/config.toml")
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
                if let Some(ref v) = args.host { fc.llm_host = v.clone(); }
                if let Some(ref v) = args.api_key { fc.api_key = v.clone(); }
                if let Some(ref v) = args.bearer_token { fc.bearer_token = Some(v.clone()); }
                if let Some(ref v) = args.m2m_oauth_url { fc.token_endpoint = Some(v.clone()); }
                if let Some(ref v) = args.client_id { fc.client_id = Some(v.clone()); }
                if let Some(ref v) = args.client_secret { fc.client_secret = Some(v.clone()); }
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
                });
                file_config.as_ref().unwrap().validate()?;
            }
        } else if file_config.is_none() {
            anyhow::bail!("Config file not found at: {}. Run 'llm-proxy install' or create it manually.", path.display());
        }

        let fc = file_config.unwrap();
        
        Ok(Self {
            listen_port: fc.listen_port,
            llm_host: fc.llm_host,
            bearer_token: fc.bearer_token,
            x_api_key: fc.api_key,
            token_endpoint: fc.token_endpoint,
            client_id: fc.client_id,
            client_secret: fc.client_secret,
            oauth_scope: fc.oauth_scope,
            ca_cert_path: fc.ca_cert_path,
            insecure_skip_tls_verify: fc.insecure_skip_tls_verify,
        })
    }
}
// Interactive Setup
// ============================================================================

async fn setup_config(config_path: Option<PathBuf>) -> Result<()> {
    use dialoguer::{Confirm, Input, Select};
    
    let path = config_path.unwrap_or_else(|| {
        home_dir().unwrap().join(".config/llm-proxy/config.toml")
    });
    
    println!("\n🔧 llm-proxy Interactive Setup");
    println!("==============================\n");
    
    if path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!("Config file already exists at {}. Overwrite?", path.display()))
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
    let auth_methods = &["M2M OAuth auto-refresh (recommended)", "Static bearer token"];
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
    };
    
    if auth_choice == 0 {
        // M2M OAuth
        let token_endpoint: String = Input::new()
            .with_prompt("M2M OAuth token endpoint URL (e.g., https://auth.example.com/oauth/token)")
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
        
        let client = Client::builder().build(https);
        Self {
            bearer_token: RwLock::new(None),
            config,
            client,
        }
    }

    async fn get_valid_bearer(&self) -> Result<String> {
        // Check cached token
        {
            let guard = self.bearer_token.read().await;
            if let Some((token, expiry)) = &*guard {
                if *expiry > Instant::now() + Duration::from_secs(60) {
                    return Ok(token.clone());
                }
            }
        }

        // Need refresh - either use static key or fetch new token
        if let Some(key) = &self.config.bearer_token {
            return Ok(key.clone());
        }

        // Fetch from token endpoint
        self.refresh_token().await
    }

    async fn get_x_api_key(&self) -> Result<String> {
        Ok(self.config.x_api_key.clone())
    }

    async fn refresh_token(&self) -> Result<String> {
        let token_url = self.config.token_endpoint.as_ref()
            .context("No token endpoint configured and no static bearer token")?;
        
        let client_id = self.config.client_id.as_ref()
            .context("client_id required for token refresh")?;
        let client_secret = self.config.client_secret.as_ref()
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
        
        let access_token = json["access_token"].as_str()
            .context("No access_token in response")?
            .to_string();
        let expires_in = json["expires_in"].as_u64().unwrap_or(3600);

        let expiry = Instant::now() + Duration::from_secs(expires_in - 60); // Refresh 1 min early
        *self.bearer_token.write().await = Some((access_token.clone(), expiry));
        
        info!("Refreshed LLM bearer token (expires in {}s)", expires_in);
        Ok(access_token)
    }
}

async fn handle_request(
    req: Request<Body>,
    token_cache: Arc<TokenCache>,
    config: Arc<Config>,
) -> Result<Response<Body>> {
    // Get path and query before consuming req
    let path_and_query = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    
    // Always inject auth headers and forward to configured LLM host
    let bearer = token_cache.get_valid_bearer().await?;
    let x_api_key = token_cache.get_x_api_key().await?;
    
    let (mut parts, body) = req.into_parts();
    
    // Rewrite URI to target the LLM host
    let new_uri = format!("https://{}{}", config.llm_host, path_and_query);
    parts.uri = new_uri.parse()?;
    
    // Inject auth headers
    parts.headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", bearer))?
    );
    
    parts.headers.insert(
        "x-apikey".parse::<hyper::header::HeaderName>()?,
        HeaderValue::from_str(&x_api_key)?
    );
    
    parts.headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate")
    );
    
    // Ensure Host header matches target (hostname only, no path)
    let host_only = config.llm_host.split('/').next().unwrap_or(&config.llm_host);
    parts.headers.insert(
        hyper::header::HOST,
        HeaderValue::from_str(host_only)?
    );
    
    debug!("Forwarding to {} with auth headers", config.llm_host);
    
    let req = Request::from_parts(parts, body);
    
    match token_cache.client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.into_body();
            
            if status == StatusCode::UNAUTHORIZED {
                warn!("Got 401 from LLM - forcing token refresh on next request");
                *token_cache.bearer_token.write().await = None;
            }
            
            Ok(Response::builder()
                .status(status)
                .body(body)?)
        }
        Err(e) => {
            error!("Upstream request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Upstream error"))?)
        }
    }
}
const SERVICE_LABEL: &str = "com.user.llm-proxy";
const KEYCHAIN_SERVICE: &str = "llm-proxy";

fn plist_path() -> Result<PathBuf> {
    let home = home_dir().context("No home directory")?;
    Ok(home.join("Library/LaunchAgents").join(format!("{}.plist", SERVICE_LABEL)))
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

fn config_path() -> PathBuf {
    home_dir().unwrap().join(".config/llm-proxy/config.toml")
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
        info!("Stored secrets in macOS Keychain (service: {})", KEYCHAIN_SERVICE);
    }

    // Write config file
    let cfg_path = config_path();
    if let Some(config_dir) = cfg_path.parent() {
        std::fs::create_dir_all(config_dir)?;
    }
    
    let config_file_content = ConfigFile {
        ca_cert_path: config.ca_cert_path.clone(),
        llm_host: config.llm_host.clone(),
        listen_port: config.listen_port,
        api_key: config.x_api_key.clone(),
        bearer_token: config.bearer_token.clone(),
        token_endpoint: config.token_endpoint.clone(),
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        oauth_scope: config.oauth_scope.clone(),
        insecure_skip_tls_verify: config.insecure_skip_tls_verify,
    };
    let toml_str = toml::to_string_pretty(&config_file_content)?;
    std::fs::write(&cfg_path, toml_str)?;
    info!("Wrote config file: {}", config_path().display());

    let bin_path = binary_path()?;
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    // Build environment dict for launchd - only pass config path
    let mut env_dict = Dictionary::new();
    env_dict.insert("LLM_PROXY_CONFIG".to_string(), PlistValue::String(config_path().to_string_lossy().to_string()));
    env_dict.insert("RUST_LOG".to_string(), PlistValue::String("info".to_string()));

    let mut plist = Dictionary::new();
    plist.insert("Label".to_string(), PlistValue::String(SERVICE_LABEL.to_string()));
    plist.insert("ProgramArguments".to_string(), PlistValue::Array(vec![
        PlistValue::String(bin_path.to_string_lossy().to_string()),
        PlistValue::String("run".to_string()),
    ]));
    plist.insert("RunAtLoad".to_string(), PlistValue::Boolean(true));
    plist.insert("KeepAlive".to_string(), PlistValue::Boolean(true));
    plist.insert("StandardOutPath".to_string(), PlistValue::String(out_log.to_string_lossy().to_string()));
    plist.insert("StandardErrorPath".to_string(), PlistValue::String(err_log.to_string_lossy().to_string()));
    plist.insert("EnvironmentVariables".to_string(), PlistValue::Dictionary(env_dict));
    plist.insert("WorkingDirectory".to_string(), PlistValue::String(home_dir().ok_or_else(|| anyhow::anyhow!("No home directory"))?.to_string_lossy().to_string()));

    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    plist::Value::Dictionary(plist).to_file_xml(&path)?;

    info!("Installed launchd service: {}", path.display());
    info!("Config: {}", config_path().display());
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

fn uninstall_service() -> Result<()> {
    let _ = stop_service();
    let path = plist_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
        info!("Removed plist: {}", path.display());
    }
    
    // Remove config file
    let cfg_path = config_path();
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
        Command::Uninstall => uninstall_service(),
    }
}

async fn run_proxy(config_file: Option<PathBuf>) -> Result<()> {
    let config = Arc::new(Config::load(config_file, None)?);
    
    let token_cache = Arc::new(TokenCache::new(config.clone()));
    
    let addr = SocketAddr::from(([127, 0, 0, 1], config.listen_port));
    info!("LLM proxy listening on {}", addr);
    info!("Target LLM host: {}", config.llm_host);

    let make_svc = make_service_fn(move |_| {
        let token_cache = token_cache.clone();
        let config = config.clone();
        async move {
            Ok::<_, anyhow::Error>(service_fn(move |req| {
                let token_cache = token_cache.clone();
                let config = config.clone();
                async move { handle_request(req, token_cache, config).await }
            }))
        }
    });

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}