//! llm-proxy - Multi-Provider LLM Proxy with auth header injection, usage tracking, and model discovery.

pub mod config;
pub mod discovery;
pub mod provider;
pub mod proxy;
pub mod router;
pub mod usage;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dirs::home_dir;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use keyring::Entry;
use plist::{Dictionary, Value as PlistValue};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::{default_usage_store_path, ConfigFile, ProviderConfig};
use crate::discovery::DiscoveryCache;
use crate::provider::KEYCHAIN_SERVICE;
use crate::proxy::handle_request;
use crate::router::Registry;
use crate::usage::UsageStore;

#[derive(Parser)]
#[command(name = "llm-proxy", version, about = "Lightweight multi-provider LLM proxy with OAuth token refresh and usage tracking")]
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
    /// List configured providers
    Providers(ProvidersArgs),
    /// Migrate keychain accounts to <provider>:<secret>
    MigrateKeychain(MigrateKeychainArgs),
    /// Uninstall the service
    Uninstall,
}

#[derive(Parser)]
struct ProvidersArgs {
    #[command(subcommand)]
    subcmd: Option<ProvidersSubcommand>,
}

#[derive(Subcommand)]
enum ProvidersSubcommand {
    /// List all configured providers
    List,
}

#[derive(Parser)]
struct MigrateKeychainArgs {
    /// Preview migrations without modifying Keychain
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser)]
struct UsageArgs {
    /// Path to usage store JSON (overrides config)
    #[arg(short = 'p', long)]
    store_path: Option<PathBuf>,

    /// Filter by provider ID
    #[arg(long)]
    provider: Option<String>,

    /// Show detailed provider breakdown
    #[arg(long)]
    by_provider: bool,

    /// Reset all usage data
    #[arg(long)]
    reset: bool,
}

#[derive(Parser, Clone)]
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
// Runtime & Service Helpers
// ============================================================================

const SERVICE_LABEL: &str = "com.user.llm-proxy";

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
    if current_exe.file_name().and_then(|s| s.to_str()) == Some("llm-proxy") {
        Ok(current_exe)
    } else {
        let home = home_dir().context("No home directory")?;
        Ok(home.join(".local/bin/llm-proxy"))
    }
}

pub fn config_path() -> Result<PathBuf> {
    let home = home_dir().context("No home directory")?;
    Ok(home.join(".config/llm-proxy/config.toml"))
}

pub fn load_config(path_override: Option<PathBuf>) -> Result<ConfigFile> {
    let path = path_override.unwrap_or_else(|| config_path().unwrap_or_else(|_| PathBuf::from("config.toml")));
    if !path.exists() {
        anyhow::bail!(
            "Config file not found at: {}. Run 'llm-proxy install' or create it manually.",
            path.display()
        );
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let cfg: ConfigFile = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
    cfg.validate()?;
    Ok(cfg)
}

async fn install_service(args: InstallArgs, config_file: Option<PathBuf>) -> Result<()> {
    let cfg_path = config_file.unwrap_or_else(|| config_path().unwrap());
    if let Some(config_dir) = cfg_path.parent() {
        std::fs::create_dir_all(config_dir)?;
    }

    let default_prov_id = "bmw".to_string();

    if args.use_keychain {
        if let Some(ref key) = args.api_key {
            Entry::new(KEYCHAIN_SERVICE, &format!("{}:api_key", default_prov_id))?.set_password(key)?;
        }
        if let Some(ref token) = args.bearer_token {
            Entry::new(KEYCHAIN_SERVICE, &format!("{}:bearer_token", default_prov_id))?.set_password(token)?;
        }
        if let Some(ref secret) = args.client_secret {
            Entry::new(KEYCHAIN_SERVICE, &format!("{}:client_secret", default_prov_id))?.set_password(secret)?;
        }
        info!("Stored secrets in macOS Keychain under namespace: {}", default_prov_id);
    }

    let prov = ProviderConfig {
        id: default_prov_id.clone(),
        base_url: args.host.unwrap_or_else(|| "api.example.com".to_string()),
        scheme: Some("https".to_string()),
        auth_style: if args.bearer_token.is_some() {
            Some(crate::config::AuthStyleConfig::StaticBearer)
        } else if args.m2m_oauth_url.is_some() {
            Some(crate::config::AuthStyleConfig::OauthM2m)
        } else {
            None
        },
        api_key: if args.use_keychain { None } else { args.api_key.clone() },
        api_key_ref: if args.use_keychain { Some(format!("keychain:{}:api_key", default_prov_id)) } else { None },
        bearer_token: if args.use_keychain { None } else { args.bearer_token.clone() },
        bearer_token_ref: if args.use_keychain { Some(format!("keychain:{}:bearer_token", default_prov_id)) } else { None },
        m2m_oauth_url: args.m2m_oauth_url.clone(),
        client_id: args.client_id.clone(),
        client_secret: if args.use_keychain { None } else { args.client_secret.clone() },
        client_secret_ref: if args.use_keychain { Some(format!("keychain:{}:client_secret", default_prov_id)) } else { None },
        oauth_scope: None,
        header_name: None,
        header_value: None,
        header_value_ref: None,
        ca_cert_path: None,
        insecure_skip_tls_verify: false,
        models: Vec::new(),
    };

    let config_file_content = ConfigFile {
        llm_host: None,
        listen_port: args.port,
        api_key: None,
        token_endpoint: None,
        client_id: None,
        client_secret: None,
        oauth_scope: None,
        bearer_token: None,
        ca_cert_path: None,
        insecure_skip_tls_verify: false,
        usage_store_path: Some(default_usage_store_path().to_string_lossy().to_string()),
        default_provider: default_prov_id,
        model_separator: '/',
        discovery_ttl_secs: 300,
        discovery_timeout_ms: 2500,
        providers: vec![prov],
    };

    let toml_str = toml::to_string_pretty(&config_file_content)?;
    std::fs::write(&cfg_path, toml_str)?;
    info!("Wrote config file: {}", cfg_path.display());

    let bin_path = binary_path()?;
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    let mut env_dict = Dictionary::new();
    env_dict.insert(
        "LLM_PROXY_CONFIG".to_string(),
        PlistValue::String(cfg_path.to_string_lossy().to_string()),
    );
    env_dict.insert(
        "RUST_LOG".to_string(),
        PlistValue::String("info".to_string()),
    );

    let mut plist = Dictionary::new();
    plist.insert("Label".to_string(), PlistValue::String(SERVICE_LABEL.to_string()));
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
    plist.insert("EnvironmentVariables".to_string(), PlistValue::Dictionary(env_dict));
    plist.insert(
        "WorkingDirectory".to_string(),
        PlistValue::String(home_dir().context("No home directory")?.to_string_lossy().to_string()),
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
    let output = std::process::Command::new("launchctl").args(args).output()?;
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

    let cfg_path = config_path()?;
    if cfg_path.exists() {
        std::fs::remove_file(&cfg_path)?;
        info!("Removed config: {}", cfg_path.display());
    }

    info!("Service uninstalled");
    Ok(())
}

async fn setup_config(config_path: Option<PathBuf>) -> Result<()> {
    use dialoguer::{Input, Select};
    let path = config_path.unwrap_or_else(|| crate::config_path().unwrap());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let host: String = Input::new()
        .with_prompt("LLM Host (e.g. api.openai.com)")
        .interact_text()?;
    let auth_type = Select::new()
        .with_prompt("Authentication Method")
        .items(&["OAuth M2M", "Static Bearer / API Key", "None"])
        .default(0)
        .interact()?;

    let install_args = match auth_type {
        0 => {
            let m2m_oauth_url: String = Input::new().with_prompt("OAuth URL").interact_text()?;
            let client_id: String = Input::new().with_prompt("Client ID").interact_text()?;
            let client_secret: String = Input::new().with_prompt("Client Secret").interact_text()?;
            let api_key: String = Input::new().with_prompt("X-API-Key").interact_text()?;
            InstallArgs {
                host: Some(host),
                api_key: Some(api_key),
                bearer_token: None,
                m2m_oauth_url: Some(m2m_oauth_url),
                client_id: Some(client_id),
                client_secret: Some(client_secret),
                port: 3128,
                use_keychain: true,
            }
        }
        1 => {
            let api_key: String = Input::new().with_prompt("API Key / Bearer Token").interact_text()?;
            InstallArgs {
                host: Some(host),
                api_key: Some(api_key.clone()),
                bearer_token: Some(api_key),
                m2m_oauth_url: None,
                client_id: None,
                client_secret: None,
                port: 3128,
                use_keychain: true,
            }
        }
        _ => InstallArgs {
            host: Some(host),
            api_key: None,
            bearer_token: None,
            m2m_oauth_url: None,
            client_id: None,
            client_secret: None,
            port: 3128,
            use_keychain: false,
        },
    };

    install_service(install_args, Some(path)).await
}

async fn usage_command(args: UsageArgs, config_file: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config_file).ok();
    let store_path = args
        .store_path
        .or_else(|| cfg.as_ref().and_then(|c| c.usage_store_path.clone().map(PathBuf::from)))
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

        if args.by_provider {
            for (prov, prov_usage) in &group_usage.providers {
                if let Some(ref filter_p) = args.provider {
                    if filter_p != prov {
                        continue;
                    }
                }
                println!("  Provider: {} ({} requests)", prov, prov_usage.requests);
                for (model, model_usage) in &prov_usage.models {
                    println!("    Model: {} ({} requests)", model, model_usage.requests);
                    for (currency, amount) in &model_usage.cost {
                        println!("      cost (reported) {}: {:.10}", currency, amount);
                    }
                    for (currency, amount) in &model_usage.cost_estimated {
                        println!("      cost (estimated) {}: {:.10}", currency, amount);
                    }
                    for (token_type, count) in &model_usage.tokens {
                        println!("      {}: {}", token_type, count);
                    }
                }
            }
        } else {
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
    }

    Ok(())
}

fn migrate_keychain(args: MigrateKeychainArgs) -> Result<()> {
    let legacy_keys = [
        ("x-api-key", "bmw:api_key"),
        ("bearer-token", "bmw:bearer_token"),
        ("client-secret", "bmw:client_secret"),
    ];

    println!("Keychain Migration:");
    for (legacy, new_account) in legacy_keys {
        if let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, legacy) {
            if let Ok(val) = entry.get_password() {
                if args.dry_run {
                    println!("  [DRY RUN] Found '{}', would copy to '{}'", legacy, new_account);
                } else {
                    let new_entry = Entry::new(KEYCHAIN_SERVICE, new_account)?;
                    new_entry.set_password(&val)?;
                    println!("  Copied '{}' -> '{}'", legacy, new_account);
                }
            } else {
                println!("  '{}' not present in Keychain (skipping)", legacy);
            }
        }
    }
    if args.dry_run {
        println!("Dry run complete. No changes made.");
    } else {
        println!("Keychain migration complete.");
    }
    Ok(())
}

fn providers_command(_args: ProvidersArgs, config_file: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config_file)?;
    let (_, providers) = cfg.normalize_providers();

    println!("Configured Providers (Default: {}):\n", cfg.default_provider);
    for p in providers {
        println!("Provider: {}", p.id);
        println!("  Base URL: {}://{}", p.scheme.as_deref().unwrap_or("https"), p.base_url);
        println!("  Auth Style: {:?}", p.auth_style);
        println!("  Models configured: {}", p.models.len());
        for m in &p.models {
            println!("    - ID: {} (alias: {:?}, hidden: {})", m.id, m.alias, m.hidden);
        }
        println!();
    }
    Ok(())
}

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
        Command::Providers(args) => providers_command(args, cli.config),
        Command::MigrateKeychain(args) => migrate_keychain(args),
        Command::Uninstall => uninstall_service(),
    }
}

async fn run_proxy(config_file: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_file)?;
    let registry = Arc::new(Registry::new(&config));
    let discovery = Arc::new(DiscoveryCache::new(&config));

    let usage_store_path = config
        .usage_store_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(default_usage_store_path);
    let usage_store = Arc::new(UsageStore::new(usage_store_path));

    // Warm discovery in background on startup
    {
        let disc = discovery.clone();
        let reg = registry.clone();
        tokio::spawn(async move {
            info!("Warming model discovery cache...");
            if let Err(e) = disc.get_models(&reg).await {
                warn!("Initial discovery warming encountered errors: {}", e);
            } else {
                info!("Model discovery cache warmed successfully");
            }
        });
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], config.listen_port));
    info!("LLM proxy listening on {}", addr);
    info!("Configured default provider: {}", registry.default_provider);

    let make_svc = make_service_fn(move |_| {
        let registry = registry.clone();
        let discovery = discovery.clone();
        let usage_store = usage_store.clone();
        async move {
            Ok::<_, anyhow::Error>(service_fn(move |req| {
                let registry = registry.clone();
                let discovery = discovery.clone();
                let usage_store = usage_store.clone();
                async move { handle_request(req, registry, discovery, usage_store).await }
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
// Unit and Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::provider::*;
    use crate::proxy::*;
    use crate::usage::*;
    use std::collections::BTreeMap;

    #[test]
    fn config_file_parses_valid_toml() {
        let content = r#"
llm_host = "api.example.com"
api_key = "test-key-123"
bearer_token = "static-token-abc"
"#;
        let cfg: ConfigFile = toml::from_str(content).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.llm_host, Some("api.example.com".to_string()));
        assert_eq!(cfg.listen_port, 3128);
        assert_eq!(cfg.api_key, Some("test-key-123".to_string()));
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
            let p_cfg = ProviderConfig {
                id: "test".to_string(),
                base_url: "api.example.com".to_string(),
                scheme: Some("https".to_string()),
                auth_style: Some(AuthStyleConfig::StaticBearer),
                api_key: Some("key".into()),
                api_key_ref: None,
                bearer_token: Some("static-token".into()),
                bearer_token_ref: None,
                m2m_oauth_url: None,
                client_id: None,
                client_secret: None,
                client_secret_ref: None,
                oauth_scope: None,
                header_name: None,
                header_value: None,
                header_value_ref: None,
                ca_cert_path: None,
                insecure_skip_tls_verify: false,
                models: Vec::new(),
            };
            let provider = Provider::new(&p_cfg).unwrap();
            let token = provider.token_cache.get_valid_bearer().await.unwrap();
            assert_eq!(token, "static-token");
        });
    }

    #[test]
    fn token_cache_clear_and_repopulate() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let p_cfg = ProviderConfig {
                id: "test".to_string(),
                base_url: "api.example.com".to_string(),
                scheme: Some("https".to_string()),
                auth_style: Some(AuthStyleConfig::StaticBearer),
                api_key: Some("key".into()),
                api_key_ref: None,
                bearer_token: Some("static-token".into()),
                bearer_token_ref: None,
                m2m_oauth_url: None,
                client_id: None,
                client_secret: None,
                client_secret_ref: None,
                oauth_scope: None,
                header_name: None,
                header_value: None,
                header_value_ref: None,
                ca_cert_path: None,
                insecure_skip_tls_verify: false,
                models: Vec::new(),
            };
            let provider = Provider::new(&p_cfg).unwrap();
            let _ = provider.token_cache.get_valid_bearer().await.unwrap();
            provider.token_cache.clear_token().await;
            let token = provider.token_cache.get_valid_bearer().await.unwrap();
            assert_eq!(token, "static-token");
        });
    }

    #[test]
    fn token_cache_returns_x_api_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let p_cfg = ProviderConfig {
                id: "test".to_string(),
                base_url: "api.example.com".to_string(),
                scheme: Some("https".to_string()),
                auth_style: Some(AuthStyleConfig::StaticBearer),
                api_key: Some("my-api-key".into()),
                api_key_ref: None,
                bearer_token: Some("token".into()),
                bearer_token_ref: None,
                m2m_oauth_url: None,
                client_id: None,
                client_secret: None,
                client_secret_ref: None,
                oauth_scope: None,
                header_name: None,
                header_value: None,
                header_value_ref: None,
                ca_cert_path: None,
                insecure_skip_tls_verify: false,
                models: Vec::new(),
            };
            let provider = Provider::new(&p_cfg).unwrap();
            let key = provider.token_cache.get_x_api_key().await.unwrap();
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

        assert_eq!(
            resolve(r#"{"model":"gpt-4o-mini"}"#, None, None),
            "gpt-4o-mini"
        );
        assert_eq!(
            resolve("{}", Some("model=claude-3-5-sonnet"), None),
            "claude-3-5-sonnet"
        );
        assert_eq!(
            resolve("{}", None, Some("custom-model-v1")),
            "custom-model-v1"
        );

        let resolve_with_resp = |resp: &serde_json::Value, req_m: Option<String>| {
            resp["model"]
                .as_str()
                .or_else(|| resp["model_id"].as_str())
                .map(|s| s.to_string())
                .or(req_m)
                .unwrap_or_else(|| "unknown".to_string())
        };
        assert_eq!(
            resolve_with_resp(&response_json, Some("gpt-4o-mini".to_string())),
            "gpt-4o-mini"
        );
    }

    #[test]
    fn parse_sse_usage_extracts_model_and_tokens_from_final_chunk() {
        let sse = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}],\"usage\":null}\n",
            "\n",
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}],\"usage\":null}\n",
            "\n",
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n",
            "\n",
            "data: [DONE]\n"
        );
        let (model, cost, tokens) = parse_sse_usage(sse.as_bytes(), None).unwrap();
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        assert_eq!(cost, None);
        assert_eq!(tokens.get("prompt_tokens").unwrap(), &11);
        assert_eq!(tokens.get("completion_tokens").unwrap(), &7);
        assert_eq!(tokens.get("total_tokens").unwrap(), &18);
    }

    #[test]
    fn parse_sse_usage_reads_cost_and_falls_back_to_request_model() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n",
            "\n",
            "data: {\"choices\":[],\"usage\":{\"total_tokens\":5},\"cost\":{\"total\":0.0042,\"currency\":\"USD\"}}\n",
            "\n",
            "data: [DONE]\n"
        );
        let (model, cost, tokens) =
            parse_sse_usage(sse.as_bytes(), Some("claude-3-5-sonnet")).unwrap();
        assert_eq!(model.as_deref(), Some("claude-3-5-sonnet"));
        assert_eq!(cost, Some((0.0042, "USD".to_string())));
        assert_eq!(tokens.get("total_tokens").unwrap(), &5);
    }

    #[test]
    fn parse_sse_usage_returns_none_without_usage_or_cost() {
        let sse = "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n";
        assert!(parse_sse_usage(sse.as_bytes(), None).is_none());
    }

    #[test]
    fn parse_sse_usage_ignores_malformed_lines() {
        let sse = concat!(
            "event: ping\n",
            "data: not-json\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"total_tokens\":3}}\n",
            "data: [DONE]\n"
        );
        let (model, _, tokens) = parse_sse_usage(sse.as_bytes(), None).unwrap();
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        assert_eq!(tokens.get("total_tokens").unwrap(), &3);
    }

    #[test]
    fn stream_flag_detected_and_stream_options_injected() {
        fn prepare(body: &str) -> (bool, serde_json::Value) {
            let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
            let is_stream = parsed
                .as_ref()
                .and_then(|v| v["stream"].as_bool())
                .unwrap_or(false);
            let mut out = parsed.clone().unwrap();
            if is_stream && out.is_object() {
                match out
                    .get_mut("stream_options")
                    .and_then(|o| o.as_object_mut())
                {
                    Some(o) => {
                        o.insert("include_usage".to_string(), serde_json::Value::Bool(true));
                    }
                    None => {
                        out["stream_options"] = serde_json::json!({ "include_usage": true });
                    }
                }
            }
            (is_stream, out)
        }

        let (is_stream, out) = prepare(r#"{"model":"gpt-4o","stream":true}"#);
        assert!(is_stream);
        assert_eq!(
            out["stream_options"]["include_usage"],
            serde_json::json!(true)
        );

        let (is_stream, out) =
            prepare(r#"{"model":"gpt-4o","stream":true,"stream_options":{"foo":1}}"#);
        assert!(is_stream);
        assert_eq!(out["stream_options"]["foo"], serde_json::json!(1));
        assert_eq!(
            out["stream_options"]["include_usage"],
            serde_json::json!(true)
        );

        let (is_stream, out) = prepare(r#"{"model":"gpt-4o","temperature":0.7}"#);
        assert!(!is_stream);
        assert!(out.get("stream_options").is_none());
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

    // ========================================================================
    // Multi-Provider New Test Cases
    // ========================================================================

    #[tokio::test]
    async fn routing_precedence_all_cases() {
        let toml_str = r#"
default_provider = "bmw"
model_separator = "/"

[[providers]]
id = "bmw"
base_url = "api.bmw.com"
auth_style = "bearer_api_key"
api_key = "bmw-key"

  [[providers.models]]
  id = "gpt-4o"
  alias = "fast"

[[providers]]
id = "openai"
base_url = "api.openai.com"
auth_style = "bearer_api_key"
api_key = "openai-key"

  [[providers.models]]
  id = "gpt-4o"
  alias = "o-fast"

  [[providers.models]]
  id = "o3-mini"
"#;
        let cfg: ConfigFile = toml::from_str(toml_str).unwrap();
        let registry = Registry::new(&cfg);

        // 1. Prefixed model
        let r1 = registry.resolve_route(Some("openai/gpt-4o"), None).await.unwrap();
        assert_eq!(r1.provider.id, "openai");
        assert_eq!(r1.upstream_model, "gpt-4o");
        assert_eq!(r1.canonical_model, "openai/gpt-4o");

        // 1b. Unknown provider prefix -> error
        assert!(registry.resolve_route(Some("unknown/model"), None).await.is_err());

        // 2. Alias
        let r2 = registry.resolve_route(Some("fast"), None).await.unwrap();
        assert_eq!(r2.provider.id, "bmw");
        assert_eq!(r2.canonical_model, "bmw/gpt-4o");

        // 3. x-llm-provider header
        let r3 = registry.resolve_route(Some("gpt-4o"), Some("openai")).await.unwrap();
        assert_eq!(r3.provider.id, "openai");
        assert_eq!(r3.canonical_model, "openai/gpt-4o");

        // 4. Unique bare-name match (o3-mini is only in openai)
        let r4 = registry.resolve_route(Some("o3-mini"), None).await.unwrap();
        assert_eq!(r4.provider.id, "openai");
        assert_eq!(r4.canonical_model, "openai/o3-mini");

        // 4b. Ambiguous bare name without provider (gpt-4o is in both bmw and openai)
        let r_amb = registry.resolve_route(Some("gpt-4o"), None).await;
        assert!(r_amb.is_err());
        assert!(r_amb.unwrap_err().to_string().contains("Ambiguous model 'gpt-4o'"));

        // 5. Fallback to default_provider for unknown un-indexed model
        let r5 = registry.resolve_route(Some("unlisted-model"), None).await.unwrap();
        assert_eq!(r5.provider.id, "bmw");
        assert_eq!(r5.upstream_model, "unlisted-model");
        assert_eq!(r5.canonical_model, "bmw/unlisted-model");
    }

    #[tokio::test]
    async fn usage_v1_to_v2_migration() {
        let v1_json = r#"{
            "groups": {
                "team-1": {
                    "requests": 2,
                    "models": {
                        "gpt-4o": {
                            "requests": 2,
                            "cost": {"USD": 0.05},
                            "tokens": {"prompt_tokens": 500}
                        }
                    },
                    "totals": {"USD": 0.05, "prompt_tokens_tokens": 500.0}
                }
            },
            "global_requests": 2,
            "global_totals": {"USD": 0.05, "prompt_tokens_tokens": 500.0}
        }"#;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), v1_json).unwrap();

        let store = UsageStore::new(tmp.path().to_path_buf());
        let data = store.get().await;

        assert_eq!(data.schema_version, 2);
        assert_eq!(data.global_requests, 2);
        assert_eq!(data.global_totals.get("USD").unwrap(), &0.05);

        let group = data.groups.get("team-1").unwrap();
        assert!(group.providers.contains_key("default"));
        let prov_usage = group.providers.get("default").unwrap();
        assert_eq!(prov_usage.requests, 2);
        assert_eq!(prov_usage.models.get("gpt-4o").unwrap().requests, 2);

        // Check that backup file was created
        let bak_path = format!("{}.v1.bak", tmp.path().display());
        assert!(std::path::Path::new(&bak_path).exists());
    }

    #[test]
    fn cost_estimation_math() {
        let p_cfg = ProviderConfig {
            id: "openai".to_string(),
            base_url: "api.openai.com".to_string(),
            scheme: Some("https".to_string()),
            auth_style: Some(AuthStyleConfig::BearerApiKey),
            api_key: Some("key".to_string()),
            api_key_ref: None,
            bearer_token: None,
            bearer_token_ref: None,
            m2m_oauth_url: None,
            client_id: None,
            client_secret: None,
            client_secret_ref: None,
            oauth_scope: None,
            header_name: None,
            header_value: None,
            header_value_ref: None,
            ca_cert_path: None,
            insecure_skip_tls_verify: false,
            models: vec![ModelSpec {
                id: "gpt-4o".to_string(),
                alias: None,
                context_window: Some(128000),
                max_output_tokens: Some(4096),
                supports_tools: Some(true),
                input_cost_per_1m: Some(2.50),
                output_cost_per_1m: Some(10.00),
                currency: "USD".to_string(),
                hidden: false,
            }],
        };
        let prov = Provider::new(&p_cfg).unwrap();

        let mut tokens = BTreeMap::new();
        tokens.insert("prompt_tokens".to_string(), 1_000_000_u64);
        tokens.insert("completion_tokens".to_string(), 500_000_u64);

        let (est_cost, currency) = estimate_cost(&tokens, &prov, "openai/gpt-4o").unwrap();
        assert_eq!(currency, "USD");
        assert_eq!(est_cost, 2.50 + 5.00); // 2.50 + 5.00 = 7.50
    }

    #[test]
    fn traffic_classification_rules() {
        let mut h = hyper::HeaderMap::new();
        assert_eq!(classify_traffic("/llm-proxy/usage", &h), TrafficClass::Local);
        assert_eq!(classify_traffic("/v1/models", &h), TrafficClass::Discovery);
        assert_eq!(classify_traffic("/v1/chat/completions", &h), TrafficClass::Billable);

        h.insert("x-llm-probe", "true".parse().unwrap());
        assert_eq!(classify_traffic("/v1/chat/completions", &h), TrafficClass::Probe);
    }
}
