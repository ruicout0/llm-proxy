use anyhow::{Context, Result};
use hyper::body::to_bytes;
use hyper::client::HttpConnector;
use hyper::Client;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnector;
use keyring::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{AuthStyleConfig, ModelSpec, ProviderConfig};

pub const KEYCHAIN_SERVICE: &str = "llm-proxy";

// No-op TLS certificate verifier for internal/self-signed certs
pub struct NoopVerifier;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialect {
    OpenAiCompatible,
}

#[derive(Debug, Clone)]
pub enum AuthStyle {
    OauthM2m {
        url: String,
        client_id: String,
        scope: Option<String>,
        secret_ref: Option<String>,
        api_key_ref: Option<String>,
        client_secret: Option<String>,
        api_key: Option<String>,
    },
    BearerApiKey {
        key_ref: Option<String>,
        api_key: Option<String>,
    },
    StaticBearer {
        token_ref: Option<String>,
        bearer_token: Option<String>,
        api_key_ref: Option<String>,
        api_key: Option<String>,
    },
    CustomHeader {
        name: String,
        value_ref: Option<String>,
        value: Option<String>,
    },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryState {
    Live,
    Stale,
    StaticOnly,
    Failed(String),
}

#[derive(Debug)]
pub struct ProviderHealth {
    pub last_success: Option<Instant>,
    pub last_failure: Option<(Instant, String)>,
    pub consecutive_failures: u32,
    pub discovery: DiscoveryState,
    pub is_failed: bool,
}

impl Default for ProviderHealth {
    fn default() -> Self {
        Self {
            last_success: None,
            last_failure: None,
            consecutive_failures: 0,
            discovery: DiscoveryState::StaticOnly,
            is_failed: false,
        }
    }
}

pub struct Provider {
    pub id: String,
    pub base_url: String,
    pub scheme: String,
    pub auth: AuthStyle,
    pub dialect: Dialect,
    pub client: Client<HttpsConnector<HttpConnector>>,
    pub token_cache: Arc<TokenCache>,
    pub models: BTreeMap<String, ModelSpec>,
    pub health: RwLock<ProviderHealth>,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider")
            .field("id", &self.id)
            .field("base_url", &self.base_url)
            .field("scheme", &self.scheme)
            .field("auth", &self.auth)
            .field("dialect", &self.dialect)
            .field("models", &self.models)
            .finish()
    }
}

impl Provider {
    pub fn new(cfg: &ProviderConfig) -> Result<Self> {
        let scheme = cfg.scheme.clone().unwrap_or_else(|| "https".to_string());
        let mut models = BTreeMap::new();
        for m in &cfg.models {
            models.insert(m.id.clone(), m.clone());
        }

        let auth = match cfg.auth_style {
            Some(AuthStyleConfig::OauthM2m) => {
                let url = cfg
                    .m2m_oauth_url
                    .clone()
                    .context(format!("Provider {}: m2m_oauth_url required for oauth_m2m", cfg.id))?;
                let client_id = cfg
                    .client_id
                    .clone()
                    .context(format!("Provider {}: client_id required for oauth_m2m", cfg.id))?;
                AuthStyle::OauthM2m {
                    url,
                    client_id,
                    scope: cfg.oauth_scope.clone(),
                    secret_ref: cfg.client_secret_ref.clone(),
                    api_key_ref: cfg.api_key_ref.clone(),
                    client_secret: cfg.client_secret.clone(),
                    api_key: cfg.api_key.clone(),
                }
            }
            Some(AuthStyleConfig::BearerApiKey) => AuthStyle::BearerApiKey {
                key_ref: cfg.api_key_ref.clone(),
                api_key: cfg.api_key.clone(),
            },
            Some(AuthStyleConfig::StaticBearer) => AuthStyle::StaticBearer {
                token_ref: cfg.bearer_token_ref.clone(),
                bearer_token: cfg.bearer_token.clone(),
                api_key_ref: cfg.api_key_ref.clone(),
                api_key: cfg.api_key.clone(),
            },
            Some(AuthStyleConfig::CustomHeader) => {
                let name = cfg
                    .header_name
                    .clone()
                    .unwrap_or_else(|| "x-api-key".to_string());
                AuthStyle::CustomHeader {
                    name,
                    value_ref: cfg.header_value_ref.clone(),
                    value: cfg.header_value.clone(),
                }
            }
            Some(AuthStyleConfig::None) => AuthStyle::None,
            None => {
                if cfg.m2m_oauth_url.is_some() || (cfg.client_id.is_some() && cfg.client_secret.is_some()) {
                    let url = cfg.m2m_oauth_url.clone().unwrap_or_default();
                    let client_id = cfg.client_id.clone().unwrap_or_default();
                    AuthStyle::OauthM2m {
                        url,
                        client_id,
                        scope: cfg.oauth_scope.clone(),
                        secret_ref: cfg.client_secret_ref.clone(),
                        api_key_ref: cfg.api_key_ref.clone(),
                        client_secret: cfg.client_secret.clone(),
                        api_key: cfg.api_key.clone(),
                    }
                } else if cfg.bearer_token.is_some() || cfg.bearer_token_ref.is_some() {
                    AuthStyle::StaticBearer {
                        token_ref: cfg.bearer_token_ref.clone(),
                        bearer_token: cfg.bearer_token.clone(),
                        api_key_ref: cfg.api_key_ref.clone(),
                        api_key: cfg.api_key.clone(),
                    }
                } else if cfg.api_key.is_some() || cfg.api_key_ref.is_some() {
                    AuthStyle::BearerApiKey {
                        key_ref: cfg.api_key_ref.clone(),
                        api_key: cfg.api_key.clone(),
                    }
                } else {
                    AuthStyle::None
                }
            }
        };

        let client = build_http_client(cfg.insecure_skip_tls_verify, cfg.ca_cert_path.as_deref())?;
        let token_cache = Arc::new(TokenCache::new(cfg.id.clone(), auth.clone(), client.clone()));

        Ok(Self {
            id: cfg.id.clone(),
            base_url: cfg.base_url.clone(),
            scheme,
            auth,
            dialect: Dialect::OpenAiCompatible,
            client,
            token_cache,
            models,
            health: RwLock::new(ProviderHealth::default()),
        })
    }

    pub async fn record_success(&self) {
        let mut h = self.health.write().await;
        h.last_success = Some(Instant::now());
        h.consecutive_failures = 0;
        h.is_failed = false;
    }

    pub async fn record_failure(&self, reason: String) {
        let mut h = self.health.write().await;
        h.last_failure = Some((Instant::now(), reason));
        h.consecutive_failures += 1;
        if h.consecutive_failures >= 3 {
            h.is_failed = true;
        }
    }
}

fn build_http_client(
    insecure_skip_tls_verify: bool,
    ca_cert_path: Option<&str>,
) -> Result<Client<HttpsConnector<HttpConnector>>> {
    let client_config = if insecure_skip_tls_verify {
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

        if let Some(cert_path) = ca_cert_path {
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

    Ok(Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(4)
        .build(https))
}

pub struct TokenCache {
    pub provider_id: String,
    pub auth: AuthStyle,
    pub bearer_token: RwLock<Option<(String, Instant)>>,
    pub client: Client<HttpsConnector<HttpConnector>>,
}

impl TokenCache {
    pub fn new(provider_id: String, auth: AuthStyle, client: Client<HttpsConnector<HttpConnector>>) -> Self {
        Self {
            provider_id,
            auth,
            bearer_token: RwLock::new(None),
            client,
        }
    }

    fn resolve_secret(key_ref: Option<&str>, default_val: Option<&str>, legacy_account: &str) -> Option<String> {
        if let Some(r) = key_ref {
            if let Some(account) = r.strip_prefix("keychain:") {
                if let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, account) {
                    if let Ok(pw) = entry.get_password() {
                        return Some(pw);
                    }
                }
            }
        }
        if let Some(val) = default_val {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
        if let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, legacy_account) {
            if let Ok(pw) = entry.get_password() {
                return Some(pw);
            }
        }
        None
    }

    pub async fn get_valid_bearer(&self) -> Result<String> {
        // Fast path: read lock first
        {
            let guard = self.bearer_token.read().await;
            if let Some((token, expiry)) = &*guard {
                if *expiry > Instant::now() + Duration::from_secs(60) {
                    return Ok(token.clone());
                }
            }
        }

        match &self.auth {
            AuthStyle::StaticBearer { token_ref, bearer_token, .. } => {
                let token = Self::resolve_secret(token_ref.as_deref(), bearer_token.as_deref(), "bearer-token")
                    .context(format!("Provider {}: No static bearer token found", self.provider_id))?;
                Ok(token)
            }
            AuthStyle::BearerApiKey { key_ref, api_key } => {
                let key = Self::resolve_secret(key_ref.as_deref(), api_key.as_deref(), "x-api-key")
                    .context(format!("Provider {}: No API key found", self.provider_id))?;
                Ok(key)
            }
            AuthStyle::OauthM2m { .. } => {
                let guard = self.bearer_token.write().await;
                if let Some((token, expiry)) = &*guard {
                    if *expiry > Instant::now() + Duration::from_secs(60) {
                        return Ok(token.clone());
                    }
                }
                drop(guard);
                self.refresh_oauth_token().await
            }
            AuthStyle::CustomHeader { .. } | AuthStyle::None => Ok("".to_string()),
        }
    }

    pub async fn get_x_api_key(&self) -> Result<String> {
        match &self.auth {
            AuthStyle::OauthM2m { api_key_ref, api_key, .. } => {
                let key = Self::resolve_secret(
                    api_key_ref.as_deref(),
                    api_key.as_deref(),
                    "x-api-key",
                )
                .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::StaticBearer { api_key_ref, api_key, .. } => {
                let key = Self::resolve_secret(
                    api_key_ref.as_deref(),
                    api_key.as_deref(),
                    "x-api-key",
                )
                .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::BearerApiKey { key_ref, api_key } => {
                let key = Self::resolve_secret(key_ref.as_deref(), api_key.as_deref(), "x-api-key")
                    .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::CustomHeader { value_ref, value, .. } => {
                let v = Self::resolve_secret(value_ref.as_deref(), value.as_deref(), "x-api-key")
                    .unwrap_or_default();
                Ok(v)
            }
            AuthStyle::None => Ok("".to_string()),
        }
    }

    async fn refresh_oauth_token(&self) -> Result<String> {
        match &self.auth {
            AuthStyle::OauthM2m {
                url,
                client_id,
                scope,
                secret_ref,
                client_secret,
                ..
            } => {
                let secret = Self::resolve_secret(
                    secret_ref.as_deref(),
                    client_secret.as_deref(),
                    "client-secret",
                )
                .context(format!(
                    "Provider {}: client_secret required for OAuth token refresh",
                    self.provider_id
                ))?;

                let form = if let Some(ref sc) = scope {
                    format!(
                        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
                        urlencoding::encode(client_id),
                        urlencoding::encode(&secret),
                        urlencoding::encode(sc)
                    )
                } else {
                    format!(
                        "grant_type=client_credentials&client_id={}&client_secret={}",
                        urlencoding::encode(client_id),
                        urlencoding::encode(&secret)
                    )
                };

                let req = Request::builder()
                    .method(Method::POST)
                    .uri(url.as_str())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Content-Length", form.len())
                    .body(hyper::Body::from(form))?;

                let resp = self.client.request(req).await?;
                let body = to_bytes(resp.into_body()).await?;
                let json: serde_json::Value = serde_json::from_slice(&body)?;

                let access_token = json["access_token"]
                    .as_str()
                    .context("No access_token in response")?
                    .to_string();
                let expires_in = json["expires_in"].as_u64().unwrap_or(3600);

                let expiry = Instant::now() + Duration::from_secs(expires_in.saturating_sub(60));
                *self.bearer_token.write().await = Some((access_token.clone(), expiry));

                info!(
                    "Refreshed LLM bearer token for provider {} (expires in {}s)",
                    self.provider_id, expires_in
                );
                Ok(access_token)
            }
            _ => Ok("".to_string()),
        }
    }

    pub async fn clear_token(&self) {
        *self.bearer_token.write().await = None;
    }
}
