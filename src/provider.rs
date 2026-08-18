use anyhow::{Context, Result};
use hyper::body::to_bytes;
use hyper::client::connect::Connection;
use hyper::service::Service;
use hyper::Client;
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnector;
use keyring::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
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
    pub client: Client<HttpsConnector<ProxyConnector>>,
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
                    .context(format!("Provider {}: header_name required for custom_header", cfg.id))?;
                AuthStyle::CustomHeader {
                    name,
                    value_ref: cfg.header_value_ref.clone(),
                    value: cfg.header_value.clone(),
                }
            }
            Some(AuthStyleConfig::None) => AuthStyle::None,
            None => {
                if cfg.m2m_oauth_url.is_some() || cfg.client_id.is_some() {
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

pub fn should_bypass_proxy(host: &str) -> bool {
    let no_proxy_env = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")).unwrap_or_default();
    if no_proxy_env.trim() == "*" {
        return true;
    }

    let host_clean = host.split(':').next().unwrap_or(host).trim();

    if host_clean.eq_ignore_ascii_case("localhost")
        || host_clean == "127.0.0.1"
        || host_clean == "::1"
    {
        return true;
    }

    for entry in no_proxy_env.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let entry_clean = entry.split(':').next().unwrap_or(entry).trim();
        if entry_clean.is_empty() {
            continue;
        }

        if let Some(suffix) = entry_clean.strip_prefix('.') {
            if host_clean.ends_with(entry_clean) || host_clean.eq_ignore_ascii_case(suffix) {
                return true;
            }
        } else {
            if host_clean.eq_ignore_ascii_case(entry_clean)
                || host_clean.ends_with(&format!(".{}", entry_clean))
            {
                return true;
            }
        }
    }

    false
}

pub fn get_outbound_proxy_url() -> Option<String> {
    std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .or_else(|_| std::env::var("ALL_PROXY"))
        .or_else(|_| std::env::var("all_proxy"))
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .or_else(|_| std::env::var("http_proxy"))
        .ok()
        .filter(|s| !s.trim().is_empty())
}

#[derive(Clone, Default)]
pub struct ProxyConnector;

impl ProxyConnector {
    pub fn new() -> Self {
        Self
    }
}

pub struct MaybeProxiedStream {
    stream: TcpStream,
}

impl AsyncRead for MaybeProxiedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MaybeProxiedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Connection for MaybeProxiedStream {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new()
    }
}

impl Service<Uri> for ProxyConnector {
    type Response = MaybeProxiedStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let host = dst.host().unwrap_or_default().to_string();
        let port = dst.port_u16().unwrap_or(if dst.scheme_str() == Some("http") { 80 } else { 443 });
        let proxy_url = get_outbound_proxy_url();
        let should_bypass = should_bypass_proxy(&host);

        Box::pin(async move {
            if let (Some(proxy), false) = (proxy_url, should_bypass) {
                let proxy_uri: Uri = proxy.parse().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid proxy URL: {}", e))
                })?;
                let p_host = proxy_uri.host().unwrap_or("127.0.0.1").to_string();
                let p_port = proxy_uri.port_u16().unwrap_or(3128);

                let mut stream = TcpStream::connect((p_host.as_str(), p_port)).await?;

                                let connect_req = format!(
                    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                    host, port, host, port
                );
                tokio::io::AsyncWriteExt::write_all(&mut stream, connect_req.as_bytes()).await?;

                let mut buf = [0u8; 2048];
                let mut pos = 0;
                loop {
                    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf[pos..]).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Proxy closed connection during CONNECT",
                        ));
                    }
                    pos += n;
                    if let Some(idx) = buf[..pos].windows(4).position(|w| w == b"\r\n\r\n") {
                        let header_part = String::from_utf8_lossy(&buf[..idx]);
                        if !header_part.starts_with("HTTP/1.1 200") && !header_part.starts_with("HTTP/1.0 200") {
                            return Err(std::io::Error::other(
                                format!("Proxy CONNECT failed: {}", header_part.lines().next().unwrap_or("")),
                            ));
                        }
                        break;
                    }
                }
                Ok(MaybeProxiedStream { stream })
            } else {
                let stream = TcpStream::connect((host.as_str(), port)).await?;
                Ok(MaybeProxiedStream { stream })
            }
        })
    }
}

fn build_http_client(
    insecure_skip_tls_verify: bool,
    ca_cert_path: Option<&str>,
) -> Result<Client<HttpsConnector<ProxyConnector>>> {
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

    let proxy_conn = ProxyConnector::new();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_or_http()
        .enable_http1()
        .wrap_connector(proxy_conn);

    Ok(Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(4)
        .build(https))
}

pub struct TokenCache {
    pub provider_id: String,
    pub auth: AuthStyle,
    pub client: Client<HttpsConnector<ProxyConnector>>,
    bearer_token: RwLock<Option<(String, Instant)>>,
    x_api_key: RwLock<Option<String>>,
}

impl TokenCache {
    pub fn new(provider_id: String, auth: AuthStyle, client: Client<HttpsConnector<ProxyConnector>>) -> Self {
        Self {
            provider_id,
            auth,
            client,
            bearer_token: RwLock::new(None),
            x_api_key: RwLock::new(None),
        }
    }

    pub async fn clear_token(&self) {
        *self.bearer_token.write().await = None;
    }

    pub fn invalidate(&self) {
        if let Ok(mut lock) = self.bearer_token.try_write() {
            *lock = None;
        }
    }

    pub async fn get_valid_bearer(&self) -> Result<String> {
        match &self.auth {
            AuthStyle::OauthM2m { .. } => {
                {
                    let r = self.bearer_token.read().await;
                    if let Some((tok, expiry)) = &*r {
                        if Instant::now() < *expiry {
                            return Ok(tok.clone());
                        }
                    }
                }
                let mut w = self.bearer_token.write().await;
                if let Some((tok, expiry)) = &*w {
                    if Instant::now() < *expiry {
                        return Ok(tok.clone());
                    }
                }
                let token = self.refresh_oauth_token().await?;
                *w = Some((token.clone(), Instant::now() + Duration::from_secs(3500)));
                Ok(token)
            }
            AuthStyle::BearerApiKey { key_ref, api_key } => {
                let key = Self::resolve_secret(key_ref.as_deref(), api_key.as_deref(), "api_key")
                    .context(format!("Missing API key for provider {}", self.provider_id))?;
                Ok(key)
            }
            AuthStyle::StaticBearer { token_ref, bearer_token, .. } => {
                let token = Self::resolve_secret(token_ref.as_deref(), bearer_token.as_deref(), "bearer_token")
                    .context(format!("Missing bearer token for provider {}", self.provider_id))?;
                Ok(token)
            }
            AuthStyle::CustomHeader { .. } | AuthStyle::None => Ok("".to_string()),
        }
    }

    pub async fn get_x_api_key(&self) -> Result<String> {
        match &self.auth {
            AuthStyle::OauthM2m { api_key_ref, api_key, .. } => {
                let mut w = self.x_api_key.write().await;
                if let Some(key) = &*w {
                    return Ok(key.clone());
                }
                let key = Self::resolve_secret(api_key_ref.as_deref(), api_key.as_deref(), "api_key")
                    .unwrap_or_default();
                *w = Some(key.clone());
                Ok(key)
            }
            AuthStyle::StaticBearer { api_key_ref, api_key, .. } => {
                let key = Self::resolve_secret(api_key_ref.as_deref(), api_key.as_deref(), "x-api-key")
                    .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::BearerApiKey { key_ref, api_key } => {
                let key = Self::resolve_secret(key_ref.as_deref(), api_key.as_deref(), "x-api-key")
                    .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::CustomHeader { value_ref, value, .. } => {
                let v = Self::resolve_secret(value_ref.as_deref(), value.as_deref(), "header_value")
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
                    "client_secret",
                )
                .context(format!("Missing client secret for provider {}", self.provider_id))?;

                let mut params = vec![
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id.as_str()),
                    ("client_secret", secret.as_str()),
                ];
                if let Some(s) = scope {
                    params.push(("scope", s.as_str()));
                }

                let body_str = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                    .collect::<Vec<_>>()
                    .join("&");

                let req = Request::builder()
                    .method(Method::POST)
                    .uri(url)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(hyper::Body::from(body_str))?;

                let resp = self.client.request(req).await?;
                if !resp.status().is_success() {
                    anyhow::bail!("OAuth token request failed with status: {}", resp.status());
                }

                let bytes = to_bytes(resp.into_body()).await?;
                let json: serde_json::Value = serde_json::from_slice(&bytes)?;
                let token = json["access_token"]
                    .as_str()
                    .context("OAuth response missing access_token")?
                    .to_string();

                let expires_in = json["expires_in"].as_u64().unwrap_or(3600);
                info!(
                    "Refreshed LLM bearer token for provider {} (expires in {}s)",
                    self.provider_id, expires_in
                );
                Ok(token)
            }
            _ => anyhow::bail!("Provider is not configured for OAuth M2M"),
        }
    }

    fn resolve_secret(reference: Option<&str>, inline: Option<&str>, label: &str) -> Option<String> {
        if let Some(r) = reference {
            if let Some(account) = r.strip_prefix("keychain:") {
                match Entry::new(KEYCHAIN_SERVICE, account) {
                    Ok(entry) => match entry.get_password() {
                        Ok(p) => return Some(p),
                        Err(e) => {
                            warn!("Failed to read keychain for account '{}': {}", account, e);
                        }
                    },
                    Err(e) => warn!("Failed to open keychain entry for '{}': {}", account, e),
                }
            }
        }
        if let Some(i) = inline {
            return Some(i.to_string());
        }
        // Legacy fallback
        if let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, label) {
            if let Ok(p) = entry.get_password() {
                return Some(p);
            }
        }
        None
    }
}
