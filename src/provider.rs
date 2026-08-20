use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::rt::{Read, Write};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use keyring::Entry;
use rustls::pki_types::{pem::PemObject, CertificateDer};
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
use tracing::{debug, info, warn};

use crate::config::{AuthStyleConfig, DialectConfig, ModelSpec, ProviderConfig};
use crate::dialect::Dialect;
use crate::sigv4::AwsCredentials;

pub const KEYCHAIN_SERVICE: &str = "llm-proxy";

// No-op TLS certificate verifier for internal/self-signed certs
#[derive(Debug)]
pub struct NoopVerifier;
impl rustls::client::danger::ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
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
    AwsSigv4 {
        region: String,
        access_key_id_ref: Option<String>,
        access_key_id: Option<String>,
        secret_access_key_ref: Option<String>,
        secret_access_key: Option<String>,
        session_token_ref: Option<String>,
        session_token: Option<String>,
        profile: Option<String>,
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
    pub client: Client<
        HttpsConnector<ProxyConnector>,
        http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>,
    >,
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

        let dialect = match cfg.dialect {
            Some(DialectConfig::BedrockConverse) => Dialect::BedrockConverse,
            Some(DialectConfig::OpenaiCompatible) => Dialect::OpenAiCompatible,
            None => {
                if matches!(cfg.auth_style, Some(AuthStyleConfig::AwsSigv4))
                    || cfg.base_url.contains("bedrock")
                {
                    Dialect::BedrockConverse
                } else {
                    Dialect::OpenAiCompatible
                }
            }
        };

        let auth = match cfg.auth_style {
            Some(AuthStyleConfig::OauthM2m) => {
                let url = cfg.m2m_oauth_url.clone().context(format!(
                    "Provider {}: m2m_oauth_url required for oauth_m2m",
                    cfg.id
                ))?;
                let client_id = cfg.client_id.clone().context(format!(
                    "Provider {}: client_id required for oauth_m2m",
                    cfg.id
                ))?;
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
                let name = cfg.header_name.clone().context(format!(
                    "Provider {}: header_name required for custom_header",
                    cfg.id
                ))?;
                AuthStyle::CustomHeader {
                    name,
                    value_ref: cfg.header_value_ref.clone(),
                    value: cfg.header_value.clone(),
                }
            }
            Some(AuthStyleConfig::AwsSigv4) => {
                let region = cfg
                    .aws_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string());
                AuthStyle::AwsSigv4 {
                    region,
                    access_key_id_ref: cfg.aws_access_key_id_ref.clone(),
                    access_key_id: cfg.aws_access_key_id.clone(),
                    secret_access_key_ref: cfg.aws_secret_access_key_ref.clone(),
                    secret_access_key: cfg.aws_secret_access_key.clone(),
                    session_token_ref: cfg.aws_session_token_ref.clone(),
                    session_token: cfg.aws_session_token.clone(),
                    profile: cfg.aws_profile.clone(),
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
        let token_cache = Arc::new(TokenCache::new(
            cfg.id.clone(),
            auth.clone(),
            client.clone(),
        ));

        Ok(Self {
            id: cfg.id.clone(),
            base_url: cfg.base_url.clone(),
            scheme,
            auth,
            dialect,
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

    pub async fn record_discovery_failure(&self, reason: String) {
        let mut h = self.health.write().await;
        h.last_failure = Some((Instant::now(), format!("Discovery: {}", reason)));
        h.discovery = DiscoveryState::Failed(reason);
        h.is_failed = true;
    }
}

pub fn should_bypass_proxy(host: &str) -> bool {
    let no_proxy_env = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
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
    buffer: std::io::Cursor<Vec<u8>>,
}

impl AsyncRead for MaybeProxiedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if (self.buffer.position() as usize) < self.buffer.get_ref().len() {
            let pos = self.buffer.position() as usize;
            let slice = &self.buffer.get_ref()[pos..];
            let to_read = std::cmp::min(buf.remaining(), slice.len());
            buf.put_slice(&slice[..to_read]);
            self.buffer.set_position((pos + to_read) as u64);
            return Poll::Ready(Ok(()));
        }
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Read for MaybeProxiedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let (result, filled_len) = {
            let mut read_buf = unsafe { ReadBuf::uninit(buf.as_mut()) };
            let result = Pin::new(&mut this.stream).poll_read(cx, &mut read_buf);
            (result, read_buf.filled().len())
        };
        if result.is_ready() && filled_len > 0 {
            unsafe { buf.advance(filled_len) };
        }
        result
    }
}

impl Write for MaybeProxiedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        false
    }
}

impl Connection for MaybeProxiedStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl tower::Service<Uri> for ProxyConnector {
    type Response = MaybeProxiedStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let host = dst.host().unwrap_or_default().to_string();
        let port = dst
            .port_u16()
            .unwrap_or(if dst.scheme_str() == Some("http") {
                80
            } else {
                443
            });
        let proxy_url = get_outbound_proxy_url();
        let should_bypass = should_bypass_proxy(&host);

        Box::pin(async move {
            if let (Some(proxy), false) = (proxy_url, should_bypass) {
                let proxy_uri: Uri = proxy.parse().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid proxy URL: {}", e),
                    )
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
                        if !header_part.starts_with("HTTP/1.1 200")
                            && !header_part.starts_with("HTTP/1.0 200")
                        {
                            return Err(std::io::Error::other(format!(
                                "Proxy CONNECT failed: {}",
                                header_part.lines().next().unwrap_or("")
                            )));
                        }
                        let leftover = buf[idx + 4..pos].to_vec();
                        return Ok(MaybeProxiedStream {
                            stream,
                            buffer: std::io::Cursor::new(leftover),
                        });
                    }
                }
            } else {
                let stream = TcpStream::connect((host.as_str(), port)).await?;
                Ok(MaybeProxiedStream {
                    stream,
                    buffer: std::io::Cursor::new(Vec::new()),
                })
            }
        })
    }
}

fn build_http_client(
    insecure_skip_tls_verify: bool,
    ca_cert_path: Option<&str>,
) -> Result<
    Client<
        HttpsConnector<ProxyConnector>,
        http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>,
    >,
> {
    let crypto_provider = rustls::crypto::ring::default_provider();
    let client_config = if insecure_skip_tls_verify {
        info!("WARNING: TLS certificate verification disabled for upstream connections");
        rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        if let Some(cert_path) = ca_cert_path {
            if let Ok(cert_data) = std::fs::read(cert_path) {
                if let Ok(certs) =
                    CertificateDer::pem_slice_iter(&cert_data).collect::<Result<Vec<_>, _>>()
                {
                    for cert in certs {
                        root_store.add(cert).ok();
                    }
                    info!("Loaded custom CA certificate from: {}", cert_path);
                } else {
                    warn!("Failed to parse CA certificate from: {}", cert_path);
                }
            } else {
                warn!("Failed to read CA certificate from: {}", cert_path);
            }
        }

        rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let proxy_conn = ProxyConnector::new();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_or_http()
        .enable_http1()
        .wrap_connector(proxy_conn);

    Ok(Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(4)
        .build(https))
}

pub struct CachedAwsCreds {
    pub credentials: AwsCredentials,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct TokenCache {
    pub provider_id: String,
    pub auth: AuthStyle,
    pub client: Client<
        HttpsConnector<ProxyConnector>,
        http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>,
    >,
    bearer_token: RwLock<Option<(String, Instant)>>,
    x_api_key: RwLock<Option<String>>,
    aws_creds: RwLock<Option<CachedAwsCreds>>,
}

impl TokenCache {
    pub fn new(
        provider_id: String,
        auth: AuthStyle,
        client: Client<
            HttpsConnector<ProxyConnector>,
            http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>,
        >,
    ) -> Self {
        Self {
            provider_id,
            auth,
            client,
            bearer_token: RwLock::new(None),
            x_api_key: RwLock::new(None),
            aws_creds: RwLock::new(None),
        }
    }

    pub async fn clear_token(&self) {
        *self.bearer_token.write().await = None;
        *self.aws_creds.write().await = None;
    }

    pub fn invalidate(&self) {
        if let Ok(mut lock) = self.bearer_token.try_write() {
            *lock = None;
        }
    }

    pub async fn get_aws_credentials(&self) -> Result<AwsCredentials> {
        match &self.auth {
            AuthStyle::AwsSigv4 {
                access_key_id_ref,
                access_key_id,
                secret_access_key_ref,
                secret_access_key,
                session_token_ref,
                session_token,
                profile,
                ..
            } => {
                // Check in-memory cached credentials with 5-minute expiry buffer
                {
                    let read_guard = self.aws_creds.read().await;
                    if let Some(ref cached) = *read_guard {
                        let now = chrono::Utc::now();
                        let is_valid = match cached.expires_at {
                            Some(exp) => exp > now + chrono::Duration::minutes(5),
                            None => true,
                        };
                        if is_valid {
                            return Ok(cached.credentials.clone());
                        }
                    }
                }

                // 1. Try dynamic AWS CLI export-credentials (handles AWS SSO auto-refresh)
                match Self::export_credentials_via_aws_cli(profile.as_deref()) {
                    Ok(cached) => {
                        let creds = cached.credentials.clone();
                        *self.aws_creds.write().await = Some(cached);
                        return Ok(creds);
                    }
                    Err(e) => {
                        debug!(
                            "aws configure export-credentials skipped/failed for provider {}: {}",
                            self.provider_id, e
                        );
                    }
                }

                // 2. Try config/keychain references or shell environment variables
                let key_id = Self::resolve_secret(
                    access_key_id_ref.as_deref(),
                    access_key_id.as_deref(),
                    "aws_access_key_id",
                )
                .or_else(|| std::env::var("AWS_ACCESS_KEY_ID").ok());

                let secret = Self::resolve_secret(
                    secret_access_key_ref.as_deref(),
                    secret_access_key.as_deref(),
                    "aws_secret_access_key",
                )
                .or_else(|| std::env::var("AWS_SECRET_ACCESS_KEY").ok());

                let token = Self::resolve_secret(
                    session_token_ref.as_deref(),
                    session_token.as_deref(),
                    "aws_session_token",
                )
                .or_else(|| std::env::var("AWS_SESSION_TOKEN").ok());

                if let (Some(k), Some(s)) = (key_id, secret) {
                    let creds = AwsCredentials {
                        access_key_id: k,
                        secret_access_key: s,
                        session_token: token,
                    };
                    *self.aws_creds.write().await = Some(CachedAwsCreds {
                        credentials: creds.clone(),
                        expires_at: None,
                    });
                    return Ok(creds);
                }

                // 3. Try ~/.aws/credentials profile parser
                if let Some(creds) = Self::load_from_aws_credentials_file(profile.as_deref()) {
                    *self.aws_creds.write().await = Some(CachedAwsCreds {
                        credentials: creds.clone(),
                        expires_at: None,
                    });
                    return Ok(creds);
                }

                Self::notify_sso_expired(profile.as_deref());
                anyhow::bail!(
                    "AWS SSO session or credentials expired for provider '{}'. Please run 'aws sso login{}' in your terminal.",
                    self.provider_id,
                    profile.as_deref().map(|p| format!(" --profile {}", p)).unwrap_or_default()
                )
            }
            _ => anyhow::bail!("Provider is not configured for AWS SigV4 auth"),
        }
    }

    fn find_aws_binary() -> std::path::PathBuf {
        let candidates = [
            "/opt/homebrew/bin/aws",
            "/usr/local/bin/aws",
            "/usr/bin/aws",
        ];
        for c in candidates {
            let p = std::path::PathBuf::from(c);
            if p.exists() {
                return p;
            }
        }
        std::path::PathBuf::from("aws")
    }

    fn export_credentials_via_aws_cli(profile: Option<&str>) -> Result<CachedAwsCreds> {
        let aws_bin = Self::find_aws_binary();
        let mut cmd = std::process::Command::new(aws_bin);
        cmd.arg("configure").arg("export-credentials");
        if let Some(p) = profile {
            if !p.is_empty() && p != "default" {
                cmd.arg("--profile").arg(p);
            }
        }
        // Remove standard proxy env vars so AWS CLI connects directly to local/AWS endpoint
        cmd.env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy");

        let output = cmd.output().context("Failed to spawn aws CLI process")?;
        if !output.status.success() {
            let err_str = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "aws configure export-credentials failed: {}",
                err_str.trim()
            );
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("Invalid JSON returned by aws configure export-credentials")?;

        let key_id = json["AccessKeyId"]
            .as_str()
            .context("Missing AccessKeyId in AWS CLI output")?
            .to_string();

        let secret = json["SecretAccessKey"]
            .as_str()
            .context("Missing SecretAccessKey in AWS CLI output")?
            .to_string();

        let token = json["SessionToken"].as_str().map(|s| s.to_string());

        let expires_at = json["Expiration"]
            .as_str()
            .and_then(|exp_str| chrono::DateTime::parse_from_rfc3339(exp_str).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        Ok(CachedAwsCreds {
            credentials: AwsCredentials {
                access_key_id: key_id,
                secret_access_key: secret,
                session_token: token,
            },
            expires_at,
        })
    }

    fn notify_sso_expired(profile: Option<&str>) {
        #[cfg(target_os = "macos")]
        {
            let prof_text = profile.unwrap_or("default");
            let aws_cmd = if prof_text == "default" {
                "aws sso login && osascript -e 'tell application \\\"Terminal\\\" to close (every window whose name contains \\\"aws sso login\\\")' 2>/dev/null || exit".to_string()
            } else {
                format!("aws sso login --profile {} && osascript -e 'tell application \\\"Terminal\\\" to close (every window whose name contains \\\"aws sso login\\\")' 2>/dev/null || exit", prof_text)
            };
            let script = format!(
                r#"try
set chosen to button returned of (display alert "llm-proxy: AWS SSO Expired" message "AWS SSO session expired for profile \"{}\". Click 'Login with AWS SSO' to authenticate." buttons {{"Dismiss", "Login with AWS SSO"}} default button 2 giving up after 45)
if chosen is "Login with AWS SSO" then
    tell application "Terminal"
        do script "{}"
        activate
    end tell
end if
end try"#,
                prof_text, aws_cmd
            );
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(script)
                .spawn();
        }
    }

    fn load_from_aws_credentials_file(profile: Option<&str>) -> Option<AwsCredentials> {
        let home = dirs::home_dir()?;
        let creds_path = home.join(".aws/credentials");
        let content = std::fs::read_to_string(creds_path).ok()?;
        let target_profile = profile.unwrap_or("default");

        let mut in_profile = false;
        let mut key_id = None;
        let mut secret = None;
        let mut token = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                let prof_name = &line[1..line.len() - 1];
                in_profile = prof_name == target_profile;
                continue;
            }
            if in_profile {
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim().to_string();
                    if k == "aws_access_key_id" {
                        key_id = Some(v);
                    } else if k == "aws_secret_access_key" {
                        secret = Some(v);
                    } else if k == "aws_session_token" {
                        token = Some(v);
                    }
                }
            }
        }

        if let (Some(k), Some(s)) = (key_id, secret) {
            Some(AwsCredentials {
                access_key_id: k,
                secret_access_key: s,
                session_token: token,
            })
        } else {
            None
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
                {
                    let r = self.bearer_token.read().await;
                    if let Some((tok, _)) = &*r {
                        return Ok(tok.clone());
                    }
                }
                let mut w = self.bearer_token.write().await;
                if let Some((tok, _)) = &*w {
                    return Ok(tok.clone());
                }
                let key = Self::resolve_secret(key_ref.as_deref(), api_key.as_deref(), "api_key")
                    .context(format!("Missing API key for provider {}", self.provider_id))?;
                *w = Some((
                    key.clone(),
                    Instant::now() + Duration::from_secs(86400 * 365),
                ));
                Ok(key)
            }
            AuthStyle::StaticBearer {
                token_ref,
                bearer_token,
                ..
            } => {
                let token = Self::resolve_secret(
                    token_ref.as_deref(),
                    bearer_token.as_deref(),
                    "bearer_token",
                )
                .context(format!(
                    "Missing bearer token for provider {}",
                    self.provider_id
                ))?;
                Ok(token)
            }
            AuthStyle::AwsSigv4 { .. } | AuthStyle::CustomHeader { .. } | AuthStyle::None => {
                Ok("".to_string())
            }
        }
    }

    pub async fn get_x_api_key(&self) -> Result<String> {
        match &self.auth {
            AuthStyle::OauthM2m {
                api_key_ref,
                api_key,
                ..
            } => {
                let mut w = self.x_api_key.write().await;
                if let Some(key) = &*w {
                    return Ok(key.clone());
                }
                let key =
                    Self::resolve_secret(api_key_ref.as_deref(), api_key.as_deref(), "api_key")
                        .unwrap_or_default();
                *w = Some(key.clone());
                Ok(key)
            }
            AuthStyle::StaticBearer {
                api_key_ref,
                api_key,
                ..
            } => {
                let key =
                    Self::resolve_secret(api_key_ref.as_deref(), api_key.as_deref(), "x-api-key")
                        .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::BearerApiKey { key_ref, api_key } => {
                let key = Self::resolve_secret(key_ref.as_deref(), api_key.as_deref(), "x-api-key")
                    .unwrap_or_default();
                Ok(key)
            }
            AuthStyle::CustomHeader {
                value_ref, value, ..
            } => {
                let v =
                    Self::resolve_secret(value_ref.as_deref(), value.as_deref(), "header_value")
                        .unwrap_or_default();
                Ok(v)
            }
            AuthStyle::AwsSigv4 { .. } | AuthStyle::None => Ok("".to_string()),
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
                .context(format!(
                    "Missing client secret for provider {}",
                    self.provider_id
                ))?;

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
                    .body(
                        Full::new(Bytes::from(body_str))
                            .map_err(|e| match e {})
                            .boxed(),
                    )?;

                let resp = self.client.request(req).await?;
                if !resp.status().is_success() {
                    anyhow::bail!("OAuth token request failed with status: {}", resp.status());
                }

                let bytes = BodyExt::collect(resp.into_body()).await?.to_bytes();
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

    fn resolve_secret(
        reference: Option<&str>,
        inline: Option<&str>,
        label: &str,
    ) -> Option<String> {
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
