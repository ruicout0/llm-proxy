use anyhow::{bail, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn default_port() -> u16 {
    3128
}

fn default_provider_id() -> String {
    "bmw".to_string()
}

fn default_model_separator() -> char {
    '/'
}

fn default_discovery_ttl_secs() -> u64 {
    300
}

fn default_discovery_timeout_ms() -> u64 {
    2500
}

pub fn default_usage_store_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/llm-proxy/usage.json")
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ModelSpec {
    pub id: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub context_window: Option<u64>,
    #[serde(default)]
    pub max_output_tokens: Option<u64>,
    #[serde(default)]
    pub supports_tools: Option<bool>,
    #[serde(default)]
    pub input_cost_per_1m: Option<f64>,
    #[serde(default)]
    pub output_cost_per_1m: Option<f64>,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub hidden: bool,
}

fn default_currency() -> String {
    "USD".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthStyleConfig {
    OauthM2m,
    BearerApiKey,
    StaticBearer,
    CustomHeader,
    AwsSigv4,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DialectConfig {
    OpenaiCompatible,
    BedrockConverse,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProviderConfig {
    pub id: String,
    pub base_url: String,
    #[serde(default = "default_scheme")]
    pub scheme: Option<String>,
    #[serde(default)]
    pub dialect: Option<DialectConfig>,
    #[serde(default)]
    pub auth_style: Option<AuthStyleConfig>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_ref: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub bearer_token_ref: Option<String>,
    #[serde(default)]
    pub m2m_oauth_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_secret_ref: Option<String>,
    #[serde(default)]
    pub oauth_scope: Option<String>,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_value: Option<String>,
    #[serde(default)]
    pub header_value_ref: Option<String>,

    // AWS SigV4 specific configuration
    #[serde(default)]
    pub aws_region: Option<String>,
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    #[serde(default)]
    pub aws_access_key_id_ref: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key_ref: Option<String>,
    #[serde(default)]
    pub aws_session_token: Option<String>,
    #[serde(default)]
    pub aws_session_token_ref: Option<String>,
    #[serde(default)]
    pub aws_profile: Option<String>,

    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    #[serde(default)]
    pub models: Vec<ModelSpec>,
}

fn default_scheme() -> Option<String> {
    Some("https".to_string())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigFile {
    // Top-level legacy fields for backwards compatibility
    #[serde(default)]
    pub llm_host: Option<String>,
    #[serde(default = "default_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default, rename = "m2m_oauth_url")]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub oauth_scope: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    #[serde(default)]
    pub usage_store_path: Option<String>,
    #[serde(default)]
    pub pricing_cache_path: Option<String>,

    // Multi-provider fields
    #[serde(default = "default_provider_id")]
    pub default_provider: String,
    #[serde(default = "default_model_separator")]
    pub model_separator: char,
    #[serde(default = "default_discovery_ttl_secs")]
    pub discovery_ttl_secs: u64,
    #[serde(default = "default_discovery_timeout_ms")]
    pub discovery_timeout_ms: u64,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
}

impl ConfigFile {
    pub fn validate(&self) -> Result<()> {
        if self.providers.is_empty() {
            let host = self.llm_host.as_deref().unwrap_or("");
            if host.is_empty() {
                bail!("llm_host or [[providers]] is required in config file");
            }
            let has_oauth = self.token_endpoint.is_some() && self.client_id.is_some();
            if self.bearer_token.is_none() && !has_oauth {
                bail!("Either bearer_token OR (m2m_oauth_url + client_id) must be provided. client_secret and api_key may be stored in keychain.");
            }
        } else {
            for provider in &self.providers {
                if provider.id.is_empty() {
                    bail!("Provider id cannot be empty");
                }
                if provider.base_url.is_empty() {
                    bail!("Provider {} base_url cannot be empty", provider.id);
                }
            }
        }
        Ok(())
    }

    /// Normalize config into multi-provider representation
    pub fn normalize_providers(&self) -> (String, Vec<ProviderConfig>) {
        if self.providers.is_empty() {
            let host = self.llm_host.clone().unwrap_or_default();
            let auth_style = if self.bearer_token.is_some() {
                Some(AuthStyleConfig::StaticBearer)
            } else if self.token_endpoint.is_some() {
                Some(AuthStyleConfig::OauthM2m)
            } else {
                None
            };
            let synth = ProviderConfig {
                id: "default".to_string(),
                base_url: host,
                scheme: Some("https".to_string()),
                dialect: Some(DialectConfig::OpenaiCompatible),
                auth_style,
                api_key: self.api_key.clone(),
                api_key_ref: None,
                bearer_token: self.bearer_token.clone(),
                bearer_token_ref: None,
                m2m_oauth_url: self.token_endpoint.clone(),
                client_id: self.client_id.clone(),
                client_secret: self.client_secret.clone(),
                client_secret_ref: None,
                oauth_scope: self.oauth_scope.clone(),
                header_name: None,
                header_value: None,
                header_value_ref: None,
                aws_region: None,
                aws_access_key_id: None,
                aws_access_key_id_ref: None,
                aws_secret_access_key: None,
                aws_secret_access_key_ref: None,
                aws_session_token: None,
                aws_session_token_ref: None,
                aws_profile: None,
                ca_cert_path: self.ca_cert_path.clone(),
                insecure_skip_tls_verify: self.insecure_skip_tls_verify,
                models: Vec::new(),
            };
            ("default".to_string(), vec![synth])
        } else {
            (self.default_provider.clone(), self.providers.clone())
        }
    }
}
