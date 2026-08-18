use anyhow::Result;
use dirs::home_dir;
use hyper::body::to_bytes;
use hyper::{Body, Client, Method, Request, Uri};
use hyper_rustls::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::ConfigFile;
use crate::provider::ProxyConnector;

const LITELLM_PRICES_URL: &str =
    "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json";

fn default_prices_cache_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/llm-proxy/prices_cache.json")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LiteLlmModelEntry {
    #[serde(default)]
    pub input_cost_per_token: Option<f64>,
    #[serde(default)]
    pub output_cost_per_token: Option<f64>,
    #[serde(default)]
    pub cache_read_input_token_cost: Option<f64>,
    #[serde(default = "default_usd")]
    pub currency: String,
}

fn default_usd() -> String {
    "USD".to_string()
}

pub struct PricingRegistry {
    entries: RwLock<HashMap<String, LiteLlmModelEntry>>,
    cache_path: PathBuf,
    last_fetched: RwLock<Option<Instant>>,
    client: Client<HttpsConnector<ProxyConnector>>,
}

impl PricingRegistry {
    pub fn new(config: &ConfigFile) -> Self {
        let cache_path = config
            .pricing_cache_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(default_prices_cache_path);

        let initial_entries = Self::load_cache_from_disk(&cache_path);

        let proxy_conn = ProxyConnector::new();
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(proxy_conn);

        let client = Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(2)
            .build(https);

        Self {
            entries: RwLock::new(initial_entries),
            cache_path,
            last_fetched: RwLock::new(None),
            client,
        }
    }

    fn load_cache_from_disk(path: &PathBuf) -> HashMap<String, LiteLlmModelEntry> {
        if !path.exists() {
            return HashMap::new();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<HashMap<String, LiteLlmModelEntry>>(&content) {
                Ok(entries) => {
                    info!("Loaded {} pricing entries from disk cache {:?}", entries.len(), path);
                    entries
                }
                Err(e) => {
                    warn!("Failed to parse pricing cache {:?}: {}", path, e);
                    HashMap::new()
                }
            },
            Err(e) => {
                warn!("Failed to read pricing cache {:?}: {}", path, e);
                HashMap::new()
            }
        }
    }

    pub async fn fetch_latest(&self) -> Result<usize> {
        info!("Fetching dynamic model price catalog from {}", LITELLM_PRICES_URL);
        let uri: Uri = LITELLM_PRICES_URL.parse()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("User-Agent", "llm-proxy/pricing-sync")
            .body(Body::empty())?;

        let resp = self.client.request(req).await?;
        if !resp.status().is_success() {
            anyhow::bail!("Failed to fetch pricing catalog: HTTP {}", resp.status());
        }

        let bytes = to_bytes(resp.into_body()).await?;
        let raw_map: HashMap<String, serde_json::Value> = serde_json::from_slice(&bytes)?;
        
        let mut parsed = HashMap::new();
        for (key, val) in raw_map {
            if key == "sample_spec" {
                continue;
            }
            if let Ok(entry) = serde_json::from_value::<LiteLlmModelEntry>(val) {
                if entry.input_cost_per_token.is_some() || entry.output_cost_per_token.is_some() {
                    parsed.insert(key, entry);
                }
            }
        }

        let count = parsed.len();

        {
            let mut guard = self.entries.write().await;
            *guard = parsed.clone();
        }
        *self.last_fetched.write().await = Some(Instant::now());

        // Save to disk cache
        if let Some(parent) = self.cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json_str) = serde_json::to_string(&parsed) {
            if let Err(e) = std::fs::write(&self.cache_path, json_str) {
                warn!("Failed to persist pricing cache to {:?}: {}", self.cache_path, e);
            }
        }

        info!("Successfully updated model price catalog ({} models)", count);
        Ok(count)
    }

    /// Lookup pricing given a model name / canonical name
    pub async fn lookup_rate(&self, model: &str) -> Option<(f64, f64, String)> {
        let guard = self.entries.read().await;

        let normalized_keys = Self::candidate_keys(model);
        for key in &normalized_keys {
            if let Some(entry) = guard.get(key) {
                if let (Some(in_cost), Some(out_cost)) = (entry.input_cost_per_token, entry.output_cost_per_token) {
                    let in_1m = in_cost * 1_000_000.0;
                    let out_1m = out_cost * 1_000_000.0;
                    return Some((in_1m, out_1m, entry.currency.clone()));
                }
            }
        }

        None
    }

    fn candidate_keys(raw: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        let clean = raw.trim();
        candidates.push(clean.to_string());

        // Strip provider prefix e.g. "google_test/gemini-3.6-flash" -> "gemini-3.6-flash"
        let without_prov = clean
            .split_once('/')
            .map(|(_, m)| m)
            .unwrap_or(clean);

        if without_prov != clean {
            candidates.push(without_prov.to_string());
        }

        // Strip "models/" prefix e.g. "models/gemini-3.6-flash" -> "gemini-3.6-flash"
        if let Some(stripped) = without_prov.strip_prefix("models/") {
            candidates.push(stripped.to_string());
        }

        // Deepinfra / Vertex AI / Gemini / OpenAI namespace checks
        candidates.push(format!("gemini/{}", without_prov));
        candidates.push(format!("vertex_ai/{}", without_prov));
        candidates.push(format!("google/{}", without_prov));

        // Version fallback logic: e.g., gemini-3.6-flash -> gemini-2.5-flash fallback if not listed yet
        if without_prov.starts_with("gemini-3.") {
            let fallback_flash = without_prov.replace("gemini-3.6-flash", "gemini-2.5-flash").replace("gemini-3.5-flash", "gemini-2.5-flash");
            candidates.push(fallback_flash.clone());
            candidates.push(format!("gemini/{}", fallback_flash));
        }

        candidates
    }
}
