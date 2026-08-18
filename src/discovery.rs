use anyhow::Result;
use hyper::body::to_bytes;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::ConfigFile;
use crate::provider::{DiscoveryState, Provider};
use crate::router::Registry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiModel {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub owned_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_tools: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiModelsList {
    pub object: String,
    pub data: Vec<OpenAiModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderModelInfo {
    pub id: String,
    pub provider: String,
    pub upstream_id: String,
    pub source: String, // "config" | "discovery"
    pub hidden: bool,
    pub context_window: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub supports_tools: Option<bool>,
}

pub struct DiscoveryCache {
    cached_response: RwLock<Option<(Instant, OpenAiModelsList, Vec<ProviderModelInfo>)>>,
    ttl: Duration,
    timeout: Duration,
}

impl DiscoveryCache {
    pub fn new(config: &ConfigFile) -> Self {
        Self {
            cached_response: RwLock::new(None),
            ttl: Duration::from_secs(config.discovery_ttl_secs),
            timeout: Duration::from_millis(config.discovery_timeout_ms),
        }
    }

    pub async fn get_models(&self, registry: &Arc<Registry>) -> Result<OpenAiModelsList> {
        let (list, _) = self.get_or_refresh(registry).await?;
        Ok(list)
    }

    pub async fn get_detailed_models(&self, registry: &Arc<Registry>) -> Result<Vec<ProviderModelInfo>> {
        let (_, details) = self.get_or_refresh(registry).await?;
        Ok(details)
    }

    async fn get_or_refresh(
        &self,
        registry: &Arc<Registry>,
    ) -> Result<(OpenAiModelsList, Vec<ProviderModelInfo>)> {
        // Check cache first
        {
            let guard = self.cached_response.read().await;
            if let Some((cached_at, ref list, ref details)) = *guard {
                if cached_at.elapsed() < self.ttl {
                    return Ok((list.clone(), details.clone()));
                }
            }
        }

        // Cache miss or expired: fetch
        match self.fetch_all(registry).await {
            Ok((list, details)) => {
                let mut guard = self.cached_response.write().await;
                *guard = Some((Instant::now(), list.clone(), details.clone()));
                Ok((list, details))
            }
            Err(e) => {
                // If failed, return stale cache if present
                let guard = self.cached_response.read().await;
                if let Some((_, ref list, ref details)) = *guard {
                    warn!("Discovery fetch failed, serving stale cache: {}", e);
                    Ok((list.clone(), details.clone()))
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn fetch_all(
        &self,
        registry: &Arc<Registry>,
    ) -> Result<(OpenAiModelsList, Vec<ProviderModelInfo>)> {
        let mut tasks = Vec::new();

        for (prov_id, prov) in &registry.providers {
            let p_id = prov_id.clone();
            let prov = prov.clone();
            let timeout = self.timeout;
            let sep = registry.separator;

            tasks.push(tokio::spawn(async move {
                let res = tokio::time::timeout(timeout, fetch_provider_models(&prov)).await;
                (p_id, prov, sep, res)
            }));
        }

        let mut models_by_id = BTreeMap::<String, OpenAiModel>::new();
        let mut model_details = Vec::<ProviderModelInfo>::new();
        let mut new_canonical = HashMap::<String, (String, String)>::new();
        let mut new_aliases = HashMap::<String, String>::new();
        let mut new_bare = HashMap::<String, Vec<String>>::new();

        for task in tasks {
            if let Ok((prov_id, prov, sep, res)) = task.await {
                let mut prov_health = prov.health.write().await;
                match res {
                    Ok(Ok(discovered_models)) => {
                        prov_health.discovery = DiscoveryState::Live;
                        drop(prov_health);

                        for dm in discovered_models {
                            let upstream_id = dm.id.clone();
                            let canonical_id = format!("{}{}{}", prov_id, sep, upstream_id);

                            // Check static config for overrides / hidden
                            let static_spec = prov.models.get(&upstream_id);
                            let is_hidden = static_spec.map(|s| s.hidden).unwrap_or(false);

                            let context_window = static_spec
                                .and_then(|s| s.context_window)
                                .or(dm.context_window);
                            let max_output_tokens = static_spec
                                .and_then(|s| s.max_output_tokens)
                                .or(dm.max_output_tokens);
                            let supports_tools = static_spec
                                .and_then(|s| s.supports_tools)
                                .or(dm.supports_tools);

                            let detailed = ProviderModelInfo {
                                id: canonical_id.clone(),
                                provider: prov_id.clone(),
                                upstream_id: upstream_id.clone(),
                                source: "discovery".to_string(),
                                hidden: is_hidden,
                                context_window,
                                max_output_tokens,
                                supports_tools,
                            };
                            model_details.push(detailed);

                            if !is_hidden {
                                models_by_id.insert(
                                    canonical_id.clone(),
                                    OpenAiModel {
                                        id: canonical_id.clone(),
                                        object: "model".to_string(),
                                        created: dm.created,
                                        owned_by: prov_id.clone(),
                                        context_window,
                                        max_output_tokens,
                                        supports_tools,
                                    },
                                );
                            }

                            new_canonical.insert(canonical_id.clone(), (prov_id.clone(), upstream_id.clone()));
                            new_bare.entry(upstream_id.clone()).or_default().push(canonical_id.clone());
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Discovery for provider '{}' failed: {}", prov_id, e);
                        prov_health.discovery = DiscoveryState::Failed(e.to_string());
                    }
                    Err(_) => {
                        warn!("Discovery for provider '{}' timed out", prov_id);
                        prov_health.discovery = DiscoveryState::Failed("timeout".to_string());
                    }
                }

                // Add statically configured models for this provider
                for (m_id, spec) in &prov.models {
                    let canonical_id = format!("{}{}{}", prov_id, sep, m_id);
                    new_canonical.insert(canonical_id.clone(), (prov_id.clone(), m_id.clone()));
                    if let Some(ref alias) = spec.alias {
                        new_aliases.insert(alias.clone(), canonical_id.clone());
                    }
                    let candidates = new_bare.entry(m_id.clone()).or_default();
                    if !candidates.contains(&canonical_id) {
                        candidates.push(canonical_id.clone());
                    }

                    if !models_by_id.contains_key(&canonical_id) {
                        let detailed = ProviderModelInfo {
                            id: canonical_id.clone(),
                            provider: prov_id.clone(),
                            upstream_id: m_id.clone(),
                            source: "config".to_string(),
                            hidden: spec.hidden,
                            context_window: spec.context_window,
                            max_output_tokens: spec.max_output_tokens,
                            supports_tools: spec.supports_tools,
                        };
                        model_details.push(detailed);

                        if !spec.hidden {
                            models_by_id.insert(
                                canonical_id.clone(),
                                OpenAiModel {
                                    id: canonical_id.clone(),
                                    object: "model".to_string(),
                                    created: 1700000000,
                                    owned_by: prov_id.clone(),
                                    context_window: spec.context_window,
                                    max_output_tokens: spec.max_output_tokens,
                                    supports_tools: spec.supports_tools,
                                },
                            );
                        }
                    }
                }
            }
        }

        // Update the Registry ModelIndex with freshly discovered models
        {
            let mut index = registry.index.write().await;
            for (k, v) in new_canonical {
                index.canonical.insert(k, v);
            }
            for (k, v) in new_aliases {
                index.aliases.insert(k, v);
            }
            for (k, mut v) in new_bare {
                let entry = index.bare.entry(k).or_default();
                for cand in v.drain(..) {
                    if !entry.contains(&cand) {
                        entry.push(cand);
                    }
                }
            }
        }

        let result = OpenAiModelsList {
            object: "list".to_string(),
            data: models_by_id.into_values().collect(),
        };

        Ok((result, model_details))
    }
}

pub async fn fetch_provider_models(prov: &Provider) -> Result<Vec<OpenAiModel>> {
    let base = prov.base_url.trim_end_matches('/');
    let uri_str = if base.ends_with("/v1") || base.ends_with("/openai") || base.contains("/v1/") || base.contains("/openai/") {
        format!("{}://{}/models", prov.scheme, base)
    } else {
        format!("{}://{}/v1/models", prov.scheme, base)
    };

    let mut req_builder = Request::builder().method(Method::GET).uri(uri_str);

    match &prov.auth {
        crate::provider::AuthStyle::OauthM2m { .. } => {
            let bearer = prov.token_cache.get_valid_bearer().await.unwrap_or_default();
            let x_api_key = prov.token_cache.get_x_api_key().await.unwrap_or_default();
            if !bearer.is_empty() {
                req_builder = req_builder.header(hyper::header::AUTHORIZATION, format!("Bearer {}", bearer));
            }
            if !x_api_key.is_empty() {
                req_builder = req_builder.header("x-apikey", x_api_key);
            }
        }
        crate::provider::AuthStyle::BearerApiKey { .. } | crate::provider::AuthStyle::StaticBearer { .. } => {
            let bearer = prov.token_cache.get_valid_bearer().await.unwrap_or_default();
            let x_api_key = prov.token_cache.get_x_api_key().await.unwrap_or_default();
            if !bearer.is_empty() {
                req_builder = req_builder.header(hyper::header::AUTHORIZATION, format!("Bearer {}", bearer));
            }
            if !x_api_key.is_empty() {
                req_builder = req_builder.header("x-apikey", x_api_key);
            }
        }
        crate::provider::AuthStyle::CustomHeader { name, .. } => {
            let val = prov.token_cache.get_x_api_key().await.unwrap_or_default();
            if !val.is_empty() {
                req_builder = req_builder.header(name.as_str(), val);
            }
        }
        crate::provider::AuthStyle::None => {}
    }

    let host_only = prov.base_url.split('/').next().unwrap_or(&prov.base_url);
    req_builder = req_builder.header(hyper::header::HOST, host_only);

    let req = req_builder.body(hyper::Body::empty())?;
    let resp = prov.client.request(req).await?;

    if !resp.status().is_success() {
        anyhow::bail!("Status {}", resp.status());
    }

    let body = to_bytes(resp.into_body()).await?;
    let json: serde_json::Value = serde_json::from_slice(&body)?;

    let mut models = Vec::new();
    if let Some(arr) = json["data"].as_array() {
        for item in arr {
            if let Some(id) = item["id"].as_str() {
                models.push(OpenAiModel {
                    id: id.to_string(),
                    object: item["object"].as_str().unwrap_or("model").to_string(),
                    created: item["created"].as_u64().unwrap_or(0),
                    owned_by: item["owned_by"].as_str().unwrap_or(&prov.id).to_string(),
                    context_window: item["context_window"].as_u64(),
                    max_output_tokens: item["max_output_tokens"].as_u64(),
                    supports_tools: item["supports_tools"].as_bool(),
                });
            }
        }
    }

    Ok(models)
}
