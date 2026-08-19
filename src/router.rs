use anyhow::{bail, Result};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::ConfigFile;
use crate::provider::Provider;

#[derive(Debug, Clone)]
pub struct Route {
    pub provider: Arc<Provider>,
    pub upstream_model: String,
    pub canonical_model: String,
}

#[derive(Debug, Clone, Default)]
pub struct ModelIndex {
    /// canonical_id (e.g. "openai/gpt-4o") -> (provider_id, upstream_model)
    pub canonical: HashMap<String, (String, String)>,
    /// alias (e.g. "fast") -> canonical_id
    pub aliases: HashMap<String, String>,
    /// bare model name (e.g. "gpt-4o") -> candidate canonical_ids
    pub bare: HashMap<String, Vec<String>>,
}

pub struct Registry {
    pub providers: BTreeMap<String, Arc<Provider>>,
    pub default_provider: String,
    pub separator: char,
    pub index: RwLock<ModelIndex>,
}

impl Registry {
    pub fn new(config: &ConfigFile) -> Self {
        let (default_provider, prov_configs) = config.normalize_providers();
        let mut providers = BTreeMap::new();

        for p_cfg in &prov_configs {
            match Provider::new(p_cfg) {
                Ok(prov) => {
                    providers.insert(p_cfg.id.clone(), Arc::new(prov));
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize provider {}: {}", p_cfg.id, e);
                }
            }
        }

        let separator = config.model_separator;
        let mut index = ModelIndex::default();

        // Build initial static model index
        for (prov_id, prov) in &providers {
            for (m_id, spec) in &prov.models {
                let canonical_id = format!("{}{}{}", prov_id, separator, m_id);
                index
                    .canonical
                    .insert(canonical_id.clone(), (prov_id.clone(), m_id.clone()));
                if let Some(ref alias) = spec.alias {
                    index.aliases.insert(alias.clone(), canonical_id.clone());
                }
                index
                    .bare
                    .entry(m_id.clone())
                    .or_default()
                    .push(canonical_id);
            }
        }

        Self {
            providers,
            default_provider,
            separator,
            index: RwLock::new(index),
        }
    }

    /// Resolve a model request using the 5-step resolution precedence:
    /// 1. Prefixed model in body (provider<sep>model) -> error if unknown provider
    /// 2. Alias -> canonical ID
    /// 3. x-llm-provider header -> resolve against that provider
    /// 4. Unique bare-name match -> error listing candidates if ambiguous
    /// 5. default_provider -> resolve against default_provider (error if Failed/missing)
    pub async fn resolve_route(
        &self,
        requested_model: Option<&str>,
        header_provider: Option<&str>,
    ) -> Result<Route> {
        let index = self.index.read().await;

        let req_model = match requested_model {
            Some(m) if !m.is_empty() => m,
            _ => {
                // If no model specified, try default provider with empty/default upstream model
                return self
                    .route_for_provider(&self.default_provider, "default", "default")
                    .await;
            }
        };

        // Step 1: Prefixed model (<provider><sep><upstream>)
        if let Some((prov_id, upstream)) = req_model.split_once(self.separator) {
            if let Some(prov) = self.providers.get(prov_id) {
                let canonical = format!("{}{}{}", prov_id, self.separator, upstream);
                return Ok(Route {
                    provider: prov.clone(),
                    upstream_model: upstream.to_string(),
                    canonical_model: canonical,
                });
            } else {
                bail!("Unknown provider '{}' in model '{}'", prov_id, req_model);
            }
        }

        // Step 2: Alias
        if let Some(canonical_id) = index.aliases.get(req_model) {
            if let Some((prov_id, upstream)) = index.canonical.get(canonical_id) {
                if let Some(prov) = self.providers.get(prov_id) {
                    return Ok(Route {
                        provider: prov.clone(),
                        upstream_model: upstream.clone(),
                        canonical_model: canonical_id.clone(),
                    });
                }
            }
        }

        // Step 3: x-llm-provider header
        if let Some(prov_id) = header_provider {
            if let Some(prov) = self.providers.get(prov_id) {
                let canonical = format!("{}{}{}", prov_id, self.separator, req_model);
                return Ok(Route {
                    provider: prov.clone(),
                    upstream_model: req_model.to_string(),
                    canonical_model: canonical,
                });
            } else {
                bail!("Header specified unknown provider '{}'", prov_id);
            }
        }

        // Step 4: Bare-name match in index
        if let Some(candidates) = index.bare.get(req_model) {
            if candidates.len() == 1 {
                let canonical_id = &candidates[0];
                if let Some((prov_id, upstream)) = index.canonical.get(canonical_id) {
                    if let Some(prov) = self.providers.get(prov_id) {
                        return Ok(Route {
                            provider: prov.clone(),
                            upstream_model: upstream.clone(),
                            canonical_model: canonical_id.clone(),
                        });
                    }
                }
            } else if candidates.len() > 1 {
                bail!(
                    "Ambiguous model '{}' matches multiple providers: [{}]. Use <provider>{}{}",
                    req_model,
                    candidates.join(", "),
                    self.separator,
                    req_model
                );
            }
        }

        // Step 5: Fallback to default_provider
        self.route_for_provider(&self.default_provider, req_model, req_model)
            .await
    }

    async fn route_for_provider(
        &self,
        prov_id: &str,
        upstream_model: &str,
        model_name: &str,
    ) -> Result<Route> {
        if let Some(prov) = self.providers.get(prov_id) {
            let h = prov.health.read().await;
            if h.is_failed {
                bail!(
                    "Default provider '{}' is currently unavailable/failed",
                    prov_id
                );
            }
            let canonical = format!("{}{}{}", prov_id, self.separator, model_name);
            Ok(Route {
                provider: prov.clone(),
                upstream_model: upstream_model.to_string(),
                canonical_model: canonical,
            })
        } else {
            bail!(
                "Default provider '{}' is not configured or failed initialization",
                prov_id
            );
        }
    }
}
