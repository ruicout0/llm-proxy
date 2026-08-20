use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use futures_util::{stream, StreamExt};
use hyper::body::to_bytes;
use hyper::header::{HeaderValue, AUTHORIZATION, CACHE_CONTROL};
use hyper::{Body, Method, Request, Response, StatusCode};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::dialect::{
    resolve_bedrock_inference_profile_id, sanitize_openai_request, sanitize_sse_chunk,
    transform_bedrock_to_openai, transform_openai_to_bedrock, Dialect, EventStreamDecoder,
};
use crate::discovery::DiscoveryCache;
use crate::pricing::PricingRegistry;
use crate::provider::{AuthStyle, Provider};
use crate::router::Registry;
use crate::sigv4::SigV4Signer;
use crate::usage::{resolve_usage_group, TrafficClass, UsageStore};

pub fn openai_error_response(
    status: StatusCode,
    message: &str,
    error_type: &str,
) -> Response<Body> {
    let error_json = serde_json::json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": null,
            "code": status.as_u16()
        }
    });
    let body_str = serde_json::to_string(&error_json).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(body_str))
        .unwrap()
}

pub fn classify_traffic(path_and_query: &str, headers: &hyper::HeaderMap) -> TrafficClass {
    if path_and_query.starts_with("/llm-proxy/") {
        return TrafficClass::Local;
    }
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    if path == "/v1/models" || path == "/v1/model/info" {
        return TrafficClass::Discovery;
    }
    if let Some(val) = headers.get("x-llm-probe").and_then(|v| v.to_str().ok()) {
        if val == "true" || val == "1" {
            return TrafficClass::Probe;
        }
    }
    TrafficClass::Billable
}

pub async fn handle_request(
    req: Request<Body>,
    registry: Arc<Registry>,
    discovery: Arc<DiscoveryCache>,
    pricing: Arc<PricingRegistry>,
    usage_store: Arc<UsageStore>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let headers = req.headers().clone();
    let traffic_class = classify_traffic(&path_and_query, &headers);

    // 1. Local endpoints
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
            .body(Body::from(crate::usage::usage_dashboard_html()))?);
    }
    if method == Method::GET && path_and_query == "/llm-proxy/models" {
        let details = discovery.get_detailed_models(&registry).await?;
        let body = serde_json::to_string_pretty(&details)?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(body))?);
    }
    if method == Method::GET && path_and_query.starts_with("/llm-proxy/health") {
        let uri = req.uri();
        let query = uri.query().unwrap_or("");
        let refresh_requested = query
            .split('&')
            .any(|pair| pair == "refresh=true" || pair == "refresh=1" || pair == "refresh");
        if refresh_requested {
            for prov in registry.providers.values() {
                prov.token_cache.clear_token().await;
            }
            let _ = discovery.refresh(&registry).await;
        }

        let mut health_map = BTreeMap::new();
        for (id, prov) in &registry.providers {
            let h = prov.health.read().await;
            let last_success_sec = h.last_success.map(|i| i.elapsed().as_secs());
            let last_failure_info = h
                .last_failure
                .as_ref()
                .map(|(i, r)| (i.elapsed().as_secs(), r.clone()));
            health_map.insert(
                id.clone(),
                serde_json::json!({
                    "status": if h.is_failed { "failed" } else { "healthy" },
                    "consecutive_failures": h.consecutive_failures,
                    "last_success_secs_ago": last_success_sec,
                    "last_failure": last_failure_info,
                    "discovery": format!("{:?}", h.discovery),
                }),
            );
        }
        let body = serde_json::to_string_pretty(&health_map)?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(body))?);
    }

    // 2. Discovery endpoints
    if traffic_class == TrafficClass::Discovery && method == Method::GET {
        match discovery.get_models(&registry).await {
            Ok(models_list) => {
                let body = serde_json::to_string_pretty(&models_list)?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))?);
            }
            Err(e) => {
                return Ok(openai_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Discovery failed: {}", e),
                    "discovery_error",
                ));
            }
        }
    }

    // 3. Buffer request body
    let (parts, body_bytes) = {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body).await?;
        (parts, bytes)
    };

    let group = match traffic_class {
        TrafficClass::Probe => "__probe".to_string(),
        _ => resolve_usage_group(&parts.headers),
    };

    let mut parsed_body: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
    let is_stream = parsed_body
        .as_ref()
        .and_then(|v| v["stream"].as_bool())
        .unwrap_or(false);

    let raw_request_model = parsed_body
        .as_ref()
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

    let header_provider = parts
        .headers
        .get("x-llm-provider")
        .and_then(|v| v.to_str().ok());

    info!(
        "Incoming request: {} {} raw_model={:?}",
        method, path_and_query, raw_request_model
    );
    if let Some(ref json_val) = parsed_body {
        info!(
            "Request payload: {}",
            serde_json::to_string(json_val).unwrap_or_default()
        );
    }

    // 4. Resolve Route
    let route = match registry
        .resolve_route(raw_request_model.as_deref(), header_provider)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let err_msg = e.to_string();
            let status = if err_msg.starts_with("Unknown provider") {
                StatusCode::NOT_FOUND
            } else if err_msg.starts_with("Ambiguous model") {
                StatusCode::BAD_REQUEST
            } else if err_msg.contains("currently unavailable") {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_REQUEST
            };
            return Ok(openai_error_response(
                status,
                &err_msg,
                "invalid_request_error",
            ));
        }
    };

    let provider = route.provider.clone();
    let canonical_model = route.canonical_model.clone();
    let upstream_model = route.upstream_model.clone();

    // 5. Dialect request translation
    let (target_path_and_query, target_body_bytes) = if provider.dialect == Dialect::BedrockConverse
    {
        if let Some(ref val) = parsed_body {
            let (m_id, bedrock_body) = transform_openai_to_bedrock(val)?;
            let raw_model = if upstream_model.is_empty() {
                m_id
            } else {
                upstream_model.clone()
            };
            let region = match &provider.auth {
                AuthStyle::AwsSigv4 { region, .. } => region.as_str(),
                _ => "eu-central-1",
            };
            let actual_model = resolve_bedrock_inference_profile_id(&raw_model, region);
            let subpath = if is_stream {
                "converse-stream"
            } else {
                "converse"
            };
            let path = format!("/model/{}/{}", actual_model, subpath);
            let bytes = Bytes::from(serde_json::to_vec(&bedrock_body)?);
            (path, bytes)
        } else {
            (path_and_query.clone(), body_bytes.clone())
        }
    } else {
        // OpenAI standard rewriting: set model to upstream_model and inject stream_options
        let mut final_bytes = body_bytes.clone();
        if let Some(ref mut v) = parsed_body {
            if v.is_object() {
                v["model"] = serde_json::Value::String(upstream_model.clone());
                sanitize_openai_request(v, &provider.base_url);

                if is_stream {
                    let opts = v.get_mut("stream_options").and_then(|o| o.as_object_mut());
                    match opts {
                        Some(o) => {
                            o.insert("include_usage".to_string(), serde_json::Value::Bool(true));
                        }
                        None => {
                            v["stream_options"] = serde_json::json!({ "include_usage": true });
                        }
                    }
                }
                if let Ok(new_bytes) = serde_json::to_vec(v) {
                    final_bytes = Bytes::from(new_bytes);
                }
            }
        }
        (path_and_query.clone(), final_bytes)
    };

    // 6. Build upstream URI
    let upstream_uri_str = build_upstream_uri(&provider, &target_path_and_query)?;
    let upstream_uri: hyper::Uri = upstream_uri_str.parse()?;

    // 7. Request forwarder closure with per-provider auth
    let parts_headers = parts.headers.clone();
    let method_clone = method.clone();
    let body_bytes_clone = target_body_bytes.clone();
    let upstream_uri_clone = upstream_uri.clone();

    let send_upstream = |provider: Arc<Provider>| {
        let parts_headers = parts_headers.clone();
        let method = method_clone.clone();
        let body_bytes = body_bytes_clone.clone();
        let uri = upstream_uri_clone.clone();

        async move {
            let host_only = provider
                .base_url
                .split('/')
                .next()
                .unwrap_or(&provider.base_url);

            let mut req_builder = Request::builder().method(method.clone()).uri(uri.clone());

            if !matches!(provider.auth, AuthStyle::AwsSigv4 { .. }) {
                for (name, value) in parts_headers.iter() {
                    let lower = name.as_str().to_lowercase();
                    if lower == "host"
                        || lower == "authorization"
                        || lower == "x-apikey"
                        || lower == "content-length"
                        || lower == "transfer-encoding"
                        || lower == "connection"
                        || lower == "x-llm-provider"
                    {
                        continue;
                    }
                    req_builder = req_builder.header(name, value);
                }
            }

            match &provider.auth {
                AuthStyle::OauthM2m { .. } => {
                    let bearer = provider.token_cache.get_valid_bearer().await?;
                    let x_api_key = provider.token_cache.get_x_api_key().await?;
                    if !bearer.is_empty() {
                        req_builder = req_builder.header(
                            AUTHORIZATION,
                            HeaderValue::from_str(&format!("Bearer {}", bearer))?,
                        );
                    }
                    if !x_api_key.is_empty() {
                        req_builder = req_builder.header(
                            "x-apikey".parse::<hyper::header::HeaderName>()?,
                            HeaderValue::from_str(&x_api_key)?,
                        );
                    }
                }
                AuthStyle::BearerApiKey { .. } => {
                    let key = provider.token_cache.get_valid_bearer().await?;
                    if !key.is_empty() {
                        req_builder = req_builder.header(
                            AUTHORIZATION,
                            HeaderValue::from_str(&format!("Bearer {}", key))?,
                        );
                        if provider.base_url.contains("googleapis.com") {
                            req_builder = req_builder.header(
                                "x-api-key".parse::<hyper::header::HeaderName>()?,
                                HeaderValue::from_str(&key)?,
                            );
                        }
                    }
                }
                AuthStyle::StaticBearer { .. } => {
                    let bearer = provider.token_cache.get_valid_bearer().await?;
                    let x_api_key = provider.token_cache.get_x_api_key().await?;
                    if !bearer.is_empty() {
                        req_builder = req_builder.header(
                            AUTHORIZATION,
                            HeaderValue::from_str(&format!("Bearer {}", bearer))?,
                        );
                    }
                    if !x_api_key.is_empty() {
                        req_builder = req_builder.header(
                            "x-apikey".parse::<hyper::header::HeaderName>()?,
                            HeaderValue::from_str(&x_api_key)?,
                        );
                    }
                }
                AuthStyle::CustomHeader { name, .. } => {
                    let val = provider.token_cache.get_x_api_key().await?;
                    if !val.is_empty() {
                        req_builder = req_builder.header(
                            name.parse::<hyper::header::HeaderName>()?,
                            HeaderValue::from_str(&val)?,
                        );
                    }
                }
                AuthStyle::AwsSigv4 { region, .. } => {
                    let creds = provider.token_cache.get_aws_credentials().await?;
                    let signer = SigV4Signer::new("bedrock", region, &creds);

                    let mut headers_map = hyper::HeaderMap::new();
                    headers_map.insert(hyper::header::HOST, HeaderValue::from_str(host_only)?);
                    headers_map.insert(
                        hyper::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    headers_map.insert(
                        CACHE_CONTROL,
                        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                    );

                    let path = uri.path();
                    let query = uri.query();
                    signer.sign_request(
                        method.as_str(),
                        path,
                        query,
                        &mut headers_map,
                        &body_bytes,
                        Utc::now(),
                    )?;

                    for (k, v) in headers_map.iter() {
                        req_builder = req_builder.header(k, v);
                    }
                }
                AuthStyle::None => {}
            }

            if !matches!(provider.auth, AuthStyle::AwsSigv4 { .. }) {
                req_builder = req_builder
                    .header(
                        CACHE_CONTROL,
                        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                    )
                    .header(hyper::header::HOST, HeaderValue::from_str(host_only)?);
            }

            let built_req = req_builder.body(Body::from(body_bytes))?;
            let resp = provider.client.request(built_req).await?;
            Ok::<Response<Body>, anyhow::Error>(resp)
        }
    };

    debug!(
        "Forwarding {} {} to provider {} (upstream_model={} canonical={})",
        method, upstream_uri, provider.id, upstream_model, canonical_model
    );

    let result = match send_upstream(provider.clone()).await {
        Ok::<Response<Body>, anyhow::Error>(resp) => {
            info!("Upstream response status: {}", resp.status());
            if resp.status() == StatusCode::UNAUTHORIZED
                && !matches!(provider.auth, AuthStyle::AwsSigv4 { .. })
            {
                warn!(
                    "Got 401 from provider {} - clearing cache and retrying once",
                    provider.id
                );
                provider.token_cache.clear_token().await;
                match send_upstream(provider.clone()).await {
                    Ok(retry_resp) => {
                        if retry_resp.status().is_success() {
                            provider.record_success().await;
                        } else {
                            provider
                                .record_failure(format!("Status {}", retry_resp.status()))
                                .await;
                        }
                        record_usage_from_response(
                            retry_resp,
                            usage_store.clone(),
                            pricing.clone(),
                            group,
                            provider.id.clone(),
                            canonical_model,
                            provider.clone(),
                            is_stream,
                        )
                        .await
                    }
                    Err(e) => {
                        provider.record_failure(e.to_string()).await;
                        error!("Retry request failed for provider {}: {}", provider.id, e);
                        Ok(openai_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Upstream error after auth refresh: {}", e),
                            "bad_gateway",
                        ))
                    }
                }
            } else {
                if resp.status().is_success() {
                    provider.record_success().await;
                } else if resp.status().is_server_error() {
                    provider
                        .record_failure(format!("Status {}", resp.status()))
                        .await;
                }
                record_usage_from_response(
                    resp,
                    usage_store.clone(),
                    pricing.clone(),
                    group,
                    provider.id.clone(),
                    canonical_model,
                    provider.clone(),
                    is_stream,
                )
                .await
            }
        }
        Err(e) => {
            provider.record_failure(e.to_string()).await;
            error!(
                "Upstream request failed for provider {}: {}",
                provider.id, e
            );
            Ok(openai_error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream request failed: {}", e),
                "bad_gateway",
            ))
        }
    };

    result
}

fn build_upstream_uri(provider: &Provider, path_and_query: &str) -> Result<String> {
    let base = provider.base_url.trim_end_matches('/');
    let pq = if base.ends_with("/v1") && path_and_query.starts_with("/v1/") {
        &path_and_query[3..] // strip /v1 to avoid double /v1/v1/
    } else {
        path_and_query
    };
    Ok(format!("{}://{}{}", provider.scheme, base, pq))
}

pub type ParsedUsage = (Option<String>, Option<(f64, String)>, BTreeMap<String, u64>);

pub fn parse_sse_usage(buf: &[u8], request_model: Option<&str>) -> Option<ParsedUsage> {
    let text = String::from_utf8_lossy(buf);
    let mut model: Option<String> = None;
    let mut cost: Option<(f64, String)> = None;
    let mut tokens: BTreeMap<String, u64> = BTreeMap::new();
    let mut found_usage = false;

    for line in text.lines() {
        let line = line.trim_start();
        let data = match line.strip_prefix("data:") {
            Some(d) => d.trim(),
            None => continue,
        };
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(j) => j,
            Err(_) => continue,
        };
        if model.is_none() {
            model = json["model"]
                .as_str()
                .or_else(|| json["model_id"].as_str())
                .map(|s| s.to_string());
        }
        if let Some((amount, currency)) = json["cost"]["total"]
            .as_f64()
            .zip(json["cost"]["currency"].as_str().map(|s| s.to_string()))
        {
            cost = Some((amount, currency));
        }
        if let Some(obj) = json["usage"].as_object() {
            for (k, v) in obj {
                if let Some(n) = v.as_u64() {
                    tokens.insert(k.clone(), n);
                    found_usage = true;
                }
            }
        }
    }

    let resolved_model = model.or_else(|| request_model.map(|s| s.to_string()));

    if found_usage || cost.is_some() {
        Some((resolved_model, cost, tokens))
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn record_usage_from_response(
    resp: Response<Body>,
    usage_store: Arc<UsageStore>,
    pricing: Arc<PricingRegistry>,
    group: String,
    provider_id: String,
    canonical_model: String,
    provider: Arc<Provider>,
    is_stream: bool,
) -> Result<Response<Body>> {
    let (mut parts, body) = resp.into_parts();

    if is_stream {
        let is_bedrock = provider.dialect == Dialect::BedrockConverse;
        let success = parts.status.is_success();

        if is_bedrock && success {
            parts.headers.insert(
                hyper::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
        }

        struct TeeState {
            body: Body,
            buf: Vec<u8>,
            usage_store: Arc<UsageStore>,
            pricing: Arc<PricingRegistry>,
            group: String,
            provider_id: String,
            canonical_model: String,
            provider: Arc<Provider>,
            success: bool,
            is_bedrock: bool,
            bedrock_decoder: EventStreamDecoder,
            pending_sse_chunks: Vec<Bytes>,
        }

        let state = TeeState {
            body,
            buf: Vec::new(),
            usage_store,
            pricing: pricing.clone(),
            group,
            provider_id,
            canonical_model: canonical_model.clone(),
            provider,
            success,
            is_bedrock,
            bedrock_decoder: EventStreamDecoder::new(canonical_model),
            pending_sse_chunks: Vec::new(),
        };

        let out = stream::unfold(state, |mut state| async move {
            loop {
                // If we have converted Bedrock SSE chunks queued, yield them first
                if !state.pending_sse_chunks.is_empty() {
                    let chunk = state.pending_sse_chunks.remove(0);
                    return Some((Ok::<Bytes, hyper::Error>(chunk), state));
                }

                match state.body.next().await {
                    Some(Ok(chunk)) => {
                        state.buf.extend_from_slice(&chunk);

                        if state.is_bedrock && state.success {
                            let sse_lines = state.bedrock_decoder.push_chunk(&chunk);
                            for line in sse_lines {
                                state.pending_sse_chunks.push(Bytes::from(line));
                            }
                            // Continue loop to emit queued chunks
                            continue;
                        } else {
                            let clean_chunk = sanitize_sse_chunk(&chunk, &state.canonical_model);
                            return Some((
                                Ok::<Bytes, hyper::Error>(Bytes::from(clean_chunk)),
                                state,
                            ));
                        }
                    }
                    Some(Err(e)) => return Some((Err(e), state)),
                    None => {
                        // End of stream
                        if state.is_bedrock && state.success {
                            // Emit terminal [DONE] if not emitted
                            state
                                .pending_sse_chunks
                                .push(Bytes::from("data: [DONE]\n\n"));
                        }

                        if state.success {
                            let parsed = if state.is_bedrock {
                                // For Bedrock, parse usage from the decoded buffer
                                parse_sse_usage(&state.buf, Some(&state.canonical_model))
                            } else {
                                parse_sse_usage(&state.buf, Some(&state.canonical_model))
                            };

                            if let Some((_model, cost_reported, tokens)) = parsed {
                                let cost_estimated = if cost_reported.is_none() {
                                    estimate_cost(
                                        &tokens,
                                        &state.provider,
                                        &state.canonical_model,
                                        &state.pricing,
                                    )
                                    .await
                                } else {
                                    None
                                };
                                debug!(
                                    "Recorded streaming usage for group={} prov={} model={} reported={:?} estimated={:?}",
                                    state.group, state.provider_id, state.canonical_model, cost_reported, cost_estimated
                                );
                                let _ = state
                                    .usage_store
                                    .record_with_provider(
                                        &state.group,
                                        &state.provider_id,
                                        &state.canonical_model,
                                        cost_reported,
                                        cost_estimated,
                                        tokens,
                                    )
                                    .await;
                            }
                        }

                        if !state.pending_sse_chunks.is_empty() {
                            let chunk = state.pending_sse_chunks.remove(0);
                            return Some((Ok::<Bytes, hyper::Error>(chunk), state));
                        }
                        return None;
                    }
                }
            }
        });
        return Ok(Response::from_parts(parts, Body::wrap_stream(out)));
    }

    // Non-streaming: buffer JSON
    let body_bytes = to_bytes(body).await?;

    let final_body_bytes =
        if provider.dialect == Dialect::BedrockConverse && parts.status.is_success() {
            if let Ok(bedrock_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                let openai_json = transform_bedrock_to_openai(&bedrock_json, &canonical_model)?;
                Bytes::from(serde_json::to_vec_pretty(&openai_json)?)
            } else {
                body_bytes
            }
        } else {
            body_bytes
        };

    if parts.status.is_success() {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&final_body_bytes) {
            let cost_reported = json["cost"]["total"]
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

            let cost_estimated = if cost_reported.is_none() {
                estimate_cost(&tokens, &provider, &canonical_model, &pricing).await
            } else {
                None
            };
            let _ = usage_store
                .record_with_provider(
                    &group,
                    &provider_id,
                    &canonical_model,
                    cost_reported,
                    cost_estimated,
                    tokens,
                )
                .await;
        }
    }

    Ok(Response::from_parts(parts, Body::from(final_body_bytes)))
}

pub async fn estimate_cost(
    tokens: &BTreeMap<String, u64>,
    provider: &Provider,
    canonical_model: &str,
    pricing: &PricingRegistry,
) -> Option<(f64, String)> {
    let upstream_key = canonical_model
        .split_once('/')
        .map(|(_, up)| up)
        .unwrap_or(canonical_model);

    // 1. Try explicit provider model spec from config
    let (in_rate, out_rate, currency) = if let Some(spec) = provider.models.get(upstream_key) {
        if let (Some(in_r), Some(out_r)) = (spec.input_cost_per_1m, spec.output_cost_per_1m) {
            (in_r, out_r, spec.currency.clone())
        } else {
            pricing.lookup_rate(canonical_model).await?
        }
    } else {
        pricing.lookup_rate(canonical_model).await?
    };

    let prompt_tokens = tokens.get("prompt_tokens").copied().unwrap_or(0);
    let completion_tokens = tokens.get("completion_tokens").copied().unwrap_or(0);

    let cost = (prompt_tokens as f64 / 1_000_000.0) * in_rate
        + (completion_tokens as f64 / 1_000_000.0) * out_rate;

    Some((cost, currency))
}
