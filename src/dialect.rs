use anyhow::{Context, Result};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialect {
    OpenAiCompatible,
    BedrockConverse,
}

// Request Transformation: OpenAI JSON -> Bedrock Converse JSON
pub fn transform_openai_to_bedrock(openai_req: &Value) -> Result<(String, Value)> {
    let model = openai_req["model"]
        .as_str()
        .context("Missing model in request")?
        .to_string();

    let mut system_prompts = Vec::new();
    let mut bedrock_messages = Vec::new();

    if let Some(messages) = openai_req["messages"].as_array() {
        for msg in messages {
            let role = msg["role"].as_str().unwrap_or("user");
            let content = msg["content"].as_str().unwrap_or("");

            match role {
                "system" => {
                    system_prompts.push(json!({ "text": content }));
                }
                "user" | "assistant" => {
                    bedrock_messages.push(json!({
                        "role": role,
                        "content": [
                            { "text": content }
                        ]
                    }));
                }
                _ => {
                    bedrock_messages.push(json!({
                        "role": "user",
                        "content": [
                            { "text": format!("{}: {}", role, content) }
                        ]
                    }));
                }
            }
        }
    }

    let mut inference_config = json!({});
    if let Some(temp) = openai_req["temperature"].as_f64() {
        inference_config["temperature"] = json!(temp);
    }
    if let Some(top_p) = openai_req["top_p"].as_f64() {
        inference_config["topP"] = json!(top_p);
    }
    if let Some(max_tokens) = openai_req["max_tokens"]
        .as_u64()
        .or_else(|| openai_req["max_completion_tokens"].as_u64())
    {
        inference_config["maxTokens"] = json!(max_tokens);
    }
    if let Some(stops) = openai_req["stop"].as_array() {
        let stop_seqs: Vec<Value> = stops
            .iter()
            .filter_map(|s| s.as_str().map(|t| json!(t)))
            .collect();
        if !stop_seqs.is_empty() {
            inference_config["stopSequences"] = json!(stop_seqs);
        }
    } else if let Some(stop_str) = openai_req["stop"].as_str() {
        inference_config["stopSequences"] = json!([stop_str]);
    }

    let mut bedrock_req = json!({
        "messages": bedrock_messages
    });

    if !system_prompts.is_empty() {
        bedrock_req["system"] = json!(system_prompts);
    }
    if inference_config
        .as_object()
        .map(|o| !o.is_empty())
        .unwrap_or(false)
    {
        bedrock_req["inferenceConfig"] = inference_config;
    }

    Ok((model, bedrock_req))
}

pub fn resolve_bedrock_inference_profile_id(model_id: &str, aws_region: &str) -> String {
    // If already has cross-region or ARN prefix, leave as-is
    if model_id.starts_with("eu.")
        || model_id.starts_with("us.")
        || model_id.starts_with("apac.")
        || model_id.starts_with("cr.")
        || model_id.starts_with("global.")
        || model_id.starts_with("arn:")
    {
        return model_id.to_string();
    }

    let geo = if aws_region.starts_with("eu-") {
        "eu"
    } else if aws_region.starts_with("us-") {
        "us"
    } else if aws_region.starts_with("ap-") {
        "apac"
    } else {
        "eu"
    };

    // Models requiring inference profile IDs on on-demand throughput:
    // Bedrock enforces inference profiles for all modern Anthropic Claude models (3.5+, 4.x, 5.x, Opus, Sonnet, Haiku, Fable),
    // Amazon Nova models, Meta Llama 3+, DeepSeek, Mistral Pixtral/Devstral, and OpenAI on Bedrock.
    if model_id.starts_with("amazon.nova-")
        || model_id.starts_with("amazon.nova")
        || model_id.starts_with("anthropic.claude-")
        || model_id.starts_with("anthropic.claude")
        || model_id.starts_with("deepseek.")
        || model_id.starts_with("mistral.pixtral-")
        || model_id.starts_with("mistral.devstral-")
        || model_id.starts_with("openai.gpt-")
        || model_id.starts_with("meta.llama3-")
        || model_id.starts_with("meta.llama-3")
        || model_id.starts_with("qwen.qwen3-")
    {
        format!("{}.{}", geo, model_id)
    } else {
        model_id.to_string()
    }
}

// Response Transformation: Bedrock Converse JSON -> OpenAI Chat Completion JSON
pub fn transform_bedrock_to_openai(bedrock_resp: &Value, model_name: &str) -> Result<Value> {
    let mut full_text = String::new();
    if let Some(contents) = bedrock_resp["output"]["message"]["content"].as_array() {
        for c in contents {
            if let Some(txt) = c["text"].as_str() {
                full_text.push_str(txt);
            }
        }
    }

    let stop_reason = bedrock_resp["stopReason"].as_str().unwrap_or("end_turn");
    let finish_reason = match stop_reason {
        "end_turn" | "stop_sequence" => "stop",
        "max_tokens" => "length",
        "tool_use" => "tool_calls",
        _ => "stop",
    };

    let input_tokens = bedrock_resp["usage"]["inputTokens"].as_u64().unwrap_or(0);
    let output_tokens = bedrock_resp["usage"]["outputTokens"].as_u64().unwrap_or(0);
    let total_tokens = bedrock_resp["usage"]["totalTokens"]
        .as_u64()
        .unwrap_or(input_tokens + output_tokens);

    let openai_resp = json!({
        "id": format!("chatcmpl-bedrock-{}", chrono::Utc::now().timestamp_millis()),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": model_name,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": full_text
                },
                "finish_reason": finish_reason
            }
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": total_tokens
        }
    });

    Ok(openai_resp)
}

// AWS Event Stream Decoder for Streaming Converse Responses
pub struct EventStreamDecoder {
    buffer: Vec<u8>,
    model: String,
    stream_id: String,
    created: i64,
}

impl EventStreamDecoder {
    pub fn new(model: String) -> Self {
        Self {
            buffer: Vec::new(),
            model,
            stream_id: format!("chatcmpl-bedrock-{}", chrono::Utc::now().timestamp_millis()),
            created: chrono::Utc::now().timestamp(),
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.extend_from_slice(chunk);
        let mut sse_lines = Vec::new();

        while self.buffer.len() >= 12 {
            let total_len = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

            if total_len == 0 || total_len > 10 * 1024 * 1024 {
                // Safeguard against invalid frame length
                self.buffer.remove(0);
                continue;
            }

            if self.buffer.len() < total_len {
                break;
            }

            let header_len = u32::from_be_bytes([
                self.buffer[4],
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
            ]) as usize;

            if total_len < 12 + header_len + 4 {
                self.buffer.remove(0);
                continue;
            }

            let payload_offset = 12 + header_len;
            let payload_len = total_len - 12 - header_len - 4; // strip 4-byte message CRC
            let payload_slice = &self.buffer[payload_offset..payload_offset + payload_len];

            // Try to parse payload as JSON
            if let Ok(event_json) = serde_json::from_slice::<Value>(payload_slice) {
                if let Some(sse) = self.convert_bedrock_event(&event_json) {
                    sse_lines.push(sse);
                }
            }

            self.buffer.drain(0..total_len);
        }

        sse_lines
    }

    fn convert_bedrock_event(&self, event: &Value) -> Option<String> {
        // 1. Delta text chunk
        if let Some(delta) = event.get("contentBlockDelta") {
            if let Some(text) = delta["delta"]["text"].as_str() {
                let chunk = json!({
                    "id": self.stream_id,
                    "object": "chat.completion.chunk",
                    "created": self.created,
                    "model": self.model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "content": text
                            },
                            "finish_reason": null
                        }
                    ]
                });
                return Some(format!(
                    "data: {}\n\n",
                    serde_json::to_string(&chunk).unwrap_or_default()
                ));
            }
        }

        // 2. Message stop / finish reason
        if let Some(stop) = event.get("messageStop") {
            let stop_reason = stop["stopReason"].as_str().unwrap_or("end_turn");
            let finish_reason = match stop_reason {
                "end_turn" | "stop_sequence" => "stop",
                "max_tokens" => "length",
                "tool_use" => "tool_calls",
                _ => "stop",
            };
            let chunk = json!({
                "id": self.stream_id,
                "object": "chat.completion.chunk",
                "created": self.created,
                "model": self.model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": finish_reason
                    }
                ]
            });
            return Some(format!(
                "data: {}\n\n",
                serde_json::to_string(&chunk).unwrap_or_default()
            ));
        }

        // 3. Metadata with token usage
        if let Some(meta) = event.get("metadata") {
            if let Some(usage) = meta.get("usage") {
                let input_tokens = usage["inputTokens"].as_u64().unwrap_or(0);
                let output_tokens = usage["outputTokens"].as_u64().unwrap_or(0);
                let total_tokens = usage["totalTokens"]
                    .as_u64()
                    .unwrap_or(input_tokens + output_tokens);

                let chunk = json!({
                    "id": self.stream_id,
                    "object": "chat.completion.chunk",
                    "created": self.created,
                    "model": self.model,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": input_tokens,
                        "completion_tokens": output_tokens,
                        "total_tokens": total_tokens
                    }
                });
                return Some(format!(
                    "data: {}\n\n",
                    serde_json::to_string(&chunk).unwrap_or_default()
                ));
            }
        }

        None
    }
}


/// Sanitizes OpenAI-compatible chat completion requests before forwarding to providers.
/// For Google Gemini:
/// 1. Strips unsupported top-level fields (e.g. `reasoning_effort`, `strict`).
/// 2. Removes empty `tools` arrays and `tool_choice`.
/// 3. In multi-turn histories containing `tool_calls` in assistant messages, Google requires
///    a `thought_signature` in each tool call's `extra_content`. If missing (e.g. from standard OpenAI
///    clients or stripped responses), injects `skip_thought_signature_validator` so Gemini accepts the history.
fn clean_null_values_in_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            clean_null_values_in_map(map);
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                clean_null_values_in_value(item);
            }
        }
        _ => {}
    }
}

fn clean_null_values_in_map(map: &mut serde_json::Map<String, serde_json::Value>) {
    let mut keys_to_remove = Vec::new();
    for (k, v) in map.iter_mut() {
        if v.is_null() {
            if k == "content" {
                *v = serde_json::Value::String(String::new());
            } else {
                keys_to_remove.push(k.clone());
            }
        } else {
            clean_null_values_in_value(v);
        }
    }
    for k in keys_to_remove {
        map.remove(&k);
    }
}

pub fn sanitize_openai_request(val: &mut serde_json::Value, base_url: &str) {
    if let Some(obj) = val.as_object_mut() {
        if base_url.contains("googleapis.com") {
            // Remove unsupported parameters that cause 400 Bad Request on Gemini
            obj.remove("reasoning_effort");
            obj.remove("strict");
            obj.remove("logit_bias");
            obj.remove("logprobs");
            obj.remove("top_logprobs");
            obj.remove("user");
            obj.remove("intent");
            obj.remove("copilot_references");
            obj.remove("references");
            obj.remove("n");
            obj.remove("best_of");
            obj.remove("service_tier");

            // If empty tools list is provided, remove tools and tool_choice
            if let Some(tools) = obj.get("tools").and_then(|t| t.as_array()) {
                if tools.is_empty() {
                    obj.remove("tools");
                    obj.remove("tool_choice");
                }
            }

            // Google Gemini /v1beta/openai rejects null in JSON schema parameter defaults or message refusal
            clean_null_values_in_map(obj);

            // Fix thought_signature requirement for Gemini tool calls in conversation history
            if let Some(messages) = obj.get_mut("messages").and_then(|m| m.as_array_mut()) {
                for msg in messages {
                    if let Some(tool_calls) = msg.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
                        for tc in tool_calls {
                            if let Some(tc_obj) = tc.as_object_mut() {
                                let has_sig = tc_obj
                                    .get("extra_content")
                                    .and_then(|ec| ec.get("google"))
                                    .and_then(|g| g.get("thought_signature"))
                                    .is_some();
                                if !has_sig {
                                    tc_obj.insert(
                                        "extra_content".to_string(),
                                        json!({
                                            "google": {
                                                "thought_signature": "skip_thought_signature_validator"
                                            }
                                        }),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Sanitizes an SSE raw byte chunk, stripping vendor-specific extensions like Google's `extra_content`
/// that cause strict OpenAI client parsers (e.g. GitHub Copilot) to throw CAPIError: 400.
pub fn sanitize_sse_chunk(chunk: &[u8], canonical_model: &str) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(chunk) {
        if !text.contains("extra_content") {
            return chunk.to_vec();
        }
        let lines = text.split('\n');
        let mut out_lines = Vec::new();
        let mut any_changed = false;
        for line in lines {
            let trimmed = line.trim_start();
            if trimmed.starts_with("data:") {
                let data = trimmed[5..].trim();
                if !data.is_empty() && data != "[DONE]" {
                    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(data) {
                        let mut changed = false;
                        if !canonical_model.is_empty() {
                            if let Some(m) = val.get("model").and_then(|v| v.as_str()) {
                                if m != canonical_model {
                                    val["model"] = serde_json::Value::String(canonical_model.to_string());
                                    changed = true;
                                }
                            }
                        }
                        if let Some(choices) = val.get_mut("choices").and_then(|c| c.as_array_mut()) {
                            for choice in choices {
                                if let Some(delta) = choice.get_mut("delta").and_then(|d| d.as_object_mut()) {
                                    if delta.remove("extra_content").is_some() {
                                        changed = true;
                                    }
                                    if let Some(tool_calls) = delta.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
                                        for tc in tool_calls {
                                            if let Some(tc_obj) = tc.as_object_mut() {
                                                if tc_obj.remove("extra_content").is_some() {
                                                    changed = true;
                                                }
                                            }
                                        }
                                    }
                                }
                                if let Some(msg) = choice.get_mut("message").and_then(|m| m.as_object_mut()) {
                                    if msg.remove("extra_content").is_some() {
                                        changed = true;
                                    }
                                    if let Some(tool_calls) = msg.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
                                        for tc in tool_calls {
                                            if let Some(tc_obj) = tc.as_object_mut() {
                                                if tc_obj.remove("extra_content").is_some() {
                                                    changed = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if changed {
                            any_changed = true;
                            if let Ok(new_json) = serde_json::to_string(&val) {
                                out_lines.push(format!("data: {}", new_json));
                                continue;
                            }
                        }
                    }
                }
            }
            out_lines.push(line.to_string());
        }
        if any_changed {
            return out_lines.join("
").into_bytes();
        }
    }
    chunk.to_vec()
}

/// Sanitizes non-streaming JSON responses, stripping non-standard fields like `extra_content`.
pub fn sanitize_openai_response(val: &mut serde_json::Value) -> bool {
    let mut modified = false;
    if let Some(choices) = val.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices {
            if let Some(message) = choice.get_mut("message").and_then(|m| m.as_object_mut()) {
                if message.remove("extra_content").is_some() {
                    modified = true;
                }
                if let Some(tool_calls) = message.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
                    for tc in tool_calls {
                        if let Some(tc_obj) = tc.as_object_mut() {
                            if tc_obj.remove("extra_content").is_some() {
                                modified = true;
                            }
                        }
                    }
                }
            }
        }
    }
    modified
}


/// Normalizes upstream error payloads to standard OpenAI format `{"error": {"message": "...", "type": "...", "code": ...}}`.
/// Google Gemini sometimes returns non-standard JSON arrays like `[{"error": {"code": 503, "message": "..."}}]`
/// or malformed bodies which cause Copilot's CAPI parser to throw CAPIError: 400.
pub fn normalize_upstream_error_response(body_bytes: &[u8], status: hyper::StatusCode) -> Option<Vec<u8>> {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        // If it's an array with an error object inside: `[{"error": ...}]`
        if let Some(arr) = val.as_array() {
            if let Some(first) = arr.first() {
                if let Some(err_obj) = first.get("error") {
                    let msg = err_obj.get("message").and_then(|m| m.as_str()).unwrap_or("Upstream error");
                    let code = err_obj.get("code").and_then(|c| c.as_u64()).unwrap_or(status.as_u16() as u64);
                    let norm = serde_json::json!({
                        "error": {
                            "message": msg,
                            "type": "upstream_error",
                            "param": null,
                            "code": code
                        }
                    });
                    return serde_json::to_vec(&norm).ok();
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_openai_to_bedrock() {
        let openai = json!({
            "model": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello!"}
            ],
            "temperature": 0.7,
            "max_tokens": 1024
        });

        let (model, bedrock) = transform_openai_to_bedrock(&openai).unwrap();
        assert_eq!(model, "anthropic.claude-3-5-sonnet-20241022-v2:0");
        assert_eq!(bedrock["system"][0]["text"], "You are a helpful assistant.");
        assert_eq!(bedrock["messages"][0]["role"], "user");
        assert_eq!(bedrock["messages"][0]["content"][0]["text"], "Hello!");
        assert_eq!(bedrock["inferenceConfig"]["temperature"], 0.7);
        assert_eq!(bedrock["inferenceConfig"]["maxTokens"], 1024);
    }

    #[test]
    fn test_transform_bedrock_to_openai() {
        let bedrock = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Hello there! How can I help you today?"}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 15,
                "outputTokens": 10,
                "totalTokens": 25
            }
        });

        let openai = transform_bedrock_to_openai(&bedrock, "bedrock/claude").unwrap();
        assert_eq!(
            openai["choices"][0]["message"]["content"],
            "Hello there! How can I help you today?"
        );
        assert_eq!(openai["choices"][0]["finish_reason"], "stop");
        assert_eq!(openai["usage"]["prompt_tokens"], 15);
        assert_eq!(openai["usage"]["completion_tokens"], 10);
        assert_eq!(openai["usage"]["total_tokens"], 25);
    }

    #[test]
    fn test_resolve_bedrock_inference_profile_id() {
        assert_eq!(
            resolve_bedrock_inference_profile_id("amazon.nova-pro-v1:0", "eu-central-1"),
            "eu.amazon.nova-pro-v1:0"
        );
        assert_eq!(
            resolve_bedrock_inference_profile_id(
                "anthropic.claude-3-5-sonnet-20241022-v2:0",
                "us-east-1"
            ),
            "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
        );
        assert_eq!(
            resolve_bedrock_inference_profile_id("eu.amazon.nova-pro-v1:0", "eu-central-1"),
            "eu.amazon.nova-pro-v1:0"
        );
        assert_eq!(
            resolve_bedrock_inference_profile_id("anthropic.claude-opus-5", "eu-central-1"),
            "eu.anthropic.claude-opus-5"
        );
        assert_eq!(
            resolve_bedrock_inference_profile_id("cohere.embed-english-v3", "eu-central-1"),
            "cohere.embed-english-v3"
        );
    }

    #[test]
    fn test_sanitize_sse_chunk_removes_extra_content() {
        let chunk = b"data: {\"choices\":[{\"delta\":{\"extra_content\":{\"google\":{\"thought_signature\":\"xyz\"}},\"role\":\"assistant\"},\"index\":0}],\"created\":123,\"id\":\"1\",\"model\":\"gemini\",\"object\":\"chat.completion.chunk\"}\n\n";
        let cleaned = sanitize_sse_chunk(chunk, "gemini");
        let cleaned_str = String::from_utf8_lossy(&cleaned);
        assert!(!cleaned_str.contains("extra_content"));
        assert!(cleaned_str.contains("assistant"));
    }

    #[test]
    fn test_sanitize_openai_request_cleans_google_fields_and_injects_thought_signature() {
        let mut req = json!({
            "model": "gemini-3.7-flash",
            "messages": [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "type": "function",
                            "function": {"name": "test_fn", "arguments": "{}"}
                        }
                    ]
                }
            ],
            "reasoning_effort": "low",
            "strict": true,
            "tools": []
        });
        sanitize_openai_request(&mut req, "generativelanguage.googleapis.com/v1beta/openai");
        assert!(req.get("reasoning_effort").is_none());
        assert!(req.get("strict").is_none());
        assert!(req.get("tools").is_none());
        assert!(req.get("tool_choice").is_none());

        // Verify thought_signature was injected on the tool call
        let tc = &req["messages"][1]["tool_calls"][0];
        assert_eq!(
            tc["extra_content"]["google"]["thought_signature"].as_str().unwrap(),
            "skip_thought_signature_validator"
        );
    }
}
