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
}
