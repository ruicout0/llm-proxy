use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn derive_signing_key(
    secret_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

pub struct SigV4Signer<'a> {
    pub service: &'a str,
    pub region: &'a str,
    pub credentials: &'a AwsCredentials,
}

impl<'a> SigV4Signer<'a> {
    pub fn new(service: &'a str, region: &'a str, credentials: &'a AwsCredentials) -> Self {
        Self {
            service,
            region,
            credentials,
        }
    }

    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &mut HeaderMap,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Result<()> {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        headers.insert(
            HeaderName::from_static("x-amz-date"),
            HeaderValue::from_str(&amz_date)?,
        );

        let payload_hash = sha256_hex(body);
        headers.insert(
            HeaderName::from_static("x-amz-content-sha256"),
            HeaderValue::from_str(&payload_hash)?,
        );

        if let Some(token) = &self.credentials.session_token {
            headers.insert(
                HeaderName::from_static("x-amz-security-token"),
                HeaderValue::from_str(token)?,
            );
        }

        // Canonical headers
        let mut canonical_headers_map: BTreeMap<String, String> = BTreeMap::new();
        for (name, val) in headers.iter() {
            let key = name.as_str().to_ascii_lowercase();
            if let Ok(v_str) = val.to_str() {
                canonical_headers_map.insert(key, v_str.trim().to_string());
            }
        }

        let mut canonical_headers_str = String::new();
        let mut signed_headers_vec = Vec::new();

        for (k, v) in &canonical_headers_map {
            let _ = writeln!(canonical_headers_str, "{}:{}", k, v);
            signed_headers_vec.push(k.as_str());
        }
        let signed_headers = signed_headers_vec.join(";");

        // Canonical Query String
        let canonical_query_str = match query {
            Some(q) if !q.is_empty() => {
                let mut pairs: Vec<(&str, &str)> = q
                    .split('&')
                    .filter(|s| !s.is_empty())
                    .map(|pair| {
                        let mut it = pair.splitn(2, '=');
                        let k = it.next().unwrap_or("");
                        let v = it.next().unwrap_or("");
                        (k, v)
                    })
                    .collect();
                pairs.sort();
                pairs
                    .into_iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&")
            }
            _ => String::new(),
        };

        // Canonical Request: AWS SigV4 requires URI path segments to be URI-encoded (e.g. ":" -> "%3A").
        let canonical_uri = if path.is_empty() {
            "/".to_string()
        } else {
            path.split("/")
                .map(|segment| urlencoding::encode(segment).to_string())
                .collect::<Vec<_>>()
                .join("/")
        };
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_query_str,
            canonical_headers_str,
            signed_headers,
            payload_hash
        );

        let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

        // Credential Scope & String to Sign
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, self.service
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date, credential_scope, canonical_request_hash
        );

        // Calculate signature
        let signing_key = derive_signing_key(
            &self.credentials.secret_access_key,
            &date_stamp,
            self.region,
            self.service,
        );
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.credentials.access_key_id, credential_scope, signed_headers, signature
        );

        headers.insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_str(&auth_header).context("Invalid authorization header value")?,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_derive_signing_key() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "bedrock",
        );
        assert_eq!(
            hex::encode(key),
            "f10f576edcc40606d8b4c80eca7b570fb7696569acb17da7fa4b2ed569a308f1"
        );
    }

    #[test]
    fn test_sign_request_structure() {
        let creds = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };

        let signer = SigV4Signer::new("bedrock", "us-east-1", &creds);
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "bedrock-runtime.us-east-1.amazonaws.com".parse().unwrap(),
        );
        headers.insert("content-type", "application/json".parse().unwrap());

        let dt = Utc.with_ymd_and_hms(2023, 5, 24, 0, 0, 0).unwrap();
        let body = b"{\"text\":\"hello\"}";

        signer
            .sign_request(
                "POST",
                "/model/claude/converse",
                None,
                &mut headers,
                body,
                dt,
            )
            .unwrap();

        assert!(headers.contains_key("x-amz-date"));
        assert_eq!(
            headers.get("x-amz-date").unwrap().to_str().unwrap(),
            "20230524T000000Z"
        );
        assert!(headers.contains_key("x-amz-content-sha256"));
        assert!(headers.contains_key(hyper::header::AUTHORIZATION));

        let auth = headers
            .get(hyper::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20230524/us-east-1/bedrock/aws4_request"
        ));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
    }
}
