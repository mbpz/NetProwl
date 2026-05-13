//! DeepSeek AI-powered Banner Semantic Parser
//!
//! Uses DeepSeek API to parse ambiguous banners into structured JSON.

use serde::{Deserialize, Serialize};

/// Banner parse result from DeepSeek AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerResult {
    /// Software name (e.g., "OpenSSH", "nginx", "Apache")
    pub software: String,
    /// Version number if extractable (e.g., "7.4", "1.20.1")
    pub version: Option<String>,
    /// Operating system if inferable (e.g., "Linux", "Windows")
    pub os: Option<String>,
    /// Confidence score 0.0-1.0
    pub confidence: f32,
}

/// Parse a banner using DeepSeek AI semantic analysis
///
/// # Arguments
/// * `banner` - The raw banner string to parse
/// * `api_key` - DeepSeek API key
///
/// # Returns
/// * `Ok(BannerResult)` - Structured banner analysis
/// * `Err(String)` - Error message if parsing fails
pub async fn parse_banner_with_ai(banner: &str, api_key: &str) -> Result<BannerResult, String> {
    let client = reqwest::Client::new();

    let prompt = format!(
        r#"You are a cybersecurity expert analyzing network service banners.
Parse the following banner into structured JSON with fields:
- software: software name
- version: version number if extractable
- os: operating system if inferable
- confidence: confidence score 0-1

Output ONLY JSON, no other text.

Banner: "{}""#,
        banner.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let request_body = serde_json::json!({
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1
    });

    let response = client
        .post("https://api.deepseek.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("DeepSeek API error ({}): {}", status, body));
    }

    let api_response: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let content = api_response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("Invalid API response: missing content")?;

    // Extract JSON from response (handle potential markdown code blocks)
    let json_str = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let result: BannerResult = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse JSON: {} - Raw: {}", e, json_str))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_result_serialization() {
        let result = BannerResult {
            software: "OpenSSH".to_string(),
            version: Some("7.4".to_string()),
            os: Some("Linux".to_string()),
            confidence: 0.95,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("OpenSSH"));
        assert!(json.contains("7.4"));
    }
}