# Phase 2 Plan: DeepSeek AI Banner 语义解析

**Goal:** DeepSeek 语义解析模糊 Banner，输出结构化 JSON

---

## Task: AI Banner 语义解析

**Files:**
- Create: `rs-core/src/ai/banner_parser.rs`
- Create: `rs-core/src/ai/mod.rs`
- Modify: `rs-core/src/lib.rs`
- Modify: `netprowl-pc/src-tauri/src/lib.rs` (Tauri commands)
- Modify: `netprowl-pc/src/stores/pipelineStore.ts` (frontend config)

**Requirements:**
```rust
pub struct BannerResult {
    pub software: String,       // e.g., "OpenSSH"
    pub version: Option<String>, // e.g., "8.1"
    pub os: Option<String>,     // e.g., "Windows"
    pub confidence: f32,        // 0.0-1.0
}

pub async fn parse_banner_with_ai(banner: &str, api_key: &str) -> Result<BannerResult, String>
// Call DeepSeek API with banner, return structured result
// Prompt: see below
```

**DeepSeek prompt:**
```
System:
你是一个网络安全专家，专门分析网络服务的 Banner 信息。
请将以下 Banner 解析为结构化 JSON，字段包括：
- software: 软件名称（如 OpenSSH、Nginx、Apache）
- version: 版本号（如能提取）
- os: 运行系统（如能推断）
- confidence: 置信度 0-1

只输出 JSON，不要任何其他文字。

User:
Banner: "{banner_text}"
```

**Frontend config UI:**
- `SettingsModal.tsx` 或 `ScanPage.tsx` - API key 输入框
- Store: `useConfigStore` - 保存 API key 到 localStorage
- 调用时从 store 读取 API key，传给 Rust backend

**Backend Tauri command:**
```rust
#[tauri::command]
async fn parse_banner_ai(banner: String, api_key: String) -> Result<BannerResult, String> {
    crate::ai::banner_parser::parse_banner_with_ai(&banner, &api_key).await
}
```

**Error handling:**
- API key empty → Err("API key required")
- Network error → Err("DeepSeek API error: {e}")
- Parse error → Err("Invalid JSON response")
- Timeout 10s

- [ ] **Step 1: Write rs-core/src/ai/banner_parser.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BannerResult {
    pub software: String,
    pub version: Option<String>,
    pub os: Option<String>,
    #[serde(default)]
    pub confidence: f32,
}

const PROMPT_TEMPLATE: &str = r#"You are a cybersecurity expert analyzing network service banners.
Parse the following banner into structured JSON with fields:
- software: software name (e.g., OpenSSH, Nginx, Apache)
- version: version number if extractable
- os: operating system if inferable
- confidence: confidence score 0-1

Output ONLY JSON, no other text.

Banner: "{}"#;

pub async fn parse_banner_with_ai(banner: &str, api_key: &str) -> Result<BannerResult, String> {
    if api_key.is_empty() {
        return Err("API key required".into());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let prompt = PROMPT_TEMPLATE.replace("{}", banner);

    let body = serde_json::json!({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    });

    let resp = client.post("https://api.deepseek.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("DeepSeek API error: {}", e))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| format!("Parse error: {}", e))?;

    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("Invalid response")?;

    // Extract JSON from response (may have markdown code block)
    let json_str = content.trim().trim_start_matches("```json").trim().trim_start_matches("```").trim();

    serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {}", e))
}
```

- [ ] **Step 2: Write rs-core/src/ai/mod.rs**

```rust
pub mod banner_parser;
pub use banner_parser::{BannerResult, parse_banner_with_ai};
```

- [ ] **Step 3: Update rs-core/src/lib.rs**

```rust
#[cfg(not(target_arch = "wasm32"))]
pub mod ai;
```

- [ ] **Step 4: Add Tauri command in netprowl-pc/src-tauri/src/lib.rs**

```rust
#[tauri::command]
async fn parse_banner_ai(banner: String, api_key: String) -> Result<BannerResult, String> {
    rs_core::ai::banner_parser::parse_banner_with_ai(&banner, &api_key).await
}
```

Add to invoke_handler.

- [ ] **Step 5: Frontend API key config**

```typescript
// src/stores/configStore.ts
interface ConfigState {
  deepseekApiKey: string;
  setApiKey: (key: string) => void;
}

export const useConfigStore = create<ConfigState>((set) => ({
  deepseekApiKey: localStorage.getItem('deepseek_api_key') || '',
  setApiKey: (key) => {
    localStorage.setItem('deepseek_api_key', key);
    set({ deepseekApiKey: key });
  },
}));
```

- [ ] **Step 6: Commit**

---

## Self-Review

1. **Spec coverage**: DeepSeek Banner 解析 ✅
2. **Placeholder scan**: no TBD/TODO
3. **Type consistency**: BannerResult struct, parse_banner_with_ai function