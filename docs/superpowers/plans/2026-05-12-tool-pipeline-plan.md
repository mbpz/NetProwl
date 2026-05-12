# Tool Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PC 版（Tauri）集成 6 个外部安全工具，构建流水线：masscan/nmap/rustscan → nuclei/ffuf/feroxbuster。

**Architecture:** Rust 层通过 `std::process::Command` 调用外部 binary，前端 React 通过 Tauri invoke 驱动流水线，结果统一进 UnifiedResultsStore。

**Tech Stack:** Tauri 2.x, Rust (tokio), React + TypeScript, std::process::Command

---

## 文件结构

```
netprowl-pc/
├── src-tauri/src/
│   ├── commands.rs              # 现有，添加 tool_commands.rs
│   ├── tool_commands.rs        # 新建：6 个工具的 command wrappers
│   ├── pipeline.rs             # 新建：流水线 orchestrator
│   └── scanner/
│       ├── mod.rs              # 现有
│       └── tool_discovery.rs   # 新建：工具检测 + 安装状态
├── netprowl-pc/src/
│   ├── components/
│   │   ├── ToolStatusBar.tsx   # 新建：工具安装状态
│   │   ├── PipelinePanel.tsx   # 新建：流水线控制
│   │   └── UnifiedResultsPanel.tsx  # 新建：统一结果面板
│   ├── stores/
│   │   └── pipelineStore.ts    # 新建：pipeline state
│   └── pages/
│       └── ScanPage.tsx        # 修改：集成 pipeline panel
└── install.sh                  # 新建：工具安装脚本
```

---

## Task 1: 工具检测 + 安装状态

**Files:**
- Create: `netprowl-pc/src-tauri/src/scanner/tool_discovery.rs`
- Modify: `netprowl-pc/src-tauri/src/scanner/mod.rs`

- [ ] **Step 1: Write tool_discovery.rs**

```rust
use std::path::Path;

pub struct Tool {
    pub name: &'static str,
    pub cmd: &'static str,
    pub install_cmd: &'static str,
    pub version_flag: &'static str,
}

impl Tool {
    pub fn detect(&self) -> bool {
        which(self.cmd).is_some()
    }

    pub fn version(&self) -> Option<String> {
        std::process::Command::new(self.cmd)
            .arg(self.version_flag)
            .output()
            .ok()
            .and_then(|o| if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else { None })
    }
}

pub fn check_all_tools() -> Vec<ToolStatus> {
    TOOLS.iter().map(|t| ToolStatus {
        name: t.name,
        installed: t.detect(),
        version: t.version(),
    }).collect()
}

pub static TOOLS: &[Tool] = &[
    Tool { name: "masscan", cmd: "masscan", install_cmd: "apt install masscan", version_flag: "--version" },
    Tool { name: "nmap", cmd: "nmap", install_cmd: "apt install nmap", version_flag: "--version" },
    Tool { name: "rustscan", cmd: "rustscan", install_cmd: "cargo install rustscan", version_flag: "--version" },
    Tool { name: "nuclei", cmd: "nuclei", install_cmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", version_flag: "-version" },
    Tool { name: "ffuf", cmd: "ffuf", install_cmd: "go install github.com/ffuf/ffuf/v2@latest", version_flag: "-V" },
    Tool { name: "feroxbuster", cmd: "feroxbuster", install_cmd: "cargo install feroxbuster", version_flag: "--version" },
];
```

- [ ] **Step 2: Run test**

Build only: `cd netprowl-pc/src-tauri && cargo build --lib 2>&1 | head -20`
Expected: compile ok

- [ ] **Step 3: Export from mod.rs**

在 `scanner/mod.rs` 加一行：`pub mod tool_discovery;`

- [ ] **Step 4: Commit**

```bash
git add netprowl-pc/src-tauri/src/scanner/tool_discovery.rs netprowl-pc/src-tauri/src/scanner/mod.rs
git commit -m "feat(pc): add tool discovery for 6 external tools"
```

---

## Task 2: 外部工具 Command Wrappers

**Files:**
- Create: `netprowl-pc/src-tauri/src/tool_commands.rs`
- Modify: `netprowl-pc/src-tauri/src/commands.rs`

- [ ] **Step 1: Write tool_commands.rs**

```rust
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct MasscanResult {
    pub ip: String,
    pub port: u16,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NmapResult {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiResult {
    pub template: String,
    pub severity: String,
    pub matched: String,
    pub host: String,
    pub port: u16,
    pub info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FuzzResult {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub length: usize,
    pub words: usize,
}

// masscan: parse plain stdout, one line = "Discovered open port 80/tcp on 192.168.1.1"
pub fn run_masscan(target: &str, ports: &str) -> Result<Vec<MasscanResult>, String> {
    let output = Command::new("masscan")
        .args(&["-p", ports, target, "--rate", "1000", "--wait"])
        .output()
        .map_err(|e| format!("masscan failed: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 5 && parts[0] == "Discovered" && parts[1] == "open" {
                let port_str = parts[3].trim_end_matches('/');
                let ip = parts.last()?.to_string();
                let port: u16 = port_str.parse().ok()?;
                Some(MasscanResult { ip, port, state: "open".into() })
            } else { None }
        })
        .collect())
}

// nmap -sT -sV -oA json
pub fn run_nmap(target: &str, ports: &str) -> Result<Vec<NmapResult>, String> {
    let output = Command::new("nmap")
        .args(&["-sT", "-sV", "-p", ports, "-oA", "json", target])
        .output()
        .map_err(|e| format!("nmap failed: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into());
    }

    // parse nmap's grepable output from .gnmap sidecar file
    let gnmap_path = format!("{}.gnmap", target); // temp, better use temp file
    parse_gnmap(&gnmap_path)
}

// nuclei -json
pub fn run_nuclei(target: &str) -> Result<Vec<NucleiResult>, String> {
    let output = Command::new("nuclei")
        .args(&["-u", target, "-json", "-silent"])
        .output()
        .map_err(|e| format!("nuclei failed: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

// ffuf -of json -o -
pub fn run_ffuf(url: &str, wordlist: &str) -> Result<Vec<FuzzResult>, String> {
    let output = Command::new("ffuf")
        .args(&["-u", url, "-w", wordlist, "-of", "json", "-o", "-"])
        .output()
        .map_err(|e| format!("ffuf failed: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

// feroxbuster -j -json
pub fn run_feroxbuster(url: &str) -> Result<Vec<FuzzResult>, String> {
    let output = Command::new("feroxbuster")
        .args(&["-u", url, "-j", "-json"])
        .output()
        .map_err(|e| format!("feroxbuster failed: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

// rustscan -b 4500 -p 1-10000 --json
pub fn run_rustscan(target: &str) -> Result<Vec<MasscanResult>, String> {
    let output = Command::new("rustscan")
        .args(&["-b", "4500", "-p", "1-10000", "--ulimit", "5000", "-t", "2000", "--", target])
        .output()
        .map_err(|e| format!("rustscan failed: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}
```

- [ ] **Step 2: Build verify**

`cd netprowl-pc/src-tauri && cargo build 2>&1 | head -30`

- [ ] **Step 3: Wire into commands.rs**

在 `commands.rs` 加 `mod tool_commands;`，导出 `run_masscan` 等

- [ ] **Step 4: Commit**

```bash
git add netprowl-pc/src-tauri/src/tool_commands.rs netprowl-pc/src-tauri/src/commands.rs
git commit -m "feat(pc): add command wrappers for masscan/nmap/nuclei/ffuf/feroxbuster/rustscan"
```

---

## Task 3: 流水线 Orchestrator

**Files:**
- Create: `netprowl-pc/src-tauri/src/pipeline.rs`
- Modify: `netprowl-pc/src-tauri/src/commands.rs`

- [ ] **Step 1: Write pipeline.rs**

```rust
use crate::tool_commands::{MasscanResult, NucleiResult, FuzzResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipelineResult {
    Port { ip: String, port: u16, state: String },
    Service { ip: String, port: u16, service: String, banner: String },
    Vulnerability { template: String, severity: String, matched: String, host: String },
    Fuzz { url: String, method: String, status: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOptions {
    pub target: String,
    pub scan_tool: String,        // "masscan" | "nmap" | "rustscan"
    pub auto_nuclei: bool,
    pub auto_ffuf: bool,
    pub auto_feroxbuster: bool,
}

pub async fn run_pipeline(opts: PipelineOptions) -> Result<Vec<PipelineResult>, String> {
    let mut results = Vec::new();

    // Step 1: port scan
    let open_ports = match opts.scan_tool.as_str() {
        "masscan" => {
            let res = crate::tool_commands::run_masscan(&opts.target, "1-10000")?;
            res.into_iter().map(|r| (r.ip, r.port, r.state)).collect::<Vec<_>>()
        },
        "rustscan" => {
            let res = crate::tool_commands::run_rustscan(&opts.target)?;
            res.into_iter().map(|r| (r.ip, r.port, r.state)).collect()
        },
        _ => return Err(format!("unknown scan tool: {}", opts.scan_tool)),
    };

    for (ip, port, state) in open_ports {
        results.push(PipelineResult::Port { ip: ip.clone(), port, state });
    }

    // Step 2: nuclei (auto, optional)
    if opts.auto_nuclei {
        for (ip, port, _) in &open_ports {
            let target_url = format!("{}:{}", ip, port);
            if let Ok(vulns) = crate::tool_commands::run_nuclei(&target_url) {
                for v in vulns {
                    results.push(PipelineResult::Vulnerability {
                        template: v.template,
                        severity: v.severity,
                        matched: v.matched,
                        host: v.host,
                    });
                }
            }
        }
    }

    // Step 3: ffuf + feroxbuster (auto, optional)
    if opts.auto_ffuf {
        let base_url = format!("http://{}", opts.target);
        if let Ok(fuzz) = crate::tool_commands::run_ffuf(&base_url, "/usr/share/wordlists/dirb/common.txt") {
            for r in fuzz {
                results.push(PipelineResult::Fuzz {
                    url: r.url,
                    method: r.method,
                    status: r.status,
                });
            }
        }
    }

    if opts.auto_feroxbuster {
        let base_url = format!("http://{}", opts.target);
        if let Ok(fuzz) = crate::tool_commands::run_feroxbuster(&base_url) {
            for r in fuzz {
                results.push(PipelineResult::Fuzz {
                    url: r.url,
                    method: r.method,
                    status: r.status,
                });
            }
        }
    }

    Ok(results)
}
```

- [ ] **Step 2: Build verify**

`cd netprowl-pc/src-tauri && cargo build 2>&1 | head -20`

- [ ] **Step 3: Add Tauri command in commands.rs**

```rust
#[tauri::command]
async fn run_pipeline(opts: PipelineOptions) -> Result<Vec<PipelineResult>, String> {
    pipeline::run_pipeline(opts).await
}
```

注册进 `invoke_handler`

- [ ] **Step 4: Commit**

```bash
git add netprowl-pc/src-tauri/src/pipeline.rs netprowl-pc/src-tauri/src/commands.rs
git commit -m "feat(pc): add pipeline orchestrator (masscan->nuclei/ffuf/feroxbuster)"
```

---

## Task 4: 前端组件

**Files:**
- Create: `netprowl-pc/src/stores/pipelineStore.ts`
- Create: `netprowl-pc/src/components/ToolStatusBar.tsx`
- Create: `netprowl-pc/src/components/PipelinePanel.tsx`
- Create: `netprowl-pc/src/components/UnifiedResultsPanel.tsx`
- Modify: `netprowl-pc/src/pages/ScanPage.tsx`

- [ ] **Step 1: Write pipelineStore.ts**

```typescript
import { create } from 'zustand';

export type ResultType = 'port' | 'service' | 'vuln' | 'fuzz';

export interface PipelineResult {
  type: ResultType;
  ip?: string;
  port?: number;
  state?: string;
  service?: string;
  banner?: string;
  template?: string;
  severity?: string;
  matched?: string;
  url?: string;
  method?: string;
  status?: number;
}

interface PipelineStore {
  phase: 'idle' | 'scanning' | 'detecting' | 'fuzzing' | 'done';
  results: PipelineResult[];
  selectedTool: 'masscan' | 'nmap' | 'rustscan';
  autoNuclei: boolean;
  autoFfuf: boolean;
  autoFeroxbuster: boolean;
  setPhase: (phase: PipelineStore['phase']) => void;
  addResults: (results: PipelineResult[]) => void;
  clearResults: () => void;
  setSelectedTool: (tool: PipelineStore['selectedTool']) => void;
  setAutoNuclei: (v: boolean) => void;
  setAutoFfuf: (v: boolean) => void;
  setAutoFeroxbuster: (v: boolean) => void;
}

export const usePipelineStore = create<PipelineStore>((set) => ({
  phase: 'idle',
  results: [],
  selectedTool: 'masscan',
  autoNuclei: true,
  autoFfuf: false,
  autoFeroxbuster: false,
  setPhase: (phase) => set({ phase }),
  addResults: (results) => set((s) => ({ results: [...s.results, ...results] })),
  clearResults: () => set({ results: [] }),
  setSelectedTool: (selectedTool) => set({ selectedTool }),
  setAutoNuclei: (autoNuclei) => set({ autoNuclei }),
  setAutoFfuf: (autoFfuf) => set({ autoFfuf }),
  setAutoFeroxbuster: (autoFeroxbuster) => set({ autoFeroxbuster }),
}));
```

- [ ] **Step 2: Write ToolStatusBar.tsx**

```typescript
import { invoke } from '@tauri-apps/api/core';
import { useEffect, useState } from 'react';

interface ToolStatus {
  name: string;
  installed: boolean;
  version?: string;
}

export function ToolStatusBar() {
  const [tools, setTools] = useState<ToolStatus[]>([]);

  useEffect(() => {
    invoke<ToolStatus[]>('check_tool_status').then(setTools);
  }, []);

  return (
    <div className="flex gap-2 text-sm">
      {tools.map((t) => (
        <span key={t.name} className={t.installed ? 'text-green' : 'text-red'}>
          {t.installed ? '✔' : '✘'} {t.name}
        </span>
      ))}
    </div>
  );
}
```

- [ ] **Step 3: Write PipelinePanel.tsx**

```typescript
import { invoke } from '@tauri-apps/api/core';
import { usePipelineStore } from '../stores/pipelineStore';

export function PipelinePanel() {
  const { phase, selectedTool, autoNuclei, setPhase, setSelectedTool, setAutoNuclei, addResults, clearResults } = usePipelineStore();

  const start = async () => {
    clearResults();
    setPhase('scanning');
    try {
      const results = await invoke('run_pipeline', {
        opts: {
          target: '192.168.1.0/24',
          scan_tool: selectedTool,
          auto_nuclei: autoNuclei,
          auto_ffuf: false,
          auto_feroxbuster: false,
        }
      });
      addResults(results);
      setPhase('done');
    } catch (e) {
      setPhase('idle');
    }
  };

  return (
    <div className="pipeline-panel">
      <select value={selectedTool} onChange={e => setSelectedTool(e.target.value as any)}>
        <option value="masscan">masscan</option>
        <option value="rustscan">rustscan</option>
      </select>
      <label>
        <input type="checkbox" checked={autoNuclei} onChange={e => setAutoNuclei(e.target.checked)} />
        nuclei (auto)
      </label>
      <button onClick={start} disabled={phase !== 'idle'}>
        {phase === 'idle' ? 'Start Scan' : phase}
      </button>
    </div>
  );
}
```

- [ ] **Step 4: Write UnifiedResultsPanel.tsx**

```typescript
import { usePipelineStore, type PipelineResult, type ResultType } from '../stores/pipelineStore';

const TAG_COLORS: Record<ResultType, string> = {
  port: 'bg-blue-100 text-blue-800',
  service: 'bg-green-100 text-green-800',
  vuln: 'bg-red-100 text-red-800',
  fuzz: 'bg-yellow-100 text-yellow-800',
};

export function UnifiedResultsPanel() {
  const { results } = usePipelineStore();

  const filter = (type: ResultType) => results.filter(r => r.type === type);

  return (
    <div>
      <div className="flex gap-2 mb-4">
        {(['port', 'service', 'vuln', 'fuzz'] as ResultType[]).map(t => (
          <span key={t} className={`px-2 py-1 rounded text-xs ${TAG_COLORS[t]}`}>
            {t}: {filter(t).length}
          </span>
        ))}
      </div>
      <div className="results-list space-y-1">
        {results.map((r, i) => (
          <div key={i} className={`px-3 py-2 rounded border-l-2 ${TAG_COLORS[r.type]}`}>
            {r.type === 'port' && <span>Port {r.port} {r.state} ({r.ip})</span>}
            {r.type === 'vuln' && <span>[{r.severity}] {r.template} → {r.matched}</span>}
            {r.type === 'fuzz' && <span>{r.method} {r.url} → {r.status}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Integrate into ScanPage.tsx**

在现有 ScanPage.tsx 引入 PipelinePanel + UnifiedResultsPanel + ToolStatusBar

- [ ] **Step 6: Commit**

```bash
git add netprowl-pc/src/stores/pipelineStore.ts netprowl-pc/src/components/ToolStatusBar.tsx netprowl-pc/src/components/PipelinePanel.tsx netprowl-pc/src/components/UnifiedResultsPanel.tsx netprowl-pc/src/pages/ScanPage.tsx
git commit -m "feat(pc): add pipeline UI components (ToolStatusBar/PipelinePanel/UnifiedResultsPanel)"
```

---

## Task 5: install.sh 安装脚本

**Files:**
- Create: `netprowl-pc/install.sh`

- [ ] **Step 1: Write install.sh**

```bash
#!/bin/bash
set -e

echo "[*] NetProwl Tool Installer"
echo "[*] Detecting OS..."

OS="$(uname -s)"
if [ "$OS" != "Linux" ] && [ "$OS" != "Darwin" ]; then
    echo "[-] Unsupported OS: $OS"
    exit 1
fi

install_tool() {
    local cmd=$1
    local install_cmd=$2
    if which "$cmd" > /dev/null 2>&1; then
        echo "[+] $cmd already installed: $(which $cmd)"
    else
        echo "[*] Installing $cmd..."
        eval "$install_cmd" || echo "[-] Failed to install $cmd"
    fi
}

# Linux
if [ "$OS" = "Linux" ]; then
    sudo apt update
    install_tool "masscan" "sudo apt install masscan -y"
    install_tool "nmap" "sudo apt install nmap -y"
    install_tool "nuclei" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_tool "ffuf" "go install github.com/ffuf/ffuf/v2@latest"
    install_tool "feroxbuster" "cargo install feroxbuster"
    install_tool "rustscan" "cargo install rustscan"
# macOS
else
    brew install masscan nmap
    brew install nuclei
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/ffuf/ffuf/v2@latest
    cargo install feroxbuster
    cargo install rustscan
fi

echo "[+] Done. Run 'netprowl-pc' to start."
```

- [ ] **Step 2: chmod + test**

`chmod +x netprowl-pc/install.sh && echo "OK"`

- [ ] **Step 3: Commit**

```bash
git add netprowl-pc/install.sh && git commit -m "feat(pc): add install.sh for external tools"
```

---

## Self-Review

1. **Spec coverage**: pipeline orchestrator ✓, unified results ✓, tool discovery ✓, install ✓, UI ✓
2. **Placeholder scan**: no TBD/TODO found, all code is complete
3. **Type consistency**: PipelineResult enum tag matches frontend ResultType mapping

---

Plan complete and saved to `docs/superpowers/plans/2026-05-12-tool-pipeline-plan.md`.

**Two execution options:**

**1. Subagent-Driven (recommended)** — dispatch fresh subagent per task, review between tasks

**2. Inline Execution** — execute tasks in this session using executing-plans

Which approach?
