//! Tool discovery for external security tools

use which::which;
use std::process::Command;

/// Represents an external security tool
pub struct Tool {
    pub name: &'static str,
    pub cmd: &'static str,
    pub version_flag: &'static str,
}

impl Tool {
    /// Detect if the tool is installed
    pub fn detect(&self) -> bool {
        which(self.cmd).is_ok()
    }

    /// Get the version of the tool by running it with the version flag
    pub fn version(&self) -> Option<String> {
        let output = Command::new(self.cmd)
            .arg(self.version_flag)
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let version = stdout.lines().next().unwrap_or("").trim().to_string();
            if version.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Some(stderr.trim().to_string())
            } else {
                Some(version)
            }
        } else {
            None
        }
    }
}

/// Status result for a tool
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolStatus {
    pub name: String,
    pub installed: bool,
    pub version: Option<String>,
    pub install_hint: String,  // Platform-appropriate install command
}

/// Platform-specific install command for a tool
fn install_hint(name: &str) -> String {
    if cfg!(target_os = "macos") {
        match name {
            "masscan" => "brew install masscan".into(),
            "nmap" => "brew install nmap".into(),
            "rustscan" => "cargo install rustscan".into(),
            "nuclei" => "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest".into(),
            "ffuf" => "go install github.com/ffuf/ffuf/v2@latest".into(),
            "feroxbuster" => "cargo install feroxbuster".into(),
            _ => format!("Install {} manually", name),
        }
    } else {
        match name {
            "masscan" => "sudo apt install masscan".into(),
            "nmap" => "sudo apt install nmap".into(),
            "rustscan" => "cargo install rustscan".into(),
            "nuclei" => "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest".into(),
            "ffuf" => "go install github.com/ffuf/ffuf/v2@latest".into(),
            "feroxbuster" => "cargo install feroxbuster".into(),
            _ => format!("Install {} manually", name),
        }
    }
}

/// Check all known tools and return their status
pub fn check_all_tools() -> Vec<ToolStatus> {
    TOOLS
        .iter()
        .map(|tool| {
            let installed = tool.detect();
            let version = if installed {
                tool.version()
            } else {
                None
            };
            ToolStatus {
                name: tool.name.to_string(),
                installed,
                version,
                install_hint: install_hint(tool.name),
            }
        })
        .collect()
}

/// List of known external security tools
pub static TOOLS: &[Tool] = &[
    Tool {
        name: "masscan",
        cmd: "masscan",
        version_flag: "--version",
    },
    Tool {
        name: "nmap",
        cmd: "nmap",
        version_flag: "--version",
    },
    Tool {
        name: "rustscan",
        cmd: "rustscan",
        version_flag: "--version",
    },
    Tool {
        name: "nuclei",
        cmd: "nuclei",
        version_flag: "-version",
    },
    Tool {
        name: "ffuf",
        cmd: "ffuf",
        version_flag: "-V",
    },
    Tool {
        name: "feroxbuster",
        cmd: "feroxbuster",
        version_flag: "--version",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_detect() {
        let tool = Tool {
            name: "masscan",
            cmd: "masscan",
            version_flag: "--version",
        };
        let _ = tool.detect();
    }

    #[test]
    fn test_check_all_tools() {
        let results = check_all_tools();
        assert_eq!(results.len(), TOOLS.len());
        for status in &results {
            println!("{}: installed={}", status.name, status.installed);
        }
    }
}
