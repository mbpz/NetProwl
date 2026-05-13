//! Tool discovery for external security tools

use which::which;
use std::process::Command;

/// Represents an external security tool
pub struct Tool {
    pub name: &'static str,
    pub cmd: &'static str,
    pub install_cmd: &'static str,
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
            }
        })
        .collect()
}

/// List of known external security tools
pub static TOOLS: &[Tool] = &[
    Tool {
        name: "masscan",
        cmd: "masscan",
        install_cmd: "apt install masscan",
        version_flag: "--version",
    },
    Tool {
        name: "nmap",
        cmd: "nmap",
        install_cmd: "apt install nmap",
        version_flag: "--version",
    },
    Tool {
        name: "rustscan",
        cmd: "rustscan",
        install_cmd: "cargo install rustscan",
        version_flag: "--version",
    },
    Tool {
        name: "nuclei",
        cmd: "nuclei",
        install_cmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        version_flag: "-version",
    },
    Tool {
        name: "ffuf",
        cmd: "ffuf",
        install_cmd: "go install github.com/ffuf/ffuf/v2@latest",
        version_flag: "-V",
    },
    Tool {
        name: "feroxbuster",
        cmd: "feroxbuster",
        install_cmd: "cargo install feroxbuster",
        version_flag: "--version",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_detect() {
        // Test with a tool that should exist (nmap or masscan likely)
        let tool = Tool {
            name: "masscan",
            cmd: "masscan",
            install_cmd: "apt install masscan",
            version_flag: "--version",
        };
        // Just verify detect doesn't panic
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
