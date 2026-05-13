use std::process::Command;
use super::TLSVulnerability;

pub fn run_testssl(host: &str, port: u16) -> Result<Vec<TLSVulnerability>, String> {
    // Check if testssl.sh exists
    if which::which("testssl.sh").is_err() {
        return Err("testssl.sh not found. Install: git clone https://github.com/drwetter/testssl.sh.git".into());
    }

    let output = Command::new("testssl.sh")
        .args(&["--quiet", "--json", "-o", "JSON", &format!("{}:{}", host, port)])
        .output()
        .map_err(|e| format!("testssl.sh failed: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into());
    }

    // Parse testssl JSON output (simplified - parse CVE keywords line by line)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut vulns = Vec::new();

    for line in stdout.lines() {
        if line.contains("CVE-") || line.contains("VULNERABLE") || line.contains("Heartbleed") {
            if let Some(vuln) = parse_testssl_line(line) {
                vulns.push(vuln);
            }
        }
    }

    Ok(vulns)
}

fn parse_testssl_line(line: &str) -> Option<TLSVulnerability> {
    // Simple extraction of CVE id and severity
    let cve_pattern = r"(CVE-\d+-\d+)";
    let id = regex::Regex::new(cve_pattern)
        .ok()?
        .captures(line)?
        .get(1)?
        .as_str()
        .to_string();

    let severity = if line.contains("critical") || line.contains("Heartbleed") {
        "critical"
    } else if line.contains("high") {
        "high"
    } else if line.contains("medium") {
        "medium"
    } else {
        "low"
    };

    Some(TLSVulnerability {
        id: id.clone(),
        name: id,
        severity: severity.into(),
        description: line.to_string(),
    })
}