use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result structure for public reconnaissance APIs (Shodan/FOFA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
    pub vulns: Vec<String>,
    pub location: Option<String>,
}

/// Public asset discovered from public network reconnaissance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicAsset {
    pub ip: String,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
    pub cves: Vec<String>,
    pub asn: Option<String>,
    pub geo: Option<String>,
    pub last_updated: Option<String>,
}

/// Shodan response structure (API reference)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanResponse {
    pub ip: String,
    pub ports: Vec<u16>,
    pub transport: String,
    pub tags: Vec<String>,
    #[serde(rename = "ip_str")]
    pub ip_str: String,
    pub data: Vec<ShodanData>,
    pub asn: Option<String>,
    pub isp: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub last_update: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanData {
    pub port: u16,
    pub transport: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FofaResponse {
    pub mode: String,
    pub query: Vec<Vec<String>>,
    pub page: u32,
    pub size: u32,
    pub results: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoomEyeResponse {
    pub total: u32,
    pub page: u32,
    pub matches: Vec<ZoomEyeMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoomEyeMatch {
    pub ip: String,
    pub port: Vec<u16>,
    pub protocol: Vec<String>,
    pub service: Option<String>,
    pub country: Option<String>,
    #[serde(rename = "geoinfo")]
    pub geo_info: Option<ZoomEyeGeo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoomEyeGeo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
}

/// Query Shodan API for IP information
pub fn query_shodan_ip(api_key: &str, ip: &str) -> Result<PublicAsset, String> {
    if api_key.is_empty() || api_key == "MOCK_KEY" {
        return Ok(mock_shodan_ip(ip));
    }

    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
    let body = reqwest::blocking::get(&url)
        .map_err(|e| format!("Shodan request failed: {}", e))?
        .text()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let resp: ShodanResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse Shodan response: {}", e))?;

    Ok(PublicAsset {
        ip: resp.ip_str,
        ports: resp.ports,
        services: resp.data.iter().filter_map(|d| d.product.clone()).collect(),
        cves: extract_cves_from_shodan(&resp.data),
        asn: resp.isp.or(resp.asn),
        geo: resp.country_name.map(|c| {
            resp.city.map(|city| format!("{}, {}", c, city)).unwrap_or_else(|| c)
        }),
        last_updated: resp.last_update,
    })
}

/// Query FOFA API for domain information
pub fn query_fofa_domain(api_key: &str, email: &str, domain: &str) -> Result<Vec<(String, String)>, String> {
    if api_key.is_empty() || api_key == "MOCK_KEY" {
        return Ok(mock_fofa_domain(domain));
    }

    let query = format!("domain=\"{}\"", domain);
    let url = format!(
        "https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&fields=host,ip",
        email,
        api_key,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &query)
    );

    let body = reqwest::blocking::get(&url)
        .map_err(|e| format!("FOFA request failed: {}", e))?
        .text()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let resp: FofaResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse FOFA response: {}", e))?;

    Ok(resp.results.into_iter().map(|r| {
        let ip = r.get(1).cloned().unwrap_or_default();
        let host = r.first().cloned().unwrap_or_default();
        (host, ip)
    }).collect())
}

/// Query ZoomEye API for IP/domain information
pub fn query_zoomeye_ip(api_key: &str, ip: &str) -> Result<PublicAsset, String> {
    if api_key.is_empty() || api_key == "MOCK_KEY" {
        return Ok(mock_zoomeye_ip(ip));
    }

    let url = format!("https://api.zoomeye.org/ip-info?ip={}&devicetype=2& plen=20&skey={}", ip, api_key);

    let body = reqwest::blocking::get(&url)
        .map_err(|e| format!("ZoomEye request failed: {}", e))?
        .text()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let resp: ZoomEyeResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse ZoomEye response: {}", e))?;

    let matches: Vec<_> = resp.matches.iter().collect();
    let first = matches.first();

    let ports: Vec<u16> = first.map(|m| m.port.clone()).unwrap_or_default();
    let services: Vec<String> = first.and_then(|m| m.service.clone()).map(|s| vec![s]).unwrap_or_default();
    let asn = first.and_then(|m| m.geo_info.as_ref()).and_then(|g| g.asn.clone());
    let geo = first.and_then(|m| m.geo_info.as_ref()).and_then(|g| {
        g.country.as_ref().map(|c| {
            g.city.as_ref().map(|city| format!("{}, {}", c, city)).unwrap_or_else(|| c.clone())
        })
    });

    Ok(PublicAsset {
        ip: ip.to_string(),
        ports,
        services,
        cves: Vec::new(),
        asn,
        geo,
        last_updated: None,
    })
}

/// Async Shodan lookup - GET https://api.shodan.io/shodan/host/{ip}?key={api_key}
pub async fn shodan_lookup(ip: &str, api_key: &str) -> Result<ReconResult, String> {
    if api_key.is_empty() || api_key == "MOCK_KEY" {
        return Ok(shodan_mock_result(ip));
    }

    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
    let client = reqwest::Client::new();
    let body = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Shodan request failed: {}", e))?
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let resp: ShodanResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse Shodan response: {}", e))?;

    let services: Vec<String> = resp.data.iter().filter_map(|d| d.product.clone()).collect();
    let vulns = extract_cves_from_shodan(&resp.data);
    let location = resp.country_name.map(|c| {
        resp.city.map(|city| format!("{}, {}", c, city)).unwrap_or_else(|| c)
    });

    Ok(ReconResult {
        ip: resp.ip_str,
        ports: resp.ports,
        services,
        vulns,
        location,
    })
}

/// Async FOFA lookup - if api_key provided
pub async fn fofa_lookup(ip: &str, api_key: &str) -> Result<ReconResult, String> {
    if api_key.is_empty() || api_key == "MOCK_KEY" {
        return Ok(fofa_mock_result(ip));
    }

    // FOFA uses email + api_key for authentication
    // Query format: ip="{ip}"
    let query = format!("ip=\"{}\"", ip);
    let qbase64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &query);

    // FOFA API requires email parameter - use a placeholder if not provided
    let email = "user@example.com";
    let url = format!(
        "https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&fields=host,ip,port,protocol",
        email,
        api_key,
        qbase64
    );

    let client = reqwest::Client::new();
    let body = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("FOFA request failed: {}", e))?
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let resp: FofaResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse FOFA response: {}", e))?;

    let mut ports: Vec<u16> = Vec::new();
    let mut services: Vec<String> = Vec::new();

    for result in resp.results {
        // FOFA returns: [host, ip, port, protocol, ...]
        if result.len() >= 3 {
            if let Some(port_str) = result.get(2) {
                if let Ok(port) = port_str.parse::<u16>() {
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                }
            }
            if let Some(service) = result.get(3) {
                if !service.is_empty() && !services.contains(service) {
                    services.push(service.clone());
                }
            }
        }
    }

    ports.sort_unstable();

    Ok(ReconResult {
        ip: ip.to_string(),
        ports,
        services,
        vulns: Vec::new(),
        location: None,
    })
}

fn shodan_mock_result(ip: &str) -> ReconResult {
    ReconResult {
        ip: ip.to_string(),
        ports: vec![22, 80, 443, 3306, 8080],
        services: vec!["SSH".to_string(), "HTTP".to_string(), "HTTPS".to_string(), "MySQL".to_string(), "HTTP-Proxy".to_string()],
        vulns: vec!["CVE-2022-1234".to_string(), "CVE-2021-43297".to_string()],
        location: Some("United States, California".to_string()),
    }
}

fn fofa_mock_result(ip: &str) -> ReconResult {
    ReconResult {
        ip: ip.to_string(),
        ports: vec![80, 443, 8080],
        services: vec!["HTTP".to_string(), "HTTPS".to_string()],
        vulns: Vec::new(),
        location: None,
    }
}

/// Aggregate data from all three sources, deduplicate
pub fn aggregate_public_assets(assets: Vec<PublicAsset>) -> PublicAsset {
    let mut all_ports: Vec<u16> = Vec::new();
    let mut all_services: Vec<String> = Vec::new();
    let mut all_cves: Vec<String> = Vec::new();
    let mut asn: Option<String> = None;
    let mut geo: Option<String> = None;
    let mut last_updated: Option<String> = None;
    let mut ip = String::new();

    for asset in &assets {
        if ip.is_empty() {
            ip = asset.ip.clone();
        }
        for port in &asset.ports {
            if !all_ports.contains(port) {
                all_ports.push(*port);
            }
        }
        for svc in &asset.services {
            if !all_services.contains(svc) {
                all_services.push(svc.clone());
            }
        }
        for cve in &asset.cves {
            if !all_cves.contains(cve) {
                all_cves.push(cve.clone());
            }
        }
        if asn.is_none() {
            asn = asset.asn.clone();
        }
        if geo.is_none() {
            geo = asset.geo.clone();
        }
        if last_updated.is_none() {
            last_updated = asset.last_updated.clone();
        }
    }

    all_ports.sort_unstable();

    PublicAsset {
        ip,
        ports: all_ports,
        services: all_services,
        cves: all_cves,
        asn,
        geo,
        last_updated,
    }
}

// =============================================================================
// Mock data for testing without API keys
// =============================================================================

fn mock_shodan_ip(ip: &str) -> PublicAsset {
    PublicAsset {
        ip: ip.to_string(),
        ports: vec![22, 80, 443, 3306, 8080],
        services: vec!["SSH".to_string(), "HTTP".to_string(), "HTTPS".to_string(), "MySQL".to_string(), "HTTP-Proxy".to_string()],
        cves: vec!["CVE-2022-1234".to_string(), "CVE-2021-43297".to_string()],
        asn: Some("AS15169 Google LLC".to_string()),
        geo: Some("United States, California".to_string()),
        last_updated: Some("2024-01-15".to_string()),
    }
}

fn mock_fofa_domain(domain: &str) -> Vec<(String, String)> {
    vec![
        (format!("www.{}", domain), "8.8.8.8".to_string()),
        (format!("api.{}", domain), "8.8.4.4".to_string()),
        (format!("cdn.{}", domain), "1.1.1.1".to_string()),
    ]
}

fn mock_zoomeye_ip(ip: &str) -> PublicAsset {
    PublicAsset {
        ip: ip.to_string(),
        ports: vec![80, 443, 22],
        services: vec!["HTTP".to_string(), "HTTPS".to_string(), "SSH".to_string()],
        cves: Vec::new(),
        asn: Some("AS13335 Cloudflare".to_string()),
        geo: Some("United States".to_string()),
        last_updated: Some("2024-02-20".to_string()),
    }
}

fn extract_cves_from_shodan(data: &[ShodanData]) -> Vec<String> {
    let mut cves = Vec::new();
    for item in data {
        if let Some(d) = &item.data {
            // Extract CVE IDs from Shodan data field using regex
            let re = regex::Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap();
            for cap in re.find_iter(d) {
                let cve = cap.as_str().to_string();
                if !cves.contains(&cve) {
                    cves.push(cve);
                }
            }
        }
    }
    cves
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_shodan_returns_valid_asset() {
        let asset = mock_shodan_ip("8.8.8.8");
        assert_eq!(asset.ip, "8.8.8.8");
        assert!(!asset.ports.is_empty());
        assert!(!asset.services.is_empty());
    }

    #[test]
    fn test_aggregate_deduplicates_ports() {
        let assets = vec![
            PublicAsset {
                ip: "1.1.1.1".to_string(),
                ports: vec![80, 443],
                services: vec!["HTTP".to_string()],
                cves: vec!["CVE-2022-1".to_string()],
                asn: Some("AS13335".to_string()),
                geo: Some("US".to_string()),
                last_updated: Some("2024-01-01".to_string()),
            },
            PublicAsset {
                ip: "1.1.1.1".to_string(),
                ports: vec![80, 22],
                services: vec!["SSH".to_string()],
                cves: vec!["CVE-2022-2".to_string()],
                asn: Some("AS13335".to_string()),
                geo: Some("US".to_string()),
                last_updated: Some("2024-01-02".to_string()),
            },
        ];
        let agg = aggregate_public_assets(assets);
        assert_eq!(agg.ports.len(), 3); // 80, 443, 22
        assert_eq!(agg.cves.len(), 2);   // both CVEs
    }

    #[test]
    fn test_query_shodan_with_mock_key() {
        let result = query_shodan_ip("MOCK_KEY", "8.8.8.8");
        assert!(result.is_ok());
        let asset = result.unwrap();
        assert_eq!(asset.ip, "8.8.8.8");
    }

    #[test]
    fn test_query_fofa_with_mock_key() {
        let result = query_fofa_domain("MOCK_KEY", "test@test.com", "example.com");
        assert!(result.is_ok());
        let items = result.unwrap();
        assert!(!items.is_empty());
    }
}
