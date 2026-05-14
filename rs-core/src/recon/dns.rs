use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::ToSocketAddrs;

#[cfg(not(target_arch = "wasm32"))]
use trust_dns_resolver::TokioAsyncResolver;
#[cfg(not(target_arch = "wasm32"))]
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// DNS record types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
   Txt,
    Ns,
}

/// DNS record value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsValue {
    pub value: String,
    pub ttl: Option<u32>,
}

/// DNS reconnaissance result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecon {
    pub domain: String,
    pub records: HashMap<DnsRecordType, Vec<DnsValue>>,
    pub subdomains: Vec<String>,
    pub cloud_provider: Option<String>,
    pub cdn: Option<String>,
}

/// Subdomain enumeration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub records: Vec<DNSRecord>,
}

/// DNS record for subdomain results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSRecord {
    pub rtype: String,
    pub value: String,
}

/// Cloud provider identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Aliyun,
    Tencent,
    Gcp,
    Azure,
    Unknown,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "AWS",
            CloudProvider::Aliyun => "Aliyun",
            CloudProvider::Tencent => "Tencent Cloud",
            CloudProvider::Gcp => "GCP",
            CloudProvider::Azure => "Azure",
            CloudProvider::Unknown => "Unknown",
        }
    }
}

/// CDN provider identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdnProvider {
    Cloudflare,
    Aliyun,
    Tencent,
    Akamai,
    Fastly,
    Unknown,
}

impl CdnProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            CdnProvider::Cloudflare => "Cloudflare",
            CdnProvider::Aliyun => "Aliyun CDN",
            CdnProvider::Tencent => "Tencent CDN",
            CdnProvider::Akamai => "Akamai",
            CdnProvider::Fastly => "Fastly",
            CdnProvider::Unknown => "Unknown",
        }
    }
}


/// Resolve domain using system DNS resolver (async)
pub async fn resolve_domain_async(domain: &str) -> Result<HashMap<DnsRecordType, Vec<DnsValue>>, String> {
    let mut records = HashMap::new();

    // Query A record (sync using std library)
    if let Ok(ips) = resolve_a(domain) {
        records.insert(DnsRecordType::A, ips);
    }

    // Query AAAA record (sync using std library)
    if let Ok(ips) = resolve_aaaa(domain) {
        records.insert(DnsRecordType::Aaaa, ips);
    }

    // Query CNAME record
    if let Ok(cnames) = resolve_cname(domain).await {
        records.insert(DnsRecordType::Cname, cnames);
    }

    // Query MX record
    if let Ok(mx) = resolve_mx(domain).await {
        records.insert(DnsRecordType::Mx, mx);
    }

    // Query TXT record
    if let Ok(txt) = resolve_txt(domain).await {
        records.insert(DnsRecordType::Txt, txt);
    }

    // Query NS record
    if let Ok(ns) = resolve_ns(domain).await {
        records.insert(DnsRecordType::Ns, ns);
    }

    Ok(records)
}

/// Resolve domain using system DNS resolver (sync wrapper)
#[allow(dead_code)]
pub fn resolve_domain(domain: &str) -> Result<HashMap<DnsRecordType, Vec<DnsValue>>, String> {
    tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?
        .block_on(resolve_domain_async(domain))
}

/// Query A record using standard library
fn resolve_a(domain: &str) -> Result<Vec<DnsValue>, String> {
    let socket_addrs: Vec<std::net::SocketAddr> = (domain, 0)
        .to_socket_addrs()
        .map_err(|e| format!("A record lookup failed: {}", e))?
        .collect();

    let values: Vec<DnsValue> = socket_addrs.iter()
        .filter(|addr| addr.is_ipv4())
        .map(|addr| DnsValue {
            value: addr.ip().to_string(),
            ttl: None,
        })
        .collect();

    Ok(values)
}

/// Query AAAA record using standard library
fn resolve_aaaa(domain: &str) -> Result<Vec<DnsValue>, String> {
    let socket_addrs: Vec<std::net::SocketAddr> = (domain, 0)
        .to_socket_addrs()
        .map_err(|e| format!("AAAA record lookup failed: {}", e))?
        .collect();

    let values: Vec<DnsValue> = socket_addrs.iter()
        .filter(|addr| addr.is_ipv6())
        .map(|addr| DnsValue {
            value: addr.ip().to_string(),
            ttl: None,
        })
        .collect();

    Ok(values)
}

/// Query CNAME record using trust-dns-resolver
#[allow(dead_code)]
pub async fn resolve_cname(domain: &str) -> Result<Vec<DnsValue>, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let name: trust_dns_resolver::Name = domain.parse()
            .map_err(|e| format!("Invalid domain name '{}': {}", domain, e))?;

        match resolver.lookup(name, trust_dns_resolver::proto::rr::RecordType::CNAME).await {
            Ok(lookup) => {
                let values: Vec<DnsValue> = lookup.iter()
                    .map(|rdata: &trust_dns_resolver::proto::rr::RData| DnsValue {
                        value: rdata.to_string(),
                        ttl: None,
                    })
                    .collect();
                Ok(values)
            }
            Err(e) => Err(format!("CNAME lookup failed: {}", e)),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Err("CNAME resolution not supported in WASM".to_string())
    }
}

/// Query MX record using trust-dns-resolver
#[allow(dead_code)]
pub async fn resolve_mx(domain: &str) -> Result<Vec<DnsValue>, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let name: trust_dns_resolver::Name = domain.parse()
            .map_err(|e| format!("Invalid domain name '{}': {}", domain, e))?;

        match resolver.lookup(name, trust_dns_resolver::proto::rr::RecordType::MX).await {
            Ok(lookup) => {
                let values: Vec<DnsValue> = lookup.iter()
                    .map(|rdata: &trust_dns_resolver::proto::rr::RData| DnsValue {
                        value: rdata.to_string(),
                        ttl: None,
                    })
                    .collect();
                Ok(values)
            }
            Err(e) => Err(format!("MX lookup failed: {}", e)),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Err("MX resolution not supported in WASM".to_string())
    }
}

/// Query TXT record using trust-dns-resolver
#[allow(dead_code)]
pub async fn resolve_txt(domain: &str) -> Result<Vec<DnsValue>, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let name: trust_dns_resolver::Name = domain.parse()
            .map_err(|e| format!("Invalid domain name '{}': {}", domain, e))?;

        match resolver.lookup(name, trust_dns_resolver::proto::rr::RecordType::TXT).await {
            Ok(lookup) => {
                let values: Vec<DnsValue> = lookup.iter()
                    .map(|rdata: &trust_dns_resolver::proto::rr::RData| DnsValue {
                        value: rdata.to_string(),
                        ttl: None,
                    })
                    .collect();
                Ok(values)
            }
            Err(e) => Err(format!("TXT lookup failed: {}", e)),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Err("TXT resolution not supported in WASM".to_string())
    }
}

/// Query NS record using trust-dns-resolver
#[allow(dead_code)]
pub async fn resolve_ns(domain: &str) -> Result<Vec<DnsValue>, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let name: trust_dns_resolver::Name = domain.parse()
            .map_err(|e| format!("Invalid domain name '{}': {}", domain, e))?;

        match resolver.lookup(name, trust_dns_resolver::proto::rr::RecordType::NS).await {
            Ok(lookup) => {
                let values: Vec<DnsValue> = lookup.iter()
                    .map(|rdata: &trust_dns_resolver::proto::rr::RData| DnsValue {
                        value: rdata.to_string(),
                        ttl: None,
                    })
                    .collect();
                Ok(values)
            }
            Err(e) => Err(format!("NS lookup failed: {}", e)),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Err("NS resolution not supported in WASM".to_string())
    }
}

/// Query Certificate Transparency (crtsh) for subdomains
pub fn query_crtsh(domain: &str) -> Result<Vec<String>, String> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

    let body = reqwest::blocking::get(&url)
        .map_err(|e| format!("crtsh request failed: {}", e))?
        .text()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Parse JSON array of cert entries
    let entries: Vec<CrtShEntry> = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse crtsh response: {}", e))?;

    let mut subdomains: Vec<String> = entries.iter()
        .filter_map(|e| e.name_value.clone())
        .filter(|name| name.contains(domain))
        .map(|name| {
            // Handle multiple names separated by newlines
            name.split('\n')
                .filter(|s| s.contains(domain) && !s.starts_with('*'))
                .map(|s| s.to_lowercase())
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect();

    subdomains.sort();
    subdomains.dedup();

    Ok(subdomains)
}

#[derive(Debug, Clone, Deserialize)]
struct CrtShEntry {
    #[serde(rename = "name_value")]
    name_value: Option<String>,
}

/// Passive DNS: resolve domain to historical IPs (using crtsh as proxy)
pub fn passive_dns(domain: &str) -> Result<Vec<String>, String> {
    // crtsh provides historical cert data which includes IPs
    let subdomains = query_crtsh(domain)?;
    Ok(subdomains)
}

/// Identify cloud provider from IP address
pub fn identify_cloud_provider(ip: &str) -> Option<CloudProvider> {
    // Simple check using known IP patterns
    let ip_lower = ip.to_lowercase();

    // Check for AWS patterns
    if ip_lower.starts_with("52.") || ip_lower.starts_with("54.") ||
       ip_lower.starts_with("18.") || ip_lower.starts_with("3.") {
        return Some(CloudProvider::Aws);
    }

    // Check for Aliyun patterns
    if ip_lower.starts_with("39.") || ip_lower.starts_with("42.") ||
       ip_lower.starts_with("47.") || ip_lower.starts_with("49.") ||
       ip_lower.starts_with("106.") || ip_lower.starts_with("119.") ||
       ip_lower.starts_with("120.") || ip_lower.starts_with("121.") {
        return Some(CloudProvider::Aliyun);
    }

    // Check for Tencent patterns
    if ip_lower.starts_with("1.") || ip_lower.starts_with("14.") ||
       ip_lower.starts_with("27.") || ip_lower.starts_with("36.") ||
       ip_lower.starts_with("58.") || ip_lower.starts_with("59.") ||
       ip_lower.starts_with("101.") || ip_lower.starts_with("103.") ||
       ip_lower.starts_with("110.") || ip_lower.starts_with("112.") {
        return Some(CloudProvider::Tencent);
    }

    // Check for GCP patterns
    if ip_lower.starts_with("34.") || ip_lower.starts_with("35.") ||
       ip_lower.starts_with("23.") || ip_lower.starts_with("104.") {
        return Some(CloudProvider::Gcp);
    }

    None
}

/// Detect CDN provider from HTTP headers
pub fn detect_cdn(headers: &HashMap<String, String>) -> Option<CdnProvider> {
    // Check for Cloudflare
    if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
        return Some(CdnProvider::Cloudflare);
    }

    // Check for Aliyun
    if headers.get("x-powered-by").map(|v| v.contains("Alibaba")).unwrap_or(false) ||
       headers.get("server").map(|v| v.contains("Tengine")).unwrap_or(false) {
        return Some(CdnProvider::Aliyun);
    }

    // Check for Tencent
    if headers.get("server").map(|v| v.contains("CDN")).unwrap_or(false) ||
       headers.contains_key("tencent-cdn") {
        return Some(CdnProvider::Tencent);
    }

    // Check for Akamai
    if headers.get("server").map(|v| v.contains("Akamai")).unwrap_or(false) {
        return Some(CdnProvider::Akamai);
    }

    // Check for Fastly
    if headers.get("server").map(|v| v.contains("Fastly")).unwrap_or(false) ||
       headers.contains_key("fastly-debug-digest") {
        return Some(CdnProvider::Fastly);
    }

    None
}

/// Perform complete DNS reconnaissance
pub fn dns_recon(domain: &str) -> DnsRecon {
    let records = resolve_domain(domain).unwrap_or_default();
    let subdomains = query_crtsh(domain).unwrap_or_default();

    // Identify cloud provider from A records
    let mut cloud_provider = None;
    if let Some(ips) = records.get(&DnsRecordType::A) {
        for ip_val in ips {
            if let Some(provider) = identify_cloud_provider(&ip_val.value) {
                cloud_provider = Some(provider.as_str().to_string());
                break;
            }
        }
    }

    DnsRecon {
        domain: domain.to_string(),
        records,
        subdomains,
        cloud_provider,
        cdn: None,
    }
}

/// Enumerate subdomains using crt.sh Certificate Transparency
pub async fn enumerate_subdomains(domain: &str) -> Result<SubdomainResult, String> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client failed: {}", e))?;

    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| format!("crt.sh request failed: {}", e))?;

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let entries: Vec<CrtShEntry> = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse crtsh response: {}", e))?;

    let subdomains: Vec<String> = entries.iter()
        .filter_map(|e| e.name_value.clone())
        .filter(|name| name.contains(domain))
        .map(|name| {
            name.split('\n')
                .filter(|s| s.contains(domain) && !s.starts_with('*'))
                .map(|s| s.to_lowercase())
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect();

    let mut subdomains = subdomains;
    subdomains.sort();
    subdomains.dedup();

    Ok(SubdomainResult {
        domain: domain.to_string(),
        subdomains,
        records: Vec::new(),
    })
}

/// Resolve DNS for a specific record type using system resolver
pub async fn resolve_dns(domain: &str, rtype: &str) -> Result<Vec<String>, String> {
    let rtype_lower = rtype.to_lowercase();
    let values: Vec<String> = match rtype_lower.as_str() {
        "a" => {
            let socket_addrs: Vec<std::net::SocketAddr> = (domain, 0)
                .to_socket_addrs()
                .map_err(|e| format!("A record lookup failed: {}", e))?
                .collect();
            socket_addrs.iter()
                .filter(|addr| addr.is_ipv4())
                .map(|addr| addr.ip().to_string())
                .collect()
        }
        "aaaa" => {
            let socket_addrs: Vec<std::net::SocketAddr> = (domain, 0)
                .to_socket_addrs()
                .map_err(|e| format!("AAAA record lookup failed: {}", e))?
                .collect();
            socket_addrs.iter()
                .filter(|addr| addr.is_ipv6())
                .map(|addr| addr.ip().to_string())
                .collect()
        }
        _ => return Err(format!("Unsupported record type: {}", rtype)),
    };
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_identification() {
        assert_eq!(identify_cloud_provider("52.86.120.100"), Some(CloudProvider::Aws));
        assert_eq!(identify_cloud_provider("39.105.60.100"), Some(CloudProvider::Aliyun));
        assert_eq!(identify_cloud_provider("1.1.1.1"), Some(CloudProvider::Tencent));
        assert_eq!(identify_cloud_provider("34.117.59.100"), Some(CloudProvider::Gcp));
    }

    #[test]
    fn test_cdn_detection_from_headers() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "abc123".to_string());
        assert_eq!(detect_cdn(&headers), Some(CdnProvider::Cloudflare));

        let mut headers2 = HashMap::new();
        headers2.insert("server".to_string(), "Tengine".to_string());
        assert_eq!(detect_cdn(&headers2), Some(CdnProvider::Aliyun));
    }

    #[test]
    fn test_dns_recon_returns_valid_structure() {
        // Note: This test may fail without network access
        let recon = dns_recon("example.com");
        assert_eq!(recon.domain, "example.com");
        // records and subdomains depend on actual DNS resolution
    }
}
