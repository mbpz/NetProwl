/// CVE rule stored in SQLite database
pub struct CveRule {
    pub software: String,
    pub version_min: String,
    pub version_max: String,
    pub cve_id: String,
    pub cvss: f32,
    pub description: String,
}

/// CVE query result returned to callers
pub struct CveResult {
    pub cve_id: String,
    pub cvss: f32,
    pub description: String,
}

impl CveRule {
    pub fn new(
        software: String,
        version_min: String,
        version_max: String,
        cve_id: String,
        cvss: f32,
        description: String,
    ) -> Self {
        Self {
            software,
            version_min,
            version_max,
            cve_id,
            cvss,
            description,
        }
    }
}

impl CveResult {
    pub fn from_rule(rule: &CveRule) -> Self {
        Self {
            cve_id: rule.cve_id.clone(),
            cvss: rule.cvss,
            description: rule.description.clone(),
        }
    }
}