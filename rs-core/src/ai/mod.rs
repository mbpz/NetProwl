//! AI Layer module for Phase 4 intelligence features
//!
//! This module implements AI-powered analysis:
//! - AI-1: Banner semantic parsing
//! - AI-2: Attack chain reasoning
//! - AI-3: Natural language network diagnosis
//! - AI-4: Context-aware fix suggestions

pub mod banner_parse;
pub mod banner_parser; // DeepSeek AI banner parser
pub mod attack_chain;
pub mod diagnosis;
pub mod fix_suggest;

// Re-export commonly used types
pub use banner_parse::{
    BannerAnalysis,
    parse_banner,
};

pub use banner_parser::{
    BannerResult,
    parse_banner_with_ai,
};

pub use attack_chain::{
    AttackChain,
    AttackNode,
    AttackEdge,
    FixSuggestion as AttackChainFixSuggestion,
    build_attack_chain,
    detect_attack_chain,
};

pub use diagnosis::{
    DiagnosisReport,
    DiagnosisDevice,
    DiagnosisResult,
    CriticalIssue,
    MediumIssue,
    diagnose_network,
    diagnose_vulnerability,
};

pub use fix_suggest::{
    FixSuggestion,
    generate_fix_suggestion,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_parse_export() {
        let result = parse_banner("SSH-2.0-OpenSSH_7.4");
        assert!(result.software.is_some());
    }

    #[test]
    fn test_module_structure() {
        // Verify all modules compile correctly
        use crate::ai::*;
        let _ = banner_parse::parse_banner("test");
        let _ = attack_chain::build_attack_chain(vec![]);
        let _ = diagnosis::diagnose_network(vec![], vec![]);
        let _ = fix_suggest::generate_fix_suggestion(
            &crate::security::report::SecurityRisk {
                ip: "0.0.0.0".to_string(),
                port: None,
                risk_type: "test".to_string(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                cvss_score: None,
                evidence: std::collections::HashMap::new(),
                risk_level: crate::security::report::RiskLevel::Info,
            },
            None,
        );
    }
}
