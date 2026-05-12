// TODO: implement service registry

use regex::Regex;

pub struct ServiceRule {
    pub pattern: Regex,
    pub service_name: &'static str,
}

pub fn match_service(_banner: &str) -> Option<String> {
    None
}

pub fn guess_service(_port: u16) -> Option<String> {
    None
}