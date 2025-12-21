use crate::config::{ResponseAction, ResponseRule};
use regex::Regex;
use std::sync::RwLock;
use tracing::debug;

/// Rule engine for matching requests and determining responses
pub struct RuleEngine {
    rules: RwLock<Vec<CompiledRule>>,
}

struct CompiledRule {
    rule: ResponseRule,
    pattern: Regex,
}

impl RuleEngine {
    pub fn new(rules: Vec<ResponseRule>) -> Self {
        let compiled = rules
            .into_iter()
            .filter_map(|rule| {
                Regex::new(&rule.match_pattern)
                    .ok()
                    .map(|pattern| CompiledRule { rule, pattern })
            })
            .collect();

        Self {
            rules: RwLock::new(compiled),
        }
    }

    pub fn add_rule(&self, rule: ResponseRule) {
        if let Ok(pattern) = Regex::new(&rule.match_pattern) {
            let mut rules = self.rules.write().unwrap();
            rules.push(CompiledRule { rule, pattern });
            rules.sort_by(|a, b| b.rule.priority.cmp(&a.rule.priority));
        }
    }

    /// Match a request against rules
    pub fn match_request(
        &self,
        protocol: &str,
        fields: &MatchFields,
    ) -> Option<(ResponseAction, String, Vec<String>)> {
        let rules = self.rules.read().unwrap();

        for compiled in rules.iter() {
            if compiled.rule.protocol != protocol && compiled.rule.protocol != "*" {
                continue;
            }

            let value = match compiled.rule.match_field.as_str() {
                "domain" => fields.domain.as_deref(),
                "uri" => fields.uri.as_deref(),
                "host" => fields.host.as_deref(),
                "user_agent" => fields.user_agent.as_deref(),
                "body" => fields.body.as_deref(),
                "any" | _ => {
                    // Try all fields
                    let all = [
                        fields.domain.as_deref(),
                        fields.uri.as_deref(),
                        fields.host.as_deref(),
                        fields.user_agent.as_deref(),
                    ];
                    all.iter().find_map(|&v| v).or(Some(""))
                }
            };

            if let Some(v) = value {
                if compiled.pattern.is_match(v) {
                    debug!(
                        "Rule {} matched: {} =~ {}",
                        compiled.rule.id, v, compiled.rule.match_pattern
                    );
                    return Some((
                        compiled.rule.action.clone(),
                        compiled.rule.id.clone(),
                        compiled.rule.tags.clone(),
                    ));
                }
            }
        }

        None
    }
}

/// Fields available for rule matching
#[derive(Default)]
pub struct MatchFields {
    pub domain: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub body: Option<String>,
    pub method: Option<String>,
}

impl MatchFields {
    pub fn dns(domain: &str) -> Self {
        Self {
            domain: Some(domain.to_string()),
            ..Default::default()
        }
    }

    pub fn http(method: &str, uri: &str, host: Option<&str>, user_agent: Option<&str>) -> Self {
        Self {
            method: Some(method.to_string()),
            uri: Some(uri.to_string()),
            host: host.map(String::from),
            user_agent: user_agent.map(String::from),
            ..Default::default()
        }
    }
}
