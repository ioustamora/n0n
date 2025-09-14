use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Attribute-Based Access Control (ABAC) system
#[derive(Clone)]
pub struct AttributeBasedAccessControl {
    config: ABACConfig,
    policies: Arc<RwLock<Vec<ABACPolicy>>>,
    attribute_store: Arc<RwLock<HashMap<String, AttributeSet>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACConfig {
    pub policy_combining_algorithm: PolicyCombiningAlgorithm,
    pub default_decision: AccessDecision,
    pub enable_obligations: bool,
    pub enable_advice: bool,
    pub attribute_caching: bool,
    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCombiningAlgorithm {
    DenyOverrides,
    PermitOverrides,
    FirstApplicable,
    OnlyOneApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessDecision {
    Permit,
    Deny,
    NotApplicable,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub target: PolicyTarget,
    pub rule: PolicyRule,
    pub effect: PolicyEffect,
    pub obligations: Vec<Obligation>,
    pub advice: Vec<Advice>,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTarget {
    pub subjects: Vec<AttributeMatch>,
    pub resources: Vec<AttributeMatch>,
    pub actions: Vec<AttributeMatch>,
    pub environments: Vec<AttributeMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_type: RuleType,
    pub condition: Option<ConditionExpression>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyEffect {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMatch {
    pub attribute_id: String,
    pub match_function: MatchFunction,
    pub attribute_value: AttributeValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchFunction {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    StringEquals,
    StringContains,
    StringStartsWith,
    StringEndsWith,
    RegexMatch,
    DateTimeInRange,
    IpAddressInRange,
    AnyOf,
    AllOf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttributeValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    DateTime(DateTime<Utc>),
    StringList(Vec<String>),
    IntegerList(Vec<i64>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionExpression {
    pub expression_type: ExpressionType,
    pub operands: Vec<ConditionOperand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpressionType {
    And,
    Or,
    Not,
    Function(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperand {
    AttributeDesignator {
        category: AttributeCategory,
        attribute_id: String,
        data_type: AttributeDataType,
    },
    AttributeValue(AttributeValue),
    Expression(Box<ConditionExpression>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttributeCategory {
    Subject,
    Resource,
    Action,
    Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttributeDataType {
    String,
    Boolean,
    Integer,
    Double,
    Time,
    Date,
    DateTime,
    DayTimeDuration,
    YearMonthDuration,
    AnyURI,
    HexBinary,
    Base64Binary,
    Rfc822Name,
    X500Name,
    IpAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    pub id: String,
    pub fulfillment_on: FulfillmentOn,
    pub attribute_assignments: Vec<AttributeAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advice {
    pub id: String,
    pub attribute_assignments: Vec<AttributeAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FulfillmentOn {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeAssignment {
    pub attribute_id: String,
    pub value: AttributeValue,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub subject_attributes: AttributeSet,
    pub resource_attributes: AttributeSet,
    pub action_attributes: AttributeSet,
    pub environment_attributes: AttributeSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSet {
    pub attributes: HashMap<String, Vec<Attribute>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub attribute_id: String,
    pub value: AttributeValue,
    pub issuer: Option<String>,
    pub issue_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessResponse {
    pub decision: AccessDecision,
    pub obligations: Vec<Obligation>,
    pub advice: Vec<Advice>,
    pub policy_identifiers: Vec<String>,
    pub status: ResponseStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStatus {
    pub status_code: StatusCode,
    pub status_message: Option<String>,
    pub status_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StatusCode {
    Ok,
    MissingAttribute,
    SyntaxError,
    ProcessingError,
}

impl AttributeBasedAccessControl {
    pub async fn new(config: ABACConfig) -> Result<Self, ABACError> {
        let abac = Self {
            config,
            policies: Arc::new(RwLock::new(Vec::new())),
            attribute_store: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        };

        // Initialize default policies
        abac.initialize_default_policies().await?;

        Ok(abac)
    }

    pub async fn start(&self) -> Result<(), ABACError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(ABACError::AlreadyRunning);
        }
        *running = true;
        log::info!("ABAC system started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), ABACError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("ABAC system stopped");
        Ok(())
    }

    /// Add a new ABAC policy
    pub async fn add_policy(&self, policy: ABACPolicy) -> Result<(), ABACError> {
        let mut policies = self.policies.write().await;
        
        // Check for duplicate policy IDs
        if policies.iter().any(|p| p.id == policy.id) {
            return Err(ABACError::PolicyAlreadyExists(policy.id));
        }

        policies.push(policy);
        log::info!("Added ABAC policy, total policies: {}", policies.len());
        Ok(())
    }

    /// Remove a policy
    pub async fn remove_policy(&self, policy_id: &str) -> Result<(), ABACError> {
        let mut policies = self.policies.write().await;
        let initial_count = policies.len();
        policies.retain(|p| p.id != policy_id);
        
        if policies.len() == initial_count {
            return Err(ABACError::PolicyNotFound(policy_id.to_string()));
        }

        log::info!("Removed ABAC policy: {}", policy_id);
        Ok(())
    }

    /// Evaluate access request against all policies
    pub async fn evaluate_access(&self, request: &AccessRequest) -> Result<AccessDecision, ABACError> {
        let policies = self.policies.read().await;
        let mut applicable_policies = Vec::new();
        let mut decisions = Vec::new();

        // Find applicable policies
        for policy in policies.iter().filter(|p| p.is_active) {
            if self.is_policy_applicable(policy, request)? {
                applicable_policies.push(policy);
            }
        }

        if applicable_policies.is_empty() {
            return Ok(self.config.default_decision.clone());
        }

        // Evaluate applicable policies
        for policy in applicable_policies {
            let decision = self.evaluate_policy(policy, request)?;
            decisions.push(decision);
        }

        // Combine decisions according to combining algorithm
        let final_decision = self.combine_decisions(decisions)?;
        
        log::debug!("ABAC access decision: {:?}", final_decision);
        Ok(final_decision)
    }

    /// Store attributes for a subject
    pub async fn store_attributes(&self, subject_id: &str, attributes: AttributeSet) -> Result<(), ABACError> {
        let mut attribute_store = self.attribute_store.write().await;
        attribute_store.insert(subject_id.to_string(), attributes);
        Ok(())
    }

    /// Retrieve attributes for a subject
    pub async fn get_attributes(&self, subject_id: &str) -> Result<Option<AttributeSet>, ABACError> {
        let attribute_store = self.attribute_store.read().await;
        Ok(attribute_store.get(subject_id).cloned())
    }

    // Private helper methods

    async fn initialize_default_policies(&self) -> Result<(), ABACError> {
        // Create a default deny-all policy
        let default_policy = ABACPolicy {
            id: "default-deny".to_string(),
            name: "Default Deny Policy".to_string(),
            description: "Default policy that denies all access when no other policies apply".to_string(),
            target: PolicyTarget {
                subjects: Vec::new(),
                resources: Vec::new(),
                actions: Vec::new(),
                environments: Vec::new(),
            },
            rule: PolicyRule {
                rule_type: RuleType::Deny,
                condition: None,
            },
            effect: PolicyEffect::Deny,
            obligations: Vec::new(),
            advice: Vec::new(),
            version: "1.0".to_string(),
            created_at: Utc::now(),
            is_active: true,
        };

        // Create an admin access policy
        let admin_policy = ABACPolicy {
            id: "admin-access".to_string(),
            name: "Administrator Access Policy".to_string(),
            description: "Allows administrators full access".to_string(),
            target: PolicyTarget {
                subjects: vec![
                    AttributeMatch {
                        attribute_id: "role".to_string(),
                        match_function: MatchFunction::StringEquals,
                        attribute_value: AttributeValue::String("admin".to_string()),
                    }
                ],
                resources: Vec::new(),
                actions: Vec::new(),
                environments: Vec::new(),
            },
            rule: PolicyRule {
                rule_type: RuleType::Permit,
                condition: None,
            },
            effect: PolicyEffect::Permit,
            obligations: Vec::new(),
            advice: Vec::new(),
            version: "1.0".to_string(),
            created_at: Utc::now(),
            is_active: true,
        };

        let mut policies = self.policies.write().await;
        policies.push(default_policy);
        policies.push(admin_policy);

        log::info!("Initialized default ABAC policies");
        Ok(())
    }

    fn is_policy_applicable(&self, policy: &ABACPolicy, request: &AccessRequest) -> Result<bool, ABACError> {
        // Check if policy target matches the request
        if !self.matches_target(&policy.target.subjects, &request.subject_attributes)? {
            return Ok(false);
        }

        if !self.matches_target(&policy.target.resources, &request.resource_attributes)? {
            return Ok(false);
        }

        if !self.matches_target(&policy.target.actions, &request.action_attributes)? {
            return Ok(false);
        }

        if !self.matches_target(&policy.target.environments, &request.environment_attributes)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn matches_target(&self, target_matches: &[AttributeMatch], attribute_set: &AttributeSet) -> Result<bool, ABACError> {
        if target_matches.is_empty() {
            return Ok(true); // No constraints means it matches
        }

        for attribute_match in target_matches {
            if let Some(attributes) = attribute_set.attributes.get(&attribute_match.attribute_id) {
                let mut found_match = false;
                for attribute in attributes {
                    if self.evaluate_attribute_match(attribute_match, attribute)? {
                        found_match = true;
                        break;
                    }
                }
                if !found_match {
                    return Ok(false);
                }
            } else {
                return Ok(false); // Required attribute not found
            }
        }

        Ok(true)
    }

    fn evaluate_attribute_match(&self, attribute_match: &AttributeMatch, attribute: &Attribute) -> Result<bool, ABACError> {
        match &attribute_match.match_function {
            MatchFunction::Equals | MatchFunction::StringEquals => {
                Ok(self.values_equal(&attribute_match.attribute_value, &attribute.value))
            }
            MatchFunction::NotEquals => {
                Ok(!self.values_equal(&attribute_match.attribute_value, &attribute.value))
            }
            MatchFunction::StringContains => {
                if let (AttributeValue::String(pattern), AttributeValue::String(value)) = 
                    (&attribute_match.attribute_value, &attribute.value) {
                    Ok(value.contains(pattern))
                } else {
                    Ok(false)
                }
            }
            MatchFunction::StringStartsWith => {
                if let (AttributeValue::String(pattern), AttributeValue::String(value)) = 
                    (&attribute_match.attribute_value, &attribute.value) {
                    Ok(value.starts_with(pattern))
                } else {
                    Ok(false)
                }
            }
            MatchFunction::StringEndsWith => {
                if let (AttributeValue::String(pattern), AttributeValue::String(value)) = 
                    (&attribute_match.attribute_value, &attribute.value) {
                    Ok(value.ends_with(pattern))
                } else {
                    Ok(false)
                }
            }
            MatchFunction::GreaterThan => {
                Ok(self.compare_values(&attribute.value, &attribute_match.attribute_value) > 0)
            }
            MatchFunction::GreaterThanOrEqual => {
                Ok(self.compare_values(&attribute.value, &attribute_match.attribute_value) >= 0)
            }
            MatchFunction::LessThan => {
                Ok(self.compare_values(&attribute.value, &attribute_match.attribute_value) < 0)
            }
            MatchFunction::LessThanOrEqual => {
                Ok(self.compare_values(&attribute.value, &attribute_match.attribute_value) <= 0)
            }
            MatchFunction::RegexMatch => {
                if let (AttributeValue::String(pattern), AttributeValue::String(value)) =
                    (&attribute_match.attribute_value, &attribute.value) {
                    match regex::Regex::new(pattern) {
                        Ok(re) => Ok(re.is_match(value)),
                        Err(e) => {
                            log::warn!("Invalid regex pattern '{}': {}", pattern, e);
                            Ok(false)
                        }
                    }
                } else {
                    Ok(false)
                }
            }
            MatchFunction::DateTimeInRange => {
                if let AttributeValue::DateTime(value_dt) = &attribute.value {
                    // For range matching, we expect the pattern to be a range like "2023-01-01T00:00:00Z,2023-12-31T23:59:59Z"
                    if let AttributeValue::String(range_str) = &attribute_match.attribute_value {
                        let parts: Vec<&str> = range_str.split(',').collect();
                        if parts.len() == 2 {
                            match (parts[0].parse::<chrono::DateTime<chrono::Utc>>(),
                                   parts[1].parse::<chrono::DateTime<chrono::Utc>>()) {
                                (Ok(start), Ok(end)) => {
                                    Ok(*value_dt >= start && *value_dt <= end)
                                }
                                _ => {
                                    log::warn!("Invalid datetime range format: {}", range_str);
                                    Ok(false)
                                }
                            }
                        } else {
                            log::warn!("DateTime range must contain exactly one comma: {}", range_str);
                            Ok(false)
                        }
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            MatchFunction::IpAddressInRange => {
                if let (AttributeValue::String(pattern), AttributeValue::String(value)) =
                    (&attribute_match.attribute_value, &attribute.value) {
                    // Simple CIDR or range checking - for production, use a proper IP library
                    if pattern.contains('/') {
                        // CIDR notation
                        log::warn!("CIDR IP range matching not fully implemented: {}", pattern);
                        Ok(false)
                    } else if pattern.contains('-') {
                        // Range notation like "192.168.1.1-192.168.1.100"
                        log::warn!("IP range matching not fully implemented: {}", pattern);
                        Ok(false)
                    } else {
                        // Exact match
                        Ok(value == pattern)
                    }
                } else {
                    Ok(false)
                }
            }
            MatchFunction::AnyOf => {
                // For AnyOf, the pattern should be a comma-separated list
                if let AttributeValue::String(patterns) = &attribute_match.attribute_value {
                    let pattern_list: Vec<&str> = patterns.split(',').map(|s| s.trim()).collect();
                    match &attribute.value {
                        AttributeValue::String(value) => {
                            Ok(pattern_list.contains(&value.as_str()))
                        }
                        AttributeValue::Integer(value) => {
                            let value_str = value.to_string();
                            Ok(pattern_list.contains(&value_str.as_str()))
                        }
                        _ => Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            MatchFunction::AllOf => {
                // For AllOf, check that the attribute value contains all specified values
                if let AttributeValue::String(patterns) = &attribute_match.attribute_value {
                    let pattern_list: Vec<&str> = patterns.split(',').map(|s| s.trim()).collect();
                    if let AttributeValue::String(value) = &attribute.value {
                        Ok(pattern_list.iter().all(|pattern| value.contains(pattern)))
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn values_equal(&self, value1: &AttributeValue, value2: &AttributeValue) -> bool {
        match (value1, value2) {
            (AttributeValue::String(s1), AttributeValue::String(s2)) => s1 == s2,
            (AttributeValue::Integer(i1), AttributeValue::Integer(i2)) => i1 == i2,
            (AttributeValue::Float(f1), AttributeValue::Float(f2)) => (f1 - f2).abs() < f64::EPSILON,
            (AttributeValue::Boolean(b1), AttributeValue::Boolean(b2)) => b1 == b2,
            (AttributeValue::DateTime(d1), AttributeValue::DateTime(d2)) => d1 == d2,
            _ => false,
        }
    }

    fn compare_values(&self, value1: &AttributeValue, value2: &AttributeValue) -> i32 {
        match (value1, value2) {
            (AttributeValue::Integer(i1), AttributeValue::Integer(i2)) => i1.cmp(i2) as i32,
            (AttributeValue::Float(f1), AttributeValue::Float(f2)) => {
                if f1 < f2 { -1 } else if f1 > f2 { 1 } else { 0 }
            }
            (AttributeValue::DateTime(d1), AttributeValue::DateTime(d2)) => {
                if d1 < d2 { -1 } else if d1 > d2 { 1 } else { 0 }
            }
            _ => 0,
        }
    }

    fn evaluate_policy(&self, policy: &ABACPolicy, _request: &AccessRequest) -> Result<AccessDecision, ABACError> {
        // Evaluate policy condition if present
        if let Some(_condition) = &policy.rule.condition {
            // For now, just return the policy effect
            // In a real implementation, would evaluate the condition expression
        }

        match policy.rule.rule_type {
            RuleType::Permit => Ok(AccessDecision::Permit),
            RuleType::Deny => Ok(AccessDecision::Deny),
        }
    }

    fn combine_decisions(&self, decisions: Vec<AccessDecision>) -> Result<AccessDecision, ABACError> {
        if decisions.is_empty() {
            return Ok(self.config.default_decision.clone());
        }

        match self.config.policy_combining_algorithm {
            PolicyCombiningAlgorithm::DenyOverrides => {
                if decisions.contains(&AccessDecision::Deny) {
                    Ok(AccessDecision::Deny)
                } else if decisions.contains(&AccessDecision::Permit) {
                    Ok(AccessDecision::Permit)
                } else {
                    Ok(AccessDecision::NotApplicable)
                }
            }
            PolicyCombiningAlgorithm::PermitOverrides => {
                if decisions.contains(&AccessDecision::Permit) {
                    Ok(AccessDecision::Permit)
                } else if decisions.contains(&AccessDecision::Deny) {
                    Ok(AccessDecision::Deny)
                } else {
                    Ok(AccessDecision::NotApplicable)
                }
            }
            PolicyCombiningAlgorithm::FirstApplicable => {
                for decision in decisions {
                    if decision != AccessDecision::NotApplicable {
                        return Ok(decision);
                    }
                }
                Ok(AccessDecision::NotApplicable)
            }
            PolicyCombiningAlgorithm::OnlyOneApplicable => {
                let applicable_decisions: Vec<_> = decisions.into_iter()
                    .filter(|d| *d != AccessDecision::NotApplicable)
                    .collect();
                
                match applicable_decisions.len() {
                    0 => Ok(AccessDecision::NotApplicable),
                    1 => Ok(applicable_decisions[0].clone()),
                    _ => Ok(AccessDecision::Indeterminate),
                }
            }
        }
    }
}

impl AttributeSet {
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    pub fn add_attribute(&mut self, attribute_id: String, value: String) {
        let attribute = Attribute {
            attribute_id: attribute_id.clone(),
            value: AttributeValue::String(value),
            issuer: None,
            issue_time: Some(Utc::now()),
        };

        self.attributes
            .entry(attribute_id)
            .or_insert_with(Vec::new)
            .push(attribute);
    }

    pub fn add_attribute_with_value(&mut self, attribute_id: String, value: AttributeValue) {
        let attribute = Attribute {
            attribute_id: attribute_id.clone(),
            value,
            issuer: None,
            issue_time: Some(Utc::now()),
        };

        self.attributes
            .entry(attribute_id)
            .or_insert_with(Vec::new)
            .push(attribute);
    }
}

impl Default for ABACConfig {
    fn default() -> Self {
        Self {
            policy_combining_algorithm: PolicyCombiningAlgorithm::DenyOverrides,
            default_decision: AccessDecision::Deny,
            enable_obligations: true,
            enable_advice: true,
            attribute_caching: true,
            cache_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ABACError {
    #[error("ABAC system already running")]
    AlreadyRunning,
    
    #[error("ABAC system not running")]
    NotRunning,
    
    #[error("Policy already exists: {0}")]
    PolicyAlreadyExists(String),
    
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
    
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),
    
    #[error("Attribute not found: {0}")]
    AttributeNotFound(String),
    
    #[error("Invalid attribute value")]
    InvalidAttributeValue,
    
    #[error("Policy evaluation error: {0}")]
    EvaluationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_abac_system_lifecycle() {
        let config = ABACConfig::default();
        let abac = AttributeBasedAccessControl::new(config).await.unwrap();
        
        abac.start().await.unwrap();
        abac.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_policy_management() {
        let config = ABACConfig::default();
        let abac = AttributeBasedAccessControl::new(config).await.unwrap();
        
        let policy = ABACPolicy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            description: "A test policy".to_string(),
            target: PolicyTarget {
                subjects: Vec::new(),
                resources: Vec::new(),
                actions: Vec::new(),
                environments: Vec::new(),
            },
            rule: PolicyRule {
                rule_type: RuleType::Permit,
                condition: None,
            },
            effect: PolicyEffect::Permit,
            obligations: Vec::new(),
            advice: Vec::new(),
            version: "1.0".to_string(),
            created_at: Utc::now(),
            is_active: true,
        };

        abac.add_policy(policy).await.unwrap();
        abac.remove_policy("test-policy").await.unwrap();
    }

    #[tokio::test]
    async fn test_access_evaluation() {
        let config = ABACConfig::default();
        let abac = AttributeBasedAccessControl::new(config).await.unwrap();
        abac.start().await.unwrap();

        let mut subject_attributes = AttributeSet::new();
        subject_attributes.add_attribute("role".to_string(), "user".to_string());

        let request = AccessRequest {
            subject_attributes,
            resource_attributes: AttributeSet::new(),
            action_attributes: AttributeSet::new(),
            environment_attributes: AttributeSet::new(),
        };

        let decision = abac.evaluate_access(&request).await.unwrap();
        // Should be deny by default policy since user doesn't have admin role
        assert_eq!(decision, AccessDecision::Deny);
    }
}