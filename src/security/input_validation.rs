use regex::Regex;
use std::collections::HashMap;
use anyhow::{Result, anyhow};

/// Input validation utilities for security
pub struct InputValidator;

impl InputValidator {
    /// Validate file paths to prevent path traversal attacks
    pub fn validate_file_path(path: &str) -> Result<()> {
        // Check for null bytes
        if path.contains('\0') {
            return Err(anyhow!("Path contains null bytes"));
        }

        // Check for path traversal attempts
        if path.contains("..") {
            return Err(anyhow!("Path traversal detected"));
        }

        // Check for absolute paths (if not allowed)
        if path.starts_with('/') || path.starts_with('\\') || path.contains(':') {
            return Err(anyhow!("Absolute paths not allowed"));
        }

        // Check for reserved Windows names
        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", 
            "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", 
            "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        ];

        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        for reserved in &reserved_names {
            if filename.to_uppercase() == *reserved || 
               filename.to_uppercase().starts_with(&format!("{}.", reserved)) {
                return Err(anyhow!("Reserved filename: {}", filename));
            }
        }

        // Check path length
        if path.len() > 260 {
            return Err(anyhow!("Path too long (max 260 characters)"));
        }

        Ok(())
    }

    /// Validate email addresses
    pub fn validate_email(email: &str) -> Result<()> {
        if email.is_empty() {
            return Err(anyhow!("Email cannot be empty"));
        }

        if email.len() > 254 {
            return Err(anyhow!("Email too long"));
        }

        let email_regex = Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).map_err(|e| anyhow!("Invalid regex: {}", e))?;

        if !email_regex.is_match(email) {
            return Err(anyhow!("Invalid email format"));
        }

        // Check for multiple @ symbols
        if email.matches('@').count() != 1 {
            return Err(anyhow!("Invalid email format"));
        }

        Ok(())
    }

    /// Validate usernames
    pub fn validate_username(username: &str) -> Result<()> {
        if username.is_empty() {
            return Err(anyhow!("Username cannot be empty"));
        }

        if username.len() < 3 {
            return Err(anyhow!("Username too short (minimum 3 characters)"));
        }

        if username.len() > 50 {
            return Err(anyhow!("Username too long (maximum 50 characters)"));
        }

        let username_regex = Regex::new(r"^[a-zA-Z0-9_-]+$")
            .map_err(|e| anyhow!("Invalid regex: {}", e))?;

        if !username_regex.is_match(username) {
            return Err(anyhow!("Username contains invalid characters"));
        }

        // Check for reserved usernames
        let reserved = ["admin", "root", "system", "user", "guest", "anonymous"];
        if reserved.iter().any(|&r| username.to_lowercase() == r) {
            return Err(anyhow!("Reserved username"));
        }

        Ok(())
    }

    /// Validate passwords
    pub fn validate_password(password: &str) -> Result<PasswordStrength> {
        if password.is_empty() {
            return Err(anyhow!("Password cannot be empty"));
        }

        if password.len() < 8 {
            return Err(anyhow!("Password too short (minimum 8 characters)"));
        }

        if password.len() > 128 {
            return Err(anyhow!("Password too long (maximum 128 characters)"));
        }

        let mut score = 0u32;
        let mut feedback = Vec::new();

        // Check for lowercase letters
        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        } else {
            feedback.push("Add lowercase letters".to_string());
        }

        // Check for uppercase letters
        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        } else {
            feedback.push("Add uppercase letters".to_string());
        }

        // Check for digits
        if password.chars().any(|c| c.is_ascii_digit()) {
            score += 1;
        } else {
            feedback.push("Add numbers".to_string());
        }

        // Check for special characters
        if password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
            score += 1;
        } else {
            feedback.push("Add special characters".to_string());
        }

        // Check length bonus
        if password.len() >= 12 {
            score += 1;
        }

        // Check for common passwords
        let common_passwords = [
            "password", "123456", "password123", "admin", "qwerty", 
            "letmein", "welcome", "monkey", "1234567890"
        ];
        
        if common_passwords.iter().any(|&p| password.to_lowercase().contains(p)) {
            score = score.saturating_sub(2);
            feedback.push("Avoid common passwords".to_string());
        }

        let strength = match score {
            0..=1 => PasswordStrength::VeryWeak,
            2 => PasswordStrength::Weak,
            3 => PasswordStrength::Medium,
            4 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        };

        Ok(strength)
    }

    /// Validate URLs
    pub fn validate_url(url: &str) -> Result<()> {
        if url.is_empty() {
            return Err(anyhow!("URL cannot be empty"));
        }

        if url.len() > 2048 {
            return Err(anyhow!("URL too long"));
        }

        let url_regex = Regex::new(
            r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$"
        ).map_err(|e| anyhow!("Invalid regex: {}", e))?;

        if !url_regex.is_match(url) {
            return Err(anyhow!("Invalid URL format"));
        }

        // Additional security checks
        let lower_url = url.to_lowercase();
        
        // Block common malicious patterns
        let dangerous_patterns = [
            "javascript:", "data:", "vbscript:", "file:", "ftp:",
            "localhost", "127.0.0.1", "0.0.0.0"
        ];

        for pattern in &dangerous_patterns {
            if lower_url.contains(pattern) {
                return Err(anyhow!("Potentially dangerous URL pattern: {}", pattern));
            }
        }

        Ok(())
    }

    /// Validate JSON input
    pub fn validate_json(json_str: &str, max_size: usize) -> Result<serde_json::Value> {
        if json_str.is_empty() {
            return Err(anyhow!("JSON cannot be empty"));
        }

        if json_str.len() > max_size {
            return Err(anyhow!("JSON too large (max {} bytes)", max_size));
        }

        // Check for potential JSON bombs (excessive nesting)
        let nesting_level = json_str.chars()
            .fold((0u32, 0u32), |(max_depth, current_depth), c| {
                match c {
                    '{' | '[' => (max_depth.max(current_depth + 1), current_depth + 1),
                    '}' | ']' => (max_depth, current_depth.saturating_sub(1)),
                    _ => (max_depth, current_depth),
                }
            }).0;

        if nesting_level > 50 {
            return Err(anyhow!("JSON nesting too deep (max 50 levels)"));
        }

        // Parse JSON
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| anyhow!("Invalid JSON: {}", e))?;

        Ok(value)
    }

    /// Validate hex strings
    pub fn validate_hex_string(hex_str: &str) -> Result<()> {
        if hex_str.is_empty() {
            return Err(anyhow!("Hex string cannot be empty"));
        }

        if hex_str.len() % 2 != 0 {
            return Err(anyhow!("Hex string must have even length"));
        }

        let hex_regex = Regex::new(r"^[0-9a-fA-F]+$")
            .map_err(|e| anyhow!("Invalid regex: {}", e))?;

        if !hex_regex.is_match(hex_str) {
            return Err(anyhow!("Invalid hex characters"));
        }

        Ok(())
    }

    /// Validate base64 strings
    pub fn validate_base64_string(b64_str: &str) -> Result<()> {
        if b64_str.is_empty() {
            return Err(anyhow!("Base64 string cannot be empty"));
        }

        let b64_regex = Regex::new(r"^[A-Za-z0-9+/]*(=|==)?$")
            .map_err(|e| anyhow!("Invalid regex: {}", e))?;

        if !b64_regex.is_match(b64_str) {
            return Err(anyhow!("Invalid base64 characters"));
        }

        // Check padding
        let padding_count = b64_str.chars().rev().take_while(|&c| c == '=').count();
        if padding_count > 2 {
            return Err(anyhow!("Invalid base64 padding"));
        }

        Ok(())
    }
}

/// Password strength levels
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "Very Weak - Unacceptable",
            PasswordStrength::Weak => "Weak - Consider strengthening",
            PasswordStrength::Medium => "Medium - Acceptable",
            PasswordStrength::Strong => "Strong - Good",
            PasswordStrength::VeryStrong => "Very Strong - Excellent",
        }
    }

    /// Check if password strength is acceptable
    pub fn is_acceptable(&self) -> bool {
        matches!(self, PasswordStrength::Medium | PasswordStrength::Strong | PasswordStrength::VeryStrong)
    }
}

/// SQL injection detection
pub struct SqlInjectionDetector;

impl SqlInjectionDetector {
    /// Detect potential SQL injection patterns
    pub fn detect(input: &str) -> bool {
        let input_lower = input.to_lowercase();
        
        let sql_keywords = [
            "union", "select", "insert", "update", "delete", "drop", "create",
            "alter", "exec", "execute", "sp_", "xp_", "--", "/*", "*/",
            "char(", "varchar(", "nchar(", "nvarchar(", "waitfor", "delay",
            "benchmark", "sleep(", "pg_sleep", "extractvalue", "updatexml"
        ];

        for keyword in &sql_keywords {
            if input_lower.contains(keyword) {
                return true;
            }
        }

        // Check for common SQL injection patterns
        let sql_patterns = [
            r"(\s|^)(union)(\s)+select",
            r"(\s|^)(insert)(\s)+into",
            r"(\s|^)(update)(\s)+\w+(\s)+set",
            r"(\s|^)(delete)(\s)+from",
            r"(\s|^)(select).+(from)",
            r"(\s|^)(drop)(\s)+(table|database)",
            r"'(\s)*(or|and)(\s)*'",
            r"'(\s)*;",
        ];

        for pattern in &sql_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&input_lower) {
                    return true;
                }
            }
        }

        false
    }
}

/// XSS (Cross-Site Scripting) detection
pub struct XssDetector;

impl XssDetector {
    /// Detect potential XSS patterns
    pub fn detect(input: &str) -> bool {
        let input_lower = input.to_lowercase();

        let xss_patterns = [
            r"<script",
            r"</script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"eval\s*\(",
            r"expression\s*\(",
            r"<iframe",
            r"<object",
            r"<embed",
            r"<form",
            r"<input",
            r"<img[^>]+src\s*=.*javascript:",
        ];

        for pattern in &xss_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&input_lower) {
                    return true;
                }
            }
        }

        false
    }

    /// Sanitize input by removing/escaping dangerous characters
    pub fn sanitize(input: &str) -> String {
        input
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('&', "&amp;")
    }
}

/// Rate limiting for input validation
pub struct RateLimiter {
    requests: HashMap<String, Vec<std::time::Instant>>,
    max_requests: usize,
    time_window: std::time::Duration,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_requests: usize, time_window: std::time::Duration) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            time_window,
        }
    }

    /// Check if a request should be allowed
    pub fn check_rate_limit(&mut self, identifier: &str) -> bool {
        let now = std::time::Instant::now();
        let cutoff = now - self.time_window;

        // Clean up old requests
        let requests = self.requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        requests.retain(|&time| time > cutoff);

        // Check if we're under the limit
        if requests.len() < self.max_requests {
            requests.push(now);
            true
        } else {
            false
        }
    }

    /// Get current request count for an identifier
    pub fn get_request_count(&self, identifier: &str) -> usize {
        self.requests.get(identifier).map(|v| v.len()).unwrap_or(0)
    }

    /// Clear all rate limiting data
    pub fn clear(&mut self) {
        self.requests.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_file_path() {
        // Valid paths
        assert!(InputValidator::validate_file_path("test.txt").is_ok());
        assert!(InputValidator::validate_file_path("folder/test.txt").is_ok());

        // Invalid paths
        assert!(InputValidator::validate_file_path("../etc/passwd").is_err());
        assert!(InputValidator::validate_file_path("/etc/passwd").is_err());
        assert!(InputValidator::validate_file_path("test\0.txt").is_err());
        assert!(InputValidator::validate_file_path("CON").is_err());
    }

    #[test]
    fn test_validate_email() {
        // Valid emails
        assert!(InputValidator::validate_email("test@example.com").is_ok());
        assert!(InputValidator::validate_email("user.name+tag@example.org").is_ok());

        // Invalid emails
        assert!(InputValidator::validate_email("").is_err());
        assert!(InputValidator::validate_email("invalid-email").is_err());
        assert!(InputValidator::validate_email("test@@example.com").is_err());
        assert!(InputValidator::validate_email("test@").is_err());
    }

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(InputValidator::validate_username("testuser").is_ok());
        assert!(InputValidator::validate_username("user_123").is_ok());

        // Invalid usernames
        assert!(InputValidator::validate_username("").is_err());
        assert!(InputValidator::validate_username("ab").is_err()); // Too short
        assert!(InputValidator::validate_username("admin").is_err()); // Reserved
        assert!(InputValidator::validate_username("test@user").is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_password() {
        // Test different strength levels
        let weak = InputValidator::validate_password("password").unwrap();
        assert_eq!(weak, PasswordStrength::VeryWeak);

        let medium = InputValidator::validate_password("Password123").unwrap();
        assert!(medium.is_acceptable());

        let strong = InputValidator::validate_password("MyStr0ng!Pass").unwrap();
        assert_eq!(strong, PasswordStrength::Strong);

        // Invalid passwords
        assert!(InputValidator::validate_password("").is_err());
        assert!(InputValidator::validate_password("short").is_err());
    }

    #[test]
    fn test_validate_url() {
        // Valid URLs
        assert!(InputValidator::validate_url("https://example.com").is_ok());
        assert!(InputValidator::validate_url("http://test.org/path").is_ok());

        // Invalid URLs
        assert!(InputValidator::validate_url("").is_err());
        assert!(InputValidator::validate_url("not-a-url").is_err());
        assert!(InputValidator::validate_url("javascript:alert('xss')").is_err());
        assert!(InputValidator::validate_url("http://localhost/").is_err());
    }

    #[test]
    fn test_validate_hex_string() {
        // Valid hex
        assert!(InputValidator::validate_hex_string("deadbeef").is_ok());
        assert!(InputValidator::validate_hex_string("DEADBEEF").is_ok());
        assert!(InputValidator::validate_hex_string("123abc").is_ok());

        // Invalid hex
        assert!(InputValidator::validate_hex_string("").is_err());
        assert!(InputValidator::validate_hex_string("xyz").is_err());
        assert!(InputValidator::validate_hex_string("123").is_err()); // Odd length
    }

    #[test]
    fn test_validate_base64_string() {
        // Valid base64
        assert!(InputValidator::validate_base64_string("SGVsbG8=").is_ok());
        assert!(InputValidator::validate_base64_string("SGVsbG8gV29ybGQ=").is_ok());

        // Invalid base64
        assert!(InputValidator::validate_base64_string("").is_err());
        assert!(InputValidator::validate_base64_string("Invalid!").is_err());
        assert!(InputValidator::validate_base64_string("SGVsb===").is_err()); // Too much padding
    }

    #[test]
    fn test_sql_injection_detection() {
        // Should detect SQL injection
        assert!(SqlInjectionDetector::detect("' OR 1=1 --"));
        assert!(SqlInjectionDetector::detect("UNION SELECT * FROM users"));
        assert!(SqlInjectionDetector::detect("DROP TABLE users"));

        // Should not detect normal input
        assert!(!SqlInjectionDetector::detect("normal user input"));
        assert!(!SqlInjectionDetector::detect("john@example.com"));
    }

    #[test]
    fn test_xss_detection() {
        // Should detect XSS
        assert!(XssDetector::detect("<script>alert('xss')</script>"));
        assert!(XssDetector::detect("javascript:alert('xss')"));
        assert!(XssDetector::detect("<img onload='alert(1)'>"));

        // Should not detect normal input
        assert!(!XssDetector::detect("normal text"));
        assert!(!XssDetector::detect("user@example.com"));
    }

    #[test]
    fn test_xss_sanitization() {
        let dangerous = "<script>alert('xss')</script>";
        let sanitized = XssDetector::sanitize(dangerous);
        assert_eq!(sanitized, "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3, std::time::Duration::from_secs(60));

        // Should allow first 3 requests
        assert!(limiter.check_rate_limit("user1"));
        assert!(limiter.check_rate_limit("user1"));
        assert!(limiter.check_rate_limit("user1"));

        // Should block 4th request
        assert!(!limiter.check_rate_limit("user1"));

        // Should allow requests from different user
        assert!(limiter.check_rate_limit("user2"));
    }
}