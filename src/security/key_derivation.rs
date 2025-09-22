use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use scrypt::Params as ScryptParams;
use argon2::{Argon2, PasswordVerifier};
use sha2::{Sha256, Sha512};
use hmac::Mac;
use zeroize::Zeroize;
use anyhow::{Result, anyhow};
use std::time::Instant;
use base64::Engine;

/// Key derivation algorithms
#[derive(Debug, Clone, Copy)]
pub enum KdfAlgorithm {
    /// PBKDF2 with SHA-256
    Pbkdf2Sha256,
    /// PBKDF2 with SHA-512
    Pbkdf2Sha512,
    /// Scrypt
    Scrypt,
    /// Argon2id (recommended)
    Argon2id,
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-512
    HkdfSha512,
}

/// Key derivation parameters
#[derive(Debug, Clone)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub iterations: u32,
    pub memory_cost: Option<u32>, // For Argon2 and Scrypt
    pub parallelism: Option<u32>,  // For Argon2
    pub salt_len: usize,
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Secure defaults for Argon2id
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            iterations: 3,
            memory_cost: Some(65536), // 64 MB
            parallelism: Some(4),
            salt_len: 32,
            output_len: 32,
        }
    }
}

impl KdfParams {
    /// Create parameters for PBKDF2
    pub fn pbkdf2_sha256(iterations: u32) -> Self {
        Self {
            algorithm: KdfAlgorithm::Pbkdf2Sha256,
            iterations,
            memory_cost: None,
            parallelism: None,
            salt_len: 32,
            output_len: 32,
        }
    }

    /// Create parameters for Scrypt
    pub fn scrypt(n: u32, r: u32, p: u32) -> Self {
        Self {
            algorithm: KdfAlgorithm::Scrypt,
            iterations: n,
            memory_cost: Some(r),
            parallelism: Some(p),
            salt_len: 32,
            output_len: 32,
        }
    }

    /// Create parameters for Argon2id
    pub fn argon2id(iterations: u32, memory_kb: u32, parallelism: u32) -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            iterations,
            memory_cost: Some(memory_kb),
            parallelism: Some(parallelism),
            salt_len: 32,
            output_len: 32,
        }
    }

    /// Create parameters for HKDF
    pub fn hkdf_sha256() -> Self {
        Self {
            algorithm: KdfAlgorithm::HkdfSha256,
            iterations: 1, // HKDF doesn't use iterations
            memory_cost: None,
            parallelism: None,
            salt_len: 32,
            output_len: 32,
        }
    }
}

/// Derived key with metadata
pub struct DerivedKey {
    key: Vec<u8>,
    salt: Vec<u8>,
    params: KdfParams,
    derivation_time: std::time::Duration,
}

impl DerivedKey {
    /// Create a new derived key
    pub fn new(
        key: Vec<u8>,
        salt: Vec<u8>,
        params: KdfParams,
        derivation_time: std::time::Duration,
    ) -> Self {
        Self {
            key,
            salt,
            params,
            derivation_time,
        }
    }

    /// Get the derived key data
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Get the salt used for derivation
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Get the parameters used for derivation
    pub fn params(&self) -> &KdfParams {
        &self.params
    }

    /// Get the time taken for derivation
    pub fn derivation_time(&self) -> std::time::Duration {
        self.derivation_time
    }

    /// Verify a password against this derived key
    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let start = Instant::now();
        
        let derived = derive_key(password.as_bytes(), Some(&self.salt), &self.params)?;
        let verification_time = start.elapsed();
        
        // Use constant-time comparison
        let matches = crate::security::memory::MemoryProtection::constant_time_compare(
            &self.key, 
            &derived.key
        );
        
        tracing::debug!(
            algorithm = ?self.params.algorithm,
            verification_time_ms = verification_time.as_millis(),
            "Password verification completed"
        );

        Ok(matches)
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
        // params and derivation_time don't need zeroizing
    }
}

/// Main key derivation function
pub fn derive_key(
    password: &[u8],
    salt: Option<&[u8]>,
    params: &KdfParams,
) -> Result<DerivedKey> {
    let start = Instant::now();
    
    // Generate salt if not provided
    let salt = if let Some(s) = salt {
        s.to_vec()
    } else {
        crate::security::memory::MemoryProtection::secure_random_bytes(params.salt_len)?
    };

    let key = match params.algorithm {
        KdfAlgorithm::Pbkdf2Sha256 => {
            pbkdf2_derive_sha256(password, &salt, params.iterations, params.output_len)?
        }
        KdfAlgorithm::Pbkdf2Sha512 => {
            pbkdf2_derive_sha512(password, &salt, params.iterations, params.output_len)?
        }
        KdfAlgorithm::Scrypt => {
            scrypt_derive(password, &salt, params)?
        }
        KdfAlgorithm::Argon2id => {
            argon2_derive(password, &salt, params)?
        }
        KdfAlgorithm::HkdfSha256 => {
            hkdf_derive_sha256(password, &salt, b"", params.output_len)?
        }
        KdfAlgorithm::HkdfSha512 => {
            hkdf_derive_sha512(password, &salt, b"", params.output_len)?
        }
    };

    let derivation_time = start.elapsed();
    
    tracing::info!(
        algorithm = ?params.algorithm,
        derivation_time_ms = derivation_time.as_millis(),
        output_length = params.output_len,
        "Key derivation completed"
    );

    Ok(DerivedKey::new(key, salt, params.clone(), derivation_time))
}

/// PBKDF2 with SHA-256
fn pbkdf2_derive_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    let mut key = vec![0u8; output_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    Ok(key)
}

/// PBKDF2 with SHA-512
fn pbkdf2_derive_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    let mut key = vec![0u8; output_len];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut key);
    Ok(key)
}

/// Scrypt key derivation
fn scrypt_derive(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<Vec<u8>> {
    let n = params.iterations;
    let r = params.memory_cost.unwrap_or(8);
    let p = params.parallelism.unwrap_or(1);
    
    let scrypt_params = ScryptParams::new(
        (n as f64).log2() as u8,
        r,
        p,
        params.output_len,
    ).map_err(|e| anyhow!("Invalid Scrypt parameters: {}", e))?;

    let mut key = vec![0u8; params.output_len];
    scrypt::scrypt(password, salt, &scrypt_params, &mut key)
        .map_err(|e| anyhow!("Scrypt derivation failed: {}", e))?;
    
    Ok(key)
}

/// Argon2id key derivation
fn argon2_derive(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<Vec<u8>> {
    let memory_cost = params.memory_cost.unwrap_or(65536);
    let time_cost = params.iterations;
    let parallelism = params.parallelism.unwrap_or(4);
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(memory_cost, time_cost, parallelism, Some(params.output_len))
            .map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?,
    );
    
    let mut output = vec![0u8; params.output_len];
    argon2.hash_password_into(password, salt, &mut output)
        .map_err(|e| anyhow!("Argon2 derivation failed: {}", e))?;
    
    Ok(output)
}

/// HKDF with SHA-256
pub fn hkdf_derive_sha256(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output)
        .map_err(|e| anyhow!("HKDF-SHA256 expansion failed: {}", e))?;
    Ok(output)
}

/// HKDF with SHA-256 (public interface)
pub fn hkdf_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    hkdf_derive_sha256(input_key_material, salt, info, output_len)
}

/// HKDF with SHA-512
fn hkdf_derive_sha512(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha512>::new(Some(salt), input_key_material);
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output)
        .map_err(|e| anyhow!("HKDF-SHA512 expansion failed: {}", e))?;
    Ok(output)
}

/// Password-based key derivation with automatic parameter tuning
pub fn derive_key_adaptive(
    password: &str,
    target_time: std::time::Duration,
    algorithm: KdfAlgorithm,
) -> Result<DerivedKey> {
    let params = tune_parameters(password.as_bytes(), target_time, algorithm)?;
    derive_key(password.as_bytes(), None, &params)
}

/// Tune KDF parameters to achieve a target derivation time
pub fn tune_parameters(
    test_password: &[u8],
    target_time: std::time::Duration,
    algorithm: KdfAlgorithm,
) -> Result<KdfParams> {
    let mut params = match algorithm {
        KdfAlgorithm::Pbkdf2Sha256 => KdfParams::pbkdf2_sha256(1000),
        KdfAlgorithm::Pbkdf2Sha512 => KdfParams {
            algorithm: KdfAlgorithm::Pbkdf2Sha512,
            iterations: 1000,
            memory_cost: None,
            parallelism: None,
            salt_len: 32,
            output_len: 32,
        },
        KdfAlgorithm::Scrypt => KdfParams::scrypt(16384, 8, 1),
        KdfAlgorithm::Argon2id => KdfParams::argon2id(3, 65536, 4),
        KdfAlgorithm::HkdfSha256 | KdfAlgorithm::HkdfSha512 => {
            // HKDF is fast and doesn't need tuning
            return Ok(KdfParams {
                algorithm,
                iterations: 1,
                memory_cost: None,
                parallelism: None,
                salt_len: 32,
                output_len: 32,
            });
        }
    };

    let test_salt = crate::security::memory::MemoryProtection::secure_random_bytes(32)?;
    
    // Binary search for optimal parameters
    let mut low = 1;
    let mut high = match algorithm {
        KdfAlgorithm::Pbkdf2Sha256 | KdfAlgorithm::Pbkdf2Sha512 => 1_000_000,
        KdfAlgorithm::Scrypt => 131072, // 2^17
        KdfAlgorithm::Argon2id => 20,
        _ => return Ok(params),
    };

    let mut best_params = params.clone();
    let tolerance = target_time.mul_f32(0.1); // 10% tolerance
    
    for _ in 0..10 { // Limit iterations to prevent infinite loop
        let mid = (low + high) / 2;
        
        match algorithm {
            KdfAlgorithm::Pbkdf2Sha256 | KdfAlgorithm::Pbkdf2Sha512 => {
                params.iterations = mid;
            }
            KdfAlgorithm::Scrypt => {
                params.iterations = mid;
            }
            KdfAlgorithm::Argon2id => {
                params.iterations = mid;
            }
            _ => break,
        }
        
        let start = Instant::now();
        let _ = derive_key(test_password, Some(&test_salt), &params)?;
        let elapsed = start.elapsed();
        
        if elapsed < target_time - tolerance {
            low = mid + 1;
        } else if elapsed > target_time + tolerance {
            high = mid - 1;
        } else {
            best_params = params.clone();
            break;
        }
        
        if elapsed <= target_time + tolerance {
            best_params = params.clone();
        }
        
        if low >= high {
            break;
        }
    }
    
    tracing::info!(
        algorithm = ?algorithm,
        tuned_iterations = best_params.iterations,
        target_time_ms = target_time.as_millis(),
        "KDF parameters tuned"
    );
    
    Ok(best_params)
}

/// Key stretching for password storage
pub struct PasswordHasher {
    algorithm: KdfAlgorithm,
    params: KdfParams,
}

impl PasswordHasher {
    /// Create a new password hasher with default parameters
    pub fn new() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            params: KdfParams::default(),
        }
    }

    /// Create with specific algorithm
    pub fn with_algorithm(algorithm: KdfAlgorithm) -> Self {
        let params = match algorithm {
            KdfAlgorithm::Argon2id => KdfParams::default(),
            KdfAlgorithm::Pbkdf2Sha256 => KdfParams::pbkdf2_sha256(600_000),
            KdfAlgorithm::Pbkdf2Sha512 => KdfParams {
                algorithm: KdfAlgorithm::Pbkdf2Sha512,
                iterations: 600_000,
                memory_cost: None,
                parallelism: None,
                salt_len: 32,
                output_len: 64,
            },
            KdfAlgorithm::Scrypt => KdfParams::scrypt(32768, 8, 1),
            _ => KdfParams::default(),
        };

        Self { algorithm, params }
    }

    /// Hash a password for storage
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let derived = derive_key(password.as_bytes(), None, &self.params)?;
        
        // Encode as a structured string for storage
        let encoded = format!(
            "${}${}${}${}${}",
            algorithm_name(self.algorithm),
            base64::engine::general_purpose::STANDARD.encode(&derived.salt),
            base64::engine::general_purpose::STANDARD.encode(&derived.key),
            format_params(&self.params),
            derived.derivation_time.as_millis()
        );
        
        Ok(encoded)
    }

    /// Verify a password against a stored hash
    pub fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool> {
        let stored_derived = parse_stored_hash(stored_hash)?;
        stored_derived.verify_password(password)
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Get algorithm name as string
fn algorithm_name(algorithm: KdfAlgorithm) -> &'static str {
    match algorithm {
        KdfAlgorithm::Pbkdf2Sha256 => "pbkdf2-sha256",
        KdfAlgorithm::Pbkdf2Sha512 => "pbkdf2-sha512",
        KdfAlgorithm::Scrypt => "scrypt",
        KdfAlgorithm::Argon2id => "argon2id",
        KdfAlgorithm::HkdfSha256 => "hkdf-sha256",
        KdfAlgorithm::HkdfSha512 => "hkdf-sha512",
    }
}

/// Format parameters as string
fn format_params(params: &KdfParams) -> String {
    match params.algorithm {
        KdfAlgorithm::Pbkdf2Sha256 | KdfAlgorithm::Pbkdf2Sha512 => {
            format!("i={}", params.iterations)
        }
        KdfAlgorithm::Scrypt => {
            format!(
                "n={},r={},p={}",
                params.iterations,
                params.memory_cost.unwrap_or(8),
                params.parallelism.unwrap_or(1)
            )
        }
        KdfAlgorithm::Argon2id => {
            format!(
                "t={},m={},p={}",
                params.iterations,
                params.memory_cost.unwrap_or(65536),
                params.parallelism.unwrap_or(4)
            )
        }
        _ => "".to_string(),
    }
}

/// Parse a stored hash back to DerivedKey
fn parse_stored_hash(stored_hash: &str) -> Result<DerivedKey> {
    let parts: Vec<&str> = stored_hash.split('$').collect();
    if parts.len() != 6 || parts[0] != "" {
        return Err(anyhow!("Invalid stored hash format"));
    }

    let algorithm = match parts[1] {
        "pbkdf2-sha256" => KdfAlgorithm::Pbkdf2Sha256,
        "pbkdf2-sha512" => KdfAlgorithm::Pbkdf2Sha512,
        "scrypt" => KdfAlgorithm::Scrypt,
        "argon2id" => KdfAlgorithm::Argon2id,
        "hkdf-sha256" => KdfAlgorithm::HkdfSha256,
        "hkdf-sha512" => KdfAlgorithm::HkdfSha512,
        _ => return Err(anyhow!("Unknown algorithm: {}", parts[1])),
    };

    let salt = base64::engine::general_purpose::STANDARD.decode(parts[2])
        .map_err(|e| anyhow!("Invalid salt encoding: {}", e))?;
    
    let key = base64::engine::general_purpose::STANDARD.decode(parts[3])
        .map_err(|e| anyhow!("Invalid key encoding: {}", e))?;
    
    let params = parse_params(algorithm, parts[4])?;
    
    let derivation_time = parts[5].parse::<u64>()
        .map(std::time::Duration::from_millis)
        .map_err(|e| anyhow!("Invalid derivation time: {}", e))?;

    Ok(DerivedKey::new(key, salt, params, derivation_time))
}

/// Parse parameters from string
fn parse_params(algorithm: KdfAlgorithm, param_str: &str) -> Result<KdfParams> {
    let mut params = KdfParams {
        algorithm,
        iterations: 1,
        memory_cost: None,
        parallelism: None,
        salt_len: 32,
        output_len: 32,
    };

    for param in param_str.split(',') {
        let kv: Vec<&str> = param.split('=').collect();
        if kv.len() != 2 {
            continue;
        }

        match kv[0] {
            "i" | "t" => {
                params.iterations = kv[1].parse()
                    .map_err(|e| anyhow!("Invalid iterations: {}", e))?;
            }
            "n" => {
                params.iterations = kv[1].parse()
                    .map_err(|e| anyhow!("Invalid n parameter: {}", e))?;
            }
            "r" | "m" => {
                params.memory_cost = Some(kv[1].parse()
                    .map_err(|e| anyhow!("Invalid memory cost: {}", e))?);
            }
            "p" => {
                params.parallelism = Some(kv[1].parse()
                    .map_err(|e| anyhow!("Invalid parallelism: {}", e))?);
            }
            _ => {} // Unknown parameter, ignore
        }
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derivation() {
        let params = KdfParams::pbkdf2_sha256(1000);
        let password = "test password";
        
        let derived = derive_key(password.as_bytes(), None, &params).unwrap();
        
        assert_eq!(derived.key().len(), 32);
        assert_eq!(derived.salt().len(), 32);
        assert!(derived.derivation_time().as_millis() > 0);
    }

    #[test]
    fn test_argon2_derivation() {
        let params = KdfParams::argon2id(1, 1024, 1); // Very low parameters for testing
        let password = "test password";
        
        let derived = derive_key(password.as_bytes(), None, &params).unwrap();
        
        assert_eq!(derived.key().len(), 32);
        assert_eq!(derived.salt().len(), 32);
    }

    #[test]
    fn test_hkdf_derivation() {
        let key_material = b"input key material";
        let salt = b"salt";
        let info = b"application info";
        
        let derived = hkdf_derive(key_material, salt, info, 32).unwrap();
        
        assert_eq!(derived.len(), 32);
        
        // Same input should produce same output
        let derived2 = hkdf_derive(key_material, salt, info, 32).unwrap();
        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_password_verification() {
        let params = KdfParams::pbkdf2_sha256(1000);
        let password = "correct password";
        let wrong_password = "wrong password";
        
        let derived = derive_key(password.as_bytes(), None, &params).unwrap();
        
        assert!(derived.verify_password(password).unwrap());
        assert!(!derived.verify_password(wrong_password).unwrap());
    }

    #[test]
    fn test_password_hasher() {
        let hasher = PasswordHasher::new();
        let password = "test password";
        
        let hash = hasher.hash_password(password).unwrap();
        assert!(!hash.is_empty());
        
        assert!(hasher.verify_password(password, &hash).unwrap());
        assert!(!hasher.verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn test_stored_hash_parsing() {
        let hasher = PasswordHasher::new();
        let password = "test password";
        
        let stored_hash = hasher.hash_password(password).unwrap();
        let parsed = parse_stored_hash(&stored_hash).unwrap();
        
        assert!(parsed.verify_password(password).unwrap());
        assert!(!parsed.verify_password("wrong password").unwrap());
    }

    #[test]
    fn test_parameter_tuning() {
        let target_time = std::time::Duration::from_millis(100);
        let test_password = b"test";
        
        let params = tune_parameters(test_password, target_time, KdfAlgorithm::Pbkdf2Sha256).unwrap();
        
        assert_eq!(params.algorithm, KdfAlgorithm::Pbkdf2Sha256);
        assert!(params.iterations > 0);
    }

    #[test]
    fn test_different_algorithms() {
        let password = "test password";
        
        let algorithms = vec![
            KdfAlgorithm::Pbkdf2Sha256,
            KdfAlgorithm::Argon2id,
            KdfAlgorithm::HkdfSha256,
        ];
        
        for algorithm in algorithms {
            let hasher = PasswordHasher::with_algorithm(algorithm);
            let hash = hasher.hash_password(password).unwrap();
            
            assert!(hasher.verify_password(password, &hash).unwrap());
            assert!(!hasher.verify_password("wrong", &hash).unwrap());
        }
    }
}