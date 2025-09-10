use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use thiserror::Error;
use uuid::Uuid;
use base64::{Engine, engine::general_purpose};
use sha2::{Sha256, Digest};

/// Certificate management system for enterprise authentication
pub struct CertificateManager {
    /// Certificate store
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
    /// Certificate authorities
    certificate_authorities: Arc<RwLock<HashMap<String, CertificateAuthority>>>,
    /// Trust stores
    trust_stores: Arc<RwLock<HashMap<String, TrustStore>>>,
    /// Certificate policies
    certificate_policies: Arc<RwLock<HashMap<String, CertificatePolicy>>>,
    /// Revocation lists
    certificate_revocation_lists: Arc<RwLock<HashMap<String, CertificateRevocationList>>>,
    /// OCSP responders
    ocsp_responders: Arc<RwLock<HashMap<String, OcspResponder>>>,
    /// Configuration
    config: CertificateManagerConfig,
}

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Certificate not found: {cert_id}")]
    CertificateNotFound { cert_id: String },
    
    #[error("Certificate validation failed: {reason}")]
    ValidationFailed { reason: String },
    
    #[error("Certificate expired: {cert_id}")]
    CertificateExpired { cert_id: String },
    
    #[error("Certificate revoked: {cert_id}")]
    CertificateRevoked { cert_id: String },
    
    #[error("Invalid certificate authority: {ca_id}")]
    InvalidCA { ca_id: String },
    
    #[error("Certificate chain validation failed: {reason}")]
    ChainValidationFailed { reason: String },
    
    #[error("OCSP validation failed: {reason}")]
    OcspValidationFailed { reason: String },
    
    #[error("Certificate generation failed: {reason}")]
    GenerationFailed { reason: String },
    
    #[error("Invalid certificate format: {reason}")]
    InvalidFormat { reason: String },
    
    #[error("Trust store error: {reason}")]
    TrustStoreError { reason: String },
    
    #[error("Policy violation: {reason}")]
    PolicyViolation { reason: String },
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// X.509 Certificate representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub serial_number: String,
    pub public_key: PublicKey,
    pub private_key: Option<PrivateKey>, // Only for certificates we own
    pub signature_algorithm: SignatureAlgorithm,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub extensions: Vec<CertificateExtension>,
    pub key_usage: Vec<KeyUsage>,
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
    pub subject_alternative_names: Vec<SubjectAlternativeName>,
    pub certificate_data: Vec<u8>, // DER encoded certificate
    pub fingerprint_sha256: String,
    pub created_at: DateTime<Utc>,
    pub status: CertificateStatus,
    pub revocation_reason: Option<RevocationReason>,
    pub policy_ids: Vec<String>,
}

/// Certificate Authority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub id: String,
    pub name: String,
    pub certificate: Certificate,
    pub signing_policy: CaSigningPolicy,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_responders: Vec<String>,
    pub issued_certificates: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub status: CaStatus,
}

/// Trust store for certificate validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trusted_certificates: Vec<String>,
    pub trusted_cas: Vec<String>,
    pub validation_policy: ValidationPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Certificate policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub key_size_requirements: KeySizeRequirements,
    pub signature_algorithms: Vec<SignatureAlgorithm>,
    pub validity_period: ValidityPeriod,
    pub key_usage_requirements: Vec<KeyUsage>,
    pub extended_key_usage_requirements: Vec<ExtendedKeyUsage>,
    pub subject_requirements: SubjectRequirements,
    pub extension_requirements: Vec<RequiredExtension>,
    pub revocation_policy: RevocationPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Certificate Revocation List
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    pub id: String,
    pub issuer: DistinguishedName,
    pub this_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
    pub revoked_certificates: Vec<RevokedCertificate>,
    pub signature_algorithm: SignatureAlgorithm,
    pub crl_data: Vec<u8>, // DER encoded CRL
}

/// OCSP Responder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponder {
    pub id: String,
    pub url: String,
    pub certificate: String, // Certificate ID for OCSP signing
    pub status: ResponderStatus,
    pub last_updated: DateTime<Utc>,
}

/// Distinguished Name (X.500)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistinguishedName {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state_or_province: Option<String>,
    pub locality: Option<String>,
    pub email_address: Option<String>,
}

/// Public Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: PublicKeyAlgorithm,
    pub key_data: Vec<u8>,
    pub key_size: usize,
    pub parameters: Option<Vec<u8>>,
}

/// Private Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub algorithm: PublicKeyAlgorithm,
    pub key_data: Vec<u8>, // Encrypted private key
    pub encryption_algorithm: Option<String>,
    pub salt: Option<Vec<u8>>,
}

/// Certificate Extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateExtension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

/// Subject Alternative Name
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubjectAlternativeName {
    DnsName(String),
    IpAddress(String),
    Email(String),
    Uri(String),
    DirectoryName(DistinguishedName),
    RegisteredId(String),
}

/// Revoked certificate entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revocation_date: DateTime<Utc>,
    pub reason: RevocationReason,
}

/// Certificate validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub certificate_id: String,
    pub is_valid: bool,
    pub validation_time: DateTime<Utc>,
    pub chain_valid: bool,
    pub not_expired: bool,
    pub not_revoked: bool,
    pub trust_anchor_found: bool,
    pub policy_compliant: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub validated_chain: Vec<String>,
}

/// Authentication request using certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthRequest {
    pub certificate_id: String,
    pub challenge: String,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub additional_claims: HashMap<String, String>,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthResponse {
    pub authenticated: bool,
    pub subject: Option<DistinguishedName>,
    pub certificate_id: Option<String>,
    pub valid_until: Option<DateTime<Utc>>,
    pub granted_permissions: Vec<String>,
    pub session_token: Option<String>,
    pub errors: Vec<String>,
}

// Enums and supporting types

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateStatus {
    Active,
    Expired,
    Revoked,
    Suspended,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CaStatus {
    Active,
    Inactive,
    Compromised,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponderStatus {
    Active,
    Inactive,
    Maintenance,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PublicKeyAlgorithm {
    RsaEncryption,
    EcPublicKey,
    Ed25519,
    DsaPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureAlgorithm {
    Sha256WithRsa,
    Sha384WithRsa,
    Sha512WithRsa,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    IkeIntermediate,
    MsSmartcardLogin,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

// Configuration structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateManagerConfig {
    pub enable_ocsp_validation: bool,
    pub enable_crl_validation: bool,
    pub cache_validation_results: bool,
    pub validation_cache_ttl: Duration,
    pub default_validity_period: Duration,
    pub max_chain_length: usize,
    pub require_policy_compliance: bool,
    pub auto_renew_certificates: bool,
    pub renew_before_expiry: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaSigningPolicy {
    pub allowed_key_sizes: Vec<usize>,
    pub allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    pub max_validity_period: Duration,
    pub require_subject_validation: bool,
    pub allowed_key_usages: Vec<KeyUsage>,
    pub allowed_extended_key_usages: Vec<ExtendedKeyUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationPolicy {
    pub require_valid_chain: bool,
    pub check_revocation: bool,
    pub allow_self_signed: bool,
    pub max_chain_length: usize,
    pub required_key_usage: Vec<KeyUsage>,
    pub allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    pub check_name_constraints: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySizeRequirements {
    pub minimum_rsa_key_size: usize,
    pub minimum_ec_key_size: usize,
    pub allowed_curves: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityPeriod {
    pub minimum_period: Duration,
    pub maximum_period: Duration,
    pub default_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectRequirements {
    pub require_common_name: bool,
    pub require_organization: bool,
    pub require_country: bool,
    pub allowed_countries: Vec<String>,
    pub subject_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredExtension {
    pub oid: String,
    pub critical: bool,
    pub required_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationPolicy {
    pub auto_revoke_on_key_compromise: bool,
    pub revocation_grace_period: Duration,
    pub crl_update_frequency: Duration,
    pub ocsp_response_validity: Duration,
}

impl CertificateManager {
    /// Create new certificate manager
    pub fn new(config: CertificateManagerConfig) -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            certificate_authorities: Arc::new(RwLock::new(HashMap::new())),
            trust_stores: Arc::new(RwLock::new(HashMap::new())),
            certificate_policies: Arc::new(RwLock::new(HashMap::new())),
            certificate_revocation_lists: Arc::new(RwLock::new(HashMap::new())),
            ocsp_responders: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new certificate
    pub async fn create_certificate(
        &self,
        subject: DistinguishedName,
        public_key: PublicKey,
        issuer_ca_id: &str,
        validity_period: Duration,
        key_usage: Vec<KeyUsage>,
        extended_key_usage: Vec<ExtendedKeyUsage>,
        subject_alternative_names: Vec<SubjectAlternativeName>,
    ) -> Result<String, CertificateError> {
        // Validate issuer CA
        let issuer_ca = {
            let cas = self.certificate_authorities.read().await;
            cas.get(issuer_ca_id)
                .ok_or_else(|| CertificateError::InvalidCA { ca_id: issuer_ca_id.to_string() })?
                .clone()
        };

        if issuer_ca.status != CaStatus::Active {
            return Err(CertificateError::InvalidCA { ca_id: issuer_ca_id.to_string() });
        }

        // Validate against CA signing policy
        self.validate_against_ca_policy(&issuer_ca.signing_policy, &public_key, &validity_period, &key_usage, &extended_key_usage)?;

        let cert_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let serial_number = self.generate_serial_number();

        // Generate certificate
        let certificate = Certificate {
            id: cert_id.clone(),
            subject: subject.clone(),
            issuer: issuer_ca.certificate.subject.clone(),
            serial_number,
            public_key,
            private_key: None, // Will be set separately if owned
            signature_algorithm: SignatureAlgorithm::Sha256WithRsa, // Default
            valid_from: now,
            valid_to: now + validity_period,
            extensions: self.generate_standard_extensions(&subject, &subject_alternative_names),
            key_usage,
            extended_key_usage,
            subject_alternative_names,
            certificate_data: self.encode_certificate_der(&subject, &issuer_ca.certificate.subject)?,
            fingerprint_sha256: String::new(), // Will be calculated
            created_at: now,
            status: CertificateStatus::Active,
            revocation_reason: None,
            policy_ids: vec![],
        };

        // Calculate fingerprint
        let mut cert_with_fingerprint = certificate.clone();
        cert_with_fingerprint.fingerprint_sha256 = self.calculate_fingerprint(&certificate.certificate_data);

        // Store certificate
        self.certificates.write().await.insert(cert_id.clone(), cert_with_fingerprint);

        // Update CA's issued certificates list
        {
            let mut cas = self.certificate_authorities.write().await;
            if let Some(ca) = cas.get_mut(issuer_ca_id) {
                ca.issued_certificates.push(cert_id.clone());
            }
        }

        Ok(cert_id)
    }

    /// Validate certificate chain
    pub async fn validate_certificate_chain(
        &self,
        cert_id: &str,
        trust_store_id: Option<&str>,
    ) -> Result<ValidationResult, CertificateError> {
        let certificate = {
            let certs = self.certificates.read().await;
            certs.get(cert_id)
                .ok_or_else(|| CertificateError::CertificateNotFound { cert_id: cert_id.to_string() })?
                .clone()
        };

        let trust_store = if let Some(ts_id) = trust_store_id {
            let trust_stores = self.trust_stores.read().await;
            Some(trust_stores.get(ts_id)
                .ok_or_else(|| CertificateError::TrustStoreError { 
                    reason: format!("Trust store {} not found", ts_id) 
                })?.clone())
        } else {
            None
        };

        let validation_time = Utc::now();
        let mut result = ValidationResult {
            certificate_id: cert_id.to_string(),
            is_valid: true,
            validation_time,
            chain_valid: true,
            not_expired: true,
            not_revoked: true,
            trust_anchor_found: false,
            policy_compliant: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            validated_chain: vec![cert_id.to_string()],
        };

        // Check expiration
        if certificate.valid_to <= validation_time {
            result.not_expired = false;
            result.is_valid = false;
            result.errors.push("Certificate has expired".to_string());
        }

        if certificate.valid_from > validation_time {
            result.not_expired = false;
            result.is_valid = false;
            result.errors.push("Certificate is not yet valid".to_string());
        }

        // Check revocation status
        if let Err(e) = self.check_revocation_status(&certificate).await {
            result.not_revoked = false;
            result.is_valid = false;
            result.errors.push(format!("Revocation check failed: {}", e));
        }

        // Build and validate certificate chain
        match self.build_certificate_chain(&certificate, trust_store.as_ref()).await {
            Ok(chain) => {
                result.validated_chain = chain;
                result.trust_anchor_found = true;
            }
            Err(e) => {
                result.chain_valid = false;
                result.is_valid = false;
                result.errors.push(format!("Chain validation failed: {}", e));
            }
        }

        // Check policy compliance
        if self.config.require_policy_compliance {
            if let Err(e) = self.check_policy_compliance(&certificate).await {
                result.policy_compliant = false;
                result.is_valid = false;
                result.errors.push(format!("Policy violation: {}", e));
            }
        }

        Ok(result)
    }

    /// Authenticate using certificate
    pub async fn authenticate_certificate(
        &self,
        auth_request: CertificateAuthRequest,
    ) -> Result<CertificateAuthResponse, CertificateError> {
        // Validate certificate
        let validation_result = self.validate_certificate_chain(&auth_request.certificate_id, None).await?;
        
        if !validation_result.is_valid {
            return Ok(CertificateAuthResponse {
                authenticated: false,
                subject: None,
                certificate_id: None,
                valid_until: None,
                granted_permissions: Vec::new(),
                session_token: None,
                errors: validation_result.errors,
            });
        }

        let certificate = {
            let certs = self.certificates.read().await;
            certs.get(&auth_request.certificate_id)
                .ok_or_else(|| CertificateError::CertificateNotFound { cert_id: auth_request.certificate_id.clone() })?
                .clone()
        };

        // Verify signature
        if !self.verify_authentication_signature(&certificate, &auth_request).await? {
            return Ok(CertificateAuthResponse {
                authenticated: false,
                subject: None,
                certificate_id: None,
                valid_until: None,
                granted_permissions: Vec::new(),
                session_token: None,
                errors: vec!["Invalid signature".to_string()],
            });
        }

        // Generate session token
        let session_token = self.generate_session_token(&certificate).await?;

        // Determine permissions based on certificate attributes
        let permissions = self.extract_permissions(&certificate).await;

        Ok(CertificateAuthResponse {
            authenticated: true,
            subject: Some(certificate.subject),
            certificate_id: Some(certificate.id),
            valid_until: Some(certificate.valid_to),
            granted_permissions: permissions,
            session_token: Some(session_token),
            errors: Vec::new(),
        })
    }

    /// Revoke certificate
    pub async fn revoke_certificate(
        &self,
        cert_id: &str,
        reason: RevocationReason,
    ) -> Result<(), CertificateError> {
        let mut certificates = self.certificates.write().await;
        let certificate = certificates.get_mut(cert_id)
            .ok_or_else(|| CertificateError::CertificateNotFound { cert_id: cert_id.to_string() })?;

        certificate.status = CertificateStatus::Revoked;
        certificate.revocation_reason = Some(reason.clone());

        // Add to CRL
        let revoked_cert = RevokedCertificate {
            serial_number: certificate.serial_number.clone(),
            revocation_date: Utc::now(),
            reason,
        };

        // Find issuer CA and update CRL
        let issuer_name = &certificate.issuer;
        let cas = self.certificate_authorities.read().await;
        for ca in cas.values() {
            if ca.certificate.subject == *issuer_name {
                // Update CRL (simplified implementation)
                break;
            }
        }

        Ok(())
    }

    /// Create certificate authority
    pub async fn create_certificate_authority(
        &self,
        name: String,
        subject: DistinguishedName,
        key_pair: (PublicKey, PrivateKey),
        signing_policy: CaSigningPolicy,
        validity_period: Duration,
    ) -> Result<String, CertificateError> {
        let ca_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Create self-signed CA certificate
        let ca_cert = Certificate {
            id: format!("{}_cert", ca_id),
            subject: subject.clone(),
            issuer: subject.clone(), // Self-signed
            serial_number: self.generate_serial_number(),
            public_key: key_pair.0,
            private_key: Some(key_pair.1),
            signature_algorithm: SignatureAlgorithm::Sha256WithRsa,
            valid_from: now,
            valid_to: now + validity_period,
            extensions: self.generate_ca_extensions(),
            key_usage: vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
            extended_key_usage: vec![],
            subject_alternative_names: vec![],
            certificate_data: self.encode_certificate_der(&subject, &subject)?,
            fingerprint_sha256: String::new(),
            created_at: now,
            status: CertificateStatus::Active,
            revocation_reason: None,
            policy_ids: vec![],
        };

        let ca = CertificateAuthority {
            id: ca_id.clone(),
            name,
            certificate: ca_cert.clone(),
            signing_policy,
            crl_distribution_points: vec![],
            ocsp_responders: vec![],
            issued_certificates: vec![],
            created_at: now,
            status: CaStatus::Active,
        };

        // Store CA and its certificate
        self.certificate_authorities.write().await.insert(ca_id.clone(), ca);
        self.certificates.write().await.insert(ca_cert.id, ca_cert);

        Ok(ca_id)
    }

    /// Create trust store
    pub async fn create_trust_store(
        &self,
        name: String,
        description: String,
        validation_policy: ValidationPolicy,
    ) -> Result<String, CertificateError> {
        let trust_store_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let trust_store = TrustStore {
            id: trust_store_id.clone(),
            name,
            description,
            trusted_certificates: vec![],
            trusted_cas: vec![],
            validation_policy,
            created_at: now,
            updated_at: now,
        };

        self.trust_stores.write().await.insert(trust_store_id.clone(), trust_store);
        Ok(trust_store_id)
    }

    // Private helper methods

    fn validate_against_ca_policy(
        &self,
        policy: &CaSigningPolicy,
        public_key: &PublicKey,
        validity_period: &Duration,
        key_usage: &[KeyUsage],
        extended_key_usage: &[ExtendedKeyUsage],
    ) -> Result<(), CertificateError> {
        // Check key size
        if !policy.allowed_key_sizes.contains(&public_key.key_size) {
            return Err(CertificateError::PolicyViolation {
                reason: format!("Key size {} not allowed", public_key.key_size),
            });
        }

        // Check validity period
        if *validity_period > policy.max_validity_period {
            return Err(CertificateError::PolicyViolation {
                reason: "Validity period exceeds maximum allowed".to_string(),
            });
        }

        // Check key usage
        for usage in key_usage {
            if !policy.allowed_key_usages.contains(usage) {
                return Err(CertificateError::PolicyViolation {
                    reason: format!("Key usage {:?} not allowed", usage),
                });
            }
        }

        // Check extended key usage
        for ext_usage in extended_key_usage {
            if !policy.allowed_extended_key_usages.contains(ext_usage) {
                return Err(CertificateError::PolicyViolation {
                    reason: format!("Extended key usage {:?} not allowed", ext_usage),
                });
            }
        }

        Ok(())
    }

    fn generate_serial_number(&self) -> String {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut serial = [0u8; 16];
        rng.fill_bytes(&mut serial);
        general_purpose::STANDARD.encode(&serial)
    }

    fn generate_standard_extensions(
        &self,
        _subject: &DistinguishedName,
        _sans: &[SubjectAlternativeName],
    ) -> Vec<CertificateExtension> {
        vec![
            CertificateExtension {
                oid: "2.5.29.14".to_string(), // Subject Key Identifier
                critical: false,
                value: vec![0x04, 0x14], // Example value
            },
            CertificateExtension {
                oid: "2.5.29.35".to_string(), // Authority Key Identifier
                critical: false,
                value: vec![0x30, 0x16], // Example value
            },
        ]
    }

    fn generate_ca_extensions(&self) -> Vec<CertificateExtension> {
        vec![
            CertificateExtension {
                oid: "2.5.29.19".to_string(), // Basic Constraints
                critical: true,
                value: vec![0x30, 0x03, 0x01, 0x01, 0xFF], // CA:TRUE
            },
            CertificateExtension {
                oid: "2.5.29.14".to_string(), // Subject Key Identifier
                critical: false,
                value: vec![0x04, 0x14], // Example value
            },
        ]
    }

    fn encode_certificate_der(
        &self,
        _subject: &DistinguishedName,
        _issuer: &DistinguishedName,
    ) -> Result<Vec<u8>, CertificateError> {
        // Simplified DER encoding - in production, use proper ASN.1 library
        Ok(b"MOCK_CERTIFICATE_DER_DATA".to_vec())
    }

    fn calculate_fingerprint(&self, cert_data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_data);
        format!("{:x}", hasher.finalize())
    }

    async fn check_revocation_status(&self, certificate: &Certificate) -> Result<(), CertificateError> {
        if certificate.status == CertificateStatus::Revoked {
            return Err(CertificateError::CertificateRevoked { cert_id: certificate.id.clone() });
        }

        // Check CRL if enabled
        if self.config.enable_crl_validation {
            // Implementation would check CRL
        }

        // Check OCSP if enabled
        if self.config.enable_ocsp_validation {
            // Implementation would check OCSP
        }

        Ok(())
    }

    async fn build_certificate_chain(
        &self,
        certificate: &Certificate,
        trust_store: Option<&TrustStore>,
    ) -> Result<Vec<String>, CertificateError> {
        let mut chain = vec![certificate.id.clone()];

        // For self-signed certificates
        if certificate.subject == certificate.issuer {
            return Ok(chain);
        }

        // Build chain by following issuer links
        let mut current_cert = certificate.clone();
        let certificates = self.certificates.read().await;
        let cas = self.certificate_authorities.read().await;

        while current_cert.subject != current_cert.issuer {
            // Find issuer certificate
            let mut issuer_found = false;
            
            // Check in CAs first
            for ca in cas.values() {
                if ca.certificate.subject == current_cert.issuer {
                    chain.push(ca.certificate.id.clone());
                    current_cert = ca.certificate.clone();
                    issuer_found = true;
                    break;
                }
            }

            // Check in regular certificates
            if !issuer_found {
                for cert in certificates.values() {
                    if cert.subject == current_cert.issuer {
                        chain.push(cert.id.clone());
                        current_cert = cert.clone();
                        issuer_found = true;
                        break;
                    }
                }
            }

            if !issuer_found {
                return Err(CertificateError::ChainValidationFailed {
                    reason: "Issuer certificate not found".to_string(),
                });
            }

            if chain.len() > self.config.max_chain_length {
                return Err(CertificateError::ChainValidationFailed {
                    reason: "Chain too long".to_string(),
                });
            }
        }

        // Validate against trust store if provided
        if let Some(ts) = trust_store {
            let root_cert_id = chain.last().unwrap();
            if !ts.trusted_certificates.contains(root_cert_id) &&
               !ts.trusted_cas.iter().any(|ca_id| {
                   cas.get(ca_id).map_or(false, |ca| ca.certificate.id == *root_cert_id)
               }) {
                return Err(CertificateError::ChainValidationFailed {
                    reason: "Root certificate not trusted".to_string(),
                });
            }
        }

        Ok(chain)
    }

    async fn check_policy_compliance(&self, _certificate: &Certificate) -> Result<(), String> {
        // Placeholder implementation for policy compliance checking
        Ok(())
    }

    async fn verify_authentication_signature(
        &self,
        certificate: &Certificate,
        auth_request: &CertificateAuthRequest,
    ) -> Result<bool, CertificateError> {
        // Simplified signature verification
        // In production, use proper cryptographic verification
        
        // Create message to verify
        let message = format!("{}{}", auth_request.challenge, auth_request.timestamp);
        
        // Simulate signature verification
        let expected_signature_len = match certificate.public_key.algorithm {
            PublicKeyAlgorithm::RsaEncryption => 256, // RSA-2048
            PublicKeyAlgorithm::EcPublicKey => 64,    // ECDSA P-256
            PublicKeyAlgorithm::Ed25519 => 64,        // Ed25519
            _ => 256,
        };

        Ok(auth_request.signature.len() == expected_signature_len && 
           !auth_request.signature.is_empty())
    }

    async fn generate_session_token(&self, certificate: &Certificate) -> Result<String, CertificateError> {
        // Generate JWT-like session token
        let payload = serde_json::json!({
            "sub": certificate.subject.common_name.clone().unwrap_or_default(),
            "cert_id": certificate.id,
            "exp": (Utc::now() + Duration::hours(24)).timestamp(),
            "iat": Utc::now().timestamp(),
        });

        let token = general_purpose::STANDARD.encode(payload.to_string());
        Ok(format!("cert_session_{}", token))
    }

    async fn extract_permissions(&self, certificate: &Certificate) -> Vec<String> {
        let mut permissions = Vec::new();

        // Extract permissions based on key usage
        for usage in &certificate.key_usage {
            match usage {
                KeyUsage::DigitalSignature => permissions.push("digital_signature".to_string()),
                KeyUsage::KeyEncipherment => permissions.push("encryption".to_string()),
                KeyUsage::DataEncipherment => permissions.push("data_encryption".to_string()),
                _ => {}
            }
        }

        // Extract permissions based on extended key usage
        for ext_usage in &certificate.extended_key_usage {
            match ext_usage {
                ExtendedKeyUsage::ServerAuth => permissions.push("server_auth".to_string()),
                ExtendedKeyUsage::ClientAuth => permissions.push("client_auth".to_string()),
                ExtendedKeyUsage::CodeSigning => permissions.push("code_signing".to_string()),
                ExtendedKeyUsage::EmailProtection => permissions.push("email_protection".to_string()),
                _ => {}
            }
        }

        // Add role-based permissions based on subject
        if let Some(ou) = &certificate.subject.organizational_unit {
            match ou.as_str() {
                "Administrators" => {
                    permissions.push("admin".to_string());
                    permissions.push("read".to_string());
                    permissions.push("write".to_string());
                }
                "Users" => {
                    permissions.push("read".to_string());
                }
                "Operators" => {
                    permissions.push("read".to_string());
                    permissions.push("write".to_string());
                }
                _ => {}
            }
        }

        permissions.sort();
        permissions.dedup();
        permissions
    }
}

impl Default for CertificateManagerConfig {
    fn default() -> Self {
        Self {
            enable_ocsp_validation: true,
            enable_crl_validation: true,
            cache_validation_results: true,
            validation_cache_ttl: Duration::minutes(30),
            default_validity_period: Duration::days(365),
            max_chain_length: 10,
            require_policy_compliance: true,
            auto_renew_certificates: true,
            renew_before_expiry: Duration::days(30),
        }
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            require_valid_chain: true,
            check_revocation: true,
            allow_self_signed: false,
            max_chain_length: 10,
            required_key_usage: vec![],
            allowed_signature_algorithms: vec![
                SignatureAlgorithm::Sha256WithRsa,
                SignatureAlgorithm::EcdsaWithSha256,
                SignatureAlgorithm::Ed25519,
            ],
            check_name_constraints: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_manager_creation() -> Result<(), Box<dyn std::error::Error>> {
        let config = CertificateManagerConfig::default();
        let cert_manager = CertificateManager::new(config);

        // Test basic creation
        assert_eq!(cert_manager.certificates.read().await.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_certificate_authority_creation() -> Result<(), Box<dyn std::error::Error>> {
        let config = CertificateManagerConfig::default();
        let cert_manager = CertificateManager::new(config);

        let subject = DistinguishedName {
            common_name: Some("Test CA".to_string()),
            organization: Some("Test Org".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state_or_province: Some("California".to_string()),
            locality: Some("San Francisco".to_string()),
            email_address: Some("ca@test.com".to_string()),
        };

        let public_key = PublicKey {
            algorithm: PublicKeyAlgorithm::RsaEncryption,
            key_data: vec![0u8; 256],
            key_size: 2048,
            parameters: None,
        };

        let private_key = PrivateKey {
            algorithm: PublicKeyAlgorithm::RsaEncryption,
            key_data: vec![0u8; 256],
            encryption_algorithm: None,
            salt: None,
        };

        let signing_policy = CaSigningPolicy {
            allowed_key_sizes: vec![2048, 4096],
            allowed_signature_algorithms: vec![SignatureAlgorithm::Sha256WithRsa],
            max_validity_period: Duration::days(365),
            require_subject_validation: true,
            allowed_key_usages: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            allowed_extended_key_usages: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
        };

        let ca_id = cert_manager.create_certificate_authority(
            "Test CA".to_string(),
            subject,
            (public_key, private_key),
            signing_policy,
            Duration::days(3650),
        ).await?;

        assert!(!ca_id.is_empty());
        assert_eq!(cert_manager.certificate_authorities.read().await.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_certificate_validation() -> Result<(), Box<dyn std::error::Error>> {
        let config = CertificateManagerConfig::default();
        let cert_manager = CertificateManager::new(config);

        // Create a mock certificate for testing
        let cert = Certificate {
            id: "test-cert".to_string(),
            subject: DistinguishedName {
                common_name: Some("Test Certificate".to_string()),
                organization: Some("Test Org".to_string()),
                organizational_unit: None,
                country: Some("US".to_string()),
                state_or_province: None,
                locality: None,
                email_address: None,
            },
            issuer: DistinguishedName {
                common_name: Some("Test CA".to_string()),
                organization: Some("Test Org".to_string()),
                organizational_unit: None,
                country: Some("US".to_string()),
                state_or_province: None,
                locality: None,
                email_address: None,
            },
            serial_number: "123456".to_string(),
            public_key: PublicKey {
                algorithm: PublicKeyAlgorithm::RsaEncryption,
                key_data: vec![0u8; 256],
                key_size: 2048,
                parameters: None,
            },
            private_key: None,
            signature_algorithm: SignatureAlgorithm::Sha256WithRsa,
            valid_from: Utc::now() - Duration::hours(1),
            valid_to: Utc::now() + Duration::days(365),
            extensions: vec![],
            key_usage: vec![KeyUsage::DigitalSignature],
            extended_key_usage: vec![ExtendedKeyUsage::ClientAuth],
            subject_alternative_names: vec![],
            certificate_data: b"MOCK_CERT_DATA".to_vec(),
            fingerprint_sha256: "mock_fingerprint".to_string(),
            created_at: Utc::now(),
            status: CertificateStatus::Active,
            revocation_reason: None,
            policy_ids: vec![],
        };

        cert_manager.certificates.write().await.insert("test-cert".to_string(), cert);

        // Test validation
        let validation_result = cert_manager.validate_certificate_chain("test-cert", None).await?;
        
        // Should not be valid because we don't have the issuer CA
        assert!(!validation_result.is_valid);
        assert!(!validation_result.chain_valid);

        Ok(())
    }
}