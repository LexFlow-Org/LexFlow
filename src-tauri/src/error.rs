// ═══════════════════════════════════════════════════════════
//  STRUCTURED ERROR TYPES — replaces Result<T, String>
// ═══════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug)]
pub enum LexFlowError {
    /// Authentication failed (wrong password, expired token, etc.)
    AuthFailed(String),
    /// Vault is locked — operation requires unlock
    Locked,
    /// Password does not meet strength requirements
    PasswordWeak(String),
    /// Cryptographic operation failed (encrypt, decrypt, HMAC, etc.)
    CryptoFailed(String),
    /// File I/O error
    Io(String),
    /// JSON serialization/deserialization error
    Serialization(String),
    /// Vault file corrupted or tampered
    VaultCorrupted(String),
    /// Record not found in vault
    RecordNotFound(String),
    /// Input validation error (missing fields, invalid format)
    Validation(String),
    /// Search engine error
    SearchError(String),
    /// License verification error
    LicenseError(String),
    /// Biometric authentication error
    BiometricError(String),
    /// Rate limited — too many failed attempts
    RateLimited(String),
    /// Rollback detected — vault may have been replaced
    RollbackDetected(String),
    /// Generic internal error
    Internal(String),
}

impl fmt::Display for LexFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed(msg) => write!(f, "{}", msg),
            Self::Locked => write!(f, "Vault bloccato"),
            Self::PasswordWeak(msg) => write!(f, "{}", msg),
            Self::CryptoFailed(msg) => write!(f, "{}", msg),
            Self::Io(msg) => write!(f, "{}", msg),
            Self::Serialization(msg) => write!(f, "{}", msg),
            Self::VaultCorrupted(msg) => write!(f, "{}", msg),
            Self::RecordNotFound(msg) => write!(f, "{}", msg),
            Self::Validation(msg) => write!(f, "{}", msg),
            Self::SearchError(msg) => write!(f, "{}", msg),
            Self::LicenseError(msg) => write!(f, "{}", msg),
            Self::BiometricError(msg) => write!(f, "{}", msg),
            Self::RateLimited(msg) => write!(f, "{}", msg),
            Self::RollbackDetected(msg) => write!(f, "{}", msg),
            Self::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for LexFlowError {}

// Tauri v2 commands return Result<T, String> — this conversion keeps
// backward compatibility with the frontend's safeInvoke error handling.
impl From<LexFlowError> for String {
    fn from(e: LexFlowError) -> Self {
        e.to_string()
    }
}

// Convenience conversions from common error types
impl From<std::io::Error> for LexFlowError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for LexFlowError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
