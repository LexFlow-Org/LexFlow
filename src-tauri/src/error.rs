// ═══════════════════════════════════════════════════════════
//  STRUCTURED ERROR TYPES — replaces Result<T, String>
// ═══════════════════════════════════════════════════════════

// TODO(audit:DEAD-CODE-ERR-1): migrate Result<T, String> call sites to
// Result<T, LexFlowError>. The structured type already exists; the migration
// is mechanical but touches every command in the crate.

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
    /// SEC-ERR-1: never forward arbitrary `String` payloads to Display, because
    /// the Display output reaches the Tauri IPC boundary and ultimately the FE.
    /// Constant Italian strings here keep error messages information-free for
    /// an attacker / logger, while Debug retains the full context for devs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AuthFailed(_) => "Autenticazione fallita",
            Self::Locked => "Vault bloccato",
            Self::PasswordWeak(_) => "Password debole",
            Self::CryptoFailed(_) => "Errore crittografico",
            Self::Io(_) => "Errore I/O",
            Self::Serialization(_) => "Errore di parsing",
            Self::VaultCorrupted(_) => "Vault corrotto",
            Self::RecordNotFound(_) => "Record non trovato",
            Self::Validation(_) => "Dati non validi",
            Self::SearchError(_) => "Errore nella ricerca",
            Self::LicenseError(_) => "Errore licenza",
            Self::BiometricError(_) => "Errore autenticazione biometrica",
            Self::RateLimited(_) => "Troppi tentativi, riprova più tardi",
            Self::RollbackDetected(_) => "Rilevato rollback del vault",
            Self::Internal(_) => "Errore interno",
        };
        f.write_str(s)
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
