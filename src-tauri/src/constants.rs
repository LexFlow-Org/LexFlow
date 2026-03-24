// ═══════════════════════════════════════════════════════════
//  CONSTANTS — Shared across all modules
// ═══════════════════════════════════════════════════════════

pub(crate) const VAULT_FILE: &str = "vault.lex";
pub(crate) const VAULT_SALT_FILE: &str = "vault.salt";
pub(crate) const VAULT_VERIFY_FILE: &str = "vault.verify";
pub(crate) const SETTINGS_FILE: &str = "settings.json";
pub(crate) const AUDIT_LOG_FILE: &str = "vault.audit";
pub(crate) const NOTIF_SCHEDULE_FILE: &str = "notification-schedule.json";
pub(crate) const LICENSE_FILE: &str = "license.json";
pub(crate) const LOCKOUT_FILE: &str = ".lockout";
pub(crate) const LICENSE_SENTINEL_FILE: &str = ".license-sentinel";
pub(crate) const BURNED_KEYS_FILE: &str = ".burned-keys";

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) const BIO_MARKER_FILE: &str = ".bio-enabled";

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) const MACHINE_ID_FILE: &str = ".machine-id";

#[allow(dead_code)]
pub(crate) const BIO_SERVICE: &str = "LexFlow_Bio";

pub(crate) const VAULT_MAGIC: &[u8] = b"LEXFLOW_V2_SECURE";

// V6: Split-file vault layout
pub(crate) const VAULT_DIR: &str = "vault-data";
pub(crate) const VAULT_HEADER_FILE: &str = "header.enc";
pub(crate) const VAULT_INDEX_FILE: &str = "index.enc";
pub(crate) const VAULT_RECORDS_DIR: &str = "records";
pub(crate) const AES_KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;

pub(crate) const ARGON2_M_COST: u32 = 16384;
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 1;

pub(crate) const MAX_SETTINGS_FILE_SIZE: u64 = 10 * 1024 * 1024;

// Platform detection helpers
#[allow(dead_code)]
pub(crate) const IS_ANDROID: bool = cfg!(target_os = "android");
#[allow(dead_code)]
pub(crate) const IS_DESKTOP: bool = cfg!(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux"
));
