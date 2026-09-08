// ═══════════════════════════════════════════════════════════
//  BIOMETRICS — Touch ID; Windows credential cleanup
// ═══════════════════════════════════════════════════════════

use crate::state::AppState;
use serde_json::Value;
use std::sync::{Mutex, OnceLock};
#[cfg(not(target_os = "windows"))]
use std::time::{Duration as StdDuration, Instant};
use tauri::State;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────
//  macOS Keychain ACL helper (HIGH-S-1 remediation)
// ─────────────────────────────────────────────────────────────────────
// macOS credentials are stored with an explicit biometric ACL. Reading an
// ordinary generic-password item is not proof of biometric authentication.
// We therefore reject legacy items that are readable while authentication UI
// is suppressed. They must be enrolled again after a normal password login.
// LocalAuthentication capability detection is compiled into the app; only
// the ACL-protected Keychain read requests Touch ID during login.
#[cfg(target_os = "macos")]
mod macos_keychain {
    use core_foundation::base::{CFRelease, CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::{CFData, CFDataRef};
    use core_foundation::string::{CFString, CFStringRef};
    use std::ptr;

    // Raw FFI bindings — Security.framework + CoreFoundation. We only
    // declare the symbols we actually call; the Apple SDK guarantees ABI
    // stability.
    #[allow(non_upper_case_globals)]
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecAccessControlCreateWithFlags(
            allocator: CFTypeRef,
            protection: CFTypeRef,
            flags: u32,
            error: *mut CFTypeRef,
        ) -> CFTypeRef;

        fn SecItemAdd(query: CFTypeRef, result: *mut CFTypeRef) -> i32;
        fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> i32;
        fn SecItemDelete(query: CFTypeRef) -> i32;

        // Keychain attribute constants come in as CFStringRef globals.
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;
        static kSecAttrAccessControl: CFStringRef;
        static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
        // Suppress the biometric prompt during ACL self-test so we can
        // detect misconfigured entries without burning a Touch ID.
        static kSecUseAuthenticationUI: CFStringRef;
        static kSecUseAuthenticationUIFail: CFStringRef;
        static kSecUseDataProtectionKeychain: CFStringRef;
    }

    // CFDictionary creation — using the CoreFoundation FFI directly so we
    // can mix value types (CFString, CFData, SecAccessControl ref) without
    // jumping through `core_foundation::dictionary::CFDictionary`'s
    // homogeneous-pair API.
    //
    // NOTE: `CFDictionaryKeyCallBacks` / `…ValueCallBacks` are exposed by
    // CoreFoundation as named structs. Rust extern statics need a `Sized`
    // type, so we declare them as opaque newtypes — we never read their
    // contents, only their address.
    #[repr(C)]
    struct CFDictionaryCallBacks {
        _private: [u8; 0],
    }

    #[allow(non_upper_case_globals)]
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFDictionaryCreate(
            allocator: CFTypeRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: isize,
            key_callbacks: *const CFDictionaryCallBacks,
            value_callbacks: *const CFDictionaryCallBacks,
        ) -> CFTypeRef;

        // CFType callback constants — opaque pointers exposed as globals.
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
    }

    // SecAccessControlCreateFlags — ABI bits per Apple SDK.
    // <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
    const K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET: u32 = 1 << 3;

    // OSStatus codes we care about.
    const ERR_SEC_SUCCESS: i32 = 0;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
    const ERR_SEC_AUTH_FAILED: i32 = -25293;

    /// Build a `CFDictionary` with the given (CFTypeRef, CFTypeRef) pairs.
    /// Returns the raw `CFTypeRef` (caller owns the returned reference and
    /// must release it with `CFRelease`).
    unsafe fn make_query(pairs: &[(CFTypeRef, CFTypeRef)]) -> CFTypeRef {
        let keys: Vec<CFTypeRef> = pairs.iter().map(|(k, _)| *k).collect();
        let vals: Vec<CFTypeRef> = pairs.iter().map(|(_, v)| *v).collect();
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            vals.as_ptr(),
            pairs.len() as isize,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }

    /// Build a `SecAccessControl` reference bound to the current
    /// biometric set. Returns the raw `CFTypeRef` (caller owns and must
    /// `CFRelease`).
    fn build_biometric_acl() -> Result<CFTypeRef, String> {
        unsafe {
            let mut error: CFTypeRef = ptr::null();
            let acl = SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET,
                &mut error as *mut CFTypeRef,
            );
            if acl.is_null() {
                if !error.is_null() {
                    CFRelease(error);
                }
                return Err("SecAccessControlCreateWithFlags returned NULL".into());
            }
            Ok(acl)
        }
    }

    /// Save the hashed password under the given service+account with a
    /// biometric ACL. If an entry already exists it is deleted first
    /// (SecItemAdd would otherwise fail with errSecDuplicateItem).
    pub(super) fn save_with_acl(
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<(), String> {
        // Delete any existing entry (ignoring not-found) so we don't
        // hit errSecDuplicateItem on re-save.
        let _ = delete(service, account);

        unsafe {
            let acl = build_biometric_acl()?;

            let svc = CFString::new(service);
            let acc = CFString::new(account);
            let data = CFData::from_buffer(password.as_bytes());

            let pairs: [(CFTypeRef, CFTypeRef); 6] = [
                (
                    kSecUseDataProtectionKeychain as CFTypeRef,
                    CFBoolean::true_value().as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (
                    kSecAttrService as CFTypeRef,
                    svc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecAttrAccount as CFTypeRef,
                    acc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecValueData as CFTypeRef,
                    data.as_concrete_TypeRef() as CFTypeRef,
                ),
                (kSecAttrAccessControl as CFTypeRef, acl),
            ];
            let query = make_query(&pairs);
            if query.is_null() {
                CFRelease(acl);
                return Err("CFDictionaryCreate returned NULL".into());
            }

            let mut result: CFTypeRef = ptr::null();
            let status = SecItemAdd(query, &mut result as *mut CFTypeRef);

            CFRelease(query);
            CFRelease(acl);

            if status == ERR_SEC_SUCCESS {
                Ok(())
            } else {
                Err(format!("Impossibile abilitare il Portachiavi biometrico protetto (macOS {}). Usa la password; verifica firma e autorizzazioni dell'app.", status))
            }
        }
    }

    /// Read the password back. This call WILL trigger a biometric
    /// prompt on a properly-ACL'd entry. If the entry was created
    /// without ACL (legacy keyring entry) the read returns the bytes
    /// directly with no prompt — which is exactly the failure mode
    /// `verify_acl_enforced()` exists to detect.
    ///
    /// This is the single authentication prompt in the macOS login flow.
    /// A preliminary suppressed-UI check rejects unprotected legacy items.
    pub(super) fn load(service: &str, account: &str) -> Result<String, String> {
        unsafe {
            let svc = CFString::new(service);
            let acc = CFString::new(account);
            let cf_true = CFBoolean::true_value();

            let pairs: [(CFTypeRef, CFTypeRef); 6] = [
                (
                    kSecUseDataProtectionKeychain as CFTypeRef,
                    CFBoolean::true_value().as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (
                    kSecAttrService as CFTypeRef,
                    svc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecAttrAccount as CFTypeRef,
                    acc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecReturnData as CFTypeRef,
                    cf_true.as_concrete_TypeRef() as CFTypeRef,
                ),
                (kSecMatchLimit as CFTypeRef, kSecMatchLimitOne as CFTypeRef),
            ];
            let query = make_query(&pairs);
            if query.is_null() {
                return Err("CFDictionaryCreate returned NULL".into());
            }

            let mut result: CFTypeRef = ptr::null();
            let status = SecItemCopyMatching(query, &mut result as *mut CFTypeRef);
            CFRelease(query);

            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Err("not-found".into());
            }
            if status != ERR_SEC_SUCCESS || result.is_null() {
                return Err(format!("SecItemCopyMatching failed: OSStatus={}", status));
            }

            let data = CFData::wrap_under_create_rule(result as CFDataRef);
            let bytes = data.bytes().to_vec();
            String::from_utf8(bytes).map_err(|e| e.to_string())
        }
    }

    /// Delete the entry. Returns Ok(()) even if the entry didn't
    /// exist (idempotent — matches the keyring crate semantics).
    pub(super) fn delete(service: &str, account: &str) -> Result<(), String> {
        unsafe {
            let svc = CFString::new(service);
            let acc = CFString::new(account);

            let pairs: [(CFTypeRef, CFTypeRef); 4] = [
                (
                    kSecUseDataProtectionKeychain as CFTypeRef,
                    CFBoolean::true_value().as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (
                    kSecAttrService as CFTypeRef,
                    svc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecAttrAccount as CFTypeRef,
                    acc.as_concrete_TypeRef() as CFTypeRef,
                ),
            ];
            let query = make_query(&pairs);
            if query.is_null() {
                return Err("CFDictionaryCreate returned NULL".into());
            }

            let status = SecItemDelete(query);
            CFRelease(query);

            if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
                Ok(())
            } else {
                Err(format!("SecItemDelete failed: OSStatus={}", status))
            }
        }
    }

    /// ACL self-test: try to read the entry with `kSecUseAuthenticationUI
    /// = kSecUseAuthenticationUIFail`. If the read SUCCEEDS, the entry
    /// has no biometric ACL (security regression). If it returns
    /// `errSecInteractionNotAllowed` / `errSecAuthFailed`, the ACL is
    /// correctly enforced. Returns `Ok(true)` when the ACL is active.
    pub(super) fn verify_acl_enforced(service: &str, account: &str) -> Result<bool, String> {
        unsafe {
            let svc = CFString::new(service);
            let acc = CFString::new(account);
            let cf_true = CFBoolean::true_value();

            let pairs: [(CFTypeRef, CFTypeRef); 6] = [
                (
                    kSecUseDataProtectionKeychain as CFTypeRef,
                    CFBoolean::true_value().as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (
                    kSecAttrService as CFTypeRef,
                    svc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecAttrAccount as CFTypeRef,
                    acc.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecReturnData as CFTypeRef,
                    cf_true.as_concrete_TypeRef() as CFTypeRef,
                ),
                (
                    kSecUseAuthenticationUI as CFTypeRef,
                    kSecUseAuthenticationUIFail as CFTypeRef,
                ),
            ];
            let query = make_query(&pairs);
            if query.is_null() {
                return Err("CFDictionaryCreate returned NULL".into());
            }

            let mut result: CFTypeRef = ptr::null();
            let status = SecItemCopyMatching(query, &mut result as *mut CFTypeRef);
            CFRelease(query);
            if !result.is_null() {
                CFRelease(result);
            }

            match status {
                // Read succeeded WITHOUT a biometric prompt → no ACL.
                ERR_SEC_SUCCESS => Ok(false),
                // The expected outcome on a properly-ACL'd entry: the
                // framework refuses to read because UI is suppressed.
                ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED => Ok(true),
                ERR_SEC_ITEM_NOT_FOUND => Err("not-found".into()),
                _ => Err(format!("verify_acl: OSStatus={}", status)),
            }
        }
    }

    /// Require the biometric ACL; never silently store an unprotected fallback.
    pub(super) fn save_protected(
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<(), String> {
        if !super::check_bio_hardware() {
            return Err("Biometria non disponibile per questa build o configurazione macOS. Usa la password; l'accesso protetto al Portachiavi richiede firma ed entitlement compatibili.".into());
        }
        save_with_acl(service, account, password)?;
        match verify_acl_enforced(service, account) {
            Ok(true) => Ok(()),
            _ => {
                delete_both(service, account);
                Err(
                    "Impossibile proteggere la credenziale con la biometria. Usa la password."
                        .into(),
                )
            }
        }
    }

    /// Require protection before releasing a credential. Never fall back to
    /// plain keyring reads: cancelling Touch ID or finding a legacy item means
    /// the user must use the vault password and enroll biometrics again.
    pub(super) fn load_protected(service: &str, account: &str) -> Result<String, String> {
        load_if_protected(verify_acl_enforced(service, account), || {
            load(service, account)
        })
    }

    fn load_if_protected(
        protection: Result<bool, String>,
        read: impl FnOnce() -> Result<String, String>,
    ) -> Result<String, String> {
        match protection {
            Ok(true) => read(),
            _ => Err("Biometria non configurata o credenziale non protetta. Accedi con la password e riconfigura la biometria nelle Impostazioni.".into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::load_if_protected;

        #[test]
        fn unprotected_or_missing_acl_never_reads_a_credential() {
            for verification in [Ok(false), Err("not-found".into()), Err("cancelled".into())] {
                assert!(
                    load_if_protected(verification, || panic!("Unprotected credential read"))
                        .is_err()
                );
            }
            assert_eq!(
                load_if_protected(Ok(true), || Ok("synthetic".into())).unwrap(),
                "synthetic"
            );
            assert!(load_if_protected(Ok(true), || Err("cancelled".into())).is_err());
        }
    }

    /// Best-effort delete: hit both the ACL'd path and the legacy
    /// keyring path so we don't leave orphaned entries behind.
    pub(super) fn delete_both(service: &str, account: &str) {
        let _ = delete(service, account);
        if let Ok(entry) = keyring::Entry::new(service, account) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "windows")))]
use serde_json::json;

#[cfg(not(target_os = "android"))]
use crate::constants::*;
#[cfg(not(any(target_os = "android", target_os = "windows")))]
use crate::io::secure_write;
#[cfg(not(any(target_os = "android", target_os = "windows")))]
use crate::lockout::check_lockout;
#[cfg(not(any(target_os = "android", target_os = "windows")))]
use crate::vault::unlock_vault_with_password;
#[cfg(not(target_os = "android"))]
use std::fs;

/// Cross-call serialisation lock: ensures `bio_login` (which reads from the
/// keyring then unlocks the vault) cannot race with a concurrent `clear_bio`
/// (which deletes the keyring entry), and vice versa. macOS authentication may
/// keep this mutex held while the OS prompt is open; it is not a timed child.
#[cfg(not(target_os = "android"))]
static BIO_OP_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(not(target_os = "android"))]
fn bio_op_lock() -> &'static Mutex<()> {
    BIO_OP_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Per-process rate limiter for `clear_bio`. Allows at most one successful
/// clear every 60 seconds — any caller that fires faster is silently
/// refused. Mitigates a low-cost DoS where an attacker repeatedly disables
/// biometric login to force the user to re-enter their password.
///
/// The inner `Option<Instant>` is `None` before the first successful clear
/// (so the first call always passes), then holds the timestamp of the last
/// allowed invocation.
#[cfg(not(target_os = "windows"))]
static LAST_CLEAR_BIO: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
#[cfg(not(target_os = "windows"))]
const CLEAR_BIO_RATE_LIMIT: StdDuration = StdDuration::from_secs(60);

/// This is checked before any keychain mutation; UI consent alone is not an
/// authorization boundary. The caller serializes with write_mutex so the vault
/// cannot change or lock after this check and before the credential is stored.
#[cfg(any(not(any(target_os = "android", target_os = "windows")), test))]
fn authorize_bio_enrollment(state: &AppState, password: &str) -> Result<(), String> {
    let session = state.document_session()?;
    if password.len() != 64 || !password.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Password biometrica non valida.".into());
    }
    let directory = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (_, verified_dek) = crate::vault_engine::open_current_vault(&directory, password)
        .map_err(|_| "Password non corretta. Biometria invariata.".to_string())?;
    state.validate_document_session(session)?;
    let active = state.vault_dek.lock().unwrap_or_else(|e| e.into_inner());
    let current = &active.as_ref().ok_or("Archivio bloccato.")?.0;
    let same_key = {
        current.len() == verified_dek.len()
            && current
                .iter()
                .zip(verified_dek.iter())
                .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                == 0
    };
    if !same_key {
        return Err("Archivio modificato. Ripeti l'accesso.".into());
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn check_bio() -> bool {
    #[cfg(target_os = "macos")]
    {
        // LocalAuthentication capability checks are prompt-free. Recheck so a
        // temporary lockout or newly enrolled finger does not last for the app's
        // entire lifetime in a cached negative result.
        check_bio_status().available
    }
    #[cfg(target_os = "windows")]
    {
        false
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        static BIO_AVAILABLE: OnceLock<bool> = OnceLock::new();
        *BIO_AVAILABLE.get_or_init(check_bio_hardware)
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BioStatus {
    available: bool,
    reason: &'static str,
    // Current policy readiness, not a claim that the device lacks a sensor.
    device_ready: Option<bool>,
    // Presence of the required app entitlement. Actual enrollment also checks
    // whether Security.framework accepts and enforces the protected item ACL.
    app_authorized: Option<bool>,
}

#[cfg(any(target_os = "macos", test))]
fn macos_status_from_flags(flags: i32) -> BioStatus {
    // ABI bits are defined in macos_biometry.m. Unknown bits fail closed.
    if flags & !3 != 0 {
        return BioStatus {
            available: false,
            reason: "check_failed",
            device_ready: None,
            app_authorized: None,
        };
    }
    let device_ready = flags & 1 != 0;
    let app_authorized = flags & 2 != 0;
    BioStatus {
        available: device_ready && app_authorized,
        reason: if !app_authorized {
            "build_not_authorized"
        } else if !device_ready {
            "device_unavailable"
        } else {
            "available"
        },
        device_ready: Some(device_ready),
        app_authorized: Some(app_authorized),
    }
}

/// Read-only diagnostics: no authentication UI and no Keychain access.
#[tauri::command]
pub(crate) fn check_bio_status() -> BioStatus {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn lexflow_biometry_status() -> i32;
        }
        // The bridge catches Objective-C exceptions before returning the flags.
        macos_status_from_flags(unsafe { lexflow_biometry_status() })
    }
    #[cfg(target_os = "windows")]
    {
        windows_bio_status(WINDOWS_BIO_CLEANUP_FAILED.load(std::sync::atomic::Ordering::Relaxed))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        BioStatus {
            available: false,
            reason: "unsupported",
            device_ready: None,
            app_authorized: None,
        }
    }
}

/// Current platform capability; macOS also needs authorized app entitlements.
#[cfg(target_os = "macos")]
fn check_bio_hardware() -> bool {
    extern "C" {
        fn lexflow_can_use_biometrics() -> i32;
    }
    // ABI is a fixed-width integer; Objective-C exceptions are caught in the bridge.
    unsafe { lexflow_can_use_biometrics() == 1 }
}

#[cfg(test)]
mod capability_status_tests {
    use super::macos_status_from_flags;

    #[test]
    fn available_requires_device_and_app_readiness() {
        let status = macos_status_from_flags(3);
        assert!(status.available);
        assert_eq!(status.reason, "available");
        assert_eq!(status.device_ready, Some(true));
        assert_eq!(status.app_authorized, Some(true));
    }

    #[test]
    fn unsigned_build_does_not_hide_a_ready_device() {
        for (flags, device_ready) in [(1, true), (0, false)] {
            let status = macos_status_from_flags(flags);
            assert!(!status.available);
            assert_eq!(status.reason, "build_not_authorized");
            assert_eq!(status.device_ready, Some(device_ready));
            assert_eq!(status.app_authorized, Some(false));
        }
    }

    #[test]
    fn device_unavailable_is_distinct_from_build_authorization() {
        let status = macos_status_from_flags(2);
        assert!(!status.available);
        assert_eq!(status.reason, "device_unavailable");
        assert_eq!(status.device_ready, Some(false));
        assert_eq!(status.app_authorized, Some(true));
    }

    #[test]
    fn bridge_error_and_unknown_bits_fail_closed() {
        for flags in [4, 7, 8, -1] {
            let status = macos_status_from_flags(flags);
            assert!(!status.available);
            assert_eq!(status.reason, "check_failed");
            assert_eq!(status.device_ready, None);
            assert_eq!(status.app_authorized, None);
        }
    }
}

// Windows Hello was removed: a consent prompt did not cryptographically protect
// the generic Credential Manager item. Never save or read such a credential.
#[cfg(target_os = "windows")]
static WINDOWS_BIO_CLEANUP_FAILED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(target_os = "windows", all(test, not(target_os = "android"))))]
fn windows_bio_status(cleanup_failed: bool) -> BioStatus {
    BioStatus {
        available: false,
        reason: if cleanup_failed {
            "windows_hello_cleanup_failed"
        } else {
            "windows_hello_removed"
        },
        // We do not inspect hardware or launch a helper on Windows.
        device_ready: None,
        app_authorized: None,
    }
}

#[cfg(any(target_os = "windows", all(test, not(target_os = "android"))))]
fn windows_bio_removed<T>() -> Result<T, String> {
    Err("Windows Hello è stato rimosso. Usa la Master Password dell'archivio.".into())
}

/// The adapter exposes deletion only. Neither migration nor its tests can read
/// a credential through this interface. A missing entry counts as deleted.
#[cfg(any(target_os = "windows", all(test, not(target_os = "android"))))]
fn remove_legacy_windows_bio_with(
    directory: &std::path::Path,
    account: &str,
    delete_credential: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    delete_credential(BIO_SERVICE, account)?;
    match fs::remove_file(directory.join(BIO_MARKER_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(
            "Vecchia credenziale Windows rimossa, ma pulizia dell'indicatore non completata. Riavvia LexFlow per riprovare.".into(),
        ),
    }
}

/// Called once during Windows startup, and on explicit clear/password change.
/// Only the old username + BIO_SERVICE entry and its marker are removed. The
/// encrypted vault and its password are untouched; future access needs that
/// password. Failure remains visible in check_bio_status and is safe to retry.
#[cfg(target_os = "windows")]
pub(crate) fn remove_legacy_windows_bio(directory: &std::path::Path) -> Result<(), String> {
    let _bio_lock = bio_op_lock().lock().unwrap_or_else(|e| e.into_inner());
    let result = remove_legacy_windows_bio_with(
        directory,
        &whoami::username(),
        |service, account| {
            let entry = keyring::Entry::new(service, account).map_err(|_| {
            "Impossibile eliminare la vecchia credenziale Windows. Riavvia LexFlow per riprovare.".to_string()
        })?;
            match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(
                "Impossibile eliminare la vecchia credenziale Windows. Riavvia LexFlow per riprovare.".into(),
            ),
        }
        },
    );
    WINDOWS_BIO_CLEANUP_FAILED.store(result.is_err(), std::sync::atomic::Ordering::Relaxed);
    result
}

#[cfg(target_os = "android")]
fn check_bio_hardware() -> bool {
    // No Android BiometricPrompt/Keystore bridge is implemented. Do not advertise
    // enrollment support: the UI must keep using the verified password flow.
    false
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "android")))]
fn check_bio_hardware() -> bool {
    false
}

#[tauri::command]
pub(crate) fn has_bio_saved(state: State<AppState>) -> bool {
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        dir.join(BIO_MARKER_FILE).exists()
    }
    #[cfg(any(target_os = "android", target_os = "windows"))]
    {
        let _ = state;
        false
    }
}

// HIGH-S-1 (remediated): on macOS the keychain entry is now created via
// `SecItemAdd` with `kSecAttrAccessControl` set to a `SecAccessControl`
// built with `kSecAccessControlBiometryCurrentSet` and protection
// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Enrolling a new
// fingerprint invalidates the stored credential. The Data Protection Keychain
// enforces the item's access control. See `macos_keychain` module
// above. Windows enrollment and login are explicitly unavailable.
#[tauri::command]
pub(crate) fn save_bio(state: State<AppState>, pwd: String) -> Result<bool, String> {
    let pwd = Zeroizing::new(pwd);
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        // Hold the bio-op mutex while we touch the keyring + marker file so a
        // concurrent `clear_bio` cannot wipe the credentials we are about to
        // commit.
        // Reject locked callers before any OS credential access. Serialize
        // verification/enrollment with lock, reset and password changes.
        let session = state.document_session()?;
        let _bio_lock = bio_op_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _write_lock = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        state.validate_document_session(session)?;
        authorize_bio_enrollment(&state, &pwd)?;
        let user = whoami::username();

        #[cfg(target_os = "macos")]
        {
            macos_keychain::save_protected(BIO_SERVICE, &user, &pwd)?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring::Entry::new(BIO_SERVICE, &user).map_err(|e| e.to_string())?;
            entry.set_password(&pwd).map_err(|e| e.to_string())?;
        }

        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // L4: If marker file write fails, delete the keyring entry to maintain
        // consistency — otherwise the keyring has credentials but there's no marker.
        if let Err(e) = secure_write(&dir.join(BIO_MARKER_FILE), b"1") {
            #[cfg(debug_assertions)]
            eprintln!(
                "[SECURITY] WARNING: bio marker file write failed: {}. Cleaning up keyring entry.",
                e
            );
            #[cfg(target_os = "macos")]
            macos_keychain::delete_both(BIO_SERVICE, &user);
            #[cfg(not(target_os = "macos"))]
            {
                if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                    let _ = entry.delete_credential();
                }
            }
            return Err(format!("Failed to save biometric marker: {}", e));
        }
        Ok(true)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = state;
        drop(pwd);
        windows_bio_removed()
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        drop(pwd);
        Err("La biometria Android non è disponibile in questa versione. Usa la password.".into())
    }
}

/// Password changes must preserve the ACL used at biometric enrolment.
#[cfg(target_os = "macos")]
pub(crate) fn refresh_macos_bio_password(password: &str) -> Result<(), String> {
    macos_keychain::save_protected(BIO_SERVICE, &whoami::username(), password)
}

#[cfg(not(any(target_os = "android", target_os = "windows")))]
#[allow(dead_code)]
fn bio_unlock_vault(state: &State<AppState>) -> Result<Value, String> {
    // Serialise with `clear_bio` / `save_bio` while we hold the keyring
    // password in memory. Without this lock a concurrent `clear_bio` could
    // delete the entry between our read and the unlock attempt.
    let _bio_lock = bio_op_lock().lock().unwrap_or_else(|e| e.into_inner());

    let user = whoami::username();
    #[cfg(target_os = "macos")]
    let saved_pwd = macos_keychain::load_protected(BIO_SERVICE, &user)?;
    #[cfg(not(target_os = "macos"))]
    let saved_pwd = keyring::Entry::new(BIO_SERVICE, &user)
        .and_then(|e| e.get_password())
        .map_err(|e| e.to_string())?;

    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    // Use the same unlock flow as manual password (handles v4)
    // Pass ownership directly — no clone needed. unlock_vault_with_password
    // takes ownership and zeroizes internally.
    let result = unlock_vault_with_password(state, saved_pwd);

    // If unlock succeeded, return success
    if result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        // The common unlock records its event while holding write_mutex.
        return Ok(result);
    }

    // The common password unlock already records an authentication failure.
    // Do not count it twice or count lockout/storage errors as another guess.

    // Bio password is stale (e.g. password changed) — clear bio credentials
    #[cfg(target_os = "macos")]
    macos_keychain::delete_both(BIO_SERVICE, &user);
    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
            let _ = entry.delete_credential();
        }
    }
    let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
    Ok(
        json!({"success": false, "error": "Password biometrica non più valida. Accedi con la password e riconfigura la biometria."}),
    )
}

#[tauri::command]
pub(crate) fn bio_login(_state: State<AppState>, window: tauri::Window) -> Result<Value, String> {
    // Prevent Touch ID from appearing over other apps when LexFlow is not focused
    #[cfg(not(target_os = "windows"))]
    if !window.is_focused().unwrap_or(false) {
        return Ok(serde_json::json!({"success": false, "error": "Window not focused"}));
    }

    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        let sec_dir = _state
            .security_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Err(locked_json) = check_lockout(&_state, &sec_dir) {
            return Ok(locked_json);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // No preliminary prompt or Swift process. load_protected requires the
        // stored biometric ACL and lets Security.framework perform authentication.
        bio_unlock_vault(&_state)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (_state, window);
        windows_bio_removed()
    }
    #[cfg(target_os = "android")]
    {
        Err("La biometria Android non è disponibile in questa versione. Usa la password.".into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "android")))]
    {
        Err("Non supportato su questa piattaforma".into())
    }
}

/// L5: SECURITY NOTE — clear_bio is destructive-only (it removes stored credentials
/// from the keyring and deletes the marker file). It does not expose or return any
/// sensitive data. Therefore, it does not require prior authentication — an attacker
/// calling this can only disable biometric login, not extract secrets.
/// This is an accepted design choice.
///
/// On platforms with biometric enrollment, clearing retains its existing rate
/// limit. Windows only retries removal of the discontinued legacy credential.
#[tauri::command]
pub(crate) fn clear_bio(state: State<AppState>) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        let directory = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // Do not mark cleanup complete on a platform error. Retrying is safe
        // because this path can only delete the discontinued credential.
        remove_legacy_windows_bio(&directory).map(|()| true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Rate limit
        let last = LAST_CLEAR_BIO.get_or_init(|| Mutex::new(None));
        {
            let mut last_g = last.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(prev) = *last_g {
                if prev.elapsed() < CLEAR_BIO_RATE_LIMIT {
                    // Silently refuse; FE treats `false` as "no-op / already cleared".
                    return Ok(false);
                }
            }
            *last_g = Some(Instant::now());
        }

        #[cfg(not(target_os = "android"))]
        {
            // Serialise with `bio_login` / `save_bio` so we don't race a concurrent
            // unlock that has just read the keyring entry into memory.
            let _bio_lock = bio_op_lock().lock().unwrap_or_else(|e| e.into_inner());
            let user = whoami::username();
            #[cfg(target_os = "macos")]
            macos_keychain::delete_both(BIO_SERVICE, &user);
            #[cfg(not(target_os = "macos"))]
            {
                if let Ok(e) = keyring::Entry::new(BIO_SERVICE, &user) {
                    let _ = e.delete_credential();
                }
            }
            let dir = state
                .data_dir
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
            Ok(true)
        }
        #[cfg(target_os = "android")]
        {
            let _ = state;
            // L-ANDROID: no native bio backend on Android — frontend manages it.
            // Returning `false` here surfaces that the native call did nothing,
            // so the FE knows to fall through to its own clearing flow.
            Ok(false)
        }
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod windows_removal_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeCredentialStore {
        entries: BTreeMap<(String, String), Vec<u8>>,
        deletions: Vec<(String, String)>,
        fail_delete: bool,
    }

    impl FakeCredentialStore {
        fn delete(&mut self, service: &str, account: &str) -> Result<(), String> {
            let key = (service.to_owned(), account.to_owned());
            self.deletions.push(key.clone());
            if self.fail_delete {
                return Err("synthetic credential-store failure".into());
            }
            self.entries.remove(&key);
            Ok(())
        }
    }

    #[test]
    fn migration_removes_only_the_legacy_entry_and_preserves_password_access() {
        let directory = tempfile::tempdir().unwrap();
        let password = "a".repeat(64);
        let (mut vault, dek) = crate::vault_engine::create_vault(&password).unwrap();
        crate::vault_engine::write_canonical_vault(directory.path(), &mut vault, &dek).unwrap();
        let vault_before = fs::read(directory.path().join(VAULT_FILE)).unwrap();
        fs::write(directory.path().join(BIO_MARKER_FILE), b"1").unwrap();
        fs::write(directory.path().join(LICENSE_FILE), b"synthetic license").unwrap();
        let legacy = (BIO_SERVICE.to_owned(), "synthetic-user".to_owned());
        let unrelated = ("Unrelated_Service".to_owned(), "synthetic-user".to_owned());
        let other_account = (BIO_SERVICE.to_owned(), "other-user".to_owned());
        let mut store = FakeCredentialStore::default();
        for key in [&legacy, &unrelated, &other_account] {
            store
                .entries
                .insert(key.clone(), b"synthetic-only".to_vec());
        }

        remove_legacy_windows_bio_with(directory.path(), "synthetic-user", |service, account| {
            store.delete(service, account)
        })
        .unwrap();

        assert_eq!(store.deletions, vec![legacy.clone()]);
        assert!(!store.entries.contains_key(&legacy));
        assert!(store.entries.contains_key(&unrelated));
        assert!(store.entries.contains_key(&other_account));
        assert!(!directory.path().join(BIO_MARKER_FILE).exists());
        assert_eq!(
            fs::read(directory.path().join(VAULT_FILE)).unwrap(),
            vault_before
        );
        assert_eq!(
            fs::read(directory.path().join(LICENSE_FILE)).unwrap(),
            b"synthetic license"
        );
        let (_, reopened_dek) =
            crate::vault_engine::open_current_vault(directory.path(), &password).unwrap();
        assert_eq!(&*reopened_dek, &*dek);
    }

    #[test]
    fn cleanup_is_idempotent_with_a_missing_entry_and_marker() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = FakeCredentialStore::default();
        for _ in 0..2 {
            remove_legacy_windows_bio_with(
                directory.path(),
                "synthetic-user",
                |service, account| store.delete(service, account),
            )
            .unwrap();
        }
        assert_eq!(store.deletions.len(), 2);
        assert!(store.entries.is_empty());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn credential_cleanup_failure_keeps_marker_and_is_retryable() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(BIO_MARKER_FILE);
        fs::write(&marker, b"1").unwrap();
        let legacy = (BIO_SERVICE.to_owned(), "synthetic-user".to_owned());
        let mut store = FakeCredentialStore {
            fail_delete: true,
            ..Default::default()
        };
        store
            .entries
            .insert(legacy.clone(), b"synthetic-only".to_vec());
        assert!(remove_legacy_windows_bio_with(
            directory.path(),
            "synthetic-user",
            |service, account| store.delete(service, account)
        )
        .is_err());
        assert!(marker.exists());
        assert!(store.entries.contains_key(&legacy));

        store.fail_delete = false;
        remove_legacy_windows_bio_with(directory.path(), "synthetic-user", |service, account| {
            store.delete(service, account)
        })
        .unwrap();
        assert!(!marker.exists());
        assert!(store.entries.is_empty());
    }

    #[test]
    fn marker_cleanup_failure_is_reported_without_deleting_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(BIO_MARKER_FILE);
        fs::create_dir(&marker).unwrap();
        fs::write(marker.join("preserve"), b"synthetic unrelated file").unwrap();
        let mut store = FakeCredentialStore::default();
        assert!(remove_legacy_windows_bio_with(
            directory.path(),
            "synthetic-user",
            |service, account| store.delete(service, account)
        )
        .is_err());
        assert_eq!(
            fs::read(marker.join("preserve")).unwrap(),
            b"synthetic unrelated file"
        );
        assert_eq!(store.deletions.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn marker_symlink_is_removed_without_touching_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("unrelated-file");
        fs::write(&target, b"preserve this file").unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join(BIO_MARKER_FILE)).unwrap();
        remove_legacy_windows_bio_with(directory.path(), "synthetic-user", |_, _| Ok(())).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"preserve this file");
        assert!(fs::symlink_metadata(directory.path().join(BIO_MARKER_FILE)).is_err());
    }

    #[test]
    fn removed_windows_backend_never_advertises_hardware_or_availability() {
        for cleanup_failed in [false, true] {
            let status = windows_bio_status(cleanup_failed);
            assert!(!status.available);
            assert_eq!(status.device_ready, None);
            assert_eq!(status.app_authorized, None);
            assert_eq!(
                status.reason,
                if cleanup_failed {
                    "windows_hello_cleanup_failed"
                } else {
                    "windows_hello_removed"
                }
            );
        }
    }

    #[test]
    fn removed_windows_operations_reject_enrollment_and_login() {
        assert!(windows_bio_removed::<bool>()
            .unwrap_err()
            .contains("Master Password"));
        assert!(windows_bio_removed::<Value>()
            .unwrap_err()
            .contains("Master Password"));
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod enrollment_authorization_tests {
    use super::*;

    #[test]
    fn enrollment_requires_unlocked_matching_vault_password() {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::new(directory.path().into(), directory.path().into());
        let password = "a".repeat(64); // Synthetic frontend prehash, never a real key.
        assert!(authorize_bio_enrollment(&state, &password).is_err());
        let (mut vault, dek) = crate::vault_engine::create_vault(&password).unwrap();
        crate::vault_engine::write_canonical_vault(directory.path(), &mut vault, &dek).unwrap();
        *state.vault_dek.lock().unwrap() = Some(crate::state::SecureKey::new(dek));
        assert!(authorize_bio_enrollment(&state, &password).is_ok());
        assert!(authorize_bio_enrollment(&state, &"b".repeat(64)).is_err());
        assert!(authorize_bio_enrollment(&state, "not-a-prehash").is_err());
        *state.vault_dek.lock().unwrap() =
            Some(crate::state::SecureKey::new(Zeroizing::new(vec![0x19; 32])));
        assert!(authorize_bio_enrollment(&state, &password).is_err());
        state.lock_vault();
        assert!(authorize_bio_enrollment(&state, &password).is_err());
        assert!(!directory.path().join(BIO_MARKER_FILE).exists());
        // This test calls no keychain functions and never resolves app folders.
    }
}
