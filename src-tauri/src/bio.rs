// ═══════════════════════════════════════════════════════════
//  BIOMETRICS — Touch ID / Windows Hello / Android
// ═══════════════════════════════════════════════════════════

use crate::state::{zeroize_password, AppState};
use serde_json::Value;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration as StdDuration, Instant};
use tauri::State;

// ─────────────────────────────────────────────────────────────────────
//  macOS Keychain ACL helper (HIGH-S-1 remediation)
// ─────────────────────────────────────────────────────────────────────
// On macOS, the legacy `keyring` crate stores generic-password items
// WITHOUT an `SecAccessControl` ACL. That means any other Apple-signed
// process trusted by the user's login keychain can read the entry —
// the biometric prompt is purely a UI gate, not a cryptographic one.
//
// This module wraps `SecAccessControlCreateWithFlags` + `SecItemAdd`
// via raw FFI (security-framework v2 does not expose ACL building on
// generic passwords) so the keychain item is created with:
//
//   * kSecAttrAccessibleWhenUnlockedThisDeviceOnly  (protection)
//   * kSecAccessControlBiometryCurrentSet            (flag)
//
// The `BiometryCurrentSet` flag binds the item to the *currently
// enrolled* set of biometrics: enrolling a new fingerprint or face
// invalidates the entry and forces re-derivation from the user
// password. Combined with `WhenUnlockedThisDeviceOnly`, this gives
// us a true biometric gate, not a UI illusion.
//
// On read failures we fall back to the plain `keyring` crate so users
// who already have a non-ACL'd entry from previous LexFlow versions
// can still log in (and on the next save_bio the entry will be
// rewritten with the ACL).
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

            let pairs: [(CFTypeRef, CFTypeRef); 5] = [
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
                Err(format!("SecItemAdd failed: OSStatus={}", status))
            }
        }
    }

    /// Read the password back. This call WILL trigger a biometric
    /// prompt on a properly-ACL'd entry. If the entry was created
    /// without ACL (legacy keyring entry) the read returns the bytes
    /// directly with no prompt — which is exactly the failure mode
    /// `verify_acl_enforced()` exists to detect.
    ///
    /// KNOWN UX TRADE-OFF: combined with the existing `bio_login`
    /// flow (which runs `LAContext.evaluatePolicy` first via a Swift
    /// child process), this produces TWO biometric prompts on macOS
    /// — one to gate the unlock UI, one to release the keychain
    /// secret. To consolidate them, future work should pass an
    /// `LAContext` to `SecItemCopyMatching` via
    /// `kSecUseAuthenticationContext`. Tracked separately; the
    /// double-prompt is annoying but strictly more secure than the
    /// previous single-prompt-with-no-ACL design.
    pub(super) fn load(service: &str, account: &str) -> Result<String, String> {
        unsafe {
            let svc = CFString::new(service);
            let acc = CFString::new(account);
            let cf_true = CFBoolean::true_value();

            let pairs: [(CFTypeRef, CFTypeRef); 5] = [
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

            let pairs: [(CFTypeRef, CFTypeRef); 3] = [
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

            let pairs: [(CFTypeRef, CFTypeRef); 5] = [
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

    /// Best-effort save: try the FFI ACL path; if anything fails, fall
    /// back to plain `keyring` and emit a security warning.
    pub(super) fn save_best_effort(
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<(), String> {
        match save_with_acl(service, account, password) {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!(
                    "[bio] WARN: macOS keychain ACL save failed ({}). Falling back to plain keyring.",
                    e
                );
                eprintln!(
                    "[bio]       The entry will NOT have kSecAccessControlBiometryCurrentSet."
                );
                eprintln!("[bio]       Other Apple-signed apps trusted by the user may read it.");
                let entry = keyring::Entry::new(service, account).map_err(|e| e.to_string())?;
                entry.set_password(password).map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    /// Best-effort load: try our ACL path first (succeeds for ACL'd
    /// entries after the user passes biometrics). Only on `not-found`
    /// do we fall back to the plain keyring crate — legacy entries
    /// created by pre-HIGH-S-1 LexFlow versions still need to unlock,
    /// but we MUST NOT silently bypass a failed biometric on a real
    /// ACL'd entry (e.g. the user cancelled the prompt).
    pub(super) fn load_with_fallback(service: &str, account: &str) -> Result<String, String> {
        match load(service, account) {
            Ok(p) => Ok(p),
            Err(e) if e == "not-found" => {
                // Either no ACL'd entry exists yet (first login after
                // upgrade) or the entry is the legacy plain one.
                let entry = keyring::Entry::new(service, account).map_err(|e| e.to_string())?;
                entry.get_password().map_err(|e| e.to_string())
            }
            Err(e) => Err(e),
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

#[cfg(not(target_os = "android"))]
use serde_json::json;

#[cfg(not(target_os = "android"))]
use crate::audit::append_audit_log;
#[cfg(not(target_os = "android"))]
use crate::constants::*;
#[cfg(not(target_os = "android"))]
use crate::io::secure_write;
#[cfg(not(target_os = "android"))]
use crate::lockout::{check_lockout, record_failed_attempt};
#[cfg(not(target_os = "android"))]
use crate::vault::unlock_vault_with_password;
#[cfg(not(target_os = "android"))]
use std::fs;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Duration;

/// Cross-call serialisation lock: ensures `bio_login` (which reads from the
/// keyring then unlocks the vault) cannot race with a concurrent `clear_bio`
/// (which deletes the keyring entry), and vice versa. The critical section is
/// short — only the keyring-touching portion of each operation holds it.
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
static LAST_CLEAR_BIO: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
const CLEAR_BIO_RATE_LIMIT: StdDuration = StdDuration::from_secs(60);

#[tauri::command]
pub(crate) fn check_bio() -> bool {
    use std::sync::OnceLock;
    static BIO_AVAILABLE: OnceLock<bool> = OnceLock::new();
    *BIO_AVAILABLE.get_or_init(check_bio_hardware)
}

/// Runtime hardware detection — cached via OnceLock (runs once per process).
#[cfg(target_os = "macos")]
fn check_bio_hardware() -> bool {
    use std::io::Write;
    // SECURITY: hardcoded Swift only — never interpolate user input here.
    let swift = "import LocalAuthentication\nlet c=LAContext();var e:NSError?\nexit(c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,error:&e) ? 0 : 1)";
    let mut cmd = std::process::Command::new("/usr/bin/swift");
    cmd.arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for (k, _) in std::env::vars() {
        if k.starts_with("DYLD_") || k.starts_with("LD_") || k == "CFNETWORK_LIBRARY_PATH" {
            cmd.env_remove(&k);
        }
    }
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(swift.as_bytes());
    }
    drop(child.stdin.take());
    child.wait().map(|s| s.success()).unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn check_bio_hardware() -> bool {
    // SECURITY: hardcoded PowerShell only — never interpolate user input here.
    let ps = r#"Add-Type -AssemblyName System.Runtime.WindowsRuntime
$m = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($t, $r) { $s = $m.MakeGenericMethod($r); $n = $s.Invoke($null, @($t)); $n.Wait(-1) | Out-Null; $n.Result }
[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
$r = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.ConsentVerifierAvailability])
if ($r -eq [Windows.Security.Credentials.UI.ConsentVerifierAvailability]::Available) { exit 0 } else { exit 1 }"#;
    let Ok(mut child) =
        std::process::Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    else {
        return false;
    };
    child.wait().map(|s| s.success()).unwrap_or(false)
}

#[cfg(target_os = "android")]
fn check_bio_hardware() -> bool {
    // KNOWN LIMITATION: Android biometric hardware availability is checked client-side
    // via the BiometricManager API in the frontend (Capacitor/WebView layer). The Rust
    // backend cannot query Android system services directly without JNI. Returning true
    // here defers the real check to the frontend, which gates the biometric UI.
    // TODO: Add JNI bridge to query BiometricManager.canAuthenticate() natively.
    true
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "android")))]
fn check_bio_hardware() -> bool {
    false
}

#[tauri::command]
pub(crate) fn has_bio_saved(state: State<AppState>) -> bool {
    #[cfg(not(target_os = "android"))]
    {
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        dir.join(BIO_MARKER_FILE).exists()
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        false
    }
}

// HIGH-S-1 (remediated): on macOS the keychain entry is now created via
// `SecItemAdd` with `kSecAttrAccessControl` set to a `SecAccessControl`
// built with `kSecAccessControlBiometryCurrentSet` and protection
// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Enrolling a new
// fingerprint or face invalidates the stored secret, and other Apple-
// signed apps trusted by the user's login keychain can no longer read
// it without passing the biometric gate. See `macos_keychain` module
// above. On Windows/Linux we keep the plain `keyring` crate — the
// equivalent guarantees are provided by DPAPI / libsecret respectively.
#[tauri::command]
pub(crate) fn save_bio(state: State<AppState>, pwd: String) -> Result<bool, String> {
    #[cfg(not(target_os = "android"))]
    {
        // Hold the bio-op mutex while we touch the keyring + marker file so a
        // concurrent `clear_bio` cannot wipe the credentials we are about to
        // commit.
        let _bio_lock = bio_op_lock().lock().unwrap_or_else(|e| e.into_inner());
        let user = whoami::username();

        #[cfg(target_os = "macos")]
        {
            if let Err(e) = macos_keychain::save_best_effort(BIO_SERVICE, &user, &pwd) {
                zeroize_password(pwd);
                return Err(e);
            }
            // Post-write self-test: verify the ACL actually took effect.
            // We call SecItemCopyMatching with kSecUseAuthenticationUI =
            // kSecUseAuthenticationUIFail — on a properly-ACL'd entry the
            // call returns errSecInteractionNotAllowed (no bio prompt is
            // raised, so this is non-disruptive). If it succeeds, the ACL
            // didn't stick and we log a security-grade warning.
            match macos_keychain::verify_acl_enforced(BIO_SERVICE, &user) {
                Ok(true) => { /* ACL enforced — happy path. */ }
                Ok(false) => {
                    eprintln!(
                        "[bio] WARN: keychain entry stored without biometric ACL (legacy fallback path)."
                    );
                }
                Err(e) => {
                    #[cfg(debug_assertions)]
                    eprintln!("[bio] verify_acl_enforced returned error: {}", e);
                    let _ = e;
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring::Entry::new(BIO_SERVICE, &user).map_err(|e| e.to_string())?;
            if let Err(e) = entry.set_password(&pwd) {
                zeroize_password(pwd);
                return Err(e.to_string());
            }
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
            zeroize_password(pwd);
            return Err(format!("Failed to save biometric marker: {}", e));
        }
        zeroize_password(pwd);
        Ok(true)
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        zeroize_password(pwd);
        // L-ANDROID: native save_bio is a stub on Android (no JNI bridge yet).
        // The frontend uses Capacitor's Keystore plugin and treats the Rust
        // call as a no-op success. If you need a hard sentinel, change this
        // to `Err("android-bio-use-frontend")`, but make sure the FE branches
        // on the error string before flipping the contract.
        Ok(true)
    }
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
fn bio_unlock_vault(state: &State<AppState>) -> Result<Value, String> {
    // Serialise with `clear_bio` / `save_bio` while we hold the keyring
    // password in memory. Without this lock a concurrent `clear_bio` could
    // delete the entry between our read and the unlock attempt.
    let _bio_lock = bio_op_lock().lock().unwrap_or_else(|e| e.into_inner());

    let user = whoami::username();
    #[cfg(target_os = "macos")]
    let saved_pwd = macos_keychain::load_with_fallback(BIO_SERVICE, &user)?;
    #[cfg(not(target_os = "macos"))]
    let saved_pwd = keyring::Entry::new(BIO_SERVICE, &user)
        .and_then(|e| e.get_password())
        .map_err(|e| e.to_string())?;

    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let sec_dir = state
        .security_dir
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
        let _ = append_audit_log(state, "Sblocco Vault (biometria)");
        return Ok(result);
    }

    // L-BIO-FAIL: feed bio failures into the same lockout counter as manual
    // password attempts, so brute-forcing via the bio path cannot bypass the
    // global rate limiter.
    record_failed_attempt(state, &sec_dir);

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
    if !window.is_focused().unwrap_or(false) {
        return Ok(serde_json::json!({"success": false, "error": "Window not focused"}));
    }

    #[cfg(not(target_os = "android"))]
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
        // SECURITY: this Swift snippet is hardcoded — never interpolate user
        // input into it. The shell/scripting boundary here is owned by the
        // process arguments and stdin only; the script body must remain a
        // string literal.
        let swift_code = "import LocalAuthentication\nlet ctx = LAContext()\nvar err: NSError?\nif ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {\n  let sema = DispatchSemaphore(value: 0)\n  var ok = false\n  ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: \"LexFlow\") { s, _ in ok = s; sema.signal() }\n  sema.wait()\n  if ok { exit(0) } else { exit(1) }\n} else { exit(1) }";

        use std::io::Write;
        let mut cmd = std::process::Command::new("/usr/bin/swift");
        cmd.arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (k, _) in std::env::vars() {
            if k.starts_with("DYLD_") || k.starts_with("LD_") || k == "CFNETWORK_LIBRARY_PATH" {
                cmd.env_remove(&k);
            }
        }
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;

        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(swift_code.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        drop(child.stdin.take());
        let timeout = Duration::from_secs(60);
        let (tx, rx) = std::sync::mpsc::channel();
        let child_arc = std::sync::Arc::new(std::sync::Mutex::new(Some(child)));
        let child_arc_thread = child_arc.clone();
        std::thread::spawn(move || {
            let result = {
                let mut guard = child_arc_thread.lock().unwrap();
                if let Some(ref mut c) = *guard {
                    Some(c.wait())
                } else {
                    None
                }
            };
            if let Some(r) = result {
                let _ = tx.send(r);
            }
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok(status)) => {
                if !status.success() {
                    // L-BIO-FAIL: count biometric rejections towards the
                    // global lockout counter to slow brute-force.
                    let sec_dir = _state
                        .security_dir
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    record_failed_attempt(&_state, &sec_dir);
                    return Ok(
                        json!({"success": false, "error": "Autenticazione biometrica fallita"}),
                    );
                }
            }
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => {
                // L-TOCTOU: prefer try_wait once before kill — handles the
                // race where the child terminated between recv_timeout
                // returning and us reaching for the kill switch.
                if let Ok(mut guard) = child_arc.lock() {
                    if let Some(ref mut c) = *guard {
                        match c.try_wait() {
                            Ok(Some(_)) => {} // already exited cleanly
                            _ => {
                                let _ = c.kill();
                            }
                        }
                    }
                }
                return Ok(
                    json!({"success": false, "error": "Timeout autenticazione biometrica (60s)"}),
                );
            }
        }

        bio_unlock_vault(&_state)
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        // SECURITY: this PowerShell snippet is hardcoded — never interpolate
        // user input into it. Command-line arguments are also kept literal.
        let ps_script = r#"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($WinRtTask, $ResultType) {
    $asTaskSpecific = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTaskSpecific.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}
[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
$result = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("LexFlow — Verifica identità")) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
if ($result -eq [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) { exit 0 } else { exit 1 }
"#;
        let child = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;

        let timeout = Duration::from_secs(60);
        let (tx, rx) = std::sync::mpsc::channel();
        let child_arc = std::sync::Arc::new(std::sync::Mutex::new(Some(child)));
        let child_arc_thread = child_arc.clone();
        std::thread::spawn(move || {
            let result = {
                let mut guard = child_arc_thread.lock().unwrap();
                if let Some(ref mut c) = *guard {
                    Some(c.wait())
                } else {
                    None
                }
            };
            if let Some(r) = result {
                let _ = tx.send(r);
            }
        });
        let status = match rx.recv_timeout(timeout) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => {
                // L-TOCTOU: prefer try_wait once before kill.
                if let Ok(mut guard) = child_arc.lock() {
                    if let Some(ref mut c) = *guard {
                        match c.try_wait() {
                            Ok(Some(_)) => {}
                            _ => {
                                let _ = c.kill();
                            }
                        }
                    }
                }
                return Ok(
                    json!({"success": false, "error": "Timeout autenticazione Windows Hello (60s)"}),
                );
            }
        };
        if !status.success() {
            // L-BIO-FAIL: feed Windows Hello rejections into the lockout counter.
            let sec_dir = _state
                .security_dir
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            record_failed_attempt(&_state, &sec_dir);
            return Ok(
                json!({"success": false, "error": "Windows Hello fallito o non disponibile"}),
            );
        }

        bio_unlock_vault(&_state)
    }
    #[cfg(target_os = "android")]
    {
        Err("android-bio-use-frontend".into())
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
/// M-CB-2: nevertheless we now rate-limit the operation to one successful
/// invocation per minute, to prevent a low-cost DoS where a malicious page
/// or process repeatedly disables biometric login to force the user to
/// re-enter their password every time.
#[tauri::command]
pub(crate) fn clear_bio(state: State<AppState>) -> bool {
    // Rate limit
    let last = LAST_CLEAR_BIO.get_or_init(|| Mutex::new(None));
    {
        let mut last_g = last.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = *last_g {
            if prev.elapsed() < CLEAR_BIO_RATE_LIMIT {
                // Silently refuse; FE treats `false` as "no-op / already cleared".
                return false;
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
        true
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        // L-ANDROID: no native bio backend on Android — frontend manages it.
        // Returning `false` here surfaces that the native call did nothing,
        // so the FE knows to fall through to its own clearing flow.
        false
    }
}
