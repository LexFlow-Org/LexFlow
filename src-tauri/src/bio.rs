// ═══════════════════════════════════════════════════════════
//  BIOMETRICS — Touch ID / Windows Hello / Android
// ═══════════════════════════════════════════════════════════

use crate::state::{zeroize_password, AppState};
use serde_json::Value;
use tauri::State;

#[cfg(not(target_os = "android"))]
use serde_json::json;

// Desktop-only imports (bio_unlock_vault, save_bio, clear_bio, bio_login)
#[cfg(not(target_os = "android"))]
use crate::audit::append_audit_log;
#[cfg(not(target_os = "android"))]
use crate::constants::*;
#[cfg(not(target_os = "android"))]
use crate::io::secure_write;
#[cfg(not(target_os = "android"))]
use crate::lockout::{check_lockout, clear_lockout};
#[cfg(not(target_os = "android"))]
use crate::state::SecureKey;
#[cfg(not(target_os = "android"))]
use crate::vault::authenticate_vault_password;
#[cfg(not(target_os = "android"))]
use std::fs;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Duration;
#[cfg(not(target_os = "android"))]
use std::time::Instant;

#[tauri::command]
pub(crate) fn check_bio() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    ))
}

#[tauri::command]
pub(crate) fn has_bio_saved(state: State<AppState>) -> bool {
    #[cfg(not(target_os = "android"))]
    {
        let dir = state
            .data_dir
            .lock()
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

#[tauri::command]
pub(crate) fn save_bio(state: State<AppState>, pwd: String) -> Result<bool, String> {
    #[cfg(not(target_os = "android"))]
    {
        let user = whoami::username();
        let entry = keyring::Entry::new(BIO_SERVICE, &user).map_err(|e| e.to_string())?;
        entry.set_password(&pwd).map_err(|e| e.to_string())?;
        let dir = state
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let _ = secure_write(&dir.join(BIO_MARKER_FILE), b"1");
        zeroize_password(pwd);
        Ok(true)
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        zeroize_password(pwd);
        Ok(true)
    }
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
fn bio_unlock_vault(state: &State<AppState>) -> Result<Value, String> {
    let user = whoami::username();
    let saved_pwd = keyring::Entry::new(BIO_SERVICE, &user)
        .and_then(|e| e.get_password())
        .map_err(|e| e.to_string())?;

    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let auth_result = authenticate_vault_password(&saved_pwd, &dir);
    zeroize_password(saved_pwd);

    match auth_result {
        Ok(k) => {
            *(state.vault_key.lock().unwrap_or_else(|e| e.into_inner())) = Some(SecureKey::new(k));
            clear_lockout(state, &sec_dir);
            *(state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())) = Instant::now();
            let _ = append_audit_log(state, "Sblocco Vault (biometria)");
            Ok(json!({"success": true}))
        }
        Err(_) => {
            if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                let _ = entry.delete_credential();
            }
            let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
            Ok(
                json!({"success": false, "error": "Password biometrica non più valida. Accedi con la password e riconfigura la biometria."}),
            )
        }
    }
}

#[tauri::command]
pub(crate) fn bio_login(_state: State<AppState>) -> Result<Value, String> {
    #[cfg(not(target_os = "android"))]
    {
        let sec_dir = _state
            .security_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Err(locked_json) = check_lockout(&_state, &sec_dir) {
            return Ok(locked_json);
        }
    }

    #[cfg(target_os = "macos")]
    {
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
        let mut child_handle = child;
        std::thread::spawn(move || {
            let result = child_handle.wait();
            let _ = tx.send((child_handle, result));
        });
        match rx.recv_timeout(timeout) {
            Ok((_child, Ok(status))) => {
                if !status.success() {
                    return Ok(
                        json!({"success": false, "error": "Autenticazione biometrica fallita"}),
                    );
                }
            }
            Ok((_child, Err(e))) => return Err(e.to_string()),
            Err(_) => {
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
        let mut child_handle = child;
        std::thread::spawn(move || {
            let result = child_handle.wait();
            let _ = tx.send((child_handle, result));
        });
        let status = match rx.recv_timeout(timeout) {
            Ok((_child, Ok(s))) => s,
            Ok((_child, Err(e))) => return Err(e.to_string()),
            Err(_) => {
                return Ok(
                    json!({"success": false, "error": "Timeout autenticazione Windows Hello (60s)"}),
                );
            }
        };
        if !status.success() {
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

#[tauri::command]
pub(crate) fn clear_bio(state: State<AppState>) -> bool {
    #[cfg(not(target_os = "android"))]
    {
        let user = whoami::username();
        if let Ok(e) = keyring::Entry::new(BIO_SERVICE, &user) {
            let _ = e.delete_credential();
        }
        let dir = state
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
        true
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        true
    }
}
