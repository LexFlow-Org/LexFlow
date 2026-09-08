//! Boundaries for offline navigation and plaintext document work files.

use std::path::{Path, PathBuf};

/// Advisory OS lock held by an open descriptor for the process lifetime.
/// A Rust mutex alone cannot protect a vault opened by two app processes.
#[cfg(unix)]
pub(crate) fn lock_instance_file(path: &Path) -> Result<std::fs::File, String> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "Impossibile acquisire il blocco dell'archivio.".to_string())?;
    // SAFETY: file owns a valid descriptor, and flock does not retain pointers.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("Archivio già aperto in un'altra istanza di LexFlow.".into());
    }
    Ok(file)
}

pub(crate) fn navigation_allowed(url: &tauri::Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match (url.scheme(), url.host_str(), url.port()) {
        ("tauri", Some("localhost"), None) => true,
        ("http" | "https", Some("tauri.localhost"), None) => true,
        #[cfg(debug_assertions)]
        ("http", Some("localhost" | "127.0.0.1"), Some(5173)) => true,
        _ => false,
    }
}

/// A unique, private directory retained until all sidecar operations complete.
/// Drop also runs on errors. Unlinking cannot guarantee erasure from SSD snapshots.
pub(crate) struct DocumentWorkspace(tempfile::TempDir);

impl DocumentWorkspace {
    pub(crate) fn new() -> Result<Self, String> {
        let mut builder = tempfile::Builder::new();
        builder.prefix("lexflow_app_private_");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        builder
            .tempdir()
            .map(Self)
            .map_err(|_| "Impossibile creare l'area temporanea privata.".to_string())
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }
}

impl Drop for DocumentWorkspace {
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(self.path()) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    let _ = crate::security::secure_delete_file(&entry.path());
                }
            }
        }
    }
}

/// Encode user input as a Typst string, never as markup or executable code.
pub(crate) fn typst_string(input: &str) -> String {
    let mut output = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => {}
            ch => output.push(ch),
        }
    }
    output
}

/// Publish a completed file without exposing an intermediate or replacing an
/// existing destination (including a symlink created after validation).
pub(crate) fn publish_new_file(source: &Path, destination: &Path) -> Result<(), String> {
    let mut input = std::fs::File::open(source).map_err(|_| "Risultato non leggibile.")?;
    stage_and_publish(destination, |output| {
        std::io::copy(&mut input, output).map(|_| ())
    })
}

/// Byte exports use the same staging boundary as native document tools.
pub(crate) fn publish_new_bytes(data: &[u8], destination: &Path) -> Result<(), String> {
    use std::io::Write;
    stage_and_publish(destination, |output| output.write_all(data))
}

fn stage_and_publish(
    destination: &Path,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> Result<(), String> {
    let parent = destination.parent().ok_or("Destinazione non valida.")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "Impossibile preparare il salvataggio.")?;
    write(staged.as_file_mut()).map_err(|_| "Salvataggio non riuscito.")?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "Salvataggio non riuscito.")?;
    staged
        .persist_noclobber(destination)
        .map_err(|_| "Destinazione già esistente o non scrivibile. Scegli un nuovo nome.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn instance_lock_excludes_second_open_and_releases_on_close() {
        let work = DocumentWorkspace::new().unwrap();
        let path = work.join("instance.lock");
        let first = lock_instance_file(&path).unwrap();
        assert!(lock_instance_file(&path).is_err());
        drop(first);
        assert!(lock_instance_file(&path).is_ok());
    }

    #[test]
    fn navigation_rejects_external_destinations_and_confusable_hosts() {
        for url in [
            "https://example.com/",
            "http://localhost:8080/",
            "https://tauri.localhost.evil.test/",
            "https://tauri.localhost@evil.test/",
            "file:///etc/passwd",
            "data:text/html,secret",
            "https://tauri.localhost:444/",
        ] {
            assert!(
                !navigation_allowed(&tauri::Url::parse(url).unwrap()),
                "{url}"
            );
        }
        for url in [
            "tauri://localhost/",
            "http://tauri.localhost/",
            "https://tauri.localhost/pratiche",
        ] {
            assert!(
                navigation_allowed(&tauri::Url::parse(url).unwrap()),
                "{url}"
            );
        }
    }

    #[test]
    fn document_workspace_is_private_unique_and_removed_on_error() {
        let first = DocumentWorkspace::new().unwrap();
        let second = DocumentWorkspace::new().unwrap();
        assert_ne!(first.path(), second.path());
        let path = first.path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::write(first.join("source.typ"), "confidential").unwrap();
        drop(first);
        assert!(!path.exists());
    }

    #[test]
    fn typst_input_cannot_close_string_literal() {
        assert_eq!(typst_string("\"\\\n\r\t\0"), "\\\"\\\\\\n\\r\\t");
        assert_eq!(typst_string("#read(\"secret\")"), "#read(\\\"secret\\\")");
    }

    #[test]
    fn publishing_never_overwrites_an_existing_file() {
        let work = DocumentWorkspace::new().unwrap();
        let source = work.join("source.pdf");
        let destination = work.join("destination.pdf");
        std::fs::write(&source, b"completed").unwrap();
        publish_new_file(&source, &destination).unwrap();
        std::fs::write(&source, b"replacement").unwrap();
        assert!(publish_new_file(&source, &destination).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"completed");
    }

    #[test]
    fn partial_byte_export_failure_leaves_no_final_file_and_can_be_retried() {
        use std::io::Write;
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("export.pdf");
        let result = stage_and_publish(&destination, |output| {
            output.write_all(b"%PDF-incomplete")?;
            Err(std::io::Error::other("synthetic write failure"))
        });
        assert!(result.is_err());
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);

        publish_new_bytes(b"%PDF-complete", &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"%PDF-complete");
        assert!(publish_new_bytes(b"replacement", &destination).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"%PDF-complete");
        assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 1);
    }
}
