//! Only explicitly sanitized records reach IPC or disk. Dependency tracing stays disabled.
use serde::Serialize;
use std::{io::Write, path::PathBuf, sync::Mutex};
use zeroize::Zeroizing;

static SECRETS: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());
static LOG_LOCK: Mutex<()> = Mutex::new(());
pub const MAX_LOG_BYTES: u64 = 128 * 1024;

pub fn register_secret(value: &str) {
    if value.is_empty() {
        return;
    }
    if let Ok(mut values) = SECRETS.lock() {
        // Fail closed once registration capacity is exhausted, never evict an active secret.
        if values.len() < 128 && !values.iter().any(|s| s.as_str() == value) {
            values.push(Zeroizing::new(value.to_owned()));
        }
    }
}

/// Final defensive pass for direct app errors and known Apple human-readable error messages.
/// Raw reports, headers, attachments, JSON, plist/XML and response bodies never enter this function.
pub fn sanitize(input: &str) -> String {
    if input.len() > 8192 {
        return "[oversized details omitted]".into();
    }
    let mut out = input.to_owned();
    let Ok(secrets) = SECRETS.lock() else {
        return "[details omitted]".into();
    };
    if secrets.len() >= 128 {
        return "[details omitted]".into();
    }
    // Longest first prevents overlapping credentials from exposing a suffix.
    let mut values: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();
    values.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for value in values {
        out = out.replace(value, "[redacted]");
        // Apple normalizes account case. Register passwords exactly, email also lowercase.
    }
    drop(secrets);
    let lower = out.to_ascii_lowercase();
    if [
        "<?xml",
        "<plist",
        "<dict",
        "{",
        "}",
        "authorization",
        "bearer ",
        "password",
        "passwd",
        "sessionkey",
        "session_key",
        "identitytoken",
        "identity_token",
        "x-apple-",
        "set-cookie",
        "cookie:",
        "pairrecord",
        "pairing record",
        "private key",
        "response body",
        "<data",
        "bplist",
        "hostprivatekey",
        "hostcertificate",
        "devicecertificate",
        "escrowbag",
        "pairingrecord",
        "pairing_data",
        "pairingdata",
        "dsid",
        "adsid",
        "idms",
        "auth-token",
        "token=",
        "token:",
        "token\"",
        "token'",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        return "[sensitive details omitted]".into();
    }
    out.split_whitespace()
        .map(|word| {
            if word.contains('@') || word.contains("://") || word.len() > 64 {
                "[redacted]".to_owned()
            } else {
                word.chars().filter(|c| !c.is_control()).collect()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(1600)
        .collect()
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub stage: String,
    pub code: Option<i64>,
    pub chain: Vec<String>,
    pub log_path: Option<String>,
}
impl Diagnostic {
    pub fn details(&self) -> String {
        let code = self.code.map(|c| format!("; code {c}")).unwrap_or_default();
        format!(
            "Stage {}{}\n{}",
            self.stage,
            code,
            self.chain.join("\nCaused by ")
        )
    }
}
fn log_directory() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Mirsa").join("logs"))
}
pub fn record(stage: &str, message: &str) -> Option<String> {
    let directory = log_directory()?;
    write_record(&directory, stage, message).ok()?;
    Some(
        directory
            .join("diagnostics.log")
            .to_string_lossy()
            .into_owned(),
    )
}
fn write_record(directory: &std::path::Path, stage: &str, message: &str) -> std::io::Result<()> {
    let _lock = LOG_LOCK
        .lock()
        .map_err(|_| std::io::Error::other("Log unavailable"))?;
    std::fs::create_dir_all(directory)?;
    let path = directory.join("diagnostics.log");
    let text = format!(
        "{} [{}] {}\n",
        chrono::Utc::now().to_rfc3339(),
        sanitize(stage),
        sanitize(message)
    );
    if std::fs::metadata(&path).is_ok_and(|m| m.len() + text.len() as u64 > MAX_LOG_BYTES) {
        // At most one rotated file and one active file, each <=128 KiB.
        let old = directory.join("diagnostics.previous.log");
        if old.exists() {
            std::fs::remove_file(&old)?;
        }
        std::fs::rename(&path, old)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(text.as_bytes())
}
pub fn stage(stage: &'static str) {
    let _ = record(stage, "started");
}

#[tauri::command]
pub async fn copy_error_details(details: String) -> Result<(), crate::error::AppError> {
    let details = sanitize(&details);
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || {
            use std::os::windows::process::CommandExt;
            use std::process::{Command, Stdio};
            // Data is only stdin, never interpolated into PowerShell source/arguments.
            let mut child = Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
                ])
                .creation_flags(0x08000000)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| crate::error::AppError::Misc("Clipboard unavailable".into()))?;
            let write = child
                .stdin
                .take()
                .ok_or_else(|| crate::error::AppError::Misc("Clipboard unavailable".into()))?
                .write_all(details.as_bytes());
            if write.is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(crate::error::AppError::Misc("Clipboard unavailable".into()));
            }
            for _ in 0..100 {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|_| crate::error::AppError::Misc("Clipboard unavailable".into()))?
                {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(crate::error::AppError::Misc("Clipboard unavailable".into()))
                    };
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
            Err(crate::error::AppError::Misc("Clipboard timed out".into()))
        })
        .await
        .map_err(|_| crate::error::AppError::Misc("Clipboard unavailable".into()))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = details;
        Err(crate::error::AppError::Misc("Use browser clipboard".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registered_secrets_and_unregistered_sensitive_payloads_are_removed() {
        register_secret("unique-test-secret-493");
        register_secret("Owner@example.com");
        let text = sanitize("Apple rejected Owner@example.com unique-test-secret-493");
        assert!(!text.contains("unique-test-secret-493"));
        assert!(!text.contains("Owner@example.com"));
        for text in [
            "Bearer abc",
            "{\"token\":\"abc\"}",
            "<plist>secret",
            "X-Apple-I-MD: blob",
            "password=secret",
            "cookie: xyz",
        ] {
            assert_eq!(sanitize(text), "[sensitive details omitted]");
        }
        assert!(
            !sanitize("failure https://server/path?secret=foo user@domain.test").contains("foo")
        );
        assert_eq!(
            sanitize("Incorrect verification code. (-21669)"),
            "Incorrect verification code. (-21669)"
        );
    }
    #[test]
    fn file_rotation_is_bounded_and_sanitized() {
        let dir = std::env::temp_dir().join(format!("mirsa-diag-test-{}", uuid::Uuid::new_v4()));
        register_secret("test-log-private-value-249");
        write_record(&dir, "test", "Account test-log-private-value-249 failed").unwrap();
        assert!(
            !std::fs::read_to_string(dir.join("diagnostics.log"))
                .unwrap()
                .contains("test-log-private-value-249")
        );
        for _ in 0..240 {
            write_record(&dir, "test", &"x ".repeat(700)).unwrap();
        }
        for name in ["diagnostics.log", "diagnostics.previous.log"] {
            assert!(std::fs::metadata(dir.join(name)).unwrap().len() <= MAX_LOG_BYTES);
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
