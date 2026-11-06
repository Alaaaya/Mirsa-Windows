use crate::diagnostics::{self, Diagnostic};
use idevice::IdeviceError;
use isideload::SideloadError;
use rootcause::Report;
use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};
mod contexts {
    include!("diagnostic_contexts.rs");
}

#[derive(Debug, thiserror::Error, Clone, strum::AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum AppError {
    #[error("{0}")]
    Diagnostic(Box<DiagnosticError>),
    #[error("{0}")]
    MaxApps(String),
    #[error("{0}")]
    NotEnoughAppIds(String),
    #[error("{0}")]
    DeviceComs(String),
    #[error("{0}")]
    Underage(String),
    #[error("{0}")]
    AccountLocked(String),
    #[error("{0}")]
    Developer(String),
    #[error("{0}")]
    Auth(String),
    #[error("{0}")]
    Download(String),
    #[error("{0}: {1}")]
    HouseArrest(String, String),
    #[error("{0}")]
    RemotePairing(String),
    #[error("{0}: {1}")]
    LockdownPairing(String, String),
    #[error("{0} canceled")]
    Canceled(String),
    #[error("Failed to emit status to frontend: {0}")]
    OperationUpdate(String),
    #[error("{0}: {1}")]
    DeviceComsWithMessage(String, String),
    #[error("{0}: {1}")]
    Usbmuxd(String, String),
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("No device selected")]
    NoDeviceSelected,
    #[error("{0}")]
    Anisette(String),
    #[error("{0}")]
    Keyring(String),
    #[error("Keyring error: {0} - {1}")]
    KeyringWithMessage(String, String),
    #[error("{0}: {1}")]
    Storage(String, String),
    #[error("{0}")]
    Misc(String),
    #[error("{0}: {1}")]
    Filesystem(String, String),
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct DiagnosticError {
    pub kind: String,
    pub message: String,
    pub diagnostic: Diagnostic,
}
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppError", 5)?;
        if let AppError::Diagnostic(error) = self {
            state.serialize_field("type", &error.kind)?;
            state.serialize_field("message", &diagnostics::sanitize(&error.message))?;
            let safe = Diagnostic {
                stage: diagnostics::sanitize(&error.diagnostic.stage),
                code: error.diagnostic.code,
                chain: error
                    .diagnostic
                    .chain
                    .iter()
                    .map(|s| diagnostics::sanitize(s))
                    .collect(),
                log_path: error
                    .diagnostic
                    .log_path
                    .as_ref()
                    .map(|s| diagnostics::sanitize(s)),
            };
            state.serialize_field("diagnostic", &safe)?;
            state.serialize_field("details", &diagnostics::sanitize(&safe.details()))?;
        } else {
            let message = diagnostics::sanitize(&self.to_string());
            let log_path = diagnostics::record("operation", &message);
            state.serialize_field("type", self.as_ref())?;
            state.serialize_field("message", &message)?;
            state.serialize_field(
                "diagnostic",
                &Diagnostic {
                    stage: "operation".into(),
                    code: None,
                    chain: vec![message.clone()],
                    log_path,
                },
            )?;
            state.serialize_field("details", &message)?;
        }
        state.end()
    }
}
impl AppError {
    pub fn from_report_at(report: Report, stage: &'static str) -> Self {
        let mut kind = "misc";
        let mut code = None;
        let mut chain = Vec::new();
        let mut selected_stage = stage.to_owned();
        for cause in report.iter_reports().take(32) {
            if cause.downcast_current_context::<keyring::Error>().is_some() {
                kind = "keyring";
                chain.push("Windows credential storage failed".into());
                continue;
            }
            if let Some(error) = cause.downcast_current_context::<SideloadError>() {
                match error {
                    SideloadError::AuthWithMessage(value, message) => {
                        code = Some(*value);
                        kind = if *value == -20209 {
                            "account_locked"
                        } else {
                            "auth"
                        };
                        chain.push(format!(
                            "Apple authentication error {}: {}",
                            value,
                            diagnostics::sanitize(message)
                        ));
                    }
                    SideloadError::DeveloperError(value, message) => {
                        code = Some(*value);
                        kind = if *value == 1102 {
                            "underage"
                        } else {
                            "developer"
                        };
                        chain.push(format!(
                            "Apple developer error {}: {}",
                            value,
                            diagnostics::sanitize(message)
                        ));
                    }
                    SideloadError::IdeviceError(IdeviceError::ApplicationVerificationFailed(
                        message,
                    )) => {
                        kind = if message.contains("maximum number of installed apps") {
                            "max_apps"
                        } else {
                            "device_coms"
                        };
                        // Verification messages can contain entitlements/profile blobs.
                        chain.push(if kind == "max_apps" { "Device rejected installation: maximum number of installed apps reached" } else { "Device application verification failed" }.into());
                    }
                    SideloadError::IdeviceError(_) => {
                        kind = "device_coms";
                        chain.push("Device communication failed".into());
                    }
                    _ => {}
                }
                continue;
            }
            if let Some(error) = cause.downcast_current_context::<reqwest::Error>() {
                let mut text = if error.is_timeout() {
                    "Network request timed out"
                } else if error.is_connect() {
                    "Network connection failed (DNS, TLS, proxy or server)"
                } else if error.is_decode() {
                    "Server response could not be decoded"
                } else {
                    "HTTP request failed"
                }
                .to_owned();
                if let Some(status) = error.status() {
                    if code.is_none() {
                        code = Some(i64::from(status.as_u16()));
                    }
                    text.push_str(&format!(" (HTTP {})", status.as_u16()));
                }
                chain.push(text);
                // URL and nested source Debug may contain tokens; never format reqwest::Error.
                continue;
            }
            // Unhooked current context only, not report formatter/attachments/error source Debug.
            // Keep exact known library-owned static context, omit dynamic/raw payloads.
            let context = format!("{}", cause.format_current_context_unhooked());
            if contexts::SAFE_CONTEXTS.contains(&context.as_str())
                || [
                    "Verification code timed out",
                    "Verification canceled",
                    "Invalid verification code",
                    "Invalid verification method",
                    "Could not request verification code",
                    "Authentication timed out",
                ]
                .contains(&context.as_str())
            {
                if context.to_ascii_lowercase().contains("anisette")
                    || context == "Failed to provision"
                {
                    selected_stage = "anisette".into();
                    if kind == "misc" {
                        kind = "anisette";
                    }
                } else if context.contains("2FA") || context.contains("Verification") {
                    selected_stage = "two_factor".into();
                }
                if !chain.contains(&context) {
                    chain.push(context);
                }
            } else if context == "Not enough available app IDs" {
                kind = "not_enough_app_ids";
                chain.push(context);
            }
        }
        if chain.is_empty() {
            chain.push(
                "Underlying error type was not safe to display; no response payload was recorded"
                    .into(),
            );
        }
        chain.truncate(16);
        let mut diagnostic = Diagnostic {
            stage: selected_stage,
            code,
            chain,
            log_path: None,
        };
        let message = diagnostic.details();
        diagnostic.log_path = diagnostics::record(&diagnostic.stage, &message);
        Self::Diagnostic(Box::new(DiagnosticError {
            kind: kind.into(),
            message,
            diagnostic,
        }))
    }
}
impl From<Report> for AppError {
    fn from(report: Report) -> Self {
        Self::from_report_at(report, "operation")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apple_codes_and_static_chain_survive_but_secrets_do_not() {
        use rootcause::prelude::*;
        diagnostics::register_secret("private-account@example.test");
        let report: Report = rootcause::report!(SideloadError::AuthWithMessage(
            -20209,
            "Account locked private-account@example.test".into()
        ))
        .context("Failed to log in to Apple ID")
        .into();
        let value = serde_json::to_value(AppError::from_report_at(report, "apple_login")).unwrap();
        assert_eq!(value["type"], "account_locked");
        assert_eq!(value["diagnostic"]["code"], -20209);
        assert!(
            value["details"]
                .as_str()
                .unwrap()
                .contains("Failed to log in to Apple ID")
        );
        assert!(!value.to_string().contains("private-account@example.test"));
    }
    #[test]
    fn raw_body_and_attachments_never_survive_serialization() {
        use rootcause::prelude::*;
        let report: Report = rootcause::report!("{}", r#"{"secret":"unknown-unregistered-body"}"#)
            .attach("private-attachment")
            .context("Failed to provision")
            .into();
        let value =
            serde_json::to_string(&AppError::from_report_at(report, "apple_login")).unwrap();
        assert!(value.contains("anisette"));
        assert!(value.contains("Failed to provision"));
        assert!(!value.contains("unknown-unregistered-body"));
        assert!(!value.contains("private-attachment"));
    }
    #[test]
    fn developer_codes_and_direct_error_serialization_are_safe() {
        diagnostics::register_secret("hidden-test-credential-846");
        let report: Report = rootcause::report!(SideloadError::DeveloperError(
            1102,
            "Account not eligible".into()
        ))
        .into();
        let value =
            serde_json::to_value(AppError::from_report_at(report, "developer_session")).unwrap();
        assert_eq!(value["type"], "underage");
        assert_eq!(value["diagnostic"]["code"], 1102);
        let direct = serde_json::to_string(&AppError::Misc(
            "hidden-test-credential-846 rejected".into(),
        ))
        .unwrap();
        assert!(!direct.contains("hidden-test-credential-846"));
    }
}
