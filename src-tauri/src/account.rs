use crate::diagnostics;
use futures::FutureExt;
use isideload::{
    anisette::{AnisetteClientInfo, remote_v3::RemoteV3AnisetteProvider},
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{certificates::DevelopmentCertificate, developer_session::DeveloperSession},
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        sideloader::Sideloader,
    },
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
pub static AUTH_EPOCH: AtomicU64 = AtomicU64::new(0);
struct OnDrop<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
static LOGIN_BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub const ANISETTE_SERVERS: &[&str] = &[
    "ani.iloader.app",
    "mac-ani.jkcoxson.com",
    "new.ani.sidestore.io",
    "ani.sidestore.io",
];
use tauri::{AppHandle, Emitter, Listener, State, Window};

use crate::{
    error::AppError, secure_storage::create_sideloading_storage, sideload::SideloaderMutex,
};

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let _busy = LOGIN_BUSY
        .try_lock()
        .map_err(|_| AppError::Auth("Sign-in already running".into()))?;
    let password = zeroize::Zeroizing::new(password);
    diagnostics::register_secret(&email);
    diagnostics::register_secret(&email.to_lowercase());
    diagnostics::register_secret(&password);
    let epoch = {
        let mut state = sideloader_state.lock().map_err(|_| AppError::NotLoggedIn)?;
        *state = None;
        AUTH_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
    };
    diagnostics::stage("account_validation");
    if email.trim().is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096
    {
        return Err(AppError::Auth(
            "Enter a valid Apple Account and non-empty credentials".into(),
        ));
    }
    let account = tokio::time::timeout(
        Duration::from_secs(300),
        login(&handle, window, &email, &password, anisette_server),
    )
    .await
    .map_err(|_| {
        AppError::from_report_at(
            rootcause::report!("Authentication timed out"),
            "apple_login",
        )
    })??;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    if AUTH_EPOCH.load(Ordering::SeqCst) != epoch {
        return Err(AppError::Canceled("Sign-in".into()));
    }
    *sideloader_guard = Some(account);
    diagnostics::stage("signed_in");

    let _ = save_credentials; // Password persistence is deliberately disabled.
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    sideloader_guard
        .as_ref()
        .map(|account| account.get_email().to_string())
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) {
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    AUTH_EPOCH.fetch_add(1, Ordering::SeqCst);
    *sideloader_guard = None;
    diagnostics::stage("signed_out");
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>, AppError> {
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();

            async move {
                diagnostics::stage("two_factor");
                let (tx, rx) = tokio::sync::oneshot::channel::<String>();
                let tx = std::sync::Mutex::new(Some(tx));
                let handler_id = window_clone.listen("2fa-recieved", move |event| {
                    if let Ok(mut slot) = tx.lock() {
                        if let Some(tx) = slot.take() {
                            let _ = tx.send(event.payload().to_string());
                        }
                    }
                });
                let cleanup_window = window_clone.clone();
                let _cleanup = OnDrop(Some(move || cleanup_window.unlisten(handler_id)));
                let allowed_numbers: Vec<u32> = params.numbers.iter().map(|n| n.id).collect();
                let mut params = params;
                params.last_error = params.last_error.map(|text| diagnostics::sanitize(&text));
                if window_clone.emit("2fa-required", params).is_err() {
                    window_clone.unlisten(handler_id);
                    rootcause::bail!("Could not request verification code");
                }
                let result = tokio::time::timeout(Duration::from_secs(120), rx).await;
                window_clone.unlisten(handler_id);
                let raw = result
                    .context("Verification code timed out")?
                    .context("Verification canceled")?;
                // Existing string-code event stays compatible. Structured actions additionally
                // let the UI select a method when Apple reports unknown 2FA requirements.
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(action) = value.get("action").and_then(|v| v.as_str()) {
                        return match action {
                            "cancel" => Ok(TwoFactorCallbackResponse::Abort),
                            "devices" => Ok(TwoFactorCallbackResponse::SendToDevices),
                            "resend" => Ok(TwoFactorCallbackResponse::ResendCode),
                            "sms" => {
                                let id = value
                                    .get("numberId")
                                    .and_then(|v| v.as_u64())
                                    .and_then(|n| u32::try_from(n).ok())
                                    .filter(|n| allowed_numbers.contains(n));
                                match id {
                                    Some(n) => Ok(TwoFactorCallbackResponse::SendSms(n)),
                                    None => {
                                        rootcause::bail!("Invalid verification method");
                                    }
                                }
                            }
                            _ => {
                                rootcause::bail!("Invalid verification method");
                            }
                        };
                    }
                }
                let code = serde_json::from_str::<String>(&raw).unwrap_or(raw);
                let code = code.trim().to_string();
                diagnostics::register_secret(&code);
                if code.is_empty() {
                    return Ok(TwoFactorCallbackResponse::Abort);
                }
                if code.len() > 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
                    rootcause::bail!("Invalid verification code");
                }
                Ok(TwoFactorCallbackResponse::SubmitCode(code))
            }
            .boxed()
        }
    };

    diagnostics::stage("anisette_configuration");
    let anisette_url = if !anisette_server.contains("://") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };
    let url = reqwest::Url::parse(&anisette_url)
        .map_err(|_| AppError::Anisette("Invalid anisette server URL".into()))?;
    if url.scheme() != "https"
        || !url
            .host_str()
            .is_some_and(|host| ANISETTE_SERVERS.contains(&host))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(AppError::Anisette(
            "Choose a supported trusted HTTPS anisette server".into(),
        ));
    }

    diagnostics::stage("anisette_provider");
    let provider = RemoteV3AnisetteProvider::default()
        .map_err(|e| AppError::from_report_at(e, "anisette_provider"))?
        .set_serial_number("0".to_string())
        .set_storage(create_sideloading_storage(app)?)
        // just temporary while waiting for the anisette servers to start reporting this
        .set_client_info_override(Some(AnisetteClientInfo {
            client_info:
                "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                    .to_string(),
            user_agent: "akd/1.0 CFNetwork/811.5.4".to_string(),
        }))
        .set_url(&anisette_url);
    let _ = diagnostics::record(
        "anisette_provider",
        url.host_str().unwrap_or("trusted server"),
    );
    diagnostics::stage("apple_login");
    let mut account = AppleAccount::builder(&email.to_lowercase())
        .anisette_provider(provider)
        .err_429_retries(None)
        .login(password, Box::new(tfa_closure))
        .await
        .map_err(|e| AppError::from_report_at(e, "apple_login"))?;

    diagnostics::stage("developer_session");
    let dev_session = DeveloperSession::from_account(&mut account)
        .await
        .map_err(|e| AppError::from_report_at(e, "developer_session"))?;

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |certs: Vec<DevelopmentCertificate>| {
            let window_clone = window.clone();
            Box::pin(async move {
                let cert_infos: Vec<CertificateInfo> = certs
                    .iter()
                    .map(|cert| CertificateInfo {
                        name: cert.name.clone(),
                        certificate_id: cert.certificate_id.clone(),
                        serial_number: cert.serial_number.clone(),
                        machine_name: cert.machine_name.clone(),
                        machine_id: cert.machine_id.clone(),
                    })
                    .collect();
                let (tx, rx) = tokio::sync::oneshot::channel::<Option<Vec<String>>>();
                let tx = std::sync::Mutex::new(Some(tx));
                let allowed: Vec<String> = cert_infos
                    .iter()
                    .filter_map(|c| c.serial_number.clone())
                    .collect();
                let handler_id = window_clone.listen("max-certs-response", move |event| {
                    if let Ok(mut slot) = tx.lock() {
                        if let Some(tx) = slot.take() {
                            let value =
                                serde_json::from_str::<Option<Vec<String>>>(event.payload())
                                    .unwrap_or(None);
                            let _ = tx.send(value);
                        }
                    }
                });
                if window_clone.emit("max-certs-reached", cert_infos).is_err() {
                    window_clone.unlisten(handler_id);
                    rootcause::bail!("Could not request certificate selection");
                }
                let result = tokio::time::timeout(Duration::from_secs(300), rx).await;
                window_clone.unlisten(handler_id);
                let selected = result
                    .context("Certificate selection timed out")?
                    .context("Certificate selection canceled")?;
                if let Some(ref values) = selected {
                    if values.is_empty() || values.iter().any(|v| !allowed.contains(v)) {
                        rootcause::bail!("Invalid certificate selection");
                    }
                }
                Ok(selected)
            })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("Mirsa".into())
        .storage(create_sideloading_storage(app)?)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::ReuseMain,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn supported_hosts_are_exact_and_include_pinned_library_default() {
        assert!(ANISETTE_SERVERS.contains(&"ani.iloader.app"));
        assert!(!ANISETTE_SERVERS.contains(&"ani.iloader.app.evil.test"));
        assert!(!ANISETTE_SERVERS.contains(&"localhost"));
    }
}
