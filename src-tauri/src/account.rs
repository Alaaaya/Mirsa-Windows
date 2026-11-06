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
use std::time::Duration;
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
    let password = zeroize::Zeroizing::new(password);
    if email.trim().is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096
    {
        return Err(AppError::Auth(
            "Enter a valid Apple Account email and password".into(),
        ));
    }
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

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
    *sideloader_guard = None;
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
                let (tx, rx) = tokio::sync::oneshot::channel::<String>();
                let tx = std::sync::Mutex::new(Some(tx));
                let handler_id = window_clone.listen("2fa-recieved", move |event| {
                    if let Ok(mut slot) = tx.lock() {
                        if let Some(tx) = slot.take() {
                            let _ = tx.send(event.payload().to_string());
                        }
                    }
                });
                if window_clone.emit("2fa-required", params).is_err() {
                    window_clone.unlisten(handler_id);
                    rootcause::bail!("Could not request verification code");
                }
                let result = tokio::time::timeout(Duration::from_secs(120), rx).await;
                window_clone.unlisten(handler_id);
                let raw = result
                    .context("Verification code timed out")?
                    .context("Verification canceled")?;
                let code = serde_json::from_str::<String>(&raw).unwrap_or(raw);
                let code = code.trim().to_string();
                if code.is_empty() || code.len() > 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
                    rootcause::bail!("Invalid verification code");
                }
                Ok(TwoFactorCallbackResponse::SubmitCode(code))
            }
            .boxed()
        }
    };

    let anisette_url = if !anisette_server.contains("://") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };
    let url = reqwest::Url::parse(&anisette_url)
        .map_err(|_| AppError::Anisette("Invalid anisette server URL".into()))?;
    if url.scheme() != "https"
        || url.host_str() != Some("ani.sidestore.io")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(AppError::Anisette(
            "Only the trusted HTTPS anisette server ani.sidestore.io is allowed".into(),
        ));
    }

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .anisette_provider(
            RemoteV3AnisetteProvider::default()?
                .set_serial_number("0".to_string())
                .set_storage(create_sideloading_storage(app)?)
                // just temporary while waiting for the anisette servers to start reporting this
                .set_client_info_override(Some(AnisetteClientInfo {
                    client_info:
                        "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                            .to_string(),
                    user_agent: "akd/1.0 CFNetwork/811.5.4".to_string(),
                }))
                .set_url(&anisette_url),
        )
        .login(password, Box::new(tfa_closure))
        .await?;

    let dev_session = DeveloperSession::from_account(&mut account).await?;

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
