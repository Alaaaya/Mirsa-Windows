//! Local selection is native-only; IPC receives a one-time token, never a supplied path or URL.
use crate::{
    device::{DeviceInfoMutex, get_provider},
    error::AppError,
    mirsa::{InstallerState, inspect_ipa},
    operation::Operation,
    sideload::{SideloaderGuard, SideloaderMutex},
};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{AppHandle, State, Window};
use tauri_plugin_dialog::DialogExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_LOCAL_IPA: u64 = 256 * 1024 * 1024;
#[derive(Default)]
pub struct LocalIpaState {
    selected: Mutex<Option<Selected>>,
}
struct Selected {
    token: String,
    path: PathBuf,
    selected_at: Instant,
}
#[derive(Serialize)]
pub struct Selection {
    token: String,
    name: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalResult {
    bundle_identifier: String,
    version: String,
    requires_first_open: bool,
}
fn failed() -> AppError {
    AppError::Misc("Could not read the selected IPA. Choose a local IPA file and try again.".into())
}
#[tauri::command]
pub async fn choose_local_ipa(
    app: AppHandle,
    local: State<'_, LocalIpaState>,
    installer: State<'_, InstallerState>,
) -> Result<Option<Selection>, AppError> {
    let _busy = installer
        .busy
        .try_lock()
        .map_err(|_| AppError::Misc("Another setup operation is running".into()))?;
    // Canceling a new selection also revokes the previous selection token.
    *local.selected.lock().map_err(|_| failed())? = None;
    let chosen = tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Choose IPA to install")
            .add_filter("iOS app", &["ipa"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| failed())?;
    let Some(chosen) = chosen else {
        return Ok(None);
    };
    let path = chosen.as_path().ok_or_else(failed)?.to_path_buf();
    if !path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ipa"))
    {
        return Err(failed());
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|_| failed())?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_LOCAL_IPA {
        return Err(failed());
    }
    let name = path
        .file_name()
        .ok_or_else(failed)?
        .to_string_lossy()
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
    let token = uuid::Uuid::new_v4().to_string();
    *local.selected.lock().map_err(|_| failed())? = Some(Selected {
        token: token.clone(),
        path,
        selected_at: Instant::now(),
    });
    Ok(Some(Selection { token, name }))
}
struct StagedIpa(PathBuf);
impl Drop for StagedIpa {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn stage(source: &std::path::Path, destination: &std::path::Path) -> Result<(), AppError> {
    let file = tokio::fs::File::open(source).await.map_err(|_| failed())?;
    let meta = file.metadata().await.map_err(|_| failed())?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_LOCAL_IPA {
        return Err(failed());
    }
    let mut reader = file.take(MAX_LOCAL_IPA + 1);
    let mut writer = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .await
        .map_err(|_| failed())?;
    let length = tokio::io::copy(&mut reader, &mut writer)
        .await
        .map_err(|_| failed())?;
    writer.flush().await.map_err(|_| failed())?;
    if length == 0 || length > MAX_LOCAL_IPA || length != meta.len() {
        return Err(failed());
    }
    Ok(())
}
#[tauri::command]
pub async fn install_local_ipa_operation(
    token: String,
    window: Window,
    local: State<'_, LocalIpaState>,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    installer: State<'_, InstallerState>,
) -> Result<LocalResult, AppError> {
    let _busy = installer
        .busy
        .try_lock()
        .map_err(|_| AppError::Misc("Another setup operation is running".into()))?;
    // Enforce sign-in server-side before network download or consuming a local selection.
    if sideloader_state
        .lock()
        .map_err(|_| AppError::NotLoggedIn)?
        .is_none()
    {
        return Err(AppError::NotLoggedIn);
    }
    let op = Operation::new("install_local".into(), &window);
    op.start("validate")?;
    let selected = {
        let mut slot = local.selected.lock().map_err(|_| failed())?;
        if !slot.as_ref().is_some_and(|s| {
            s.token == token && s.selected_at.elapsed() < Duration::from_secs(1800)
        }) {
            return op.fail(
                "validate",
                AppError::Misc(
                    "The IPA selection expired or was already used. Choose it again.".into(),
                ),
            );
        }
        slot.take().ok_or_else(failed)?
    };
    let staged =
        StagedIpa(std::env::temp_dir().join(format!("Mirsa-local-{}.ipa", uuid::Uuid::new_v4())));
    op.fail_if_err("validate", stage(&selected.path, &staged.0).await)?;
    // Validate the private snapshot that will actually be signed, not the user-controlled original.
    let path = staged.0.clone();
    let identity = op.fail_if_err(
        "validate",
        tokio::task::spawn_blocking(move || inspect_ipa(&path))
            .await
            .map_err(|_| failed())
            .and_then(|v| v),
    )?;
    op.move_on("validate", "install")?;
    let device = device_state
        .lock()
        .map_err(|_| failed())?
        .clone()
        .ok_or(AppError::NoDeviceSelected)?;
    let provider = op.fail_if_err("install", get_provider(&device.info).await)?;
    let mut account = op.fail_if_err("install", SideloaderGuard::take(&sideloader_state))?;
    let team = op.fail_if_err(
        "install",
        account
            .get_mut()
            .get_team()
            .await
            .map_err(|e| AppError::from_report_at(e, "install")),
    )?;
    let signed_id = format!("{}.{}", identity.bundle_identifier, team.team_id);
    // A generic IPA may replace a previously installed Mirsa. Revoke any earlier handoff authorization.
    // Generic mode NEVER grants installed state or pushes pairing/credentials, even for a Mirsa ID.
    *installer.installed.lock().map_err(|_| failed())? = None;
    *installer.pending.lock().map_err(|_| failed())? = None;
    op.fail_if_err(
        "install",
        account
            .get_mut()
            .install_app(
                &provider,
                staged.0.clone(),
                true,
                None::<fn(f32) -> std::future::Ready<()>>,
                None,
            )
            .await
            .map_err(|e| AppError::from_report_at(e, "sign_install")),
    )?;
    op.complete("install")?;
    Ok(LocalResult {
        bundle_identifier: signed_id,
        version: identity.version,
        requires_first_open: false,
    })
}
