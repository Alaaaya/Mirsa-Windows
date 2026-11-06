//! Official-release-only installer. No user URL/path execution or archive extraction here.
use crate::{
    device::{DeviceInfoMutex, get_provider},
    error::AppError,
    operation::Operation,
    pairing::place_file,
    sideload::{SideloaderGuard, SideloaderMutex},
};
use idevice::{IdeviceService, installation_proxy::InstallationProxyClient};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tauri::{State, Window};
use tokio::io::AsyncWriteExt;

pub const FEED: &str = "https://mirsa-app.github.io/source.json";
pub const BUNDLE: &str = "com.alaa.mirsa.setup";
pub const PAIRING_FILENAME: &str = "aircard_pairing.plist"; // iOS compatibility, not a display name
const MAX_IPA: u64 = 256 * 1024 * 1024;
#[derive(Default)]
pub struct InstallerState {
    pub installed: Mutex<Option<InstalledMirsa>>,
    pub pending: Mutex<Option<(String, String)>>, // session UUID + UDID, never credentials
    pub busy: tokio::sync::Mutex<()>,
}
#[derive(Clone)]
pub struct InstalledMirsa {
    pub udid: String,
    pub bundle_id: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MirsaRelease {
    pub name: String,
    pub bundle_identifier: String,
    pub version: String,
    #[serde(rename = "downloadURL")]
    pub download_url: String,
    pub size: u64,
}
#[derive(Deserialize)]
struct Feed {
    apps: Vec<MirsaRelease>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    bundle_identifier: String,
    version: String,
    requires_first_open: bool,
}

fn download_error() -> AppError {
    AppError::Download("Official Mirsa download failed. Check your connection and retry.".into())
}
fn allowed_asset_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().starts_with("/Alaaaya/Mirsa/releases/download/")
        && url.path().ends_with(".ipa")
        && !url.path().contains('%')
}
fn client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let u = attempt.url();
            if attempt.previous().len() > 5 {
                return attempt.error("Too many redirects");
            }
            if u.scheme() == "https"
                && u.username().is_empty()
                && u.password().is_none()
                && u.port().is_none()
                && matches!(
                    u.host_str(),
                    Some(
                        "github.com"
                            | "release-assets.githubusercontent.com"
                            | "objects.githubusercontent.com"
                    )
                )
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|_| download_error())
}
async fn bounded_response(
    mut response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, AppError> {
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > limit) {
        return Err(download_error());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| download_error())? {
        if bytes.len() as u64 + chunk.len() as u64 > limit {
            return Err(download_error());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[tauri::command]
pub async fn get_mirsa_release() -> Result<MirsaRelease, AppError> {
    let response = client()?
        .get(FEED)
        .send()
        .await
        .map_err(|_| download_error())?;
    let feed: Feed = serde_json::from_slice(&bounded_response(response, 1024 * 1024).await?)
        .map_err(|_| AppError::Download("The official Mirsa source is invalid".into()))?;
    let mut candidates = feed
        .apps
        .into_iter()
        .filter(|a| a.bundle_identifier == BUNDLE);
    let release = candidates
        .next()
        .ok_or_else(|| AppError::Download("Mirsa is absent from the official source".into()))?;
    if candidates.next().is_some()
        || release.size == 0
        || release.size > MAX_IPA
        || !reqwest::Url::parse(&release.download_url).is_ok_and(|u| allowed_asset_url(&u))
    {
        return Err(AppError::Download(
            "The official Mirsa release metadata is invalid".into(),
        ));
    }
    Ok(release)
}
fn bad_archive() -> AppError {
    AppError::Download("The Mirsa IPA did not pass identity and archive safety checks".into())
}
pub fn validate_ipa(path: &Path, bundle: &str) -> Result<(), AppError> {
    let file = std::fs::File::open(path).map_err(|_| bad_archive())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| bad_archive())?;
    if archive.len() > 20_000 {
        return Err(bad_archive());
    }
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut main = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|_| bad_archive())?;
        let name = entry.name();
        if name.is_empty()
            || name.starts_with('/')
            || name.contains(['\\', ':'])
            || name.chars().any(|c| c.is_control())
            || name
                .split('/')
                .any(|c| c == ".." || c == "." || c.ends_with('.') || c.ends_with(' '))
            || entry.enclosed_name().is_none()
            || !seen.insert(name.to_string())
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(bad_archive());
        }
        total = total.checked_add(entry.size()).ok_or_else(bad_archive)?;
        if total > 512 * 1024 * 1024 || entry.size() > 128 * 1024 * 1024 {
            return Err(bad_archive());
        }
        let parts: Vec<_> = name.split('/').collect();
        if parts.len() == 3
            && parts[0] == "Payload"
            && parts[1].ends_with(".app")
            && parts[2] == "Info.plist"
        {
            if main.is_some() || entry.size() > 1024 * 1024 {
                return Err(bad_archive());
            }
            main = Some(index);
        }
    }
    let index = main.ok_or_else(bad_archive)?;
    let entry = archive.by_index(index).map_err(|_| bad_archive())?;
    let mut data = Vec::new();
    entry
        .take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| bad_archive())?;
    let info = plist::Value::from_reader(Cursor::new(data)).map_err(|_| bad_archive())?;
    if info
        .as_dictionary()
        .and_then(|d| d.get("CFBundleIdentifier"))
        .and_then(|v| v.as_string())
        != Some(bundle)
    {
        return Err(bad_archive());
    }
    Ok(())
}
struct TempIpa(PathBuf);
impl Drop for TempIpa {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[tauri::command]
pub async fn install_mirsa_operation(
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    installer: State<'_, InstallerState>,
) -> Result<InstallResult, AppError> {
    let _busy = installer
        .busy
        .try_lock()
        .map_err(|_| AppError::Misc("Another setup operation is running".into()))?;
    let op = Operation::new("install_mirsa".into(), &window);
    op.start("download")?;
    let release = op.fail_if_err("download", get_mirsa_release().await)?;
    let device = device_state
        .lock()
        .map_err(|_| AppError::NoDeviceSelected)?
        .clone()
        .ok_or(AppError::NoDeviceSelected)?;
    let dest = TempIpa(std::env::temp_dir().join(format!("Mirsa-{}.ipa", uuid::Uuid::new_v4())));
    let download = async {
        let mut response = client()?
            .get(&release.download_url)
            .send()
            .await
            .map_err(|_| download_error())?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > MAX_IPA)
        {
            return Err(download_error());
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest.0)
            .await
            .map_err(|_| download_error())?;
        let mut length = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|_| download_error())? {
            length += chunk.len() as u64;
            if length > MAX_IPA || length > release.size {
                return Err(download_error());
            }
            file.write_all(&chunk).await.map_err(|_| download_error())?;
        }
        file.flush().await.map_err(|_| download_error())?;
        drop(file);
        if length != release.size {
            return Err(download_error());
        }
        validate_ipa(&dest.0, &release.bundle_identifier)
    }
    .await;
    op.fail_if_err("download", download)?;
    op.move_on("download", "install")?;
    let provider = get_provider(&device.info).await?;
    let mut account = SideloaderGuard::take(&sideloader_state)?;
    let team = op.fail_if_err(
        "install",
        account.get_mut().get_team().await.map_err(AppError::from),
    )?;
    let installed_id = format!("{}.{}", release.bundle_identifier, team.team_id);
    op.fail_if_err(
        "install",
        account
            .get_mut()
            .install_app(
                &provider,
                dest.0.clone(),
                true,
                None::<fn(f32) -> std::future::Ready<()>>,
                None,
            )
            .await
            .map_err(AppError::from),
    )?;
    op.move_on("install", "pairing")?;
    let mut proxy = InstallationProxyClient::connect(&provider)
        .await
        .map_err(|_| AppError::DeviceComs("Could not verify Mirsa installation".into()))?;
    let apps = proxy
        .get_apps(Some("User"), None)
        .await
        .map_err(|_| AppError::DeviceComs("Could not verify Mirsa installation".into()))?;
    if !apps.contains_key(&installed_id) {
        return op.fail(
            "pairing",
            AppError::DeviceComs("The expected signed Mirsa app was not found".into()),
        );
    }
    op.fail_if_err(
        "pairing",
        place_file(
            device.pairing,
            &provider,
            installed_id.clone(),
            PAIRING_FILENAME.into(),
        )
        .await,
    )?;
    *installer
        .installed
        .lock()
        .map_err(|_| AppError::Misc("Setup state unavailable".into()))? = Some(InstalledMirsa {
        udid: device.info.udid,
        bundle_id: installed_id.clone(),
    });
    *installer
        .pending
        .lock()
        .map_err(|_| AppError::Misc("Setup state unavailable".into()))? = None;
    op.complete("pairing")?;
    Ok(InstallResult {
        bundle_identifier: installed_id,
        version: release.version,
        requires_first_open: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_url_is_pinned() {
        for url in [
            "http://github.com/Alaaaya/Mirsa/releases/download/setup/Mirsa.ipa",
            "https://github.com/other/repo/releases/download/a/b.ipa",
            "https://github.com.evil/Alaaaya/Mirsa/releases/download/a/b.ipa",
            "https://github.com/Alaaaya/Mirsa/releases/download/a/b.ipa?x=1",
        ] {
            assert!(!allowed_asset_url(&reqwest::Url::parse(url).unwrap()));
        }
        assert!(allowed_asset_url(
            &reqwest::Url::parse(
                "https://github.com/Alaaaya/Mirsa/releases/download/setup/Mirsa-Setup.ipa"
            )
            .unwrap()
        ));
    }
}
