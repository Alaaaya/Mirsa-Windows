//! Pinned official installer and shared strict IPA validation. No arbitrary URL execution.
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
    AppError::Download("The IPA did not pass identity and archive safety checks".into())
}
#[derive(Clone)]
pub struct IpaIdentity {
    pub bundle_identifier: String,
    pub version: String,
}
pub fn validate_ipa(path: &Path, bundle: &str) -> Result<(), AppError> {
    let identity = inspect_ipa(path)?;
    if identity.bundle_identifier != bundle {
        return Err(bad_archive());
    }
    Ok(())
}
fn safe_component(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.ends_with(['.', ' '])
        && !c.contains(['<', '>', '"', '|', '?', '*'])
        && !matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}
fn check_macho(bytes: &[u8]) -> Result<(), AppError> {
    use goblin::mach::{Mach, SingleArch, load_command::CommandVariant};
    fn thin(m: &goblin::mach::MachO<'_>) -> Result<(), AppError> {
        for command in &m.load_commands {
            let encrypted = match command.command {
                CommandVariant::EncryptionInfo32(ref c) => c.cryptid != 0,
                CommandVariant::EncryptionInfo64(ref c) => c.cryptid != 0,
                _ => false,
            };
            if encrypted {
                return Err(AppError::Misc("This IPA contains an encrypted App Store binary and cannot be signed. Choose an unencrypted IPA you are authorized to install.".into()));
            }
        }
        Ok(())
    }
    match Mach::parse(bytes).map_err(|_| bad_archive())? {
        Mach::Binary(m) => thin(&m),
        Mach::Fat(fat) => {
            let arches = fat.arches().map_err(|_| bad_archive())?;
            if arches.is_empty() || arches.len() > 32 {
                return Err(bad_archive());
            }
            for i in 0..arches.len() {
                match fat.get(i).map_err(|_| bad_archive())? {
                    SingleArch::MachO(m) => thin(&m)?,
                    _ => return Err(bad_archive()),
                }
            }
            Ok(())
        }
    }
}
pub fn inspect_ipa(path: &Path) -> Result<IpaIdentity, AppError> {
    let file = std::fs::File::open(path).map_err(|_| bad_archive())?;
    if file.metadata().map_err(|_| bad_archive())?.len() > MAX_IPA {
        return Err(bad_archive());
    }
    let mut archive = zip::ZipArchive::new(file).map_err(|_| bad_archive())?;
    if archive.len() == 0 || archive.len() > 20_000 {
        return Err(bad_archive());
    }
    let mut seen = HashSet::new();
    let mut files = HashSet::new();
    let mut paths = Vec::new();
    let mut total = 0u64;
    let mut main = None;
    let mut app_roots = HashSet::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|_| bad_archive())?;
        let name = entry.name();
        let trimmed = name.trim_end_matches('/');
        if name.is_empty()
            || name.starts_with('/')
            || name.contains(['\\', ':'])
            || name.chars().any(|c| c.is_control())
            || name.ends_with("//")
            || !trimmed.split('/').all(safe_component)
            || entry.enclosed_name().is_none()
            || !seen.insert(trimmed.to_lowercase())
            || entry.unix_mode().is_some_and(|mode| {
                mode & 0o170000 != 0 && !matches!(mode & 0o170000, 0o100000 | 0o040000)
            })
        {
            return Err(bad_archive());
        }
        if !entry.is_dir() {
            files.insert(trimmed.to_lowercase());
        }
        paths.push(trimmed.to_lowercase());
        total = total.checked_add(entry.size()).ok_or_else(bad_archive)?;
        if total > 512 * 1024 * 1024 || entry.size() > 128 * 1024 * 1024 {
            return Err(bad_archive());
        }
        let parts: Vec<_> = trimmed.split('/').collect();
        if parts.len() >= 2 && parts[0] == "Payload" && parts[1].ends_with(".app") {
            app_roots.insert(parts[1].to_string());
        }
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
    if app_roots.len() != 1 {
        return Err(bad_archive());
    }
    for path in paths {
        for (offset, _) in path.match_indices('/') {
            if files.contains(&path[..offset]) {
                return Err(bad_archive());
            }
        }
    }
    let index = main.ok_or_else(bad_archive)?;
    let mut entry = archive.by_index(index).map_err(|_| bad_archive())?;
    let prefix = entry
        .name()
        .rsplit_once('/')
        .ok_or_else(bad_archive)?
        .0
        .to_string();
    let mut data = Vec::new();
    entry
        .by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| bad_archive())?;
    if data.len() > 1024 * 1024 {
        return Err(bad_archive());
    }
    let info = plist::Value::from_reader(Cursor::new(data)).map_err(|_| bad_archive())?;
    let dict = info.as_dictionary().ok_or_else(bad_archive)?;
    let bundle = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .ok_or_else(bad_archive)?;
    if bundle.is_empty()
        || bundle.len() > 255
        || !bundle
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    {
        return Err(bad_archive());
    }
    let executable = dict
        .get("CFBundleExecutable")
        .and_then(|v| v.as_string())
        .ok_or_else(bad_archive)?;
    if !safe_component(executable) || executable.contains(['/', '\\', ':']) {
        return Err(bad_archive());
    }
    let executable_path = format!("{}/{}", prefix, executable);
    let identity = IpaIdentity {
        bundle_identifier: bundle.to_string(),
        version: dict
            .get("CFBundleShortVersionString")
            .and_then(|v| v.as_string())
            .unwrap_or("Unknown")
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect(),
    };
    drop(entry);
    let mut main_checked = false;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|_| bad_archive())?;
        if entry.is_dir() || entry.size() < 4 {
            continue;
        }
        let mut magic = [0u8; 4];
        entry.read_exact(&mut magic).map_err(|_| bad_archive())?;
        let macho = matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        );
        let is_main = entry.name() == executable_path;
        if is_main && !macho {
            return Err(bad_archive());
        }
        if macho {
            let expected = entry.size();
            let mut bytes = magic.to_vec();
            entry
                .take(128 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| bad_archive())?;
            if bytes.len() as u64 != expected || bytes.len() > 128 * 1024 * 1024 {
                return Err(bad_archive());
            }
            check_macho(&bytes)?;
            if is_main {
                main_checked = true;
            }
        }
    }
    if !main_checked {
        return Err(bad_archive());
    }
    Ok(identity)
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
    // Enforce sign-in server-side before network download or consuming a local selection.
    if sideloader_state
        .lock()
        .map_err(|_| AppError::NotLoggedIn)?
        .is_none()
    {
        return Err(AppError::NotLoggedIn);
    }
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
        account
            .get_mut()
            .get_team()
            .await
            .map_err(|e| AppError::from_report_at(e, "install")),
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
            .map_err(|e| AppError::from_report_at(e, "sign_install")),
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
    fn macho(encrypted: bool) -> Vec<u8> {
        let words: [u32; 14] = [
            0xfeedfacf,
            0x0100000c,
            0,
            2,
            1,
            24,
            0,
            0,
            0x2c,
            24,
            0,
            0,
            u32::from(encrypted),
            0,
        ];
        words.into_iter().flat_map(u32::to_le_bytes).collect()
    }
    fn fixture(extra: Option<(&str, &[u8])>, encrypted: bool) -> TempIpa {
        use std::io::Write;
        let path =
            TempIpa(std::env::temp_dir().join(format!("Mirsa-test-{}.ipa", uuid::Uuid::new_v4())));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path.0)
            .unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(br#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.test</string><key>CFBundleExecutable</key><string>Test</string><key>CFBundleShortVersionString</key><string>1.2</string></dict></plist>"#).unwrap();
        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(&macho(encrypted)).unwrap();
        if let Some((name, bytes)) = extra {
            zip.start_file(name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
        path
    }
    #[test]
    fn local_identity_and_official_identity_are_distinct() {
        let file = fixture(None, false);
        let identity = inspect_ipa(&file.0).unwrap();
        assert_eq!(identity.bundle_identifier, "com.example.test");
        assert_eq!(identity.version, "1.2");
        assert!(validate_ipa(&file.0, BUNDLE).is_err());
        assert!(validate_ipa(&file.0, "com.example.test").is_ok());
    }
    #[test]
    fn encrypted_main_and_nested_binaries_rejected() {
        let main = fixture(None, true);
        assert!(inspect_ipa(&main.0).is_err());
        let encrypted = macho(true);
        let nested = fixture(
            Some(("Payload/Test.app/Frameworks/Hidden.dylib", &encrypted)),
            false,
        );
        assert!(inspect_ipa(&nested.0).is_err());
    }
    #[test]
    fn archive_path_ambiguity_rejected() {
        for path in [
            "../escape",
            "Payload/Test.app/../escape",
            "Payload/Test.app/CON.txt",
            "Payload/Test.app/test",
            "Payload/Test.app/INFO.PLIST",
            "Payload/Test.app/File.",
            "Payload/Test.app//file",
            "Payload/Test.app/Thing:stream",
            "Payload/Other.app/file",
        ] {
            let file = fixture(Some((path, b"bad")), false);
            assert!(inspect_ipa(&file.0).is_err(), "accepted {}", path);
        }
    }
    #[test]
    fn malformed_binary_rejected() {
        assert!(check_macho(&[0u8; 32]).is_err());
        assert!(check_macho(&macho(false)).is_ok());
        assert!(check_macho(&macho(true)).is_err());
    }
}
