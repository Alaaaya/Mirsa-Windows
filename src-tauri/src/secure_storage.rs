use crate::error::AppError;
use isideload::util::{keyring_storage::KeyringStorage, storage::SideloadingStorage};
use tauri::AppHandle;

#[tauri::command]
pub fn keyring_available() -> bool {
    let Ok(entry) = keyring::Entry::new("Mirsa", "availability-probe") else {
        return false;
    };
    let ok = entry.set_password("probe").is_ok() && entry.get_password().is_ok();
    let _ = entry.delete_credential();
    ok
}

pub fn create_sideloading_storage(
    _app: &AppHandle,
) -> Result<Box<dyn SideloadingStorage>, AppError> {
    if !keyring_available() {
        return Err(AppError::Keyring(
            "Windows credential storage is unavailable. No insecure fallback is used.".into(),
        ));
    }
    Ok(Box::new(KeyringStorage::new("Mirsa".into())))
}
