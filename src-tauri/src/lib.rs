mod account;
mod device;
mod error;
mod handoff;
mod local_ipa;
mod mirsa;
mod operation;
mod pairing;
mod secure_storage;
mod sideload;

use account::{invalidate_account, logged_in_as, login_new};
use device::{
    DeviceInfoMutex, PairingCancelToken, cancel_pairing, list_devices, set_selected_device,
};
use handoff::{finish_mirsa_setup, mirsa_handoff_status};
use local_ipa::{LocalIpaState, choose_local_ipa, install_local_ipa_operation};
use mirsa::{InstallerState, get_mirsa_release, install_mirsa_operation};
use pairing::export_pairing_cmd;
use secure_storage::keyring_available;
use sideload::SideloaderMutex;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Deliberately NO tracing subscriber, file logger or frontend log forwarding.
    // Dependencies can log authentication bodies at debug/trace. Disable all levels.
    let _ = tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default());
    let _ = isideload::init(); // Install library error-format hooks, never log payloads.
    std::panic::set_hook(Box::new(|_| {})); // Never print secret-bearing panic payloads.
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .setup(|app| {
            app.manage(DeviceInfoMutex::new(None));
            app.manage(SideloaderMutex::new(None));
            app.manage(PairingCancelToken::new(None));
            app.manage(InstallerState::default());
            app.manage(LocalIpaState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            login_new,
            invalidate_account,
            logged_in_as,
            list_devices,
            set_selected_device,
            cancel_pairing,
            export_pairing_cmd,
            keyring_available,
            choose_local_ipa,
            install_local_ipa_operation,
            get_mirsa_release,
            install_mirsa_operation,
            finish_mirsa_setup,
            mirsa_handoff_status,
        ])
        .run(tauri::generate_context!())
        .expect("Mirsa could not start");
}
