//! X25519 + HKDF-SHA256 + AES-256-GCM, interoperable with CryptoKit.
use crate::{
    device::{DeviceInfoMutex, get_provider},
    error::AppError,
    mirsa::{InstalledMirsa, InstallerState},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use idevice::{
    IdeviceService,
    afc::{AfcClient, opcode::AfcFopenMode},
    house_arrest::HouseArrestClient,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tauri::State;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;
const REQUEST: &str = "/Documents/mirsa-handoff-request.json";
const ENVELOPE: &str = "/Documents/mirsa-handoff-envelope.json";
const RECEIPT: &str = "/Documents/mirsa-handoff-receipt.json";
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    version: u32,
    session_id: String,
    public_key: String,
    created_at: i64,
    expires_at: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Credentials<'a> {
    version: u32,
    session_id: &'a str,
    expires_at: i64,
    email: &'a str,
    password: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    version: u32,
    session_id: String,
    public_key: String,
    sealed: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    version: u32,
    session_id: String,
    status: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    status: &'static str,
    session_id: Option<String>,
}
fn invalid() -> AppError {
    AppError::Misc("The encrypted account handoff could not be verified. Open the compatible Mirsa app and retry.".into())
}
async fn connection(
    device_state: &DeviceInfoMutex,
    installer: &InstallerState,
) -> Result<(AfcClient, InstalledMirsa), AppError> {
    let installed = installer
        .installed
        .lock()
        .map_err(|_| invalid())?
        .clone()
        .ok_or_else(|| AppError::Misc("Install Mirsa in this session first".into()))?;
    let selected = device_state
        .lock()
        .map_err(|_| invalid())?
        .clone()
        .ok_or(AppError::NoDeviceSelected)?;
    if selected.info.udid != installed.udid {
        return Err(AppError::Misc(
            "Select the iPhone used for this installation".into(),
        ));
    }
    let provider = get_provider(&selected.info).await?;
    let arrest = HouseArrestClient::connect(&provider)
        .await
        .map_err(|_| invalid())?;
    let afc = arrest
        .vend_documents(&installed.bundle_id)
        .await
        .map_err(|_| invalid())?;
    Ok((afc, installed))
}
async fn read_bounded(afc: &mut AfcClient, path: &str, max: usize) -> Result<Vec<u8>, AppError> {
    let info = afc.get_file_info(path).await.map_err(|_| invalid())?;
    if info.size == 0 || info.size > max || info.st_ifmt != "S_IFREG" {
        return Err(invalid());
    }
    let mut file = afc
        .open(path, AfcFopenMode::RdOnly)
        .await
        .map_err(|_| invalid())?;
    let data = file.read_n(max + 1).await.map_err(|_| invalid());
    let closed = file.close().await.map_err(|_| invalid());
    let data = data?;
    closed?;
    if data.len() > max {
        return Err(invalid());
    }
    Ok(data)
}
fn encrypt(request: &Request, email: &str, password: &str, now: i64) -> Result<Vec<u8>, AppError> {
    if request.version != 1
        || request.created_at > now + 30
        || request.expires_at <= now
        || request.created_at < now - 600
        || request.expires_at - request.created_at != 600
        || uuid::Uuid::parse_str(&request.session_id)
            .ok()
            .is_none_or(|v| v.to_string() != request.session_id)
        || email.trim().is_empty()
        || email.len() > 320
        || password.is_empty()
        || password.len() > 4096
    {
        return Err(invalid());
    }
    let peer: [u8; 32] = STANDARD
        .decode(&request.public_key)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(invalid());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(request.session_id.as_bytes()), shared.as_bytes())
        .expand(b"Mirsa Windows Handoff v1", key.as_mut())
        .map_err(|_| invalid())?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| invalid())?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let credentials = Credentials {
        version: 1,
        session_id: &request.session_id,
        expires_at: request.expires_at,
        email,
        password,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&credentials).map_err(|_| invalid())?);
    if plaintext.len() > 16384 {
        return Err(invalid());
    }
    let aad = format!(
        "mirsa-handoff-v1|{}|{}",
        request.session_id, request.expires_at
    );
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| invalid())?;
    let combined = [nonce.as_slice(), sealed.as_slice()].concat();
    serde_json::to_vec(&Envelope {
        version: 1,
        session_id: request.session_id.clone(),
        public_key: STANDARD.encode(public.as_bytes()),
        sealed: STANDARD.encode(combined),
    })
    .map_err(|_| invalid())
}
#[tauri::command]
pub async fn finish_mirsa_setup(
    email: String,
    password: String,
    device_state: State<'_, DeviceInfoMutex>,
    installer: State<'_, InstallerState>,
) -> Result<Status, AppError> {
    let password = Zeroizing::new(password);
    crate::diagnostics::register_secret(&email);
    crate::diagnostics::register_secret(&email.to_lowercase());
    crate::diagnostics::register_secret(&password);
    let _busy = installer
        .busy
        .try_lock()
        .map_err(|_| AppError::Misc("Another setup operation is running".into()))?;
    let (mut afc, installed) = connection(&device_state, &installer).await?;
    let bytes=read_bounded(&mut afc,REQUEST,4096).await.map_err(|_|AppError::Misc("Open Mirsa on your iPhone first. This release may not support encrypted account handoff yet; you can sign in on the phone instead.".into()))?;
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let data = encrypt(&request, &email, &password, chrono::Utc::now().timestamp())?;
    let temporary = format!("{}.{}", ENVELOPE, uuid::Uuid::new_v4());
    let mut file = afc
        .open(&temporary, AfcFopenMode::Wr)
        .await
        .map_err(|_| invalid())?;
    let written = file.write_entire(&data).await.map_err(|_| invalid());
    let closed = file.close().await.map_err(|_| invalid());
    if written.is_err() || closed.is_err() {
        let _ = afc.remove(&temporary).await;
        return Err(invalid());
    }
    // Request session binding prevents stale or replayed envelopes from being accepted.
    let _ = afc.remove(RECEIPT).await;
    let _ = afc.remove(ENVELOPE).await;
    if afc.rename(&temporary, ENVELOPE).await.is_err() {
        let _ = afc.remove(&temporary).await;
        return Err(invalid());
    }
    *installer.pending.lock().map_err(|_| invalid())? =
        Some((request.session_id.clone(), installed.udid));
    Ok(Status {
        status: "transferred",
        session_id: Some(request.session_id),
    })
}
#[tauri::command]
pub async fn mirsa_handoff_status(
    device_state: State<'_, DeviceInfoMutex>,
    installer: State<'_, InstallerState>,
) -> Result<Status, AppError> {
    let pending = installer.pending.lock().map_err(|_| invalid())?.clone();
    let Some((session, udid)) = pending else {
        return Ok(Status {
            status: "waiting",
            session_id: None,
        });
    };
    let (mut afc, installed) = connection(&device_state, &installer).await?;
    if installed.udid != udid {
        return Err(invalid());
    }
    // No receipt is normal until iOS validates and writes Keychain successfully.
    if afc.get_file_info(RECEIPT).await.is_err() {
        return Ok(Status {
            status: "waiting",
            session_id: Some(session),
        });
    }
    let data = read_bounded(&mut afc, RECEIPT, 4096).await?;
    let receipt: Receipt = serde_json::from_slice(&data).map_err(|_| invalid())?;
    if receipt.version != 1 || receipt.session_id != session {
        return Err(invalid());
    }
    let status = match receipt.status.as_str() {
        "consumed" => "consumed",
        "rejected" => "rejected",
        _ => return Err(invalid()),
    };
    Ok(Status {
        status,
        session_id: Some(session),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_expired_and_low_order_requests() {
        let r = Request {
            version: 1,
            session_id: "77d97ac7-68d4-4f13-b996-56cd03f40f97".into(),
            public_key: STANDARD.encode([0u8; 32]),
            created_at: 1000,
            expires_at: 1600,
        };
        assert!(encrypt(&r, "a@example.com", "password", 1600).is_err());
        assert!(encrypt(&r, "a@example.com", "password", 1100).is_err());
    }
    #[test]
    fn encrypt_roundtrip() {
        use x25519_dalek::StaticSecret;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let r = Request {
            version: 1,
            session_id: "77d97ac7-68d4-4f13-b996-56cd03f40f97".into(),
            public_key: STANDARD.encode(public.as_bytes()),
            created_at: 1000,
            expires_at: 1600,
        };
        let result = encrypt(&r, "test@example.com", "test-password", 1100).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(!String::from_utf8_lossy(&result).contains("test-password"));
        let sender: [u8; 32] = STANDARD
            .decode(v["publicKey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let shared = secret.diffie_hellman(&PublicKey::from(sender));
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(r.session_id.as_bytes()), shared.as_bytes())
            .expand(b"Mirsa Windows Handoff v1", &mut key)
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let sealed = STANDARD.decode(v["sealed"].as_str().unwrap()).unwrap();
        let aad = format!("mirsa-handoff-v1|{}|{}", r.session_id, r.expires_at);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&sealed[..12]),
                Payload {
                    msg: &sealed[12..],
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let credentials: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(credentials["password"], "test-password");
        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&sealed[..12]),
                    Payload {
                        msg: &sealed[12..],
                        aad: b"wrong session"
                    }
                )
                .is_err()
        );
    }
}
