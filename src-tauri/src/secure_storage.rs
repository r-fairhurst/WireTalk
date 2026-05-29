use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStorageFile {
    pub version: u8,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub updated_at: DateTime<Utc>,
}

pub fn resolve_storage_path(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data directory: {}", e))?;

    std::fs::create_dir_all(&app_data_dir)
        .map_err(|e| format!("Failed to create app data directory: {}", e))?;

    Ok(app_data_dir.join("secure_vault.json"))
}

pub fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    if password.len() < 4 {
        return Err("Password/PIN must be at least 4 characters".to_string());
    }

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Failed to derive encryption key: {}", e))?;

    Ok(key)
}

pub fn encrypt_payload_with_salt(
    payload_json: &str,
    password: &str,
    salt: [u8; 16],
) -> Result<(EncryptedStorageFile, [u8; 32]), String> {
    let key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to initialize storage cipher: {}", e))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, payload_json.as_bytes())
        .map_err(|e| format!("Failed to encrypt storage payload: {}", e))?;

    let file = EncryptedStorageFile {
        version: 1,
        salt_b64: STANDARD.encode(salt),
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
        updated_at: Utc::now(),
    };

    Ok((file, key))
}

pub fn decrypt_payload(file: &EncryptedStorageFile, password: &str) -> Result<(String, [u8; 32]), String> {
    if file.version != 1 {
        return Err(format!("Unsupported storage version: {}", file.version));
    }

    let salt_bytes = STANDARD
        .decode(&file.salt_b64)
        .map_err(|e| format!("Invalid storage salt encoding: {}", e))?;
    if salt_bytes.len() != 16 {
        return Err("Invalid storage salt length".to_string());
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_bytes);

    let key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to initialize storage cipher: {}", e))?;

    let nonce_bytes = STANDARD
        .decode(&file.nonce_b64)
        .map_err(|e| format!("Invalid storage nonce encoding: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Invalid storage nonce length".to_string());
    }

    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = STANDARD
        .decode(&file.ciphertext_b64)
        .map_err(|e| format!("Invalid storage ciphertext encoding: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Failed to decrypt storage. Invalid password/PIN or corrupted data".to_string())?;

    let json = String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid decrypted UTF-8 payload: {}", e))?;

    Ok((json, key))
}

pub async fn write_file(path: &Path, file: &EncryptedStorageFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(file)
        .map_err(|e| format!("Failed to serialize encrypted storage file: {}", e))?;

    tokio::fs::write(path, json)
        .await
        .map_err(|e| format!("Failed to write encrypted storage file: {}", e))
}

pub async fn read_file(path: &Path) -> Result<EncryptedStorageFile, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("Failed to read encrypted storage file: {}", e))?;

    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse encrypted storage file: {}", e))
}
