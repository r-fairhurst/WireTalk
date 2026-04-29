use std::collections::HashMap;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng as RandOsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub type Result<T> = std::result::Result<T, EncryptionError>;

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("Invalid key format")]
    InvalidKey,
    #[error("Peer key not found: {0}")]
    PeerKeyNotFound(String),
}

/// Represents a user's cryptographic identity
#[derive(Clone, Serialize, Deserialize)]
pub struct CryptoIdentity {
    pub public_key: [u8; 32],
    pub key_fingerprint: String,
    #[serde(skip)]
    private_key: Option<StaticSecret>,
}

// Manual Debug implementation to avoid showing private key
impl std::fmt::Debug for CryptoIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoIdentity")
            .field("public_key", &self.public_key)
            .field("key_fingerprint", &self.key_fingerprint)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl CryptoIdentity {
    /// Generate a new cryptographic identity
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(&mut RandOsRng);
        let public_key = PublicKey::from(&private_key);
        let key_fingerprint = Self::compute_fingerprint(&public_key);

        Self {
            public_key: *public_key.as_bytes(),
            key_fingerprint,
            private_key: Some(private_key),
        }
    }

    /// Create identity from existing private key bytes
    pub fn from_private_bytes(private_bytes: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(private_bytes);
        let public_key = PublicKey::from(&private_key);
        let key_fingerprint = Self::compute_fingerprint(&public_key);

        Self {
            public_key: *public_key.as_bytes(),
            key_fingerprint,
            private_key: Some(private_key),
        }
    }

    /// Create identity from public key only (for peers)
    pub fn from_public_key(public_key: [u8; 32]) -> Self {
        let public_key_obj = PublicKey::from(public_key);
        let key_fingerprint = Self::compute_fingerprint(&public_key_obj);

        Self {
            public_key,
            key_fingerprint,
            private_key: None,
        }
    }

    /// Compute SHA-256 fingerprint of public key for MITM protection
    fn compute_fingerprint(public_key: &PublicKey) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)[..16].to_string().to_uppercase() // First 16 chars for display
    }

    /// Get the public key as X25519 PublicKey object
    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }

    /// Get private key bytes for secure storage
    pub fn get_private_bytes(&self) -> Option<[u8; 32]> {
        self.private_key.as_ref().map(|sk: &StaticSecret| sk.to_bytes())
    }

    /// Perform ECDH key agreement with peer's public key
    pub fn derive_shared_secret(&self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        let private_key = self.private_key.as_ref()
            .ok_or(EncryptionError::InvalidKey)?;
        
        let peer_key = PublicKey::from(*peer_public_key);
        let shared_secret = private_key.diffie_hellman(&peer_key);
        
        // Derive encryption key from shared secret using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 32]; // 256-bit key for AES-256
        hk.expand(b"WireTalk-E2EE-v1", &mut okm)
            .map_err(|e| EncryptionError::KeyDerivation(e.to_string()))?;
        
        Ok(okm)
    }
}

/// Encrypted message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender_public_key: [u8; 32],
    pub encrypted_content: Vec<u8>,
    pub nonce: [u8; 12], // AES-GCM nonce
    pub room_id: String, // Kept plaintext for routing
}

/// Key exchange message for secure peer discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeMessage {
    pub sender_id: String,
    pub sender_username: String,
    pub public_key: [u8; 32],
    pub key_fingerprint: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Message encryption/decryption engine
#[derive(Debug)]
pub struct MessageCrypto {
    identity: CryptoIdentity,
    peer_keys: HashMap<String, CryptoIdentity>, // peer_id -> identity
    shared_secrets: HashMap<String, [u8; 32]>,  // peer_id -> shared secret
}

impl MessageCrypto {
    /// Create new MessageCrypto with generated identity
    pub fn new() -> Self {
        Self {
            identity: CryptoIdentity::new(),
            peer_keys: HashMap::new(),
            shared_secrets: HashMap::new(),
        }
    }

    /// Create MessageCrypto from existing private key
    pub fn from_private_key(private_bytes: [u8; 32]) -> Self {
        Self {
            identity: CryptoIdentity::from_private_bytes(private_bytes),
            peer_keys: HashMap::new(),
            shared_secrets: HashMap::new(),
        }
    }

    /// Get our public identity for sharing
    pub fn get_identity(&self) -> &CryptoIdentity {
        &self.identity
    }

    /// Add a peer's public key (after verification)
    pub fn add_peer_key(&mut self, peer_id: &str, peer_identity: CryptoIdentity) -> Result<()> {
        // Derive shared secret for this peer
        let shared_secret = self.identity.derive_shared_secret(&peer_identity.public_key)?;
        
        self.peer_keys.insert(peer_id.to_string(), peer_identity);
        self.shared_secrets.insert(peer_id.to_string(), shared_secret);
        
        Ok(())
    }

    /// Encrypt a message for a specific peer
    pub fn encrypt_message(&self, content: &str, peer_id: &str, room_id: &str) -> Result<EncryptedMessage> {
        let shared_secret = self.shared_secrets.get(peer_id)
            .ok_or_else(|| EncryptionError::PeerKeyNotFound(peer_id.to_string()))?;

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(shared_secret)
            .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt the content
        let encrypted_content = cipher.encrypt(&nonce, content.as_bytes())
            .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

        Ok(EncryptedMessage {
            sender_public_key: self.identity.public_key,
            encrypted_content,
            nonce: *nonce.as_ref(),
            room_id: room_id.to_string(),
        })
    }

    /// Decrypt a message from a peer
    pub fn decrypt_message(&self, encrypted_msg: &EncryptedMessage, peer_id: &str) -> Result<String> {
        let shared_secret = self.shared_secrets.get(peer_id)
            .ok_or_else(|| EncryptionError::PeerKeyNotFound(peer_id.to_string()))?;

        // Verify sender's public key matches expected peer
        let peer_identity = self.peer_keys.get(peer_id)
            .ok_or_else(|| EncryptionError::PeerKeyNotFound(peer_id.to_string()))?;
        
        if encrypted_msg.sender_public_key != peer_identity.public_key {
            return Err(EncryptionError::Decryption("Sender public key mismatch".to_string()));
        }

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(shared_secret)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

        // Decrypt the content
        let nonce = Nonce::from_slice(&encrypted_msg.nonce);
        let decrypted_bytes = cipher.decrypt(nonce, encrypted_msg.encrypted_content.as_ref())
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

        String::from_utf8(decrypted_bytes)
            .map_err(|e| EncryptionError::Decryption(format!("Invalid UTF-8: {}", e)))
    }

    /// Get all known peer identities
    pub fn get_peer_identities(&self) -> &HashMap<String, CryptoIdentity> {
        &self.peer_keys
    }

    /// Remove a peer (when they disconnect)
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peer_keys.remove(peer_id);
        self.shared_secrets.remove(peer_id);
    }

    /// Verify a peer's key fingerprint for MITM protection
    pub fn verify_peer_fingerprint(&self, peer_id: &str, expected_fingerprint: &str) -> bool {
        if let Some(peer_identity) = self.peer_keys.get(peer_id) {
            peer_identity.key_fingerprint == expected_fingerprint
        } else {
            false
        }
    }

    /// Create key exchange message for announcing our identity
    pub fn create_key_exchange(&self, our_id: &str, our_username: &str) -> KeyExchangeMessage {
        KeyExchangeMessage {
            sender_id: our_id.to_string(),
            sender_username: our_username.to_string(),
            public_key: self.identity.public_key,
            key_fingerprint: self.identity.key_fingerprint.clone(),
            timestamp: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity1 = CryptoIdentity::new();
        let identity2 = CryptoIdentity::new();
        
        // Different identities should have different keys and fingerprints
        assert_ne!(identity1.public_key, identity2.public_key);
        assert_ne!(identity1.key_fingerprint, identity2.key_fingerprint);
    }

    #[test]
    fn test_key_agreement() {
        let identity1 = CryptoIdentity::new();
        let identity2 = CryptoIdentity::new();
        
        // Both sides should derive the same shared secret
        let secret1 = identity1.derive_shared_secret(&identity2.public_key).unwrap();
        let secret2 = identity2.derive_shared_secret(&identity1.public_key).unwrap();
        
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_message_encryption() {
        let mut crypto1 = MessageCrypto::new();
        let mut crypto2 = MessageCrypto::new();
        
        // Exchange public keys
        let id1_clone = crypto1.get_identity().clone();
        let id2_clone = crypto2.get_identity().clone();
        
        crypto1.add_peer_key("peer2", CryptoIdentity::from_public_key(id2_clone.public_key)).unwrap();
        crypto2.add_peer_key("peer1", CryptoIdentity::from_public_key(id1_clone.public_key)).unwrap();
        
        // Test encryption/decryption
        let message = "Hello, secure world!";
        let encrypted = crypto1.encrypt_message(message, "peer2", "room1").unwrap();
        let decrypted = crypto2.decrypt_message(&encrypted, "peer1").unwrap();
        
        assert_eq!(message, decrypted);
    }
}