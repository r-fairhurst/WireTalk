use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::Result;



mod p2p_network;
mod encryption;
use p2p_network::P2PNetwork;
use encryption::{MessageCrypto, CryptoIdentity, KeyExchangeMessage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub username: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub room_id: String,
    pub encrypted: bool, // Whether this message is encrypted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub username: String,
    pub public_key: [u8; 32],
    pub key_fingerprint: String,
    pub connected_at: DateTime<Utc>,
    pub verified: bool, // Whether we've verified their key fingerprint
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub p2p_network: Arc<Mutex<Option<P2PNetwork>>>,
    pub messages: Arc<Mutex<Vec<Message>>>,
    pub current_username: Arc<Mutex<Option<String>>>,
    pub joined_rooms: Arc<Mutex<Vec<Room>>>,
    pub current_room: Arc<Mutex<Option<String>>>,
    pub message_crypto: Arc<Mutex<Option<MessageCrypto>>>,
    pub pending_key_exchanges: Arc<Mutex<Vec<KeyExchangeMessage>>>,
    pub encryption_enabled: Arc<Mutex<bool>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            p2p_network: Arc::new(Mutex::new(None)),
            messages: Arc::new(Mutex::new(Vec::new())),
            current_username: Arc::new(Mutex::new(None)),
            joined_rooms: Arc::new(Mutex::new(Vec::new())),
            current_room: Arc::new(Mutex::new(None)),
            message_crypto: Arc::new(Mutex::new(None)),
            pending_key_exchanges: Arc::new(Mutex::new(Vec::new())),
            encryption_enabled: Arc::new(Mutex::new(true)), // E2EE enabled by default
        }
    }
}

#[tauri::command]
async fn start_p2p_network(
    username: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<String, String> {
    // Initialize tracing for libp2p logs
    tracing_subscriber::fmt::init();

    let (network, mut event_receiver) = P2PNetwork::new(username.clone()).await
        .map_err(|e| format!("Failed to start P2P network: {}", e))?;

    let peer_id = network.get_peer_id();

    // Initialize encryption system
    let message_crypto = MessageCrypto::new();
    let our_identity = message_crypto.get_identity().clone();

    // Store the network, username, and crypto
    {
        let mut p2p_lock = state.p2p_network.lock().await;
        *p2p_lock = Some(network);
    }
    {
        let mut username_lock = state.current_username.lock().await;
        *username_lock = Some(username.clone());
    }
    {
        let mut crypto_lock = state.message_crypto.lock().await;
        *crypto_lock = Some(message_crypto);
    }

    // Handle P2P events in a separate task
    let app_clone = app.clone();
    let state_arc = Arc::new((*state).clone());
    tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            match event {
                p2p_network::P2PEvent::MessageReceived(message) => {
                    // Check if this is an encrypted message
                    if let Ok(encrypted_data) = serde_json::from_str::<serde_json::Value>(&message.content) {
                        if encrypted_data.get("type").and_then(|t| t.as_str()) == Some("encrypted_message") {
                            // This is an encrypted message, try to decrypt it
                            let crypto_lock = state_arc.message_crypto.lock().await;
                            if let Some(crypto) = &*crypto_lock {
                                if let (Some(encrypted_content), Some(sender)) = (
                                    encrypted_data.get("content").and_then(|c| c.as_str()),
                                    encrypted_data.get("sender").and_then(|s| s.as_str())
                                ) {
                                    // Parse the encrypted content as EncryptedMessage
                                    if let Ok(encrypted_msg) = serde_json::from_str::<crate::encryption::EncryptedMessage>(encrypted_content) {
                                        let mut decrypted_content = None;
                                        
                                        // Try using sender_peer_id first (preferred method)
                                        if let Some(sender_peer_id) = encrypted_data.get("sender_peer_id").and_then(|p| p.as_str()) {
                                            if let Ok(content) = crypto.decrypt_message(&encrypted_msg, sender_peer_id) {
                                                decrypted_content = Some(content);
                                            }
                                        }
                                        
                                        // Fallback: try using username (for backward compatibility)
                                        if decrypted_content.is_none() {
                                            if let Ok(content) = crypto.decrypt_message(&encrypted_msg, &message.username) {
                                                decrypted_content = Some(content);
                                            }
                                        }
                                        
                                        if let Some(content) = decrypted_content {
                                        // Create decrypted message
                                        let decrypted_message = Message {
                                            id: message.id,
                                            username: sender.to_string(),
                                            content,
                                            timestamp: message.timestamp,
                                            room_id: message.room_id,
                                            encrypted: true,
                                        };
                                        let _ = app_clone.emit("message_received", &decrypted_message);
                                    } else {
                                        // Couldn't decrypt, show as encrypted
                                        let encrypted_message = Message {
                                            id: message.id,
                                            username: sender.to_string(),
                                            content: "[ENCRYPTED MESSAGE - No shared key]".to_string(),
                                            timestamp: message.timestamp,
                                            room_id: message.room_id,
                                            encrypted: true,
                                        };
                                        let _ = app_clone.emit("message_received", &encrypted_message);
                                    }
                                } else {
                                    // Failed to parse encrypted message
                                    let encrypted_message = Message {
                                        id: message.id.clone(),
                                        username: sender.to_string(),
                                        content: "[ENCRYPTED MESSAGE - Parse failed]".to_string(),
                                        timestamp: message.timestamp,
                                        room_id: message.room_id.clone(),
                                        encrypted: true,
                                    };
                                    let _ = app_clone.emit("message_received", &encrypted_message);
                                }
                            }
                            } else {
                                // No crypto available, show as encrypted
                                let encrypted_message = Message {
                                    id: message.id.clone(),
                                    username: message.username.clone(),
                                    content: "[ENCRYPTED MESSAGE]".to_string(),
                                    timestamp: message.timestamp,
                                    room_id: message.room_id.clone(),
                                    encrypted: true,
                                };
                                let _ = app_clone.emit("message_received", &encrypted_message);
                            }
                            return; // Don't process as regular message
                        }
                    }
                    
                    // Regular message handling
                    let _ = app_clone.emit("message_received", &message);
                }
                p2p_network::P2PEvent::KeyExchangeReceived { peer_id, public_key, key_fingerprint } => {
                    // Automatically add the received public key
                    let mut crypto_lock = state_arc.message_crypto.lock().await;
                    if let Some(crypto) = &mut *crypto_lock {
                        // Check if we already have a key for this peer
                        let already_have_key = crypto.get_peer_identities().contains_key(&peer_id);
                        
                        if let Ok(public_key_bytes) = hex::decode(&public_key) {
                            // Create CryptoIdentity from the received key  
                            if public_key_bytes.len() == 32 {
                                let mut key_array = [0u8; 32];
                                key_array.copy_from_slice(&public_key_bytes);
                                
                                let peer_identity = crate::encryption::CryptoIdentity::from_public_key(key_array);
                                
                                if crypto.add_peer_key(&peer_id, peer_identity).is_ok() {
                                    tracing::info!("Automatically added key from peer: {}", peer_id);
                                    // Emit success event to frontend
                                    let _ = app_clone.emit("key_exchange_received", serde_json::json!({
                                        "peer_id": peer_id,
                                        "public_key": public_key,
                                        "key_fingerprint": key_fingerprint,
                                        "success": true
                                    }));
                                    
                                    // Only send our key back if we didn't already have a key for this peer
                                    // This prevents infinite key exchange loops
                                    if !already_have_key {
                                        let our_identity = crypto.get_identity();
                                        let our_public_key_hex = hex::encode(our_identity.public_key);
                                        
                                        let network_lock = state_arc.p2p_network.lock().await;
                                        if let Some(network) = &*network_lock {
                                            if let Err(e) = network.send_key_exchange(
                                                our_public_key_hex, 
                                                our_identity.key_fingerprint.clone(), 
                                                peer_id.clone()
                                            ).await {
                                                tracing::error!("Failed to send key exchange back: {}", e);
                                            } else {
                                                tracing::info!("Sent our key back to peer: {}", peer_id);
                                            }
                                        }
                                    } else {
                                        tracing::debug!("Key exchange already completed with peer: {}", peer_id);
                                    }
                                } else {
                                    tracing::error!("Failed to add peer key for: {}", peer_id);
                                    let _ = app_clone.emit("key_exchange_received", serde_json::json!({
                                        "peer_id": peer_id,
                                        "success": false,
                                        "error": "Failed to add peer key"
                                    }));
                                }
                            } else {
                                tracing::error!("Invalid public key length from peer: {}", peer_id);
                                let _ = app_clone.emit("key_exchange_received", serde_json::json!({
                                    "peer_id": peer_id,
                                    "success": false,
                                    "error": "Invalid key length"
                                }));
                            }
                        } else {
                            tracing::error!("Failed to decode public key from peer: {}", peer_id);
                        }
                    }
                }
                p2p_network::P2PEvent::PeerJoined { peer_id, username } => {
                    let user = User {
                        id: peer_id.to_string(),
                        username: username.unwrap_or_else(|| "Anonymous".to_string()),
                        connected_at: Utc::now(),
                    };
                    let _ = app_clone.emit("peer_joined", &user);
                }
                p2p_network::P2PEvent::PeerLeft { peer_id, username } => {
                    let user = User {
                        id: peer_id.to_string(),
                        username,
                        connected_at: Utc::now(),
                    };
                    let _ = app_clone.emit("peer_left", &user);
                }
                p2p_network::P2PEvent::PeerListUpdated { peers } => {
                    let _ = app_clone.emit("peer_list_updated", &peers);
                }
            }
        }
    });

    // Emit to frontend that we're ready with encryption info
    app.emit("p2p_network_started", serde_json::json!({
        "peer_id": peer_id.to_string(),
        "public_key": hex::encode(our_identity.public_key),
        "key_fingerprint": our_identity.key_fingerprint
    }))
    .map_err(|e| format!("Failed to emit network start event: {}", e))?;

    Ok(format!("P2P network started with peer ID: {} (E2EE enabled)", peer_id))
}

// E2EE Commands

#[tauri::command]
async fn get_our_identity(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let crypto_lock = state.message_crypto.lock().await;
    if let Some(crypto) = &*crypto_lock {
        let identity = crypto.get_identity();
        Ok(serde_json::json!({
            "public_key": hex::encode(identity.public_key),
            "key_fingerprint": identity.key_fingerprint
        }))
    } else {
        Err("Encryption not initialized".to_string())
    }
}

#[tauri::command]
async fn get_peer_identities(state: State<'_, AppState>) -> Result<Vec<PeerInfo>, String> {
    let crypto_lock = state.message_crypto.lock().await;
    if let Some(crypto) = &*crypto_lock {
        let peer_identities = crypto.get_peer_identities();
        let peers: Vec<PeerInfo> = peer_identities.iter().map(|(peer_id, identity)| {
            PeerInfo {
                id: peer_id.clone(),
                username: "Unknown".to_string(), // TODO: Store usernames
                public_key: identity.public_key,
                key_fingerprint: identity.key_fingerprint.clone(),
                connected_at: Utc::now(), // TODO: Store actual connection time
                verified: false, // TODO: Implement verification tracking
            }
        }).collect();
        Ok(peers)
    } else {
        Err("Encryption not initialized".to_string())
    }
}

#[tauri::command]
async fn add_peer_key(
    peer_id: String,
    public_key_hex: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let public_key_bytes = hex::decode(&public_key_hex)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;
    
    if public_key_bytes.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&public_key_bytes);

    let peer_identity = CryptoIdentity::from_public_key(key_array);
    
    let mut crypto_lock = state.message_crypto.lock().await;
    if let Some(crypto) = &mut *crypto_lock {
        crypto.add_peer_key(&peer_id, peer_identity.clone())
            .map_err(|e| format!("Failed to add peer key: {}", e))?;
        Ok(format!("Added peer key for {} (fingerprint: {})", peer_id, peer_identity.key_fingerprint))
    } else {
        Err("Encryption not initialized".to_string())
    }
}

#[tauri::command]
async fn verify_peer_fingerprint(
    peer_id: String,
    expected_fingerprint: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let crypto_lock = state.message_crypto.lock().await;
    if let Some(crypto) = &*crypto_lock {
        Ok(crypto.verify_peer_fingerprint(&peer_id, &expected_fingerprint))
    } else {
        Err("Encryption not initialized".to_string())
    }
}

#[tauri::command]
async fn toggle_encryption(
    enabled: bool,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    {
        let mut encryption_enabled_lock = state.encryption_enabled.lock().await;
        *encryption_enabled_lock = enabled;
    }
    
    app.emit("encryption_toggled", enabled)
        .map_err(|e| format!("Failed to emit encryption toggle: {}", e))?;
    
    Ok(())
}

#[tauri::command]
async fn is_encryption_enabled(state: State<'_, AppState>) -> Result<bool, String> {
    let encryption_enabled_lock = state.encryption_enabled.lock().await;
    Ok(*encryption_enabled_lock)
}

#[tauri::command]
async fn invite_to_room(
    peer_id: String,
    room_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let p2p_lock = state.p2p_network.lock().await;
    if let Some(network) = &*p2p_lock {
        // Convert string peer_id to PeerId
        let peer_id_parsed = peer_id.parse::<libp2p::PeerId>()
            .map_err(|e| format!("Invalid peer ID: {}", e))?;
        
        network.invite_to_room(peer_id_parsed, room_id.clone()).await
            .map_err(|e| format!("Failed to invite peer to room: {}", e))?;
        
        // Send room information to the peer via gossipsub
        let _invitation_message = serde_json::json!({
            "type": "room_invitation",
            "room_id": room_id,
            "inviter": network.get_peer_id().to_string()
        });
        
        // Emit success to frontend
        app.emit("peer_invited", serde_json::json!({
            "peer_id": peer_id,
            "room_id": room_id
        }))
        .map_err(|e| format!("Failed to emit invitation event: {}", e))?;
        
        Ok(())
    } else {
        Err("P2P network not initialized".to_string())
    }
}

#[tauri::command]
async fn auto_share_keys_with_peer(
    peer_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<String, String> {
    let crypto_lock = state.message_crypto.lock().await;
    if let Some(crypto) = &*crypto_lock {
        // Check if we already have a key for this peer
        if crypto.get_peer_identities().contains_key(&peer_id) {
            return Ok(format!("Key already exchanged with peer: {}", peer_id));
        }
        
        let our_identity = crypto.get_identity();
        let _key_exchange = crypto.create_key_exchange(&peer_id, "Auto-shared");
        
        let public_key_hex = hex::encode(our_identity.public_key);
        
        // Actually send the key via P2P network
        let network_lock = state.p2p_network.lock().await;
        if let Some(network) = &*network_lock {
            network
                .send_key_exchange(public_key_hex.clone(), our_identity.key_fingerprint.clone(), peer_id.clone())
                .await
                .map_err(|e| format!("Failed to send key exchange: {}", e))?;
        } else {
            return Err("P2P network not initialized".to_string());
        }
        
        // Still emit event to frontend for UI feedback
        app.emit("key_exchange_sent", serde_json::json!({
            "peer_id": peer_id,
            "public_key": public_key_hex,
            "key_fingerprint": our_identity.key_fingerprint
        }))
        .map_err(|e| format!("Failed to emit key exchange: {}", e))?;
        
        Ok(format!("Key sent to peer: {}", peer_id))
    } else {
        Err("Encryption not initialized".to_string())
    }
}

#[tauri::command]
async fn get_peer_public_key(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let crypto_lock = state.message_crypto.lock().await;
    if let Some(crypto) = &*crypto_lock {
        let peer_identities = crypto.get_peer_identities();
        if let Some(identity) = peer_identities.get(&peer_id) {
            Ok(Some(hex::encode(identity.public_key)))
        } else {
            Ok(None)
        }
    } else {
        Err("Encryption not initialized".to_string())
    }
}

#[tauri::command]
async fn send_p2p_message(
    content: String,
    room_id: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let username = {
        let username_lock = state.current_username.lock().await;
        username_lock.clone().unwrap_or_else(|| "Anonymous".to_string())
    };

    let current_room = room_id.or_else(|| {
        // Use current room if no room_id provided
        futures::executor::block_on(async {
            let current_room_lock = state.current_room.lock().await;
            current_room_lock.clone()
        })
    });

    let room_id = current_room.unwrap_or_else(|| "default".to_string());

    // Check if encryption is enabled
    let encryption_enabled = {
        let encryption_enabled_lock = state.encryption_enabled.lock().await;
        *encryption_enabled_lock
    };

    let message = Message {
        id: Uuid::new_v4().to_string(),
        username: username.clone(),
        content: content.clone(),
        timestamp: Utc::now(),
        room_id: room_id.clone(),
        encrypted: encryption_enabled,
    };

    // Store message locally (always store decrypted version)
    {
        let mut messages = state.messages.lock().await;
        messages.push(message.clone());
    }

    // Send message via P2P network
    if encryption_enabled {
        // Check if we have keys for all connected peers
        let crypto_lock = state.message_crypto.lock().await;
        if let Some(crypto) = &*crypto_lock {
            let peer_identities = crypto.get_peer_identities();
            let p2p_lock = state.p2p_network.lock().await;
            
            if let Some(network) = &*p2p_lock {
                let connected_peers = network.get_connected_peers().await
                    .map_err(|e| format!("Failed to get connected peers: {}", e))?;
                
                // Check if we have keys for any connected peers
                let peers_with_keys: Vec<_> = connected_peers
                    .iter()
                    .filter(|peer| peer_identities.contains_key(&peer.id))
                    .collect();
                
                if !peers_with_keys.is_empty() {
                    // Encrypt message for each peer we have keys for
                    let mut encrypted_for_peers = Vec::new();
                    
                    for peer in &peers_with_keys {
                        if let Ok(_encrypted_content) = crypto.encrypt_message(&content, &peer.id, &room_id) {
                            encrypted_for_peers.push(peer.id.clone());
                        }
                    }
                    
                    if !encrypted_for_peers.is_empty() {
                        // Send encrypted message (for simplicity, we'll encrypt once and send to all)
                        // In a real implementation, you'd encrypt separately for each peer
                        if let Ok(encrypted_msg) = crypto.encrypt_message(&content, &peers_with_keys[0].id, &room_id) {
                            let encrypted_message_json = serde_json::to_string(&encrypted_msg)
                                .map_err(|e| format!("Failed to serialize encrypted message: {}", e))?;
                            
                            // Get our peer_id for the encrypted wrapper
                            let our_peer_id = network.get_peer_id().to_string();
                            
                            let encrypted_wrapper = serde_json::json!({
                                "type": "encrypted_message", 
                                "content": encrypted_message_json,
                                "sender": username,
                                "sender_peer_id": our_peer_id,
                                "encrypted_for": encrypted_for_peers
                            });
                            
                            network.send_message_to_room(
                                encrypted_wrapper.to_string(), 
                                username.clone(), 
                                room_id.clone()
                            ).await
                                .map_err(|e| format!("Failed to send encrypted P2P message: {}", e))?;
                        } else {
                            return Err("Failed to encrypt message".to_string());
                        }
                    } else {
                        return Err("Failed to encrypt message for any peer".to_string());
                    }
                } else {
                    // No peer keys available, send as plaintext with warning
                    tracing::warn!("Encryption enabled but no peer keys available, sending as plaintext");
                    network.send_message_to_room(content.clone(), username.clone(), room_id.clone()).await
                        .map_err(|e| format!("Failed to send P2P message: {}", e))?;
                }
            } else {
                return Err("P2P network not initialized".to_string());
            }
        } else {
            return Err("Encryption not initialized".to_string());
        }
    } else {
        // Send plaintext message
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            network.send_message_to_room(content.clone(), username.clone(), room_id.clone()).await
                .map_err(|e| format!("Failed to send P2P message: {}", e))?;
        } else {
            return Err("P2P network not initialized".to_string());
        }
    }

    // Emit to frontend for immediate display
    app.emit("message_sent", &message)
        .map_err(|e| format!("Failed to emit message: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn create_room(
    name: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<Room, String> {
    let room = Room {
        id: Uuid::new_v4().to_string(),
        name: name.clone(),
        created_at: Utc::now(),
    };

    // Add to joined rooms
    {
        let mut rooms_lock = state.joined_rooms.lock().await;
        rooms_lock.push(room.clone());
    }

    // Set as current room
    {
        let mut current_room_lock = state.current_room.lock().await;
        *current_room_lock = Some(room.id.clone());
    }

    // Subscribe to room topic in P2P network
    {
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            network.join_room(room.id.clone()).await
                .map_err(|e| format!("Failed to join room in P2P network: {}", e))?;
        }
    }

    // Emit to frontend
    app.emit("room_created", &room)
        .map_err(|e| format!("Failed to emit room creation: {}", e))?;
    
    app.emit("room_joined", &room.id)
        .map_err(|e| format!("Failed to emit room joined: {}", e))?;

    Ok(room)
}

#[tauri::command]
async fn join_room(
    room_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // Check if room is already joined
    {
        let rooms_lock = state.joined_rooms.lock().await;
        if !rooms_lock.iter().any(|r| r.id == room_id) {
            // Create room entry (for now, we'll assume the room exists)
            let room = Room {
                id: room_id.clone(),
                name: format!("Room {}", &room_id[..8]),
                created_at: Utc::now(),
            };
            drop(rooms_lock);
            
            let mut rooms_lock = state.joined_rooms.lock().await;
            rooms_lock.push(room);
        }
    }

    // Set as current room
    {
        let mut current_room_lock = state.current_room.lock().await;
        *current_room_lock = Some(room_id.clone());
    }

    // Subscribe to room topic in P2P network
    {
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            network.join_room(room_id.clone()).await
                .map_err(|e| format!("Failed to join room in P2P network: {}", e))?;
        }
    }

    // Emit to frontend
    app.emit("room_joined", &room_id)
        .map_err(|e| format!("Failed to emit room joined: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn leave_room(
    room_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // Remove from joined rooms
    {
        let mut rooms_lock = state.joined_rooms.lock().await;
        rooms_lock.retain(|r| r.id != room_id);
    }

    // Clear current room if it's the one being left
    {
        let mut current_room_lock = state.current_room.lock().await;
        if let Some(current_id) = current_room_lock.as_ref() {
            if current_id == &room_id {
                *current_room_lock = None;
            }
        }
    }

    // Unsubscribe from room topic in P2P network
    {
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            network.leave_room(room_id.clone()).await
                .map_err(|e| format!("Failed to leave room in P2P network: {}", e))?;
        }
    }

    // Emit to frontend
    app.emit("room_left", &room_id)
        .map_err(|e| format!("Failed to emit room left: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn get_joined_rooms(state: State<'_, AppState>) -> Result<Vec<Room>, String> {
    let rooms_lock = state.joined_rooms.lock().await;
    Ok(rooms_lock.clone())
}

#[tauri::command]
async fn get_current_room(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let current_room_lock = state.current_room.lock().await;
    Ok(current_room_lock.clone())
}

#[tauri::command]
async fn switch_room(
    room_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // Check if room is joined
    {
        let rooms_lock = state.joined_rooms.lock().await;
        if !rooms_lock.iter().any(|r| r.id == room_id) {
            return Err("Room not joined".to_string());
        }
    }

    // Set as current room
    {
        let mut current_room_lock = state.current_room.lock().await;
        *current_room_lock = Some(room_id.clone());
    }

    // Emit to frontend
    app.emit("room_switched", &room_id)
        .map_err(|e| format!("Failed to emit room switch: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn get_messages(room_id: Option<String>, state: State<'_, AppState>) -> Result<Vec<Message>, String> {
    let messages = state.messages.lock().await;
    
    match room_id {
        Some(room) => {
            // Filter messages by room
            Ok(messages.iter().filter(|msg| msg.room_id == room).cloned().collect())
        }
        None => {
            // Return all messages if no room specified
            Ok(messages.clone())
        }
    }
}

#[tauri::command]
async fn update_username(
    new_username: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // Update local username
    {
        let mut username_lock = state.current_username.lock().await;
        *username_lock = Some(new_username.clone());
    }

    // Update P2P network username
    {
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            network.update_username(new_username.clone()).await
                .map_err(|e| format!("Failed to update P2P username: {}", e))?;
        }
    }

    // Emit to frontend
    app.emit("username_updated", &new_username)
        .map_err(|e| format!("Failed to emit username update: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn get_connected_peers(state: State<'_, AppState>) -> Result<Vec<User>, String> {
    let p2p_lock = state.p2p_network.lock().await;
    if let Some(network) = &*p2p_lock {
        network.get_connected_peers().await
            .map_err(|e| format!("Failed to get connected peers: {}", e))
    } else {
        Ok(Vec::new())
    }
}

#[tauri::command]
async fn get_network_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let p2p_lock = state.p2p_network.lock().await;
    let is_connected = p2p_lock.is_some();
    
    let status = if is_connected {
        serde_json::json!({
            "connected": true,
            "peer_id": p2p_lock.as_ref().map(|n| n.get_peer_id().to_string()),
            "status": "Connected to P2P network"
        })
    } else {
        serde_json::json!({
            "connected": false,
            "status": "Not connected to P2P network"
        })
    };

    Ok(status)
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to WireTalk P2P!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            greet,
            start_p2p_network,
            send_p2p_message,
            get_messages,
            update_username,
            get_network_status,
            get_connected_peers,
            create_room,
            join_room,
            leave_room,
            get_joined_rooms,
            get_current_room,
            switch_room,
            invite_to_room,
            // E2EE Commands
            get_our_identity,
            get_peer_identities,
            add_peer_key,
            verify_peer_fingerprint,
            toggle_encryption,
            is_encryption_enabled,
            auto_share_keys_with_peer,
            get_peer_public_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
