use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::Result;



mod p2p_network;
mod encryption;
mod wireguard;
use p2p_network::P2PNetwork;
use encryption::{MessageCrypto, CryptoIdentity, KeyExchangeMessage};
use wireguard::{WireGuardManager, WireGuardConfig, ShareablePeerConfig};

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
    pub wireguard: Arc<Mutex<WireGuardManager>>,
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
            wireguard: Arc::new(Mutex::new(WireGuardManager::new())),
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
                            // Ignore encrypted envelopes that target other peers.
                            let local_peer_id = {
                                let network_lock = state_arc.p2p_network.lock().await;
                                network_lock.as_ref().map(|n| n.get_peer_id().to_string())
                            };

                            if let (Some(targets), Some(local_id)) = (
                                encrypted_data.get("encrypted_for").and_then(|v| v.as_array()),
                                local_peer_id.as_ref(),
                            ) {
                                let intended_for_us = targets
                                    .iter()
                                    .filter_map(|v| v.as_str())
                                    .any(|id| id == local_id);

                                if !intended_for_us {
                                    continue;
                                }
                            }

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
                            continue; // Don't process as regular message
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
                                
                                let peer_identity = CryptoIdentity::from_public_key(key_array);
                                
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
                p2p_network::P2PEvent::RoomInvitationReceived { room_id, inviter_peer_id, inviter_username } => {
                    // Auto-join invited room to reduce manual setup for recipients.
                    {
                        let mut rooms_lock = state_arc.joined_rooms.lock().await;
                        if !rooms_lock.iter().any(|r| r.id == room_id) {
                            rooms_lock.push(Room {
                                id: room_id.clone(),
                                name: format!("Invited room {}", &room_id[..8.min(room_id.len())]),
                                created_at: Utc::now(),
                            });
                        }
                    }

                    {
                        let mut current_room_lock = state_arc.current_room.lock().await;
                        *current_room_lock = Some(room_id.clone());
                    }

                    {
                        let network_lock = state_arc.p2p_network.lock().await;
                        if let Some(network) = &*network_lock {
                            if let Err(e) = network.join_room(room_id.clone()).await {
                                tracing::error!("Failed to auto-join invited room {}: {}", room_id, e);
                            }
                        }
                    }

                    let _ = app_clone.emit("room_invitation_received", serde_json::json!({
                        "room_id": room_id,
                        "inviter_peer_id": inviter_peer_id,
                        "inviter_username": inviter_username
                    }));
                }
                p2p_network::P2PEvent::PeerSubscribed { peer_id: peer_id_str } => {
                    // Gossipsub has confirmed the peer is subscribed to the chat topic.
                    // This is the right moment to send the key exchange \u2014 no more InsufficientPeers.
                    let maybe_key_payload = {
                        let crypto_lock = state_arc.message_crypto.lock().await;
                        if let Some(crypto) = &*crypto_lock {
                            if crypto.get_peer_identities().contains_key(&peer_id_str) {
                                None // Already have their key; KeyExchangeReceived will handle the reply
                            } else {
                                let identity = crypto.get_identity();
                                Some((
                                    hex::encode(identity.public_key),
                                    identity.key_fingerprint.clone(),
                                ))
                            }
                        } else {
                            None
                        }
                    };

                    if let Some((public_key_hex, key_fingerprint)) = maybe_key_payload {
                        let network_lock = state_arc.p2p_network.lock().await;
                        if let Some(network) = &*network_lock {
                            if let Err(e) = network
                                .send_key_exchange(public_key_hex, key_fingerprint, peer_id_str.clone())
                                .await
                            {
                                tracing::error!("Failed to send key exchange to {}: {}", peer_id_str, e);
                            } else {
                                tracing::info!("Sent key exchange to {} (on gossipsub subscription)", peer_id_str);
                            }
                        }
                    }
                }
                p2p_network::P2PEvent::PeerJoined { peer_id, username } => {
                    let peer_id_str = peer_id.to_string();
                    let user = User {
                        id: peer_id_str,
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
        // Validate peer id format before sending invitation.
        let _ = peer_id.parse::<libp2p::PeerId>()
            .map_err(|e| format!("Invalid peer ID: {}", e))?;

        network.invite_to_room(peer_id.clone(), room_id.clone()).await
            .map_err(|e| format!("Failed to invite peer to room: {}", e))?;

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
                    // Encrypt and publish one message per recipient peer.
                    let our_peer_id = network.get_peer_id().to_string();
                    let mut sent_count = 0usize;

                    for peer in &peers_with_keys {
                        if let Ok(encrypted_msg) = crypto.encrypt_message(&content, &peer.id, &room_id) {
                            let encrypted_message_json = serde_json::to_string(&encrypted_msg)
                                .map_err(|e| format!("Failed to serialize encrypted message: {}", e))?;

                            let encrypted_wrapper = serde_json::json!({
                                "type": "encrypted_message",
                                "content": encrypted_message_json,
                                "sender": username,
                                "sender_peer_id": our_peer_id,
                                "encrypted_for": [peer.id.clone()]
                            });

                            network.send_message_to_room(
                                encrypted_wrapper.to_string(),
                                username.clone(),
                                room_id.clone()
                            ).await
                                .map_err(|e| format!("Failed to send encrypted P2P message: {}", e))?;

                            sent_count += 1;
                        }
                    }

                    if sent_count == 0 {
                        return Err("Failed to encrypt message for any peer".to_string());
                    }
                } else {
                    // No peer keys available — refuse to send as plaintext
                    tracing::warn!("Encryption enabled but no peer keys available, refusing to send plaintext");
                    return Err("Keys not yet exchanged with any peer. Please wait a moment and try again.".to_string());
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

// ─── WireGuard Commands ────────────────────────────────────────────────────────

/// Check whether WireGuard tools are installed on this machine.
#[tauri::command]
async fn check_wireguard_deps() -> Result<bool, String> {
    Ok(WireGuardManager::check_dependencies().is_ok())
}

/// Auto-generate keys, write a config, and bring up the WireGuard interface.
/// `interface_ip` must be CIDR, e.g. "10.10.10.1/24".
#[tauri::command]
async fn setup_wireguard(
    interface_ip: String,
    listen_port: Option<u16>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireGuardConfig, String> {
    let port = listen_port.unwrap_or(wireguard::DEFAULT_LISTEN_PORT);

    let mut wg = state.wireguard.lock().await;

    // If already active, report that
    if wg.is_active() {
        return Err("WireGuard interface is already up. Tear it down first.".to_string());
    }

    wg.setup(interface_ip, port)
        .map_err(|e| format!("WireGuard setup failed: {}", e))?;

    let config = wg
        .get_config()
        .ok_or_else(|| "Failed to retrieve WireGuard config after setup".to_string())?;

    app.emit("wireguard_status_changed", serde_json::json!({ "active": true }))
        .map_err(|e| format!("Failed to emit WG status: {}", e))?;

    Ok(config)
}

/// Bring down the WireGuard interface.
#[tauri::command]
async fn teardown_wireguard(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let mut wg = state.wireguard.lock().await;
    wg.teardown()
        .map_err(|e| format!("WireGuard teardown failed: {}", e))?;

    app.emit("wireguard_status_changed", serde_json::json!({ "active": false }))
        .map_err(|e| format!("Failed to emit WG status: {}", e))?;

    Ok(())
}

/// Add a peer to the running WireGuard interface.
/// `allowed_ip` is the peer's tunnel IP in CIDR, e.g. "10.10.10.2/32".
/// `endpoint` is optional: "203.0.113.5:51820".
#[tauri::command]
async fn add_wireguard_peer(
    public_key: String,
    allowed_ip: String,
    endpoint: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut wg = state.wireguard.lock().await;
    wg.add_peer(public_key.clone(), allowed_ip.clone(), endpoint)
        .map_err(|e| format!("Failed to add WireGuard peer: {}", e))?;

    Ok(format!(
        "Peer {} added with allowed IP {}",
        &public_key[..8],
        allowed_ip
    ))
}

/// Remove a peer from the running WireGuard interface by its public key.
#[tauri::command]
async fn remove_wireguard_peer(
    public_key: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut wg = state.wireguard.lock().await;
    wg.remove_peer(&public_key)
        .map_err(|e| format!("Failed to remove WireGuard peer: {}", e))?;
    Ok(format!("Peer {} removed", &public_key[..8]))
}

/// Return the current WireGuard config (no private key).
#[tauri::command]
async fn get_wireguard_config(state: State<'_, AppState>) -> Result<Option<WireGuardConfig>, String> {
    let wg = state.wireguard.lock().await;
    Ok(wg.get_config())
}

/// Return a compact JSON blob the user can share with peers so they can be added automatically.
/// `my_endpoint` is the caller's optional external IP:port (e.g. "203.0.113.5:51820").
/// Automatically embeds the libp2p peer ID and TCP port so the recipient can auto-dial.
#[tauri::command]
async fn get_wireguard_shareable_config(
    my_endpoint: Option<String>,
    state: State<'_, AppState>,
) -> Result<Option<ShareablePeerConfig>, String> {
    // Gather libp2p peer_id and listen port from the P2P network (if started)
    let (libp2p_peer_id, libp2p_port) = {
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            let pid = network.peer_id.to_string();
            // Parse TCP port from the first listen address of the form /ip4/.../tcp/PORT
            let port = network
                .get_listen_addresses()
                .await
                .ok()
                .and_then(|addrs| {
                    addrs.into_iter().find_map(|addr| {
                        let parts: Vec<&str> = addr.split('/').collect();
                        parts
                            .windows(2)
                            .find(|w| w[0] == "tcp")
                            .and_then(|w| w[1].parse::<u16>().ok())
                    })
                });
            (Some(pid), port)
        } else {
            (None, None)
        }
    };

    let wg = state.wireguard.lock().await;
    Ok(wg.get_shareable_config(my_endpoint, libp2p_peer_id, libp2p_port))
}

/// Return whether the WireGuard interface is currently active.
#[tauri::command]
async fn get_wireguard_status(state: State<'_, AppState>) -> Result<bool, String> {
    let wg = state.wireguard.lock().await;
    Ok(wg.is_active())
}

/// Best-effort startup cleanup for stale WireGuard interfaces left by previous runs.
/// Returns true if cleanup was performed, false if there was nothing to clean.
#[tauri::command]
async fn cleanup_stale_wireguard(state: State<'_, AppState>) -> Result<bool, String> {
    let mut wg = state.wireguard.lock().await;
    if wg.is_active() {
        wg.teardown()
            .map_err(|e| format!("Failed to cleanup stale WireGuard interface: {}", e))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Parse a peer's shareable config JSON and automatically add them.
/// This is the one-click "add peer" from the UI.
#[tauri::command]
async fn add_wireguard_peer_from_config(
    peer_config_json: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let peer_cfg: ShareablePeerConfig = serde_json::from_str(&peer_config_json)
        .map_err(|e| format!("Invalid peer config JSON: {}", e))?;

    let allowed_ip = format!("{}/32", peer_cfg.tunnel_ip);
    let endpoint = peer_cfg
        .endpoint
        .map(|ep| {
            // If the endpoint doesn't include a port, append the peer's listen port
            if ep.contains(':') {
                ep
            } else {
                format!("{}:{}", ep, peer_cfg.listen_port)
            }
        });

    let mut wg = state.wireguard.lock().await;
    wg.add_peer(peer_cfg.public_key.clone(), allowed_ip.clone(), endpoint)
        .map_err(|e| format!("Failed to add peer from config: {}", e))?;
    drop(wg); // release lock before touching p2p_network

    // Auto-dial the libp2p layer if the config includes peer_id and libp2p_port
    let dial_result = if let (Some(pid), Some(port)) = (&peer_cfg.peer_id, peer_cfg.libp2p_port) {
        let multiaddr = format!("/ip4/{}/tcp/{}/p2p/{}", peer_cfg.tunnel_ip, port, pid);
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            match network.dial_peer(multiaddr.clone()).await {
                Ok(_) => format!(" — P2P auto-dial initiated to {}", multiaddr),
                Err(e) => format!(" — P2P dial failed: {}", e),
            }
        } else {
            " — P2P network not started; join a room to enable auto-dial".to_string()
        }
    } else {
        String::new()
    };

    Ok(format!(
        "Peer {} (tunnel IP {}) added successfully{}",
        &peer_cfg.public_key[..8],
        peer_cfg.tunnel_ip,
        dial_result
    ))
}

// ─── P2P Direct Dial Commands ─────────────────────────────────────────────────

/// Return the libp2p listen addresses (useful for sharing the WireGuard tunnel address).
#[tauri::command]
async fn get_listen_addresses(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let p2p_lock = state.p2p_network.lock().await;
    if let Some(network) = &*p2p_lock {
        network
            .get_listen_addresses()
            .await
            .map_err(|e| format!("Failed to get listen addresses: {}", e))
    } else {
        Ok(Vec::new())
    }
}

/// Dial a peer directly using a libp2p multiaddr.
/// Example: "/ip4/10.10.10.2/tcp/45678/p2p/12D3KooW..."
#[tauri::command]
async fn dial_peer(
    multiaddr: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let p2p_lock = state.p2p_network.lock().await;
    if let Some(network) = &*p2p_lock {
        network
            .dial_peer(multiaddr.clone())
            .await
            .map_err(|e| format!("Failed to dial peer: {}", e))?;
        Ok(format!("Dialing {}", multiaddr))
    } else {
        Err("P2P network not initialized".to_string())
    }
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
            toggle_encryption,
            is_encryption_enabled,
            // WireGuard commands
            check_wireguard_deps,
            setup_wireguard,
            teardown_wireguard,
            add_wireguard_peer,
            remove_wireguard_peer,
            get_wireguard_config,
            get_wireguard_shareable_config,
            get_wireguard_status,
            cleanup_stale_wireguard,
            add_wireguard_peer_from_config,
            // Direct dial commands
            get_listen_addresses,
            dial_peer
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
