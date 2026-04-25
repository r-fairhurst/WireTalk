use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::Result;

mod p2p_network;
use p2p_network::P2PNetwork;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub username: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub room_id: String,
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

#[derive(Debug)]
pub struct AppState {
    pub p2p_network: Arc<Mutex<Option<P2PNetwork>>>,
    pub messages: Arc<Mutex<Vec<Message>>>,
    pub current_username: Arc<Mutex<Option<String>>>,
    pub joined_rooms: Arc<Mutex<Vec<Room>>>,
    pub current_room: Arc<Mutex<Option<String>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            p2p_network: Arc::new(Mutex::new(None)),
            messages: Arc::new(Mutex::new(Vec::new())),
            current_username: Arc::new(Mutex::new(None)),
            joined_rooms: Arc::new(Mutex::new(Vec::new())),
            current_room: Arc::new(Mutex::new(None)),
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

    // Store the network and username
    {
        let mut p2p_lock = state.p2p_network.lock().await;
        *p2p_lock = Some(network);
    }
    {
        let mut username_lock = state.current_username.lock().await;
        *username_lock = Some(username);
    }

    // Handle P2P events in a separate task
    let app_clone = app.clone();
    tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            match event {
                p2p_network::P2PEvent::MessageReceived(message) => {
                    let _ = app_clone.emit("message_received", &message);
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

    // Emit to frontend that we're ready
    app.emit("p2p_network_started", &peer_id.to_string())
        .map_err(|e| format!("Failed to emit network start event: {}", e))?;

    Ok(format!("P2P network started with peer ID: {}", peer_id))
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

    let message = Message {
        id: Uuid::new_v4().to_string(),
        username: username.clone(),
        content: content.clone(),
        timestamp: Utc::now(),
        room_id: room_id.clone(),
    };

    // Store message locally
    {
        let mut messages = state.messages.lock().await;
        messages.push(message.clone());
    }

    // Send via P2P network with room context
    {
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
            switch_room
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
