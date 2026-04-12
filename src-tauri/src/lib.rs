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
}

impl AppState {
    pub fn new() -> Self {
        Self {
            p2p_network: Arc::new(Mutex::new(None)),
            messages: Arc::new(Mutex::new(Vec::new())),
            current_username: Arc::new(Mutex::new(None)),
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
                p2p_network::P2PEvent::PeerJoined { peer_id, username: _ } => {
                    let _ = app_clone.emit("peer_joined", &peer_id.to_string());
                }
                p2p_network::P2PEvent::PeerLeft { peer_id } => {
                    let _ = app_clone.emit("peer_left", &peer_id.to_string());
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
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let username = {
        let username_lock = state.current_username.lock().await;
        username_lock.clone().unwrap_or_else(|| "Anonymous".to_string())
    };

    let message = Message {
        id: Uuid::new_v4().to_string(),
        username: username.clone(),
        content: content.clone(),
        timestamp: Utc::now(),
    };

    // Store message locally
    {
        let mut messages = state.messages.lock().await;
        messages.push(message.clone());
    }

    // Send via P2P network
    {
        let p2p_lock = state.p2p_network.lock().await;
        if let Some(network) = &*p2p_lock {
            network.send_message(content.clone(), username.clone()).await
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
async fn get_messages(state: State<'_, AppState>) -> Result<Vec<Message>, String> {
    let messages = state.messages.lock().await;
    Ok(messages.clone())
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
            get_connected_peers
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
