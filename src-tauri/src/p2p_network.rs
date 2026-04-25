use libp2p::{
    gossipsub, identify, mdns, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    PeerId, SwarmBuilder, Swarm,
};
use futures::StreamExt;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use anyhow::Result;

use crate::{Message, User};

/// Network behavior combining all libp2p protocols
#[derive(NetworkBehaviour)]
pub struct P2PNetworkBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

#[derive(Debug)]
pub struct P2PNetwork {
    pub peer_id: PeerId,
    pub username: String,
    pub message_sender: mpsc::UnboundedSender<P2PCommand>,
    pub event_sender: mpsc::UnboundedSender<P2PEvent>,
}

#[derive(Debug)]
pub enum P2PCommand {
    SendMessage { content: String, username: String },
    SendMessageToRoom { content: String, username: String, room_id: String },
    JoinRoom { room_id: String },
    LeaveRoom { room_id: String },
    UpdateUsername { username: String },
    GetPeers { respond_to: mpsc::UnboundedSender<Vec<User>> },
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum P2PEvent {
    MessageReceived(Message),
    PeerJoined { peer_id: PeerId, username: Option<String> },
    PeerLeft { peer_id: PeerId, username: String },
    PeerListUpdated { peers: Vec<User> },
}

impl P2PNetwork {
    pub async fn new(username: String) -> Result<(Self, mpsc::UnboundedReceiver<P2PEvent>)> {
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Generate a unique peer ID
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        // Create the swarm
        let username_clone = username.clone();
        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(move |key| {
                // Create gossipsub with message signing
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .build()
                    .expect("Valid gossipsub config");

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                ).expect("Correct gossipsub configuration");

                // Create mDNS for peer discovery
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(), 
                    key.public().to_peer_id()
                )?;

                // Create identify protocol  
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/wiretalk/1.0.0".to_string(),
                    key.public(),
                ).with_agent_version(username_clone));

                // Create ping protocol
                let ping = ping::Behaviour::new(ping::Config::new());

                Ok(P2PNetworkBehaviour {
                    gossipsub,
                    mdns,
                    identify,
                    ping,
                })
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Listen on all interfaces
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        // Subscribe to the main chat topic
        let topic = gossipsub::IdentTopic::new("wiretalk-chat");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        // Start the network event loop
        let network = Self {
            peer_id: local_peer_id,
            username: username.clone(),
            message_sender: command_sender,
            event_sender: event_sender.clone(),
        };

        tokio::spawn(Self::run_network_loop(swarm, command_receiver, event_sender));

        Ok((network, event_receiver))
    }

    async fn run_network_loop(
        mut swarm: Swarm<P2PNetworkBehaviour>,
        mut command_receiver: mpsc::UnboundedReceiver<P2PCommand>,
        event_sender: mpsc::UnboundedSender<P2PEvent>,
    ) {
        let default_topic = gossipsub::IdentTopic::new("wiretalk-chat");
        let mut connected_peers: HashMap<PeerId, User> = HashMap::new();
        let mut subscribed_rooms: HashSet<String> = HashSet::new();
        
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    Self::handle_swarm_event(&mut swarm, event, &event_sender, &mut connected_peers).await;
                }
                command = command_receiver.recv() => {
                    match command {
                        Some(P2PCommand::SendMessage { content, username }) => {
                            let message = Message {
                                id: uuid::Uuid::new_v4().to_string(),
                                username,
                                content,
                                timestamp: chrono::Utc::now(),
                                room_id: "default".to_string(),
                            };
                            
                            let message_json = serde_json::to_string(&message)
                                .expect("Failed to serialize message");
                            
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(default_topic.clone(), message_json.as_bytes()) {
                                tracing::error!("Failed to publish message: {}", e);
                            }
                        }
                        Some(P2PCommand::SendMessageToRoom { content, username, room_id }) => {
                            let message = Message {
                                id: uuid::Uuid::new_v4().to_string(),
                                username,
                                content,
                                timestamp: chrono::Utc::now(),
                                room_id: room_id.clone(),
                            };
                            
                            let message_json = serde_json::to_string(&message)
                                .expect("Failed to serialize message");
                            
                            let room_topic = gossipsub::IdentTopic::new(format!("wiretalk-room-{}", room_id));
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(room_topic, message_json.as_bytes()) {
                                tracing::error!("Failed to publish room message: {}", e);
                            }
                        }
                        Some(P2PCommand::JoinRoom { room_id }) => {
                            if !subscribed_rooms.contains(&room_id) {
                                let room_topic = gossipsub::IdentTopic::new(format!("wiretalk-room-{}", room_id));
                                if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&room_topic) {
                                    tracing::error!("Failed to subscribe to room {}: {}", room_id, e);
                                } else {
                                    subscribed_rooms.insert(room_id.clone());
                                    tracing::info!("Joined room: {}", room_id);
                                }
                            }
                        }
                        Some(P2PCommand::LeaveRoom { room_id }) => {
                            if subscribed_rooms.contains(&room_id) {
                                let room_topic = gossipsub::IdentTopic::new(format!("wiretalk-room-{}", room_id));
                                if let Err(e) = swarm.behaviour_mut().gossipsub.unsubscribe(&room_topic) {
                                    tracing::error!("Failed to unsubscribe from room {}: {}", room_id, e);
                                } else {
                                    subscribed_rooms.remove(&room_id);
                                    tracing::info!("Left room: {}", room_id);
                                }
                            }
                        }
                        Some(P2PCommand::UpdateUsername { username: _ }) => {
                            // Username updates will be reflected in future messages
                            // The identify behavior cannot be easily updated at runtime
                        }
                        Some(P2PCommand::GetPeers { respond_to }) => {
                            let peers: Vec<User> = connected_peers.values().cloned().collect();
                            let _ = respond_to.send(peers);
                        }
                        Some(P2PCommand::Shutdown) => {
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    async fn handle_swarm_event(
        swarm: &mut Swarm<P2PNetworkBehaviour>,
        event: SwarmEvent<P2PNetworkBehaviourEvent>,
        event_sender: &mpsc::UnboundedSender<P2PEvent>,
        connected_peers: &mut HashMap<PeerId, User>,
    ) {
        match event {
            SwarmEvent::Behaviour(event) => match event {
                P2PNetworkBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: _,
                    message_id: _,
                    message,
                }) => {
                    // Handle incoming chat messages
                    if let Ok(message_str) = String::from_utf8(message.data.clone()) {
                        if let Ok(chat_message) = serde_json::from_str::<Message>(&message_str) {
                            tracing::info!("Received message: {:?}", chat_message);
                            
                            // Update peer username if we have this peer connected
                            if let Some(source_peer) = message.source {
                                if let Some(peer_info) = connected_peers.get_mut(&source_peer) {
                                    if peer_info.username != chat_message.username {
                                        peer_info.username = chat_message.username.clone();
                                        
                                        // Send updated peer list
                                        let peers: Vec<User> = connected_peers.values().cloned().collect();
                                        let _ = event_sender.send(P2PEvent::PeerListUpdated { peers });
                                    }
                                }
                            }
                            
                            let _ = event_sender.send(P2PEvent::MessageReceived(chat_message));
                        }
                    }
                }
                P2PNetworkBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                    // Handle discovered peers
                    for (peer_id, multiaddr) in list {
                        tracing::debug!("Discovered peer: {} at {}", peer_id, multiaddr);
                        let _ = swarm.dial(multiaddr);
                    }
                }
                P2PNetworkBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                    // Handle expired peers
                    for (peer_id, _) in list {
                        tracing::debug!("Peer expired: {}", peer_id);
                    }
                }
                P2PNetworkBehaviourEvent::Identify(identify::Event::Received {
                    peer_id, info, ..
                }) => {
                    tracing::debug!("Identified peer: {} with protocols: {:?}", peer_id, info.protocols);
                    
                    // Update peer username from identify agent version
                    if let Some(peer_info) = connected_peers.get_mut(&peer_id) {
                        let username = info.agent_version.clone();
                        if peer_info.username != username {
                            tracing::info!("Updated peer {} username to: {}", peer_id, username);
                            peer_info.username = username;
                            
                            // Send updated peer list
                            let peers: Vec<User> = connected_peers.values().cloned().collect();
                            let _ = event_sender.send(P2PEvent::PeerListUpdated { peers });
                        }
                    }
                }
                _ => {}
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                // Only send peer joined event if this is the first connection to this peer
                let is_new_peer = !connected_peers.contains_key(&peer_id);
                
                if is_new_peer {
                    tracing::info!("New peer connected: {}", peer_id);
                    
                    // Create a user entry for the connected peer
                    let user = User {
                        id: peer_id.to_string(),
                        username: format!("Peer_{}", &peer_id.to_string()[..8]),
                        connected_at: chrono::Utc::now(),
                    };
                    
                    connected_peers.insert(peer_id, user.clone());
                    
                    let _ = event_sender.send(P2PEvent::PeerJoined { peer_id, username: Some(user.username) });
                    
                    // Send updated peer list only when there's a new peer
                    let peers: Vec<User> = connected_peers.values().cloned().collect();
                    let _ = event_sender.send(P2PEvent::PeerListUpdated { peers });
                } else {
                    tracing::debug!("Additional connection established with existing peer: {}", peer_id);
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                // Only send peer left event if this peer was in our connected list
                if let Some(user) = connected_peers.get(&peer_id) {
                    let username = user.username.clone();
                    tracing::info!("Peer disconnected: {}", peer_id);
                    connected_peers.remove(&peer_id);
                    
                    let _ = event_sender.send(P2PEvent::PeerLeft { peer_id, username });
                    
                    // Send updated peer list
                    let peers: Vec<User> = connected_peers.values().cloned().collect();
                    let _ = event_sender.send(P2PEvent::PeerListUpdated { peers });
                } else {
                    tracing::debug!("Additional connection closed with peer: {}", peer_id);
                }
            }
            _ => {}
        }
    }

    pub async fn send_message(&self, content: String, username: String) -> Result<()> {
        self.message_sender
            .send(P2PCommand::SendMessage { content, username })
            .map_err(|e| anyhow::anyhow!("Failed to send message command: {}", e))
    }

    pub async fn send_message_to_room(&self, content: String, username: String, room_id: String) -> Result<()> {
        self.message_sender
            .send(P2PCommand::SendMessageToRoom { content, username, room_id })
            .map_err(|e| anyhow::anyhow!("Failed to send room message command: {}", e))
    }

    pub async fn join_room(&self, room_id: String) -> Result<()> {
        self.message_sender
            .send(P2PCommand::JoinRoom { room_id })
            .map_err(|e| anyhow::anyhow!("Failed to send join room command: {}", e))
    }

    pub async fn leave_room(&self, room_id: String) -> Result<()> {
        self.message_sender
            .send(P2PCommand::LeaveRoom { room_id })
            .map_err(|e| anyhow::anyhow!("Failed to send leave room command: {}", e))
    }

    pub async fn invite_to_room(&self, peer_id: PeerId, room_id: String) -> Result<()> {
        // In a real implementation, you would send a direct message to the peer with the room invitation
        // For simplicity, we will just log this action
        tracing::info!("Inviting peer {} to room {}", peer_id, room_id);
        Ok(())
    }

    pub async fn update_username(&self, username: String) -> Result<()> {
        self.message_sender
            .send(P2PCommand::UpdateUsername { username })
            .map_err(|e| anyhow::anyhow!("Failed to send username update: {}", e))
    }

    pub async fn get_connected_peers(&self) -> Result<Vec<User>> {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        
        self.message_sender
            .send(P2PCommand::GetPeers { respond_to: sender })
            .map_err(|e| anyhow::anyhow!("Failed to send get peers command: {}", e))?;
            
        receiver.recv().await
            .ok_or_else(|| anyhow::anyhow!("Failed to receive peers response"))
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.peer_id
    }
}