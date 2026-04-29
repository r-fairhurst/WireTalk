import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface Message {
  id: string;
  username: string;
  content: string;
  timestamp: string;
  room_id: string;
  encrypted: boolean; // Whether this message is encrypted
}

interface PeerInfo {
  id: string;
  username: string;
  public_key: number[]; // Array representation of [u8; 32]
  key_fingerprint: string;
  connected_at: string;
  verified: boolean;
}

interface CryptoIdentity {
  public_key: string; // Hex encoded
  key_fingerprint: string;
}

interface User {
  id: string;
  username: string;
  connected_at: string;
}

interface Room {
  id: string;
  name: string;
  created_at: string;
}

interface NetworkStatus {
  connected: boolean;
  peer_id?: string;
  public_key?: string;
  key_fingerprint?: string;
  status: string;
}

class P2PChatApp {
  private username: string = "";
  private connected: boolean = false;
  private peerId: string = "";
  private currentRoom: string | null = null;
  private joinedRooms: Room[] = [];
  private encryptionEnabled: boolean = true;
  private ourFingerprint: string = "";
  private peerKeys: PeerInfo[] = [];
  
  // DOM elements
  private usernameInput!: HTMLInputElement;
  private setUsernameBtn!: HTMLButtonElement;
  private joinNetworkBtn!: HTMLButtonElement;
  private messageInput!: HTMLInputElement;
  private sendBtn!: HTMLButtonElement;
  private messagesContainer!: HTMLElement;
  private peersList!: HTMLElement;
  private peerCount!: HTMLElement;
  private statusIndicator!: HTMLElement;
  private statusText!: HTMLElement;
  private messageForm!: HTMLFormElement;
  private peerInfo!: HTMLElement;
  private peerIdDisplay!: HTMLElement;
  
  // Room-related DOM elements
  private roomsSection!: HTMLElement;
  private roomNameInput!: HTMLInputElement;
  private createRoomBtn!: HTMLButtonElement;
  private roomIdInput!: HTMLInputElement;
  private joinRoomBtn!: HTMLButtonElement;
  private currentRoomDiv!: HTMLElement;
  private currentRoomName!: HTMLElement;
  private copyCurrentRoomBtn!: HTMLButtonElement;
  private leaveCurrentRoomBtn!: HTMLButtonElement;
  private invitePeerBtn!: HTMLButtonElement;
  private roomsList!: HTMLElement;
  private roomsCount!: HTMLElement;
  
  // E2EE-related DOM elements
  private encryptionSection!: HTMLElement;
  private encryptionToggle!: HTMLInputElement;
  private encryptionIndicator!: HTMLElement;
  private encryptionStatusText!: HTMLElement;
  private ourFingerprintEl!: HTMLElement;
  private copyFingerprintBtn!: HTMLButtonElement;
  private peerKeyInput!: HTMLInputElement;
  private peerIdInputE2EE!: HTMLInputElement;
  private addPeerKeyBtn!: HTMLButtonElement;
  private autoShareAllBtn!: HTMLButtonElement;
  private requestAllKeysBtn!: HTMLButtonElement;
  private peerKeysList!: HTMLElement;
  private mitmWarning!: HTMLElement;

  constructor() {
    this.initDOM();
    this.setupEventListeners();
    this.setupTauriEventListeners();
    this.checkNetworkStatus();
  }

  private initDOM(): void {
    this.usernameInput = document.getElementById("username-input") as HTMLInputElement;
    this.setUsernameBtn = document.getElementById("set-username-btn") as HTMLButtonElement;
    this.joinNetworkBtn = document.getElementById("join-network-btn") as HTMLButtonElement;
    this.messageInput = document.getElementById("message-input") as HTMLInputElement;
    this.sendBtn = document.getElementById("send-btn") as HTMLButtonElement;
    this.messagesContainer = document.getElementById("messages-container")!;
    this.peersList = document.getElementById("peers-list")!;
    this.peerCount = document.getElementById("peer-count")!;
    this.statusIndicator = document.getElementById("status-indicator")!;
    this.statusText = document.getElementById("status-text")!;
    this.messageForm = document.getElementById("message-form") as HTMLFormElement;
    this.peerInfo = document.getElementById("peer-info")!;
    this.peerIdDisplay = document.getElementById("peer-id-display")!;
    
    // Room-related elements
    this.roomsSection = document.getElementById("rooms-section")!;
    this.roomNameInput = document.getElementById("room-name-input") as HTMLInputElement;
    this.createRoomBtn = document.getElementById("create-room-btn") as HTMLButtonElement;
    this.roomIdInput = document.getElementById("room-id-input") as HTMLInputElement;
    this.joinRoomBtn = document.getElementById("join-room-btn") as HTMLButtonElement;
    this.currentRoomDiv = document.getElementById("current-room")!;
    this.currentRoomName = document.getElementById("current-room-name")!;
    this.copyCurrentRoomBtn = document.getElementById("copy-current-room-btn") as HTMLButtonElement;
    this.leaveCurrentRoomBtn = document.getElementById("leave-current-room-btn") as HTMLButtonElement;
    this.invitePeerBtn = document.getElementById("invite-peer-btn") as HTMLButtonElement;
    this.roomsList = document.getElementById("rooms-list")!;
    this.roomsCount = document.getElementById("rooms-count")!;
    
    // E2EE-related elements
    this.encryptionSection = document.getElementById("encryption-section")!;
    this.encryptionToggle = document.getElementById("encryption-toggle") as HTMLInputElement;
    this.encryptionIndicator = document.getElementById("encryption-indicator")!;
    this.encryptionStatusText = document.getElementById("encryption-status-text")!;
    this.ourFingerprintEl = document.getElementById("our-fingerprint")!;
    this.copyFingerprintBtn = document.getElementById("copy-fingerprint-btn") as HTMLButtonElement;
    this.peerKeyInput = document.getElementById("peer-key-input") as HTMLInputElement;
    this.peerIdInputE2EE = document.getElementById("peer-id-input") as HTMLInputElement;
    this.addPeerKeyBtn = document.getElementById("add-peer-key-btn") as HTMLButtonElement;
    this.autoShareAllBtn = document.getElementById("auto-share-all-btn") as HTMLButtonElement;
    this.requestAllKeysBtn = document.getElementById("request-all-keys-btn") as HTMLButtonElement;
    this.peerKeysList = document.getElementById("peer-keys-list")!;
    this.mitmWarning = document.getElementById("mitm-warning")!;
  }

  private setupEventListeners(): void {
    this.setUsernameBtn.addEventListener("click", () => this.setUsername());
    this.joinNetworkBtn.addEventListener("click", () => this.joinP2PNetwork());
    this.messageForm.addEventListener("submit", (e) => this.sendMessage(e));
    
    this.usernameInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.setUsername();
    });

    this.messageInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage(e);
      }
    });

    // Room event listeners
    this.createRoomBtn.addEventListener("click", () => this.createRoom());
    this.joinRoomBtn.addEventListener("click", () => this.joinRoom());
    this.copyCurrentRoomBtn.addEventListener("click", () => this.copyCurrentRoomId());
    this.leaveCurrentRoomBtn.addEventListener("click", () => this.leaveCurrentRoom());
    this.invitePeerBtn.addEventListener("click", () => this.invitePeerToCurrentRoom());
    this.roomNameInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.createRoom();
    });
    
    this.roomIdInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.joinRoom();
    });
    
    // E2EE event listeners
    this.encryptionToggle.addEventListener("change", () => this.toggleEncryption());
    this.copyFingerprintBtn.addEventListener("click", () => this.copyOurFingerprint());
    this.addPeerKeyBtn.addEventListener("click", () => this.addPeerKey());
    this.autoShareAllBtn.addEventListener("click", () => this.autoShareKeysWithAllPeers());
    this.requestAllKeysBtn.addEventListener("click", () => this.requestKeysFromAllPeers());
    this.peerKeyInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.addPeerKey();
    });
  }

  private async setupTauriEventListeners(): Promise<void> {
    // Listen for P2P network events
    await listen<any>("p2p_network_started", (event) => {
      const data = event.payload;
      this.peerId = typeof data === 'string' ? data : data.peer_id;
      this.ourFingerprint = data.key_fingerprint || '';
      this.connected = true;
      this.updateConnectionStatus("connected", "Connected to P2P network (E2EE enabled)");
      this.peerIdDisplay.textContent = this.peerId;
      this.peerInfo.style.display = "block";
      this.roomsSection.style.display = "block";
      this.encryptionSection.style.display = "block"; // Show E2EE section
      this.messageInput.disabled = false;
      this.sendBtn.disabled = false;
      this.joinNetworkBtn.disabled = true;
      this.addSystemMessage("Connected to P2P network with E2EE!");
      this.addSystemMessage(`Your peer ID: ${this.peerId.slice(0, 12)}...`);
      this.addSystemMessage(`Key fingerprint: ${this.ourFingerprint}`);
      this.addSystemMessage("Create or join a room to start chatting!");
      this.updateOurIdentityDisplay();
      this.updatePeersList();
      this.updateRoomsList();
      this.loadPeerKeys();
    });
    
    // Listen for E2EE events
    await listen<boolean>("encryption_toggled", (event) => {
      this.encryptionEnabled = event.payload;
      this.updateEncryptionStatus();
      const status = this.encryptionEnabled ? "enabled" : "disabled";
      this.addSystemMessage(`End-to-end encryption ${status}`);
    });

    await listen<Message>("message_sent", (event) => {
      this.displayMessage(event.payload, true);
    });

    await listen<Message>("message_received", (event) => {
      this.displayMessage(event.payload, false);
    });

    await listen<string>("username_updated", (event) => {
      this.addSystemMessage(`Username updated to: ${event.payload}`);
    });

    // Listen for peer events
    await listen<User>("peer_joined", (event) => {
      const peer = event.payload;
      this.addSystemMessage(`Peer joined: ${peer.username}`);
      this.updatePeersList();
      // Automatically try to share keys with new peer
      this.autoShareKeyWithPeer(peer.id);
    });
    
    await listen<any>("key_exchange_sent", (event) => {
      const data = event.payload;
      this.addSystemMessage(`Key sent to peer ${data.peer_id.slice(0, 12)}...`);
    });
    
    await listen<any>("key_exchange_received", (event) => {
      const data = event.payload;
      if (data.success) {
        this.addSystemMessage(`Received and added key from peer ${data.peer_id.slice(0, 12)}...`);
        this.addSystemMessage(`Fingerprint: ${data.key_fingerprint}`);
        // Refresh peer list to show key status
        this.updatePeersList();
      } else {
        this.addSystemMessage(`Failed to add key from peer ${data.peer_id.slice(0, 12)}...: ${data.error || 'Unknown error'}`);
      }
    });
    
    await listen<any>("peer_invited", (event) => {
      const data = event.payload;
      this.addSystemMessage(`Successfully invited peer ${data.peer_id.slice(0, 12)}... to room ${data.room_id}`);
    });

    await listen<User>("peer_left", (event) => {
      const peer = event.payload;
      this.addSystemMessage(`Peer left: ${peer.username}`);
      this.updatePeersList();
    });

    await listen<User[]>("peer_list_updated", (event) => {
      this.displayPeersList(event.payload);
    });

    // Room event listeners
    await listen<Room>("room_created", (event) => {
      this.addSystemMessage(`Room created: ${event.payload.name}`);
      this.updateRoomsList();
    });

    await listen<string>("room_joined", (event) => {
      this.currentRoom = event.payload;
      this.updateCurrentRoomDisplay();
      this.updateRoomsList();
      this.clearAndLoadMessages();
      this.addSystemMessage(`Joined room: ${event.payload}`);
    });

    await listen<string>("room_left", (event) => {
      this.addSystemMessage(`Left room: ${event.payload}`);
      this.updateRoomsList();
      if (this.currentRoom === event.payload) {
        this.currentRoom = null;
        this.updateCurrentRoomDisplay();
        this.clearMessages();
      }
    });

    await listen<string>("room_switched", (event) => {
      this.currentRoom = event.payload;
      this.updateCurrentRoomDisplay();
      this.clearAndLoadMessages();
      this.addSystemMessage(`Switched to room: ${event.payload}`);
    });
  }

  private async checkNetworkStatus(): Promise<void> {
    try {
      const status = await invoke<NetworkStatus>("get_network_status");
      if (status.connected) {
        this.connected = true;
        this.peerId = status.peer_id || "";
        this.updateConnectionStatus("connected", status.status);
        this.peerIdDisplay.textContent = this.peerId;
        this.peerInfo.style.display = "block";
        this.messageInput.disabled = false;
        this.sendBtn.disabled = false;
        this.joinNetworkBtn.disabled = true;
      } else {
        this.updateConnectionStatus("disconnected", status.status);
      }
    } catch (error) {
      console.error("Failed to check network status:", error);
    }
  }

  private setUsername(): void {
    const username = this.usernameInput.value.trim();
    if (!username) {
      alert("Please enter a username");
      return;
    }

    this.username = username;
    this.usernameInput.disabled = true;
    this.setUsernameBtn.disabled = true;
    this.joinNetworkBtn.disabled = false;
    this.addSystemMessage(`Username set to: ${username}`);

    // Update username in P2P network if already connected
    if (this.connected) {
      this.updateUsernameInNetwork();
    }
  }

  private async updateUsernameInNetwork(): Promise<void> {
    try {
      await invoke("update_username", { newUsername: this.username });
    } catch (error) {
      console.error("Failed to update username in network:", error);
    }
  }

  private async joinP2PNetwork(): Promise<void> {
    if (!this.username) {
      alert("Please set a username first");
      return;
    }

    this.updateConnectionStatus("connecting", "Joining P2P network...");
    this.joinNetworkBtn.disabled = true;

    try {
      const result = await invoke<string>("start_p2p_network", {
        username: this.username
      });
      console.log(result);
    } catch (error) {
      console.error("Failed to join P2P network:", error);
      alert(`Failed to join P2P network: ${error}`);
      this.updateConnectionStatus("disconnected", "Failed to join network");
      this.joinNetworkBtn.disabled = false;
    }
  }

  private async sendMessage(event: Event): Promise<void> {
    event.preventDefault();
    
    const content = this.messageInput.value.trim();
    if (!content || !this.connected) return;

    if (!this.currentRoom) {
      this.addSystemMessage("Please join a room before sending messages!");
      return;
    }

    try {
      await invoke("send_p2p_message", {
        content: content,
        roomId: this.currentRoom
      });

      this.messageInput.value = "";
    } catch (error) {
      console.error("Failed to send message:", error);
      this.addSystemMessage("Failed to send message");
    }
  }

  private async createRoom(): Promise<void> {
    const roomName = this.roomNameInput.value.trim();
    if (!roomName) {
      alert("Please enter a room name");
      return;
    }

    if (!this.connected) {
      alert("Please connect to the P2P network first");
      return;
    }

    try {
      const room = await invoke<Room>("create_room", { name: roomName });
      this.roomNameInput.value = "";
      this.addSystemMessage(`Created and joined room: ${room.name} (ID: ${room.id})`);
    } catch (error) {
      console.error("Failed to create room:", error);
      alert(`Failed to create room: ${error}`);
    }
  }

  private async joinRoom(): Promise<void> {
    const roomId = this.roomIdInput.value.trim();
    if (!roomId) {
      alert("Please enter a room ID");
      return;
    }

    if (!this.connected) {
      alert("Please connect to the P2P network first");
      return;
    }

    try {
      await invoke("join_room", { roomId: roomId });
      this.roomIdInput.value = "";
    } catch (error) {
      console.error("Failed to join room:", error);
      alert(`Failed to join room: ${error}`);
    }
  }

  private async leaveCurrentRoom(): Promise<void> {
    if (!this.currentRoom) return;

    try {
      await invoke("leave_room", { roomId: this.currentRoom });
    } catch (error) {
      console.error("Failed to leave room:", error);
      this.addSystemMessage("Failed to leave room");
    }
  }

  private async switchToRoom(roomId: string): Promise<void> {
    try {
      await invoke("switch_room", { roomId: roomId });
    } catch (error) {
      console.error("Failed to switch room:", error);
      this.addSystemMessage("Failed to switch room");
    }
  }

    private async invitePeerToCurrentRoom(): Promise<void> {
    if (!this.currentRoom) {
      alert("Please join a room first");
      return;
    }

    try {
      const peers = await invoke<User[]>("get_connected_peers");
      if (peers.length === 0) {
        alert("No connected peers to invite");
        return;
      }

      // Create a more user-friendly selection interface
      const peerOptions = peers.map((peer, index) => 
        `${index + 1}. ${peer.username} (${peer.id.slice(0, 12)}...)`
      ).join('\n');
      
      const selection = prompt(`Select a peer to invite to the current room:\n\n${peerOptions}\n\nEnter the number:`);
      
      if (!selection) return;

      const selectedIndex = parseInt(selection) - 1;
      if (isNaN(selectedIndex) || selectedIndex < 0 || selectedIndex >= peers.length) {
        alert("Invalid selection");
        return;
      }

      const selectedPeer = peers[selectedIndex];
      await invoke("invite_to_room", { peerId: selectedPeer.id, roomId: this.currentRoom });
      this.addSystemMessage(`Invited ${selectedPeer.username} to room ${this.currentRoom}`);
    } catch (error) {
      console.error("Failed to invite peer:", error);
      alert(`Failed to invite peer: ${error}`);
    }
  }

  private displayMessage(message: Message, isOwn: boolean = false): void {
    // Only display messages for current room
    if (message.room_id !== this.currentRoom) return;
    
    const messageEl = document.createElement('div');
    messageEl.className = `message ${isOwn ? 'own' : ''} ${message.encrypted ? 'encrypted' : 'plaintext'}`;
    
    const timestamp = new Date(message.timestamp).toLocaleTimeString();
    
    // Add encryption indicator
    const encryptionIcon = message.encrypted ? '[ENC]' : '[PLAIN]';
    const encryptionTitle = message.encrypted ? 'Encrypted message' : 'Plaintext message';
    
    messageEl.innerHTML = `
      <div class="message-header">
        <span class="message-username">${this.escapeHtml(message.username)}</span>
        <span class="encryption-indicator" title="${encryptionTitle}">${encryptionIcon}</span>
        <span class="message-time">${timestamp}</span>
      </div>
      <div class="message-content">${this.escapeHtml(message.content)}</div>
    `;

    // Remove welcome message if it exists
    const welcomeMessage = this.messagesContainer.querySelector('.welcome-message');
    if (welcomeMessage) {
      welcomeMessage.remove();
    }

    this.messagesContainer.appendChild(messageEl);
    this.scrollToBottom();
  }

  private async updateRoomsList(): Promise<void> {
    try {
      const rooms = await invoke<Room[]>("get_joined_rooms");
      this.joinedRooms = rooms;
      this.displayRoomsList(rooms);
    } catch (error) {
      console.error("Failed to get joined rooms:", error);
    }
  }

  private displayRoomsList(rooms: Room[]): void {
    this.roomsList.innerHTML = '';
    this.roomsCount.textContent = rooms.length.toString();

    if (rooms.length === 0) {
      const emptyEl = document.createElement('li');
      emptyEl.textContent = 'No rooms joined';
      this.roomsList.appendChild(emptyEl);
      return;
    }

    rooms.forEach(room => {
      const roomEl = document.createElement('li');
      roomEl.className = `room-item ${room.id === this.currentRoom ? 'active' : ''}`;
      
      const roomInfo = document.createElement('div');
      roomInfo.className = 'room-info';
      roomInfo.innerHTML = `
        <div class="room-details">
          <span class="room-name">${this.escapeHtml(room.name)}</span>
          <div class="room-id-container">
            <span class="room-id" title="${room.id}">${room.id}</span>
            <button class="copy-btn" title="Copy Room ID">Copy</button>
          </div>
        </div>
      `;
      
      // Add copy functionality
      const copyBtn = roomInfo.querySelector('.copy-btn') as HTMLButtonElement;
      copyBtn.addEventListener('click', () => this.copyToClipboard(room.id));
      
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'room-actions';
      
      if (room.id !== this.currentRoom) {
        const switchBtn = document.createElement('button');
        switchBtn.textContent = 'Switch';
        switchBtn.className = 'small-btn';
        switchBtn.addEventListener('click', () => this.switchToRoom(room.id));
        actionsDiv.appendChild(switchBtn);
      }
      
      const leaveBtn = document.createElement('button');
      leaveBtn.textContent = 'Leave';
      leaveBtn.className = 'small-btn danger';
      leaveBtn.addEventListener('click', () => this.leaveRoom(room.id));
      actionsDiv.appendChild(leaveBtn);
      
      roomEl.appendChild(roomInfo);
      roomEl.appendChild(actionsDiv);
      this.roomsList.appendChild(roomEl);
    });
  }

  private async leaveRoom(roomId: string): Promise<void> {
    try {
      await invoke("leave_room", { roomId: roomId });
    } catch (error) {
      console.error("Failed to leave room:", error);
      this.addSystemMessage("Failed to leave room");
    }
  }

  private updateCurrentRoomDisplay(): void {
    if (this.currentRoom) {
      const room = this.joinedRooms.find(r => r.id === this.currentRoom);
      const roomName = room ? room.name : `Room ${this.currentRoom}`;
      this.currentRoomName.textContent = roomName;
      this.currentRoomDiv.style.display = "block";
      this.copyCurrentRoomBtn.style.display = "inline-block";
    } else {
      this.currentRoomName.textContent = "None";
      this.currentRoomDiv.style.display = "none";
      this.copyCurrentRoomBtn.style.display = "none";
    }
    this.updateRoomsList(); // Refresh the rooms list to update active state
  }

  private async clearAndLoadMessages(): Promise<void> {
    this.clearMessages();
    if (this.currentRoom) {
      try {
        const messages = await invoke<Message[]>("get_messages", { roomId: this.currentRoom });
        messages.forEach(message => this.displayMessage(message, message.username === this.username));
      } catch (error) {
        console.error("Failed to load messages:", error);
      }
    }
  }

  private clearMessages(): void {
    this.messagesContainer.innerHTML = '<div class="welcome-message"><p>Switch to a room to see messages</p></div>';
  }

  private async copyCurrentRoomId(): Promise<void> {
    if (this.currentRoom) {
      await this.copyToClipboard(this.currentRoom);
    }
  }

  private async copyToClipboard(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.addSystemMessage(`Room ID copied to clipboard: ${text}`);
    } catch (error) {
      console.error("Failed to copy to clipboard:", error);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        this.addSystemMessage(`Room ID copied to clipboard: ${text}`);
      } catch (fallbackError) {
        console.error("Fallback copy failed:", fallbackError);
        this.addSystemMessage("Failed to copy room ID");
      }
      document.body.removeChild(textArea);
    }
  }

  private addSystemMessage(content: string): void {
    const messageEl = document.createElement('div');
    messageEl.className = 'message system';
    messageEl.innerHTML = `<div class="message-content">${this.escapeHtml(content)}</div>`;
    
    this.messagesContainer.appendChild(messageEl);
    this.scrollToBottom();
  }

  private async updatePeersList(): Promise<void> {
    try {
      const peers = await invoke<User[]>("get_connected_peers");
      this.displayPeersList(peers);
    } catch (error) {
      console.error("Failed to get peers:", error);
    }
  }

  private displayPeersList(peers: User[]): void {
    this.peersList.innerHTML = '';
    this.peerCount.textContent = peers.length.toString();

    if (peers.length === 0) {
      const emptyEl = document.createElement('li');
      emptyEl.textContent = 'No connected peers';
      this.peersList.appendChild(emptyEl);
      return;
    }

    peers.forEach(peer => {
      const peerEl = document.createElement('li');
      peerEl.className = 'peer-item';
      
      const peerInfo = document.createElement('div');
      peerInfo.className = 'peer-info-content';
      peerInfo.innerHTML = `
        <span class="peer-name">${this.escapeHtml(peer.username)}</span>
        <span class="peer-id-short">${peer.id.slice(0, 8)}...</span>
      `;
      
      const peerActions = document.createElement('div');
      peerActions.className = 'peer-actions-inline';
      
      const shareKeyBtn = document.createElement('button');
      shareKeyBtn.textContent = 'Share Key';
      shareKeyBtn.className = 'small-btn';
      shareKeyBtn.addEventListener('click', () => this.autoShareKeyWithPeer(peer.id));
      
      const inviteBtn = document.createElement('button');
      inviteBtn.textContent = 'Invite';
      inviteBtn.className = 'small-btn';
      inviteBtn.addEventListener('click', () => this.invitePeerToRoom(peer.id));
      
      peerActions.appendChild(shareKeyBtn);
      if (this.currentRoom) {
        peerActions.appendChild(inviteBtn);
      }
      
      peerEl.appendChild(peerInfo);
      peerEl.appendChild(peerActions);
      this.peersList.appendChild(peerEl);
    });
  }

  private updateConnectionStatus(status: string, text: string): void {
    this.statusIndicator.className = `status-indicator ${status}`;
    this.statusText.textContent = text;
  }

  private scrollToBottom(): void {
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  // E2EE Functions
  
  private async toggleEncryption(): Promise<void> {
    try {
      const enabled = this.encryptionToggle.checked;
      await invoke("toggle_encryption", { enabled });
      this.encryptionEnabled = enabled;
      this.updateEncryptionStatus();
    } catch (error) {
      console.error("Failed to toggle encryption:", error);
      // Revert checkbox state on error
      this.encryptionToggle.checked = this.encryptionEnabled;
    }
  }
  
  private updateEncryptionStatus(): void {
    if (this.encryptionEnabled) {
      this.encryptionStatusText.textContent = "Messages are encrypted";
      this.encryptionIndicator.className = "encryption-indicator enabled";
    } else {
      this.encryptionStatusText.textContent = "Messages are NOT encrypted";
      this.encryptionIndicator.className = "encryption-indicator disabled";
    }
  }
  
  private async updateOurIdentityDisplay(): Promise<void> {
    try {
      const identity = await invoke<CryptoIdentity>("get_our_identity");
      this.ourFingerprint = identity.key_fingerprint;
      this.ourFingerprintEl.textContent = identity.key_fingerprint;
    } catch (error) {
      console.error("Failed to get our identity:", error);
      this.ourFingerprintEl.textContent = "Error loading";
    }
  }
  
  private async copyOurFingerprint(): Promise<void> {
    if (this.ourFingerprint) {
      await this.copyToClipboard(this.ourFingerprint);
      this.addSystemMessage(`Your key fingerprint copied: ${this.ourFingerprint}`);
    }
  }
  
  private async addPeerKey(): Promise<void> {
    const publicKeyHex = this.peerKeyInput.value.trim();
    const peerId = this.peerIdInputE2EE.value.trim();
    
    if (!publicKeyHex || !peerId) {
      alert("Please enter both peer ID and public key");
      return;
    }
    
    // Validate hex format (64 characters for 32 bytes)
    if (!/^[0-9a-fA-F]{64}$/.test(publicKeyHex)) {
      alert("Public key must be 64 hex characters (32 bytes)");
      return;
    }
    
    try {
      const result = await invoke<string>("add_peer_key", {
        peerId,
        publicKeyHex
      });
      
      this.addSystemMessage(`${result}`);
      this.peerKeyInput.value = "";
      this.peerIdInputE2EE.value = "";
      this.loadPeerKeys();
      this.showMitmWarning();
    } catch (error) {
      console.error("Failed to add peer key:", error);
      alert(`Failed to add peer key: ${error}`);
    }
  }
  
  private async loadPeerKeys(): Promise<void> {
    try {
      const peers = await invoke<PeerInfo[]>("get_peer_identities");
      this.peerKeys = peers;
      this.displayPeerKeys(peers);
    } catch (error) {
      console.error("Failed to load peer keys:", error);
    }
  }
  
  private displayPeerKeys(peers: PeerInfo[]): void {
    this.peerKeysList.innerHTML = '';
    
    if (peers.length === 0) {
      const emptyEl = document.createElement('li');
      emptyEl.className = 'empty-state';
      emptyEl.textContent = 'No peer keys added yet';
      this.peerKeysList.appendChild(emptyEl);
      return;
    }
    
    peers.forEach(peer => {
      const peerEl = document.createElement('li');
      peerEl.className = 'peer-key-item';
      
      const verificationStatus = peer.verified ? 'Verified' : 'Unverified';
      const verificationClass = peer.verified ? 'verified' : 'unverified';
      
      peerEl.innerHTML = `
        <div class="peer-key-info">
          <div class="peer-id">${this.escapeHtml(peer.id.slice(0, 12))}...</div>
          <div class="peer-fingerprint">${peer.key_fingerprint}</div>
          <div class="verification-status ${verificationClass}">${verificationStatus}</div>
        </div>
        <div class="peer-key-actions">
          <button class="verify-btn small-btn" title="Verify fingerprint">Verify</button>
          <button class="copy-fingerprint-btn small-btn" title="Copy fingerprint">Copy</button>
        </div>
      `;
      
      // Add event listeners
      const verifyBtn = peerEl.querySelector('.verify-btn') as HTMLButtonElement;
      const copyBtn = peerEl.querySelector('.copy-fingerprint-btn') as HTMLButtonElement;
      
      verifyBtn.addEventListener('click', () => this.verifyPeerFingerprint(peer));
      copyBtn.addEventListener('click', () => this.copyToClipboard(peer.key_fingerprint));
      
      this.peerKeysList.appendChild(peerEl);
    });
  }
  
  private async verifyPeerFingerprint(peer: PeerInfo): Promise<void> {
    const userInput = prompt(
      `Verify ${peer.id.slice(0, 12)}...'s key fingerprint:\\n\\n` +
      `Expected: ${peer.key_fingerprint}\\n\\n` +
      `Please verify this fingerprint through a secure channel (voice call, in person, etc.)\\n` +
      `Type 'VERIFIED' if the fingerprint matches:`
    );
    
    if (userInput === 'VERIFIED') {
      try {
        const isValid = await invoke<boolean>("verify_peer_fingerprint", {
          peerId: peer.id,
          expectedFingerprint: peer.key_fingerprint
        });
        
        if (isValid) {
          this.addSystemMessage(`Peer ${peer.id.slice(0, 12)}... verified successfully`);
          peer.verified = true; // Update local state
          this.displayPeerKeys(this.peerKeys); // Refresh display
        } else {
          this.addSystemMessage(`Fingerprint verification failed for ${peer.id.slice(0, 12)}...`);
        }
      } catch (error) {
        console.error("Failed to verify peer fingerprint:", error);
        this.addSystemMessage("Verification failed");
      }
    } else if (userInput !== null) {
      this.addSystemMessage("Verification cancelled - peer remains unverified");
    }
  }
  
  private showMitmWarning(): void {
    this.mitmWarning.style.display = "block";
    // Auto-hide after 10 seconds
    setTimeout(() => {
      this.mitmWarning.style.display = "none";
    }, 10000);
  }
  
  private async autoShareKeysWithAllPeers(): Promise<void> {
    try {
      const peers = await invoke<User[]>("get_connected_peers");
      if (peers.length === 0) {
        this.addSystemMessage("No connected peers to share keys with");
        return;
      }
      
      let successCount = 0;
      for (const peer of peers) {
        try {
          await this.autoShareKeyWithPeer(peer.id);
          successCount++;
        } catch (error) {
          console.error(`Failed to share key with ${peer.id}:`, error);
        }
      }
      
      this.addSystemMessage(`Initiated key sharing with ${successCount}/${peers.length} peers`);
    } catch (error) {
      console.error("Failed to get connected peers:", error);
      this.addSystemMessage("Failed to share keys with peers");
    }
  }
  
  private async autoShareKeyWithPeer(peerId: string): Promise<void> {
    try {
      const result = await invoke<string>("auto_share_keys_with_peer", { peerId });
      console.log(`Key sharing result for ${peerId}:`, result);
    } catch (error) {
      console.error(`Failed to share key with ${peerId}:`, error);
      throw error;
    }
  }
  
  private async requestKeysFromAllPeers(): Promise<void> {
    try {
      const peers = await invoke<User[]>("get_connected_peers");
      if (peers.length === 0) {
        this.addSystemMessage("No connected peers to request keys from");
        return;
      }
      
      this.addSystemMessage(`Requesting public keys from ${peers.length} peer(s)...`);
      this.addSystemMessage("In a production app, this would send key requests via P2P network");
      
      // Show peer information for manual key exchange
      for (const peer of peers) {
        this.addSystemMessage(`Peer: ${peer.username} (ID: ${peer.id})`);
      }
      
      this.addSystemMessage("Ask peers to share their keys using the 'Auto-Share' button or provide them manually");
    } catch (error) {
      console.error("Failed to request keys:", error);
      this.addSystemMessage("Failed to request keys from peers");
    }
  }
  
  private async invitePeerToRoom(peerId: string): Promise<void> {
    if (!this.currentRoom) {
      this.addSystemMessage("Please join a room first");
      return;
    }
    
    try {
      await invoke("invite_to_room", { peerId, roomId: this.currentRoom });
      this.addSystemMessage(`Invited peer ${peerId.slice(0, 12)}... to room`);
    } catch (error) {
      console.error("Failed to invite peer:", error);
      this.addSystemMessage("Failed to invite peer to room");
    }
  }
}

// Initialize app when DOM is loaded
window.addEventListener("DOMContentLoaded", () => {
  new P2PChatApp();
});
