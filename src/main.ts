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

interface RoomInvitationPayload {
  room_id: string;
  inviter_peer_id: string;
  inviter_username: string;
}

interface StorageStatus {
  initialized: boolean;
  unlocked: boolean;
  file_exists: boolean;
  file_path?: string;
}

class P2PChatApp {
  private username: string = "";
  private connected: boolean = false;
  private joiningNetwork: boolean = false;
  private peerId: string = "";
  private currentRoom: string | null = null;
  private joinedRooms: Room[] = [];
  private encryptionEnabled: boolean = true;
  private ourFingerprint: string = "";
  private wgActive: boolean = false;
  private storageUnlocked: boolean = false;

  // DOM elements
  private usernameInput!: HTMLInputElement;
  private setUsernameBtn!: HTMLButtonElement;
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
  private storageSection!: HTMLElement;
  private storagePasswordInput!: HTMLInputElement;
  private unlockStorageBtn!: HTMLButtonElement;
  private lockStorageBtn!: HTMLButtonElement;
  private storageStatusText!: HTMLElement;
  
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


  // WireGuard DOM elements
  private wgSetupBtn!: HTMLButtonElement;
  private wgIpInput!: HTMLInputElement;
  private wgPortInput!: HTMLInputElement;
  private wgSetupPanel!: HTMLElement;
  private wgActivePanel!: HTMLElement;
  private wgStatusIndicator!: HTMLElement;
  private wgStatusText!: HTMLElement;
  private wgPublicKey!: HTMLElement;
  private wgTunnelIp!: HTMLElement;
  private wgMyEndpointInput!: HTMLInputElement;
  private wgCopyConfigBtn!: HTMLButtonElement;
  private wgPeerConfigInput!: HTMLTextAreaElement;
  private wgAddPeerBtn!: HTMLButtonElement;
  private wgMultiaddrInput!: HTMLInputElement;
  private wgDialBtn!: HTMLButtonElement;
  private wgCopyAddrsBtn!: HTMLButtonElement;
  private wgTeardownBtn!: HTMLButtonElement;

  constructor() {
    this.initDOM();
    this.setupEventListeners();
    this.setupTauriEventListeners();
    this.cleanupStaleWireGuardOnStartup();
    this.checkStorageStatus();
    this.cleanupStaleWireGuardOnStartup();
    this.checkNetworkStatus();
  }

  private initDOM(): void {
    this.usernameInput = document.getElementById("username-input") as HTMLInputElement;
    this.setUsernameBtn = document.getElementById("set-username-btn") as HTMLButtonElement;
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
    this.storageSection = document.getElementById("storage-section")!;
    this.storagePasswordInput = document.getElementById("storage-password-input") as HTMLInputElement;
    this.unlockStorageBtn = document.getElementById("unlock-storage-btn") as HTMLButtonElement;
    this.lockStorageBtn = document.getElementById("lock-storage-btn") as HTMLButtonElement;
    this.storageStatusText = document.getElementById("storage-status-text")!;
    
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


    // WireGuard elements
    this.wgSetupBtn = document.getElementById("wg-setup-btn") as HTMLButtonElement;
    this.wgIpInput = document.getElementById("wg-ip-input") as HTMLInputElement;
    this.wgPortInput = document.getElementById("wg-port-input") as HTMLInputElement;
    this.wgSetupPanel = document.getElementById("wg-setup-panel")!;
    this.wgActivePanel = document.getElementById("wg-active-panel")!;
    this.wgStatusIndicator = document.getElementById("wg-status-indicator")!;
    this.wgStatusText = document.getElementById("wg-status-text")!;
    this.wgPublicKey = document.getElementById("wg-public-key")!;
    this.wgTunnelIp = document.getElementById("wg-tunnel-ip")!;
    this.wgMyEndpointInput = document.getElementById("wg-my-endpoint-input") as HTMLInputElement;
    this.wgCopyConfigBtn = document.getElementById("wg-copy-config-btn") as HTMLButtonElement;
    this.wgPeerConfigInput = document.getElementById("wg-peer-config-input") as HTMLTextAreaElement;
    this.wgAddPeerBtn = document.getElementById("wg-add-peer-btn") as HTMLButtonElement;
    this.wgMultiaddrInput = document.getElementById("wg-multiaddr-input") as HTMLInputElement;
    this.wgDialBtn = document.getElementById("wg-dial-btn") as HTMLButtonElement;
    this.wgCopyAddrsBtn = document.getElementById("wg-copy-addrs-btn") as HTMLButtonElement;
    this.wgTeardownBtn = document.getElementById("wg-teardown-btn") as HTMLButtonElement;

  }

  private setupEventListeners(): void {
    this.setUsernameBtn.addEventListener("click", () => this.setUsername());
    this.messageForm.addEventListener("submit", (e) => this.sendMessage(e));
    this.unlockStorageBtn.addEventListener("click", () => this.unlockStorage());
    this.lockStorageBtn.addEventListener("click", () => this.lockStorage());
    
    this.usernameInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.setUsername();
    });

    this.usernameInput.addEventListener("change", () => {
      if (!this.username && this.usernameInput.value.trim()) {
        this.setUsername();
      }
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

    this.storagePasswordInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.unlockStorage();
    });

    // WireGuard event listeners
    this.wgSetupBtn.addEventListener("click", () => this.setupWireGuard());
    this.wgCopyConfigBtn.addEventListener("click", () => this.copyWireGuardConfig());
    this.wgAddPeerBtn.addEventListener("click", () => this.addWireGuardPeerFromConfig());
    this.wgDialBtn.addEventListener("click", () => this.dialPeerViaWireGuard());
    this.wgCopyAddrsBtn.addEventListener("click", () => this.copyListenAddresses());
    this.wgTeardownBtn.addEventListener("click", () => this.teardownWireGuard());
  }

  private async setupTauriEventListeners(): Promise<void> {
    // Listen for P2P network events
    await listen<any>("p2p_network_started", (event) => {
      const data = event.payload;
      this.peerId = typeof data === 'string' ? data : data.peer_id;
      this.ourFingerprint = data.key_fingerprint || '';
      this.connected = true;
      this.joiningNetwork = false;
      this.updateConnectionStatus("connected", "Connected to P2P network (E2EE enabled)");
      this.peerIdDisplay.textContent = this.peerId;
      this.peerInfo.style.display = "block";
      this.roomsSection.style.display = "block";
      this.encryptionSection.style.display = "block"; // Show E2EE section
      this.messageInput.disabled = false;
      this.sendBtn.disabled = false;
      this.addSystemMessage("Connected to P2P network with E2EE!");
      this.addSystemMessage(`Your peer ID: ${this.peerId.slice(0, 12)}...`);
      this.addSystemMessage(`Key fingerprint: ${this.ourFingerprint}`);
      this.addSystemMessage("Create or join a room to start chatting!");
      this.updateOurIdentityDisplay();
      this.updatePeersList();
      this.updateRoomsList();
    });
    
    // Listen for E2EE events
    await listen<boolean>("encryption_toggled", (event) => {
      this.encryptionEnabled = event.payload;
      this.updateEncryptionStatus();
      const status = this.encryptionEnabled ? "enabled" : "disabled";
      this.addSystemMessage(`End-to-end encryption ${status}`);
    });

    await listen<boolean>("storage_unlocked", () => {
      this.storageUnlocked = true;
      this.updateStorageStatusText(true);
    });

    await listen<boolean>("storage_locked", () => {
      this.storageUnlocked = false;
      this.updateStorageStatusText(false);
      this.clearMessages();
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
    });
    
    await listen<any>("key_exchange_received", (event) => {
      const data = event.payload;
      if (data.success) {
        this.updatePeersList();
      }
    });
    
    await listen<any>("peer_invited", (event) => {
      const data = event.payload;
      this.addSystemMessage(`Successfully invited peer ${data.peer_id.slice(0, 12)}... to room ${data.room_id}`);
    });

    await listen<RoomInvitationPayload>("room_invitation_received", (event) => {
      const data = event.payload;
      this.currentRoom = data.room_id;
      this.updateCurrentRoomDisplay();
      this.clearAndLoadMessages();
      this.addSystemMessage(
        `${data.inviter_username} invited you to a room. Joined automatically: ${data.room_id}`
      );
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

    // WireGuard events
    await listen<{ active: boolean }>("wireguard_status_changed", (event) => {
      this.wgActive = event.payload.active;
      this.updateWireGuardStatusDisplay();
      const statusMsg = event.payload.active
        ? "WireGuard tunnel is now active"
        : "WireGuard tunnel has been torn down";
      this.addSystemMessage(statusMsg);
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
      } else {
        this.updateConnectionStatus("disconnected", status.status);
      }
    } catch (error) {
      console.error("Failed to check network status:", error);
    }
  }

  private async checkStorageStatus(): Promise<void> {
    try {
      const status = await invoke<StorageStatus>("get_storage_status");
      this.storageUnlocked = status.unlocked;
      this.updateStorageStatusText(status.unlocked);

      if (status.unlocked) {
        this.addSystemMessage("Secure vault unlocked. Encrypted history is available.");
        await this.updateRoomsList();
        await this.clearAndLoadMessages();
      } else if (status.file_exists) {
        this.addSystemMessage("Encrypted vault detected. Enter password/PIN to unlock history.");
      } else {
        this.addSystemMessage("No vault found. Set a password/PIN to create one.");
      }
    } catch (error) {
      console.error("Failed to check storage status:", error);
      this.updateStorageStatusText(false);
    }
  }

  private updateStorageStatusText(unlocked: boolean): void {
    this.storageStatusText.textContent = unlocked ? "Vault unlocked" : "Vault locked";
    this.lockStorageBtn.disabled = !unlocked;
    this.unlockStorageBtn.disabled = unlocked;
    this.storagePasswordInput.disabled = unlocked;
    this.storageSection.classList.toggle("vault-unlocked", unlocked);
  }

  private async unlockStorage(): Promise<void> {
    const password = this.storagePasswordInput.value.trim();
    if (!password) {
      alert("Please enter a password/PIN");
      return;
    }

    try {
      await invoke<string>("unlock_secure_storage", {
        password,
        createIfMissing: true,
        // Compatibility fallback for command argument decoding.
        create_if_missing: true,
      });

      this.storageUnlocked = true;
      this.updateStorageStatusText(true);
      this.storagePasswordInput.value = "";
      this.addSystemMessage("Secure vault unlocked");

      await this.updateRoomsList();
      await this.clearAndLoadMessages();
    } catch (error) {
      console.error("Failed to unlock secure vault:", error);
      const message = typeof error === "string"
        ? error
        : (error && typeof error === "object" && "message" in error)
          ? String((error as { message?: unknown }).message)
          : JSON.stringify(error);
      alert(`Failed to unlock secure vault: ${message}`);
      this.storageUnlocked = false;
      this.updateStorageStatusText(false);
    }
  }

  private async lockStorage(): Promise<void> {
    try {
      await invoke<string>("lock_secure_storage");
      this.storageUnlocked = false;
      this.updateStorageStatusText(false);
      this.addSystemMessage("Secure vault locked");
      this.clearMessages();
    } catch (error) {
      console.error("Failed to lock secure vault:", error);
      this.addSystemMessage("Failed to lock secure vault");
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
    this.addSystemMessage(`Username set to: ${username}`);

    // Update username in P2P network if already connected
    if (this.connected) {
      this.updateUsernameInNetwork();
    } else {
      this.joinP2PNetwork();
    }
  }

  private generateGuestUsername(): string {
    return `Guest-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
  }

  private ensureUsernameReady(): void {
    if (this.username) return;

    const typedName = this.usernameInput.value.trim();
    this.username = typedName || this.generateGuestUsername();
    this.usernameInput.value = this.username;
    this.usernameInput.disabled = true;
    this.setUsernameBtn.disabled = true;
    this.addSystemMessage(`Username set to: ${this.username}`);
  }

  private async updateUsernameInNetwork(): Promise<void> {
    try {
      await invoke("update_username", { newUsername: this.username });
    } catch (error) {
      console.error("Failed to update username in network:", error);
    }
  }

  private async joinP2PNetwork(): Promise<void> {
    if (this.connected || this.joiningNetwork) return;

    this.ensureUsernameReady();
    this.joiningNetwork = true;

    if (!this.storageUnlocked) {
      alert("Unlock the secure local vault first.");
      this.joiningNetwork = false;
      return;
    }

    this.updateConnectionStatus("connecting", "Joining P2P network...");

    try {
      const result = await invoke<string>("start_p2p_network", {
        username: this.username
      });
      console.log(result);
    } catch (error) {
      console.error("Failed to join P2P network:", error);
      alert(`Failed to join P2P network: ${error}`);
      this.updateConnectionStatus("disconnected", "Failed to join network");
      this.joiningNetwork = false;
      this.usernameInput.disabled = false;
      this.setUsernameBtn.disabled = false;
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
      const msg = String(error);
      if (msg.includes("Keys not yet exchanged")) {
        this.addSystemMessage("Exchanging encryption keys with peers, please try again in a moment...");
      } else {
        this.addSystemMessage("Failed to send message");
      }
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
      this.addSystemMessage(`Share this invite code: ${this.buildRoomInviteCode(room.id)}`);
    } catch (error) {
      console.error("Failed to create room:", error);
      alert(`Failed to create room: ${error}`);
    }
  }

  private async joinRoom(): Promise<void> {
    const rawInput = this.roomIdInput.value.trim();
    if (!rawInput) {
      alert("Please enter a room ID");
      return;
    }

    const roomId = this.extractRoomId(rawInput);
    if (!roomId) {
      alert("Invalid room ID or invite code");
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

  private buildRoomInviteCode(roomId: string): string {
    return `wiretalk:room:${roomId}`;
  }

  private extractRoomId(input: string): string | null {
    const trimmed = input.trim();
    const directUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    if (directUuid.test(trimmed)) {
      return trimmed;
    }

    const invitePrefix = "wiretalk:room:";
    if (trimmed.toLowerCase().startsWith(invitePrefix)) {
      const extracted = trimmed.slice(invitePrefix.length).trim();
      return directUuid.test(extracted) ? extracted : null;
    }

    return null;
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
    
    // Add encryption indicator (lock icon for encrypted only)
    const encryptionIcon = message.encrypted ? '<span class="lock-icon" title="Encrypted">[E]</span>' : '';
    
    messageEl.innerHTML = `
      <div class="message-header">
        <span class="message-username">${this.escapeHtml(message.username)}</span>
        ${encryptionIcon}
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
        </div>
      `;
      
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
      const inviteCode = this.buildRoomInviteCode(this.currentRoom);
      await this.copyToClipboard(inviteCode);
      this.addSystemMessage(`Copied invite code: ${inviteCode}`);
    }
  }

  private async copyToClipboard(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.addSystemMessage(`Copied to clipboard: ${text}`);
    } catch (error) {
      console.error("Failed to copy to clipboard:", error);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        this.addSystemMessage(`Copied to clipboard: ${text}`);
      } catch (fallbackError) {
        console.error("Fallback copy failed:", fallbackError);
        this.addSystemMessage("Failed to copy text");
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
      
      const inviteBtn = document.createElement('button');
      inviteBtn.textContent = 'Invite';
      inviteBtn.className = 'small-btn';
      inviteBtn.addEventListener('click', () => this.invitePeerToRoom(peer.id));
      
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
  

  
  // ─── WireGuard Methods ───────────────────────────────────────────────────

  private async cleanupStaleWireGuardOnStartup(): Promise<void> {
    try {
      const cleaned = await invoke<boolean>("cleanup_stale_wireguard");
      if (cleaned) {
        this.addSystemMessage("Cleaned up stale WireGuard interface from previous run.");
      }
    } catch (error) {
      console.error("Startup WireGuard cleanup failed:", error);
    } finally {
      await this.checkWireGuardStatus();
    }
  }

  private async checkWireGuardStatus(): Promise<void> {
    try {
      const active = await invoke<boolean>("get_wireguard_status");
      this.wgActive = active;
      this.updateWireGuardStatusDisplay();
      if (active) {
        // Restore config display
        const config = await invoke<any>("get_wireguard_config");
        if (config) {
          this.wgPublicKey.textContent = config.public_key;
          this.wgTunnelIp.textContent = config.interface_ip;
        }
      }
    } catch (error) {
      console.error("Failed to check WireGuard status:", error);
    }
  }

  private updateWireGuardStatusDisplay(): void {
    if (this.wgActive) {
      this.wgStatusIndicator.className = "status-indicator connected";
      this.wgStatusText.textContent = "Active";
      this.wgSetupPanel.style.display = "none";
      this.wgActivePanel.style.display = "block";
    } else {
      this.wgStatusIndicator.className = "status-indicator";
      this.wgStatusText.textContent = "Not configured";
      this.wgSetupPanel.style.display = "block";
      this.wgActivePanel.style.display = "none";
    }
  }

  private async setupWireGuard(): Promise<void> {
    const interfaceIp = this.wgIpInput.value.trim();
    const listenPort = parseInt(this.wgPortInput.value.trim()) || 51820;

    if (!interfaceIp) {
      alert("Please enter a tunnel IP address (e.g. 10.10.10.1/24)");
      return;
    }

    // Validate CIDR format
    if (!/^\/?(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(interfaceIp) &&
        !/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(interfaceIp)) {
      alert("Please use CIDR notation, e.g. 10.10.10.1/24");
      return;
    }

    this.wgSetupBtn.disabled = true;
    this.wgSetupBtn.textContent = "Setting up...";

    try {
      const config = await invoke<any>("setup_wireguard", {
        interfaceIp,
        listenPort
      });

      this.wgPublicKey.textContent = config.public_key;
      this.wgTunnelIp.textContent = config.interface_ip;
      this.wgActive = true;
      this.updateWireGuardStatusDisplay();

      this.addSystemMessage("WireGuard tunnel setup complete!");
      this.addSystemMessage(`Your public key: ${config.public_key}`);
      this.addSystemMessage(`Tunnel IP: ${config.interface_ip}`);
      this.addSystemMessage("Copy your shareable config and send it to peers, then have them paste it into 'Add Peer'.");
    } catch (error) {
      console.error("WireGuard setup failed:", error);
      alert(`WireGuard setup failed: ${error}`);
    } finally {
      this.wgSetupBtn.disabled = false;
      this.wgSetupBtn.textContent = "Setup WireGuard";
    }
  }

  private async teardownWireGuard(): Promise<void> {
    if (!confirm("Tear down the WireGuard tunnel? This will disconnect cross-network peers.")) return;

    try {
      await invoke("teardown_wireguard");
      this.wgActive = false;
      this.updateWireGuardStatusDisplay();
      this.addSystemMessage("WireGuard tunnel torn down.");
    } catch (error) {
      console.error("WireGuard teardown failed:", error);
      alert(`Teardown failed: ${error}`);
    }
  }

  private async copyWireGuardConfig(): Promise<void> {
    const endpoint = this.wgMyEndpointInput.value.trim() || undefined;
    try {
      const shareableCfg = await invoke<any>("get_wireguard_shareable_config", {
        myEndpoint: endpoint ?? null
      });
      if (!shareableCfg) {
        alert("No WireGuard config available.");
        return;
      }
      const json = JSON.stringify(shareableCfg, null, 2);
      await navigator.clipboard.writeText(json);
      this.addSystemMessage("Shareable config copied to clipboard! Send it to your peer.");
      this.addSystemMessage(`Config: ${JSON.stringify(shareableCfg)}`);
    } catch (error) {
      console.error("Failed to copy WireGuard config:", error);
      alert(`Failed: ${error}`);
    }
  }

  private async addWireGuardPeerFromConfig(): Promise<void> {
    const raw = this.wgPeerConfigInput.value.trim();
    if (!raw) {
      alert("Paste the peer's shareable config JSON first.");
      return;
    }

    // Validate it's valid JSON with expected keys before sending to backend
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      alert("Invalid JSON. Please paste the exact config your peer copied.");
      return;
    }

    if (!parsed.public_key || !parsed.tunnel_ip) {
      alert("Config is missing required fields (public_key, tunnel_ip).");
      return;
    }

    this.wgAddPeerBtn.disabled = true;
    this.wgAddPeerBtn.textContent = "Adding...";

    try {
      const result = await invoke<string>("add_wireguard_peer_from_config", {
        peerConfigJson: raw
      });
      this.wgPeerConfigInput.value = "";
      this.addSystemMessage(`WireGuard peer added: ${result}`);
      if (parsed.peer_id && parsed.libp2p_port) {
        this.addSystemMessage(`Auto-dialing P2P layer at ${parsed.tunnel_ip}:${parsed.libp2p_port}...`);
      } else {
        this.addSystemMessage(`Peer is reachable at ${parsed.tunnel_ip} — ask them to share a config generated after joining the P2P network for auto-dial.`);
      }
    } catch (error) {
      console.error("Failed to add WireGuard peer:", error);
      alert(`Failed to add peer: ${error}`);
    } finally {
      this.wgAddPeerBtn.disabled = false;
      this.wgAddPeerBtn.textContent = "Add Peer Automatically";
    }
  }

  private async dialPeerViaWireGuard(): Promise<void> {
    const multiaddr = this.wgMultiaddrInput.value.trim();
    if (!multiaddr) {
      alert("Enter a multiaddr, e.g. /ip4/10.10.10.2/tcp/PORT/p2p/PEER_ID");
      return;
    }

    if (!this.connected) {
      alert("Join the P2P network first.");
      return;
    }

    try {
      const result = await invoke<string>("dial_peer", { multiaddr });
      this.addSystemMessage(`Dialing peer: ${result}`);
    } catch (error) {
      console.error("Dial failed:", error);
      alert(`Dial failed: ${error}`);
    }
  }

  private async copyListenAddresses(): Promise<void> {
    if (!this.connected) {
      alert("Join the P2P network first to see listen addresses.");
      return;
    }
    try {
      const addrs = await invoke<string[]>("get_listen_addresses");
      if (addrs.length === 0) {
        this.addSystemMessage("No listen addresses available yet. Wait a moment and try again.");
        return;
      }
      const text = addrs.join("\n");
      await navigator.clipboard.writeText(text);
      this.addSystemMessage("Your listen addresses copied to clipboard:");
      addrs.forEach(a => this.addSystemMessage(`  ${a}`));
    } catch (error) {
      console.error("Failed to get listen addresses:", error);
      alert(`Failed: ${error}`);
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
