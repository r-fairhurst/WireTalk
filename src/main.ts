import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface Message {
  id: string;
  username: string;
  content: string;
  timestamp: string;
  room_id: string;
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
  status: string;
}

class P2PChatApp {
  private username: string = "";
  private connected: boolean = false;
  private peerId: string = "";
  private currentRoom: string | null = null;
  private joinedRooms: Room[] = [];
  
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
  }

  private async setupTauriEventListeners(): Promise<void> {
    // Listen for P2P network events
    await listen<string>("p2p_network_started", (event) => {
      this.peerId = event.payload;
      this.connected = true;
      this.updateConnectionStatus("connected", "Connected to P2P network");
      this.peerIdDisplay.textContent = this.peerId;
      this.peerInfo.style.display = "block";
      this.roomsSection.style.display = "block";
      this.messageInput.disabled = false;
      this.sendBtn.disabled = false;
      this.joinNetworkBtn.disabled = true;
      this.addSystemMessage("Connected to P2P network!");
      this.addSystemMessage(`Your peer ID: ${this.peerId.slice(0, 12)}...`);
      this.addSystemMessage("Create or join a room to start chatting!");
      this.updatePeersList(); // Update peer list when network starts
      this.updateRoomsList(); // Initialize rooms list
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

      const peerOptions = peers.map(peer => `${peer.username} (${peer.id.slice(0, 12)}...)`);
      const peerSelection = prompt(`Enter the number of the peer to invite:\n${peerOptions.map((opt, i) => `${i + 1}. ${opt}`).join('\n')}`);
      
      if (!peerSelection) return;

      const selectedIndex = parseInt(peerSelection) - 1;
      if (isNaN(selectedIndex) || selectedIndex < 0 || selectedIndex >= peers.length) {
        alert("Invalid selection");
        return;
      }

      const selectedPeer = peers[selectedIndex];
      await invoke("invite_to_room", { peerId: selectedPeer.id, roomId: this.currentRoom });
      this.addSystemMessage(`Invited ${selectedPeer.username} to the room`);
    } catch (error) {
      console.error("Failed to invite peer:", error);
      alert(`Failed to invite peer: ${error}`);
    }
  }

  private displayMessage(message: Message, isOwn: boolean = false): void {
    // Only display messages for current room
    if (message.room_id !== this.currentRoom) return;
    
    const messageEl = document.createElement('div');
    messageEl.className = `message ${isOwn ? 'own' : ''}`;
    
    const timestamp = new Date(message.timestamp).toLocaleTimeString();
    
    messageEl.innerHTML = `
      <div class="message-header">
        <span class="message-username">${this.escapeHtml(message.username)}</span>
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
      peerEl.textContent = peer.username;
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
}

// Initialize app when DOM is loaded
window.addEventListener("DOMContentLoaded", () => {
  new P2PChatApp();
});
