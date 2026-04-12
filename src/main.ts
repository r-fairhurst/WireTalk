import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface Message {
  id: string;
  username: string;
  content: string;
  timestamp: string;
}

interface User {
  id: string;
  username: string;
  connected_at: string;
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
  }

  private async setupTauriEventListeners(): Promise<void> {
    // Listen for P2P network events
    await listen<string>("p2p_network_started", (event) => {
      this.peerId = event.payload;
      this.connected = true;
      this.updateConnectionStatus("connected", "Connected to P2P network");
      this.peerIdDisplay.textContent = this.peerId;
      this.peerInfo.style.display = "block";
      this.messageInput.disabled = false;
      this.sendBtn.disabled = false;
      this.joinNetworkBtn.disabled = true;
      this.addSystemMessage("Connected to P2P network!");
      this.addSystemMessage(`Your peer ID: ${this.peerId.slice(0, 12)}...`);
      this.updatePeersList(); // Update peer list when network starts
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
    await listen<string>("peer_joined", (event) => {
      const peerId = event.payload;
      this.addSystemMessage(`Peer joined: ${peerId.slice(0, 12)}...`);
      this.updatePeersList();
    });

    await listen<string>("peer_left", (event) => {
      const peerId = event.payload;
      this.addSystemMessage(`Peer left: ${peerId.slice(0, 12)}...`);
      this.updatePeersList();
    });

    await listen<User[]>("peer_list_updated", (event) => {
      this.displayPeersList(event.payload);
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

    try {
      await invoke("send_p2p_message", {
        content: content
      });

      this.messageInput.value = "";
    } catch (error) {
      console.error("Failed to send message:", error);
      this.addSystemMessage("Failed to send message");
    }
  }

  private displayMessage(message: Message, isOwn: boolean = false): void {
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
      emptyEl.style.fontStyle = 'italic';
      emptyEl.style.color = '#999';
      this.peersList.appendChild(emptyEl);
      return;
    }

    peers.forEach(peer => {
      const peerEl = document.createElement('li');
      const peerId = peer.id.slice(0, 12);
      peerEl.textContent = `${peer.username} (${peerId}...)`;
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
