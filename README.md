# WireTalk
A serverless, end-to-end encrypted chat application for private, real-time communication within user-controlled networks.

## WireTalk — 10 Week Development Plan
## Week 1 — Project Setup & Foundations
#### Goals
- Plan out the coming weeks
- Create basic Tauri app
#### Tasks
- Initialize Git repo
- Set up Tauri project
- Create simple UI (input + message box)
- Build basic Node.js WebSocket server (ws library)
- Connect client → client
#### Deliverable
- Client connects to server successfully

## Week 2 — Real-Time Messaging
#### Goals
- Send and receive messages
#### Tasks
- Implement message sending
- Broadcast messages to all clients
- Display messages in UI
- Handle connect/disconnect events
#### Deliverable
- Functional chat (with no sessions or encryption yet)

## Week 3 — Session System (UUID Rooms)
#### Goals
- Add isolated chat rooms
#### Tasks
- Generate session IDs (UUID)
- Join/create session UI
- routes messages by session
- Prevent cross-session message leaks
#### Deliverable
- Multiple isolated chat rooms working

## Week 4 — Encryption Basics (E2EE v1)
#### Goals
- Add client-side encryption
#### Tasks
- Learn basics of End-to-End Encryption
- Generate encryption keys in client
- Encrypt messages before sending
- Decrypt messages on receive
- Ensure server only sees ciphertext
#### Deliverable
- Messages are encrypted in transit

## Week 5 — Key Exchange & Security
#### Goals
- Make encryption actually usable
#### Tasks
- Implement key exchange (simple version first)
- Decide:
  - Shared key? OR
  - Public/private key system?
- Add optional shared secret input (like a passphrase maybe)
- Prevent unauthorized decryption
#### Deliverable
- Users can securely communicate with shared keys

## Week 6 — Authentication Layer
#### Goals
- Control access to sessions
#### Tasks
- Add UUID + shared secret validation
- Restrict session entry
- Handle invalid credentials
- Improve session lifecycle
#### Deliverable
- Basic access control working

## Week 7 — WireGuard Integration
#### Goals
- Enable cross-network communication
#### Tasks
- Install and configure WireGuard
- Set up two peers (different networks ideally)
- Route WebSocket traffic through tunnel
- Test remote connectivity
#### Deliverable
- Chat works across different networks (assuming wiregaurd is in place)

## Week 8 — Security Analysis
#### Goals
- Think like an attacker
#### Tasks
Analyze:
- MITM attacks
- Packet interception
- Replay attacks
Other:
- Verify encryption effectiveness
- Document weaknesses
- Suggest mitigations
#### Deliverable
- Written security analysis

## Week 9 — Testing & Debugging
#### Goals
- Stabilize system
#### Tasks
Test:
- Multiple users
- Multiple sessions
- Network interruptions
Other:
- Fix bugs
- Improve UI/UX
- Add logging/debug tools
#### Deliverable
- Stable, usable application

## Week 10 — Documentation & Finalization
#### Goals
- Polish and finalize project
#### Tasks
- Finalize architecture diagrams
Write:
- How it works
- Security design
- Tradeoffs
- Record demo (if time)
- Clean up codebase
#### Deliverable
- Complete, presentable project

## Stretch Goals
- Move encryption into Rust (Tauri backend)
- Add peer-to-peer mode (no central server)
- Implement public-key auth
- Add message persistence (encrypted)
- CLI client
