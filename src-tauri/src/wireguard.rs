use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const INTERFACE_NAME: &str = "wiretalk-wg";
pub const DEFAULT_LISTEN_PORT: u16 = 51820;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    /// The public key for this node (safe to share)
    pub public_key: String,
    /// The tunnel IP assigned to this node (e.g. "10.10.10.1/24")
    pub interface_ip: String,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeer>,
    /// Private key is stored separately and never sent to the frontend
    #[serde(skip)]
    pub private_key: String,
}

/// A compact config a peer shares with others so they can be added automatically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareablePeerConfig {
    pub public_key: String,
    /// Tunnel-side IP of the peer (without prefix length, e.g. "10.10.10.2")
    pub tunnel_ip: String,
    /// Optional external endpoint the peer can be reached at, e.g. "203.0.113.5:51820"
    pub endpoint: Option<String>,
    pub listen_port: u16,
    /// libp2p peer ID — included so the recipient can auto-dial the P2P layer
    pub peer_id: Option<String>,
    /// TCP port the libp2p stack is listening on inside the tunnel
    pub libp2p_port: Option<u16>,
}

#[derive(Debug)]
pub struct WireGuardManager {
    config: Option<WireGuardConfig>,
    config_path: PathBuf,
}

impl WireGuardManager {
    pub fn new() -> Self {
        let config_path = std::env::temp_dir().join("wiretalk-wg.conf");
        Self {
            config: None,
            config_path,
        }
    }

    // ─── Dependency checks ──────────────────────────────────────────────────

    /// Returns an error if `wg` or `wg-quick` are not found in PATH.
    pub fn check_dependencies() -> Result<()> {
        let wg = Command::new("which").arg("wg").output()?;
        if !wg.status.success() {
            return Err(anyhow!(
                "WireGuard tools (wg) not found. Install wireguard-tools: sudo apt install wireguard-tools"
            ));
        }
        let wg_quick = Command::new("which").arg("wg-quick").output()?;
        if !wg_quick.status.success() {
            return Err(anyhow!(
                "wg-quick not found. Install wireguard-tools: sudo apt install wireguard-tools"
            ));
        }
        Ok(())
    }

    // ─── Key generation ─────────────────────────────────────────────────────

    /// Generate a new WireGuard key pair using the system `wg` binary.
    /// Returns `(private_key, public_key)`.
    pub fn generate_keypair() -> Result<(String, String)> {
        // Generate private key
        let priv_out = Command::new("wg")
            .arg("genkey")
            .output()
            .map_err(|e| anyhow!("Failed to run `wg genkey`: {}", e))?;

        if !priv_out.status.success() {
            return Err(anyhow!("`wg genkey` failed"));
        }

        let private_key = String::from_utf8(priv_out.stdout)
            .map_err(|e| anyhow!("Invalid genkey output: {}", e))?
            .trim()
            .to_string();

        // Derive public key
        let mut child = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to run `wg pubkey`: {}", e))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(private_key.as_bytes())
                .map_err(|e| anyhow!("Failed to write to wg pubkey stdin: {}", e))?;
        }

        let pub_out = child
            .wait_with_output()
            .map_err(|e| anyhow!("`wg pubkey` failed: {}", e))?;

        let public_key = String::from_utf8(pub_out.stdout)
            .map_err(|e| anyhow!("Invalid pubkey output: {}", e))?
            .trim()
            .to_string();

        Ok((private_key, public_key))
    }

    // ─── Setup / teardown ───────────────────────────────────────────────────

    /// Generate keys, write the config file, and bring up the WireGuard interface.
    /// `interface_ip` should be in CIDR notation, e.g. `"10.10.10.1/24"`.
    pub fn setup(&mut self, interface_ip: String, listen_port: u16) -> Result<()> {
        Self::check_dependencies()?;

        // Recover from stale interface state left by previous runs.
        if self.is_active() {
            self.teardown()?;
        }

        let (private_key, public_key) = Self::generate_keypair()?;

        let config = WireGuardConfig {
            private_key: private_key.clone(),
            public_key,
            interface_ip,
            listen_port,
            peers: Vec::new(),
        };

        Self::write_config_file(&self.config_path, &config)?;
        self.config = Some(config);

        self.bring_up()?;

        Ok(())
    }

    /// Bring down the WireGuard interface and clean up.
    pub fn teardown(&mut self) -> Result<()> {
        if self.config_path.exists() {
            let output = self
                .privileged_command(&["wg-quick", "down", &self.config_path.to_string_lossy()])
                .map_err(|e| anyhow!("Failed to run wg-quick down: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("wg-quick down failed, will try fallback cleanup: {}", stderr);
            }

            let _ = std::fs::remove_file(&self.config_path);
        }

        // Fallback: remove stale interface even if config file is missing or wg-quick failed.
        if self.is_active() {
            let output = self
                .privileged_command(&["ip", "link", "delete", INTERFACE_NAME])
                .map_err(|e| anyhow!("Failed to delete stale interface: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "Failed to delete stale interface {}: {}",
                    INTERFACE_NAME,
                    stderr
                ));
            }
        }

        self.config = None;
        Ok(())
    }

    // ─── Peer management ────────────────────────────────────────────────────

    /// Dynamically add a peer to the running interface and persist it to the config file.
    /// `allowed_ips` is the peer's tunnel IP in CIDR, e.g. `"10.10.10.2/32"`.
    pub fn add_peer(
        &mut self,
        public_key: String,
        allowed_ips: String,
        endpoint: Option<String>,
    ) -> Result<()> {
        // Validate the interface is up
        if !self.is_active() {
            return Err(anyhow!(
                "WireGuard interface is not up. Run Setup first."
            ));
        }

        // Build the `wg set` arguments
        let mut args: Vec<String> = vec![
            "wg".to_string(),
            "set".to_string(),
            INTERFACE_NAME.to_string(),
            "peer".to_string(),
            public_key.clone(),
            "allowed-ips".to_string(),
            allowed_ips.clone(),
        ];
        if let Some(ep) = &endpoint {
            args.push("endpoint".to_string());
            args.push(ep.clone());
        }

        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self
            .privileged_command(&arg_refs)
            .map_err(|e| anyhow!("Failed to run `wg set` for peer: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("`wg set peer` failed: {}", stderr));
        }

        // Persist to config
        if let Some(config) = &mut self.config {
            // Replace if the public key already exists, otherwise push
            if let Some(existing) = config.peers.iter_mut().find(|p| p.public_key == public_key) {
                existing.allowed_ips = allowed_ips;
                existing.endpoint = endpoint;
            } else {
                config.peers.push(WireGuardPeer {
                    public_key,
                    allowed_ips,
                    endpoint,
                });
            }
        }
        // Write config snapshot after releasing mutable borrow
        let snapshot = self.config.clone();
        if let Some(config) = &snapshot {
            Self::write_config_file(&self.config_path, config)?;
        }

        Ok(())
    }

    /// Remove a peer by public key from the running interface and config.
    pub fn remove_peer(&mut self, public_key: &str) -> Result<()> {
        if !self.is_active() {
            return Err(anyhow!("WireGuard interface is not active."));
        }

        let output = self
            .privileged_command(&[
                "wg",
                "set",
                INTERFACE_NAME,
                "peer",
                public_key,
                "remove",
            ])
            .map_err(|e| anyhow!("Failed to run `wg set` remove: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("`wg peer remove` failed: {}", stderr));
        }

        if let Some(config) = &mut self.config {
            config.peers.retain(|p| p.public_key != public_key);
        }
        let snapshot = self.config.clone();
        if let Some(config) = &snapshot {
            Self::write_config_file(&self.config_path, config)?;
        }

        Ok(())
    }

    // ─── Info ────────────────────────────────────────────────────────────────

    /// Return the public configuration (no private key) for this node.
    pub fn get_config(&self) -> Option<WireGuardConfig> {
        self.config.clone()
    }

    /// Build the shareable peer config.
    /// `endpoint` is the caller's external IP:port (optional — they may be behind NAT).
    /// `peer_id` and `libp2p_port` are included so recipients can auto-dial the P2P layer.
    pub fn get_shareable_config(
        &self,
        endpoint: Option<String>,
        peer_id: Option<String>,
        libp2p_port: Option<u16>,
    ) -> Option<ShareablePeerConfig> {
        self.config.as_ref().map(|c| {
            let tunnel_ip = c
                .interface_ip
                .split('/')
                .next()
                .unwrap_or(&c.interface_ip)
                .to_string();
            ShareablePeerConfig {
                public_key: c.public_key.clone(),
                tunnel_ip,
                endpoint,
                listen_port: c.listen_port,
                peer_id,
                libp2p_port,
            }
        })
    }

    /// Check whether the WireGuard interface currently exists in the kernel.
    pub fn is_active(&self) -> bool {
        Command::new("ip")
            .args(["link", "show", INTERFACE_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Return the WireGuard interface status from `wg show`.
    pub fn get_status(&self) -> Option<String> {
        if !self.is_active() {
            return None;
        }
        Command::new("wg")
            .args(["show", INTERFACE_NAME])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    fn write_config_file(config_path: &PathBuf, config: &WireGuardConfig) -> Result<()> {
        let mut contents = format!(
            "[Interface]\nAddress = {}\nListenPort = {}\nPrivateKey = {}\n",
            config.interface_ip, config.listen_port, config.private_key
        );

        for peer in &config.peers {
            contents.push_str("\n[Peer]\n");
            contents.push_str(&format!("PublicKey = {}\n", peer.public_key));
            contents.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
            if let Some(ep) = &peer.endpoint {
                contents.push_str(&format!("Endpoint = {}\n", ep));
            }
            // Keep alive helps with NAT traversal
            contents.push_str("PersistentKeepalive = 25\n");
        }

        fs::write(config_path, contents)
            .map_err(|e| anyhow!("Failed to write WireGuard config to {:?}: {}", config_path, e))?;

        // Avoid wg-quick warning about world-readable config files.
        fs::set_permissions(config_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow!("Failed to set permissions on {:?}: {}", config_path, e))
    }

    fn bring_up(&self) -> Result<()> {
        let output = self
            .privileged_command(&["wg-quick", "up", &self.config_path.to_string_lossy()])
            .map_err(|e| anyhow!("Failed to run wg-quick up: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("wg-quick up failed: {}", stderr));
        }

        Ok(())
    }

    /// Run a command with privilege escalation.
    /// Tries `pkexec` (graphical sudo) first; falls back to `sudo`.
    fn privileged_command(&self, args: &[&str]) -> std::io::Result<std::process::Output> {
        let pkexec_result = Command::new("pkexec").args(args).output();

        match pkexec_result {
            Ok(output) if output.status.success() => return Ok(output),
            // pkexec succeeded but the command itself failed — return that failure
            Ok(output) if !output.status.success() => {
                // If pkexec error indicates it's not available, fall through to sudo
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("pkexec")
                    && !stderr.contains("not found")
                    && !stderr.contains("No such file")
                {
                    return Ok(output);
                }
            }
            _ => {}
        }

        // Fall back to sudo
        Command::new("sudo").args(args).output()
    }
}
