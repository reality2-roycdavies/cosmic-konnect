#![allow(dead_code)]
//! Wi-Fi Direct (P2P) support for Linux
//!
//! Uses wpa_supplicant's D-Bus interface for P2P operations.
//! Requires wpa_supplicant to be running with P2P support.
//!
//! Note: Wi-Fi Direct on Linux requires:
//! - wpa_supplicant with P2P support
//! - A Wi-Fi adapter that supports P2P
//! - Proper configuration in wpa_supplicant.conf

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};
use zbus::{proxy, Connection};

/// Discovered device via Wi-Fi Direct
#[derive(Debug, Clone)]
pub struct P2pDevice {
    pub address: String,
    pub name: String,
    pub device_type: String,
    pub config_methods: u16,
    pub device_capability: u8,
    pub group_capability: u8,
}

/// P2P group information
#[derive(Debug, Clone)]
pub struct P2pGroupInfo {
    pub interface: String,
    pub ssid: String,
    pub role: P2pRole,
    pub frequency: u32,
    pub passphrase: Option<String>,
}

/// P2P role (Group Owner or Client)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum P2pRole {
    GroupOwner,
    Client,
}

/// Events from Wi-Fi Direct
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A P2P device was discovered
    DeviceFound(P2pDevice),
    /// A P2P device was lost
    DeviceLost(String),
    /// P2P group started
    GroupStarted(P2pGroupInfo),
    /// P2P group removed
    GroupFinished,
    /// Connected to a P2P group
    Connected {
        interface: String,
        ip_address: Option<IpAddr>,
    },
    /// Disconnected from P2P group
    Disconnected,
    /// Error occurred
    Error(String),
}

/// Wi-Fi Direct manager for Linux
pub struct WifiDirectManager {
    interface: String,
    event_tx: broadcast::Sender<P2pEvent>,
    discovered_devices: Arc<RwLock<HashMap<String, P2pDevice>>>,
    group_info: Arc<RwLock<Option<P2pGroupInfo>>>,
}

impl WifiDirectManager {
    /// Create a new Wi-Fi Direct manager
    ///
    /// # Arguments
    /// * `interface` - Wi-Fi interface name (e.g., "wlan0")
    pub fn new(interface: &str) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            interface: interface.to_string(),
            event_tx,
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            group_info: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to P2P events
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    /// Check if Wi-Fi Direct is available
    pub async fn is_available(&self) -> bool {
        // Check if wpa_supplicant is running and has P2P support
        if let Ok(output) = Command::new("wpa_cli")
            .args(["-i", &self.interface, "p2p_find", "0"])
            .output()
        {
            if output.status.success() {
                // Stop the find we just started
                let _ = Command::new("wpa_cli")
                    .args(["-i", &self.interface, "p2p_stop_find"])
                    .output();
                return true;
            }
        }
        false
    }

    /// Start P2P device discovery
    pub async fn start_discovery(&self) -> Result<(), P2pError> {
        info!("Starting Wi-Fi Direct discovery on {}", self.interface);

        let output = Command::new("wpa_cli")
            .args(["-i", &self.interface, "p2p_find"])
            .output()
            .map_err(|e| P2pError::Command(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(P2pError::Discovery(stderr.to_string()));
        }

        // Start monitoring for discovered devices
        let interface = self.interface.clone();
        let event_tx = self.event_tx.clone();
        let discovered_devices = self.discovered_devices.clone();

        tokio::spawn(async move {
            monitor_p2p_devices(&interface, &event_tx, &discovered_devices).await;
        });

        Ok(())
    }

    /// Stop P2P discovery
    pub async fn stop_discovery(&self) -> Result<(), P2pError> {
        info!("Stopping Wi-Fi Direct discovery");

        let output = Command::new("wpa_cli")
            .args(["-i", &self.interface, "p2p_stop_find"])
            .output()
            .map_err(|e| P2pError::Command(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to stop P2P discovery: {}", stderr);
        }

        Ok(())
    }

    /// Connect to a P2P device
    ///
    /// # Arguments
    /// * `device_address` - MAC address of the device to connect to
    /// * `go_intent` - Group Owner intent (0-15, higher = more likely to be GO)
    pub async fn connect(&self, device_address: &str, go_intent: u8) -> Result<(), P2pError> {
        info!("Connecting to P2P device: {}", device_address);

        // Use PBC (Push Button Configuration) method
        let output = Command::new("wpa_cli")
            .args([
                "-i",
                &self.interface,
                "p2p_connect",
                device_address,
                "pbc",
                &format!("go_intent={}", go_intent.min(15)),
            ])
            .output()
            .map_err(|e| P2pError::Command(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(P2pError::Connection(stderr.to_string()));
        }

        Ok(())
    }

    /// Create a P2P group (become Group Owner)
    pub async fn create_group(&self) -> Result<(), P2pError> {
        info!("Creating P2P group on {}", self.interface);

        let output = Command::new("wpa_cli")
            .args(["-i", &self.interface, "p2p_group_add"])
            .output()
            .map_err(|e| P2pError::Command(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(P2pError::Group(stderr.to_string()));
        }

        Ok(())
    }

    /// Remove current P2P group
    pub async fn remove_group(&self) -> Result<(), P2pError> {
        info!("Removing P2P group");

        // Get the P2P group interface
        let group_info = self.group_info.read().await;
        let group_interface = group_info
            .as_ref()
            .map(|g| g.interface.clone())
            .unwrap_or_else(|| format!("p2p-{}-0", self.interface));
        drop(group_info);

        let output = Command::new("wpa_cli")
            .args(["-i", &self.interface, "p2p_group_remove", &group_interface])
            .output()
            .map_err(|e| P2pError::Command(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to remove P2P group: {}", stderr);
        }

        *self.group_info.write().await = None;
        let _ = self.event_tx.send(P2pEvent::GroupFinished);

        Ok(())
    }

    /// Get list of discovered P2P devices
    pub async fn get_discovered_devices(&self) -> Vec<P2pDevice> {
        self.discovered_devices.read().await.values().cloned().collect()
    }

    /// Get current group info
    pub async fn get_group_info(&self) -> Option<P2pGroupInfo> {
        self.group_info.read().await.clone()
    }

    /// Get the IP address of the P2P interface
    pub async fn get_p2p_ip_address(&self) -> Option<IpAddr> {
        let group_info = self.group_info.read().await;
        let interface = group_info.as_ref().map(|g| g.interface.clone())?;
        drop(group_info);

        get_interface_ip(&interface)
    }
}

/// Monitor for P2P device discovery events
async fn monitor_p2p_devices(
    interface: &str,
    event_tx: &broadcast::Sender<P2pEvent>,
    discovered_devices: &Arc<RwLock<HashMap<String, P2pDevice>>>,
) {
    loop {
        // Get list of peers
        if let Ok(output) = Command::new("wpa_cli")
            .args(["-i", interface, "p2p_peers"])
            .output()
        {
            if output.status.success() {
                let peers = String::from_utf8_lossy(&output.stdout);
                for addr in peers.lines().filter(|l| !l.is_empty()) {
                    // Get peer info
                    if let Ok(info_output) = Command::new("wpa_cli")
                        .args(["-i", interface, "p2p_peer", addr])
                        .output()
                    {
                        if info_output.status.success() {
                            let info = String::from_utf8_lossy(&info_output.stdout);
                            if let Some(device) = parse_peer_info(addr, &info) {
                                let is_new = {
                                    let mut devices = discovered_devices.write().await;
                                    let was_present = devices.contains_key(&device.address);
                                    devices.insert(device.address.clone(), device.clone());
                                    !was_present
                                };

                                if is_new {
                                    info!("P2P device found: {} ({})", device.name, device.address);
                                    let _ = event_tx.send(P2pEvent::DeviceFound(device));
                                }
                            }
                        }
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Parse P2P peer info from wpa_cli output
fn parse_peer_info(address: &str, info: &str) -> Option<P2pDevice> {
    let mut name = String::new();
    let mut device_type = String::new();
    let mut config_methods = 0u16;
    let mut device_capability = 0u8;
    let mut group_capability = 0u8;

    for line in info.lines() {
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }

        match parts[0] {
            "device_name" => name = parts[1].to_string(),
            "pri_dev_type" => device_type = parts[1].to_string(),
            "config_methods" => config_methods = u16::from_str_radix(parts[1].trim_start_matches("0x"), 16).unwrap_or(0),
            "dev_capab" => device_capability = u8::from_str_radix(parts[1].trim_start_matches("0x"), 16).unwrap_or(0),
            "group_capab" => group_capability = u8::from_str_radix(parts[1].trim_start_matches("0x"), 16).unwrap_or(0),
            _ => {}
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(P2pDevice {
        address: address.to_string(),
        name,
        device_type,
        config_methods,
        device_capability,
        group_capability,
    })
}

/// Get IP address of an interface
fn get_interface_ip(interface: &str) -> Option<IpAddr> {
    let output = Command::new("ip")
        .args(["addr", "show", interface])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip_cidr = parts[1];
                let ip_str = ip_cidr.split('/').next()?;
                return ip_str.parse().ok();
            }
        }
    }

    None
}

/// P2P-related errors
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("Command error: {0}")]
    Command(String),

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Group error: {0}")]
    Group(String),

    #[error("Not available: {0}")]
    NotAvailable(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_peer_info() {
        let info = r#"
device_name=TestDevice
pri_dev_type=1-0050F204-1
config_methods=0x188
dev_capab=0x25
group_capab=0x00
"#;

        let device = parse_peer_info("aa:bb:cc:dd:ee:ff", info);
        assert!(device.is_some());

        let device = device.unwrap();
        assert_eq!(device.name, "TestDevice");
        assert_eq!(device.address, "aa:bb:cc:dd:ee:ff");
    }
}
