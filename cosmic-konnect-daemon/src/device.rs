//! Device management
//!
//! Tracks discovered and paired devices, manages device state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::DeviceType;
use crate::error::DaemonError;

/// Device state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    /// Device has been discovered but not yet connected
    #[default]
    Discovered,
    /// Currently connecting
    Connecting,
    /// Connected and active
    Connected,
    /// Was connected, now disconnected
    Disconnected,
}

/// A known device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique device identifier
    pub device_id: String,

    /// Human-readable device name
    pub name: String,

    /// Device type
    pub device_type: DeviceType,

    /// Current state
    #[serde(skip)]
    pub state: DeviceState,

    /// Known IP addresses
    #[serde(skip)]
    pub addresses: Vec<IpAddr>,

    /// TCP port for connections
    pub tcp_port: u16,

    /// Whether this device is paired
    pub paired: bool,

    /// Pairing key (hex encoded) if paired
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_key: Option<String>,

    /// When the device was first seen (Unix timestamp)
    pub first_seen: u64,

    /// When the device was last seen (Unix timestamp)
    #[serde(skip)]
    pub last_seen: u64,

    /// When the device was paired (if paired)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paired_at: Option<u64>,
}

impl Device {
    /// Create a new discovered device
    pub fn new_discovered(
        device_id: String,
        name: String,
        device_type: DeviceType,
        addresses: Vec<IpAddr>,
        tcp_port: u16,
    ) -> Self {
        let now = now_unix();
        Self {
            device_id,
            name,
            device_type,
            state: DeviceState::Discovered,
            addresses,
            tcp_port,
            paired: false,
            pairing_key: None,
            first_seen: now,
            last_seen: now,
            paired_at: None,
        }
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = now_unix();
    }

    /// Check if device is currently reachable
    pub fn is_reachable(&self) -> bool {
        matches!(self.state, DeviceState::Connected | DeviceState::Discovered)
    }
}

/// Device manager handles tracking all known devices
pub struct DeviceManager {
    /// All known devices by ID
    devices: Arc<RwLock<HashMap<String, Device>>>,
}

impl DeviceManager {
    /// Create a new device manager
    pub fn new() -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a clone of the devices map for sharing
    pub fn devices_ref(&self) -> Arc<RwLock<HashMap<String, Device>>> {
        self.devices.clone()
    }

    /// Add or update a discovered device
    pub async fn device_discovered(
        &self,
        device_id: String,
        name: String,
        device_type: DeviceType,
        addresses: Vec<IpAddr>,
        tcp_port: u16,
    ) -> bool {
        let mut devices = self.devices.write().await;

        if let Some(existing) = devices.get_mut(&device_id) {
            // Update existing device
            existing.name = name;
            existing.addresses = addresses;
            existing.tcp_port = tcp_port;
            existing.touch();

            if existing.state == DeviceState::Disconnected {
                existing.state = DeviceState::Discovered;
            }

            debug!("Updated device: {} ({})", existing.name, device_id);
            false // Not new
        } else {
            // New device
            let device = Device::new_discovered(device_id.clone(), name.clone(), device_type, addresses, tcp_port);
            info!("Discovered new device: {} ({})", name, device_id);
            devices.insert(device_id, device);
            true // Is new
        }
    }

    /// Mark device as connected
    pub async fn device_connected(&self, device_id: &str) {
        let mut devices = self.devices.write().await;
        if let Some(device) = devices.get_mut(device_id) {
            device.state = DeviceState::Connected;
            device.touch();
            info!("Device connected: {} ({})", device.name, device_id);
        }
    }

    /// Mark device as disconnected
    pub async fn device_disconnected(&self, device_id: &str) {
        let mut devices = self.devices.write().await;
        if let Some(device) = devices.get_mut(device_id) {
            device.state = DeviceState::Disconnected;
            info!("Device disconnected: {} ({})", device.name, device_id);
        }
    }

    /// Mark device as paired
    pub async fn device_paired(&self, device_id: &str, pairing_key: [u8; 32]) {
        let mut devices = self.devices.write().await;
        if let Some(device) = devices.get_mut(device_id) {
            device.paired = true;
            device.pairing_key = Some(hex::encode(pairing_key));
            device.paired_at = Some(now_unix());
            info!("Device paired: {} ({})", device.name, device_id);
        }
    }

    /// Get a device by ID
    pub async fn get_device(&self, device_id: &str) -> Option<Device> {
        self.devices.read().await.get(device_id).cloned()
    }

    /// Get all devices
    pub async fn get_all_devices(&self) -> Vec<Device> {
        self.devices.read().await.values().cloned().collect()
    }

    /// Get all paired devices
    pub async fn get_paired_devices(&self) -> Vec<Device> {
        self.devices
            .read()
            .await
            .values()
            .filter(|d| d.paired)
            .cloned()
            .collect()
    }

    /// Get all connected devices
    pub async fn get_connected_devices(&self) -> Vec<Device> {
        self.devices
            .read()
            .await
            .values()
            .filter(|d| d.state == DeviceState::Connected)
            .cloned()
            .collect()
    }

    /// Load paired devices from storage
    pub async fn load_paired_devices(&self, data_dir: &std::path::Path) -> Result<(), DaemonError> {
        let paired_file = data_dir.join("paired_devices.json");

        if !paired_file.exists() {
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&paired_file).await?;
        let stored: Vec<Device> = serde_json::from_str(&content)?;

        let mut devices = self.devices.write().await;
        for device in stored {
            if device.paired {
                info!("Loaded paired device: {} ({})", device.name, device.device_id);
                devices.insert(device.device_id.clone(), device);
            }
        }

        Ok(())
    }

    /// Save paired devices to storage
    pub async fn save_paired_devices(&self, data_dir: &std::path::Path) -> Result<(), DaemonError> {
        let paired_file = data_dir.join("paired_devices.json");

        let paired: Vec<Device> = self.get_paired_devices().await;
        let content = serde_json::to_string_pretty(&paired)?;

        tokio::fs::create_dir_all(data_dir).await?;
        tokio::fs::write(&paired_file, content).await?;

        debug!("Saved {} paired devices", paired.len());
        Ok(())
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current Unix timestamp
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_device_discovery() {
        let manager = DeviceManager::new();

        let is_new = manager.device_discovered(
            "test_device".to_string(),
            "Test Device".to_string(),
            DeviceType::Phone,
            vec!["192.168.1.100".parse().unwrap()],
            51716,
        ).await;

        assert!(is_new);

        let device = manager.get_device("test_device").await.unwrap();
        assert_eq!(device.name, "Test Device");
        assert_eq!(device.state, DeviceState::Discovered);
    }
}
