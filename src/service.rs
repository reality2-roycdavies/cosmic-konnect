//! D-Bus Service for cosmic-konnect
//!
//! Exposes device information and controls via D-Bus for GUI communication.
//!
//! ## D-Bus Interface
//!
//! Service name: `io.github.cosmickonnect.Service1`
//! Object path: `/io/github/cosmickonnect/Service1`
//!
//! ### Methods
//! - `GetDevices()` - Get list of connected devices
//! - `PingDevice(device_id: String)` - Send ping to a device
//! - `GetAutoAcceptPairing()` - Check if auto-accept is enabled
//! - `SetAutoAcceptPairing(enabled: bool)` - Enable/disable auto-accept
//!
//! ### Signals
//! - `DevicesChanged()` - Emitted when device list changes
//! - `DeviceConnected(device_id, name)` - Emitted when device connects
//! - `DeviceDisconnected(device_id)` - Emitted when device disconnects

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::{interface, object_server::SignalEmitter};

use crate::connection::DeviceSenders;
use crate::protocol::NetworkPacket;

/// D-Bus service name
pub const SERVICE_NAME: &str = "io.github.cosmickonnect.Service1";

/// D-Bus object path
pub const OBJECT_PATH: &str = "/io/github/cosmickonnect/Service1";

/// Device information (D-Bus serializable)
#[derive(Debug, Clone, zbus::zvariant::Type, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub battery: i32, // -1 means unknown
    pub is_paired: bool,
}

/// Shared service state between tray and D-Bus service
pub struct ServiceState {
    pub devices: HashMap<String, DeviceInfo>,
    pub auto_accept_pairing: bool,
    pub status_message: String,
    pub own_device_id: String,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            devices: HashMap::new(),
            auto_accept_pairing: true,
            status_message: "Ready".to_string(),
            own_device_id: String::new(),
        }
    }
}

impl ServiceState {
    pub fn add_device(&mut self, id: String, name: String, device_type: String) {
        self.devices.insert(
            id.clone(),
            DeviceInfo {
                id,
                name,
                device_type,
                battery: -1,
                is_paired: false,
            },
        );
    }

    pub fn remove_device(&mut self, id: &str) {
        self.devices.remove(id);
    }

    pub fn update_battery(&mut self, id: &str, battery: i32) {
        if let Some(device) = self.devices.get_mut(id) {
            device.battery = battery;
        }
    }

    pub fn set_paired(&mut self, id: &str, paired: bool) {
        if let Some(device) = self.devices.get_mut(id) {
            device.is_paired = paired;
        }
    }
}

/// The D-Bus interface implementation
pub struct KonnectService {
    state: Arc<RwLock<ServiceState>>,
    device_senders: DeviceSenders,
}

impl KonnectService {
    pub fn new(state: Arc<RwLock<ServiceState>>, device_senders: DeviceSenders) -> Self {
        Self { state, device_senders }
    }
}

#[interface(name = "io.github.cosmickonnect.Service1")]
impl KonnectService {
    /// Get list of connected devices (excluding self)
    async fn get_devices(&self) -> Vec<DeviceInfo> {
        let state = self.state.read().await;
        state.devices.values()
            .filter(|d| d.id != state.own_device_id)
            .cloned()
            .collect()
    }

    /// Get a specific device by ID (returns empty device if not found)
    async fn get_device(&self, device_id: String) -> DeviceInfo {
        let state = self.state.read().await;
        state.devices.get(&device_id).cloned().unwrap_or_else(|| DeviceInfo {
            id: String::new(),
            name: String::new(),
            device_type: String::new(),
            battery: -1,
            is_paired: false,
        })
    }

    /// Get the number of connected devices
    async fn get_device_count(&self) -> u32 {
        let state = self.state.read().await;
        state.devices.len() as u32
    }

    /// Send ping to a device
    async fn ping_device(&self, device_id: String) -> zbus::fdo::Result<()> {
        // Check if device exists
        {
            let state = self.state.read().await;
            if !state.devices.contains_key(&device_id) {
                return Err(zbus::fdo::Error::Failed(format!(
                    "Device {} not found",
                    device_id
                )));
            }
        }

        // Send the ping packet
        let ping = NetworkPacket::new("kdeconnect.ping", serde_json::json!({}));
        let senders = self.device_senders.read().await;
        if let Some(sender) = senders.get(&device_id) {
            sender.send(ping).await.map_err(|_| {
                zbus::fdo::Error::Failed(format!("Failed to send ping to {}", device_id))
            })?;

            // Update status
            let mut state = self.state.write().await;
            state.status_message = format!("Ping sent to {}", device_id);
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(format!(
                "Device {} not connected",
                device_id
            )))
        }
    }

    /// Ring a device to find it
    async fn find_phone(&self, device_id: String) -> zbus::fdo::Result<()> {
        // Check if device exists
        {
            let state = self.state.read().await;
            if !state.devices.contains_key(&device_id) {
                return Err(zbus::fdo::Error::Failed(format!(
                    "Device {} not found",
                    device_id
                )));
            }
        }

        // Send the find my phone packet
        let packet = NetworkPacket::new("kdeconnect.findmyphone.request", serde_json::json!({}));
        let senders = self.device_senders.read().await;
        if let Some(sender) = senders.get(&device_id) {
            sender.send(packet).await.map_err(|_| {
                zbus::fdo::Error::Failed(format!("Failed to send find request to {}", device_id))
            })?;

            // Update status
            let mut state = self.state.write().await;
            state.status_message = format!("Ringing {}", device_id);
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(format!(
                "Device {} not connected",
                device_id
            )))
        }
    }

    /// Check if auto-accept pairing is enabled
    async fn get_auto_accept_pairing(&self) -> bool {
        let state = self.state.read().await;
        state.auto_accept_pairing
    }

    /// Enable or disable auto-accept pairing
    async fn set_auto_accept_pairing(&self, enabled: bool) -> zbus::fdo::Result<()> {
        let mut state = self.state.write().await;
        state.auto_accept_pairing = enabled;
        Ok(())
    }

    /// Get the current status message
    async fn get_status(&self) -> String {
        let state = self.state.read().await;
        state.status_message.clone()
    }

    // === Signals ===

    /// Signal emitted when device list changes
    #[zbus(signal)]
    pub async fn devices_changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    /// Signal emitted when a device connects
    #[zbus(signal)]
    pub async fn device_connected(
        emitter: &SignalEmitter<'_>,
        device_id: &str,
        name: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when a device disconnects
    #[zbus(signal)]
    pub async fn device_disconnected(emitter: &SignalEmitter<'_>, device_id: &str) -> zbus::Result<()>;

    /// Signal emitted when battery status updates
    #[zbus(signal)]
    pub async fn battery_updated(
        emitter: &SignalEmitter<'_>,
        device_id: &str,
        battery: i32,
    ) -> zbus::Result<()>;
}
