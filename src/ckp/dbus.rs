//! D-Bus interface for CKP service
//!
//! Exposes the CKP service over D-Bus for integration with
//! system tray, GUI, and other applications.
//!
//! Uses the same interface as the legacy KDE Connect service for GUI compatibility.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use zbus::{interface, Connection};

use super::message::DeviceType;
use super::service::{CkpServiceCommand, DeviceState};
use crate::service::DeviceInfo;

/// D-Bus service name (same as legacy for GUI compatibility)
pub const DBUS_SERVICE_NAME: &str = "io.github.cosmickonnect.Service1";

/// D-Bus object path (same as legacy for GUI compatibility)
pub const DBUS_OBJECT_PATH: &str = "/io/github/cosmickonnect/Service1";

/// D-Bus interface for CKP (compatible with GUI)
pub struct CkpDbusService {
    command_tx: mpsc::Sender<CkpServiceCommand>,
    devices: Arc<RwLock<HashMap<String, DeviceState>>>,
    device_id: String,
    device_name: String,
    auto_accept_pairing: Arc<RwLock<bool>>,
    status_message: Arc<RwLock<String>>,
}

impl CkpDbusService {
    pub fn new(
        command_tx: mpsc::Sender<CkpServiceCommand>,
        devices: Arc<RwLock<HashMap<String, DeviceState>>>,
        device_id: String,
        device_name: String,
    ) -> Self {
        Self {
            command_tx,
            devices,
            device_id,
            device_name,
            auto_accept_pairing: Arc::new(RwLock::new(true)),
            status_message: Arc::new(RwLock::new("Ready".to_string())),
        }
    }

    /// Update the status message
    pub async fn set_status(&self, message: String) {
        *self.status_message.write().await = message;
    }
}

/// Use the same interface name as the legacy service for GUI compatibility
#[interface(name = "io.github.cosmickonnect.Service1")]
impl CkpDbusService {
    /// Get this device's ID
    #[zbus(property)]
    async fn device_id(&self) -> String {
        self.device_id.clone()
    }

    /// Get this device's name
    #[zbus(property)]
    async fn device_name(&self) -> String {
        self.device_name.clone()
    }

    // === Methods expected by GUI (matching legacy service) ===

    /// Get list of connected devices (GUI-compatible)
    async fn get_devices(&self) -> Vec<DeviceInfo> {
        let devices = self.devices.read().await;
        devices
            .values()
            .filter(|d| d.connected && d.device_id != self.device_id)  // Exclude self, only connected
            .map(|d| DeviceInfo {
                id: d.device_id.clone(),
                name: d.name.clone(),
                device_type: format!("{:?}", d.device_type).to_lowercase(),
                battery: -1,  // CKP doesn't have battery info yet
                is_paired: d.paired,
            })
            .collect()
    }

    /// Get a specific device by ID (returns empty device if not found)
    async fn get_device(&self, device_id: String) -> DeviceInfo {
        let devices = self.devices.read().await;
        devices.get(&device_id)
            .map(|d| DeviceInfo {
                id: d.device_id.clone(),
                name: d.name.clone(),
                device_type: format!("{:?}", d.device_type).to_lowercase(),
                battery: -1,
                is_paired: d.paired,
            })
            .unwrap_or_else(|| DeviceInfo {
                id: String::new(),
                name: String::new(),
                device_type: String::new(),
                battery: -1,
                is_paired: false,
            })
    }

    /// Get the number of connected devices
    async fn get_device_count(&self) -> u32 {
        let devices = self.devices.read().await;
        devices.values().filter(|d| d.connected && d.device_id != self.device_id).count() as u32
    }

    /// Send ping to a device (GUI-compatible name)
    async fn ping_device(&self, device_id: String) -> zbus::fdo::Result<()> {
        self.command_tx
            .send(CkpServiceCommand::SendPing {
                device_id: device_id.clone(),
                message: Some("Ping from Cosmic Konnect".to_string())
            })
            .await
            .map_err(|_| zbus::fdo::Error::Failed(format!("Failed to ping {}", device_id)))?;
        Ok(())
    }

    /// Ring a device to find it (GUI-compatible name)
    async fn find_phone(&self, device_id: String) -> zbus::fdo::Result<()> {
        self.command_tx
            .send(CkpServiceCommand::FindDevice { device_id: device_id.clone() })
            .await
            .map_err(|_| zbus::fdo::Error::Failed(format!("Failed to find {}", device_id)))?;
        Ok(())
    }

    /// Check if auto-accept pairing is enabled
    async fn get_auto_accept_pairing(&self) -> bool {
        *self.auto_accept_pairing.read().await
    }

    /// Enable or disable auto-accept pairing
    async fn set_auto_accept_pairing(&self, enabled: bool) -> zbus::fdo::Result<()> {
        *self.auto_accept_pairing.write().await = enabled;
        Ok(())
    }

    /// Get the current status message
    async fn get_status(&self) -> String {
        self.status_message.read().await.clone()
    }

    // === Additional CKP-specific methods ===

    /// Get list of all discovered devices as JSON
    async fn get_all_devices(&self) -> String {
        let devices = self.devices.read().await;
        let list: Vec<LocalDeviceInfo> = devices
            .values()
            .filter(|d| d.device_id != self.device_id)  // Exclude self
            .map(|d| LocalDeviceInfo {
                device_id: d.device_id.clone(),
                name: d.name.clone(),
                device_type: format!("{:?}", d.device_type).to_lowercase(),
                paired: d.paired,
                connected: d.connected,
            })
            .collect();
        serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
    }

    /// Connect to a device by ID
    async fn connect(&self, device_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::Connect { device_id })
            .await
            .is_ok()
    }

    /// Disconnect from a device by ID
    async fn disconnect(&self, device_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::Disconnect { device_id })
            .await
            .is_ok()
    }

    /// Request pairing with a device
    async fn request_pairing(&self, device_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::RequestPairing { device_id })
            .await
            .is_ok()
    }

    /// Accept a pairing request
    async fn accept_pairing(&self, device_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::AcceptPairing { device_id })
            .await
            .is_ok()
    }

    /// Reject a pairing request
    async fn reject_pairing(&self, device_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::RejectPairing { device_id })
            .await
            .is_ok()
    }

    /// Send a ping to a device with custom message
    async fn ping(&self, device_id: String, message: String) -> bool {
        let msg = if message.is_empty() { None } else { Some(message) };
        self.command_tx
            .send(CkpServiceCommand::SendPing { device_id, message: msg })
            .await
            .is_ok()
    }

    /// Send clipboard content to a device
    async fn send_clipboard(&self, device_id: String, content: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::SendClipboard { device_id, content })
            .await
            .is_ok()
    }

    /// Find device (ring phone) - CKP variant
    async fn find_device(&self, device_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::FindDevice { device_id })
            .await
            .is_ok()
    }

    /// Share a URL with a device
    async fn share_url(&self, device_id: String, url: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::ShareUrl { device_id, url })
            .await
            .is_ok()
    }

    /// Share text with a device
    async fn share_text(&self, device_id: String, text: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::ShareText { device_id, text })
            .await
            .is_ok()
    }

    /// Dismiss a notification
    async fn dismiss_notification(&self, device_id: String, notification_id: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::DismissNotification { device_id, notification_id })
            .await
            .is_ok()
    }

    /// Send a file to a device
    async fn send_file(&self, device_id: String, file_path: String) -> bool {
        self.command_tx
            .send(CkpServiceCommand::SendFile {
                device_id,
                path: file_path.into(),
            })
            .await
            .is_ok()
    }

    // === Signals (matching legacy service) ===

    #[zbus(signal)]
    pub async fn devices_changed(signal_ctxt: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn device_connected(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn device_disconnected(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn battery_updated(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        battery: i32,
    ) -> zbus::Result<()>;

    // === Additional CKP-specific signals ===

    #[zbus(signal)]
    pub async fn device_discovered(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        name: &str,
        device_type: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn device_lost(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn pairing_requested(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        name: &str,
        verification_code: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn device_paired(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn ping_received(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        message: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn clipboard_received(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        content: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn notification_received(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        notification_json: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn file_offered(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        transfer_id: &str,
        filename: &str,
        size: u64,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn find_device_received(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn url_received(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        url: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn text_received(
        signal_ctxt: &zbus::object_server::SignalEmitter<'_>,
        device_id: &str,
        text: &str,
    ) -> zbus::Result<()>;
}

/// Device info for JSON serialization (local use)
#[derive(serde::Serialize)]
struct LocalDeviceInfo {
    device_id: String,
    name: String,
    device_type: String,
    paired: bool,
    connected: bool,
}
