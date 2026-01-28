//! D-Bus API for the daemon
//!
//! Exposes the daemon's functionality over the session bus for UI clients.
//!
//! Interface: io.github.reality2_roycdavies.CosmicKonnect
//! Object path: /io/github/reality2_roycdavies/CosmicKonnect

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use zbus::{connection, interface};

use crate::AppState;

/// D-Bus service name
pub const DBUS_NAME: &str = "io.github.reality2_roycdavies.CosmicKonnect";

/// D-Bus object path
pub const DBUS_PATH: &str = "/io/github/reality2_roycdavies/CosmicKonnect";

/// D-Bus service wrapper
pub struct DbusService {
    state: Arc<RwLock<AppState>>,
}

impl DbusService {
    /// Create a new D-Bus service
    pub fn new(state: Arc<RwLock<AppState>>) -> Self {
        Self { state }
    }

    /// Run the D-Bus service
    pub async fn run(&self) -> Result<(), crate::error::DaemonError> {
        info!("Starting D-Bus service: {}", DBUS_NAME);

        let api = CosmicKonnectApi {
            state: self.state.clone(),
        };

        let _connection = connection::Builder::session()?
            .name(DBUS_NAME)?
            .serve_at(DBUS_PATH, api)?
            .build()
            .await?;

        info!("D-Bus service registered at {}", DBUS_PATH);

        // Keep the connection alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }
}

/// The main D-Bus interface implementation
struct CosmicKonnectApi {
    state: Arc<RwLock<AppState>>,
}

#[interface(name = "io.github.reality2_roycdavies.CosmicKonnect")]
impl CosmicKonnectApi {
    /// Get the daemon version
    async fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Get our device ID
    async fn device_id(&self) -> String {
        let state = self.state.read().await;
        state.config.identity.device_id.clone()
    }

    /// Get our device name
    async fn device_name(&self) -> String {
        let state = self.state.read().await;
        state.config.identity.device_name.clone()
    }

    /// Get list of all known devices
    /// Returns array of (device_id, name, device_type, state, paired)
    async fn list_devices(&self) -> Vec<(String, String, String, String, bool)> {
        let state = self.state.read().await;
        state.device_manager
            .get_all_devices()
            .await
            .into_iter()
            .map(|d| (
                d.device_id,
                d.name,
                d.device_type.to_string(),
                format!("{:?}", d.state).to_lowercase(),
                d.paired,
            ))
            .collect()
    }

    /// Get list of paired devices
    async fn list_paired_devices(&self) -> Vec<(String, String, String)> {
        let state = self.state.read().await;
        state.device_manager
            .get_paired_devices()
            .await
            .into_iter()
            .map(|d| (d.device_id, d.name, d.device_type.to_string()))
            .collect()
    }

    /// Get list of connected devices
    async fn list_connected_devices(&self) -> Vec<(String, String)> {
        let state = self.state.read().await;
        state.device_manager
            .get_connected_devices()
            .await
            .into_iter()
            .map(|d| (d.device_id, d.name))
            .collect()
    }

    /// Connect to a device by ID
    async fn connect(&self, device_id: String) -> bool {
        debug!("D-Bus: Connect request for {}", device_id);
        // TODO: Implement connection logic
        false
    }

    /// Disconnect from a device
    async fn disconnect(&self, device_id: String) -> bool {
        debug!("D-Bus: Disconnect request for {}", device_id);
        // TODO: Implement disconnection logic
        false
    }

    /// Request pairing with a device
    async fn request_pairing(&self, device_id: String) -> bool {
        debug!("D-Bus: Pairing request for {}", device_id);
        // TODO: Implement pairing request
        false
    }

    /// Accept a pending pairing request
    async fn accept_pairing(&self, device_id: String) -> bool {
        debug!("D-Bus: Accept pairing for {}", device_id);
        // TODO: Implement accept pairing
        false
    }

    /// Reject a pending pairing request
    async fn reject_pairing(&self, device_id: String) -> bool {
        debug!("D-Bus: Reject pairing for {}", device_id);
        // TODO: Implement reject pairing
        false
    }

    /// Unpair a device
    async fn unpair(&self, device_id: String) -> bool {
        debug!("D-Bus: Unpair request for {}", device_id);
        // TODO: Implement unpairing
        false
    }

    /// Send clipboard content to a device
    async fn send_clipboard(&self, device_id: String, content: String) -> bool {
        debug!("D-Bus: Send clipboard to {} ({} bytes)", device_id, content.len());
        // TODO: Implement clipboard send
        false
    }

    /// Broadcast clipboard to all connected devices
    async fn broadcast_clipboard(&self, content: String) -> u32 {
        debug!("D-Bus: Broadcast clipboard ({} bytes)", content.len());
        // TODO: Implement clipboard broadcast
        0
    }

    /// Send a ping to a device
    async fn ping(&self, device_id: String) -> bool {
        debug!("D-Bus: Ping {}", device_id);
        // TODO: Implement ping
        false
    }

    /// Ring/find a device
    async fn find_device(&self, device_id: String) -> bool {
        debug!("D-Bus: Find device {}", device_id);
        // TODO: Implement find device
        false
    }

    /// Share a URL with a device
    async fn share_url(&self, device_id: String, url: String) -> bool {
        debug!("D-Bus: Share URL with {}: {}", device_id, url);
        // TODO: Implement URL sharing
        false
    }

    /// Share text with a device
    async fn share_text(&self, device_id: String, text: String) -> bool {
        debug!("D-Bus: Share text with {} ({} bytes)", device_id, text.len());
        // TODO: Implement text sharing
        false
    }

    /// Send a file to a device
    async fn send_file(&self, device_id: String, file_path: String) -> bool {
        debug!("D-Bus: Send file to {}: {}", device_id, file_path);
        // TODO: Implement file send
        false
    }

    /// Enable or disable BLE discovery
    async fn set_ble_enabled(&self, enabled: bool) {
        debug!("D-Bus: Set BLE enabled: {}", enabled);
        let mut state = self.state.write().await;
        state.config.ble_enabled = enabled;
    }

    /// Check if BLE discovery is enabled
    async fn is_ble_enabled(&self) -> bool {
        self.state.read().await.config.ble_enabled
    }

    /// Enable or disable mDNS discovery
    async fn set_mdns_enabled(&self, enabled: bool) {
        debug!("D-Bus: Set mDNS enabled: {}", enabled);
        let mut state = self.state.write().await;
        state.config.mdns_enabled = enabled;
    }

    /// Check if mDNS discovery is enabled
    async fn is_mdns_enabled(&self) -> bool {
        self.state.read().await.config.mdns_enabled
    }

    // === Signals ===

    /// Signal emitted when a device is discovered
    #[zbus(signal)]
    async fn device_discovered(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        name: &str,
        device_type: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when a device is lost
    #[zbus(signal)]
    async fn device_lost(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when connected to a device
    #[zbus(signal)]
    async fn device_connected(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        name: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when disconnected from a device
    #[zbus(signal)]
    async fn device_disconnected(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when pairing is requested
    #[zbus(signal)]
    async fn pairing_requested(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        name: &str,
        verification_code: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when pairing is complete
    #[zbus(signal)]
    async fn device_paired(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        name: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when clipboard is received
    #[zbus(signal)]
    async fn clipboard_received(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        content: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when a notification is received
    #[zbus(signal)]
    async fn notification_received(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        app_name: &str,
        title: &str,
        text: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when a file offer is received
    #[zbus(signal)]
    async fn file_offer_received(
        ctx: &zbus::SignalContext<'_>,
        device_id: &str,
        transfer_id: &str,
        filename: &str,
        size: u64,
    ) -> zbus::Result<()>;
}
