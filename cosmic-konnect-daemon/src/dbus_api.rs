//! D-Bus API for the daemon
//!
//! Exposes the daemon's functionality over the session bus for UI clients.
//!
//! Interface: io.github.reality2_roycdavies.CosmicKonnect
//! Object path: /io/github/reality2_roycdavies/CosmicKonnect

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zbus::{connection, interface};

use crate::AppState;
use crate::protocol::connection::ConnectionManager;
use crate::protocol::message::*;

/// D-Bus service name
pub const DBUS_NAME: &str = "io.github.reality2_roycdavies.CosmicKonnect";

/// D-Bus object path
pub const DBUS_PATH: &str = "/io/github/reality2_roycdavies/CosmicKonnect";

/// D-Bus service wrapper
pub struct DbusService {
    state: Arc<RwLock<AppState>>,
    connection_manager: Arc<ConnectionManager>,
}

impl DbusService {
    /// Create a new D-Bus service
    pub fn new(state: Arc<RwLock<AppState>>, connection_manager: Arc<ConnectionManager>) -> Self {
        Self { state, connection_manager }
    }

    /// Start the D-Bus service and return the connection for signal emission
    pub async fn start(&self) -> Result<zbus::Connection, crate::error::DaemonError> {
        info!("Starting D-Bus service: {}", DBUS_NAME);

        let api = CosmicKonnectApi {
            state: self.state.clone(),
            connection_manager: self.connection_manager.clone(),
        };

        let connection = connection::Builder::session()?
            .name(DBUS_NAME)?
            .serve_at(DBUS_PATH, api)?
            .build()
            .await?;

        info!("D-Bus service registered at {}", DBUS_PATH);

        Ok(connection)
    }
}

/// Emit D-Bus signals from a connection. These are helper functions that
/// can be called from outside the interface impl (e.g., the event handler).
pub struct DbusSignals;

impl DbusSignals {
    pub async fn device_discovered(conn: &zbus::Connection, device_id: &str, name: &str, device_type: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::device_discovered(ctxt, device_id, name, device_type).await {
                warn!("Failed to emit device_discovered signal: {}", e);
            }
        }
    }

    pub async fn device_connected(conn: &zbus::Connection, device_id: &str, name: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::device_connected(ctxt, device_id, name).await {
                warn!("Failed to emit device_connected signal: {}", e);
            }
        }
    }

    pub async fn device_disconnected(conn: &zbus::Connection, device_id: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::device_disconnected(ctxt, device_id).await {
                warn!("Failed to emit device_disconnected signal: {}", e);
            }
        }
    }

    pub async fn pairing_requested(conn: &zbus::Connection, device_id: &str, name: &str, code: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::pairing_requested(ctxt, device_id, name, code).await {
                warn!("Failed to emit pairing_requested signal: {}", e);
            }
        }
    }

    pub async fn device_paired(conn: &zbus::Connection, device_id: &str, name: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::device_paired(ctxt, device_id, name).await {
                warn!("Failed to emit device_paired signal: {}", e);
            }
        }
    }

    pub async fn clipboard_received(conn: &zbus::Connection, device_id: &str, content: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::clipboard_received(ctxt, device_id, content).await {
                warn!("Failed to emit clipboard_received signal: {}", e);
            }
        }
    }

    pub async fn notification_received(conn: &zbus::Connection, device_id: &str, app_name: &str, title: &str, text: &str) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::notification_received(ctxt, device_id, app_name, title, text).await {
                warn!("Failed to emit notification_received signal: {}", e);
            }
        }
    }

    pub async fn file_offer_received(conn: &zbus::Connection, device_id: &str, transfer_id: &str, filename: &str, size: u64) {
        if let Ok(iface_ref) = conn.object_server().interface::<_, CosmicKonnectApi>(DBUS_PATH).await {
            let ctxt = iface_ref.signal_context();
            if let Err(e) = CosmicKonnectApi::file_offer_received(ctxt, device_id, transfer_id, filename, size).await {
                warn!("Failed to emit file_offer_received signal: {}", e);
            }
        }
    }
}

/// The main D-Bus interface implementation
struct CosmicKonnectApi {
    state: Arc<RwLock<AppState>>,
    connection_manager: Arc<ConnectionManager>,
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
        let state = self.state.read().await;
        if let Some(device) = state.device_manager.get_device(&device_id).await {
            if let Some(addr) = device.addresses.first() {
                let socket_addr = std::net::SocketAddr::new(*addr, device.tcp_port);
                if let Err(e) = self.connection_manager.connect(socket_addr).await {
                    warn!("Failed to connect to {}: {}", device_id, e);
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Disconnect from a device
    async fn disconnect(&self, device_id: String) -> bool {
        debug!("D-Bus: Disconnect request for {}", device_id);
        self.connection_manager.disconnect(&device_id).await.is_ok()
    }

    /// Request pairing with a device
    async fn request_pairing(&self, device_id: String) -> bool {
        debug!("D-Bus: Pairing request for {}", device_id);
        self.connection_manager.request_pairing(&device_id).await.is_ok()
    }

    /// Accept a pending pairing request
    async fn accept_pairing(&self, device_id: String) -> bool {
        debug!("D-Bus: Accept pairing for {}", device_id);
        self.connection_manager.accept_pairing(&device_id).await.is_ok()
    }

    /// Reject a pending pairing request
    async fn reject_pairing(&self, device_id: String) -> bool {
        debug!("D-Bus: Reject pairing for {}", device_id);
        self.connection_manager.reject_pairing(&device_id).await.is_ok()
    }

    /// Unpair a device
    async fn unpair(&self, device_id: String) -> bool {
        debug!("D-Bus: Unpair request for {}", device_id);
        // Disconnect and remove pairing info
        let _ = self.connection_manager.disconnect(&device_id).await;
        true
    }

    /// Send clipboard content to a device
    async fn send_clipboard(&self, device_id: String, content: String) -> bool {
        debug!("D-Bus: Send clipboard to {} ({} bytes)", device_id, content.len());
        let msg = Message::Clipboard(Clipboard {
            msg_type: MessageType::Clipboard,
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        });
        self.connection_manager.send_to(&device_id, msg).await.is_ok()
    }

    /// Broadcast clipboard to all connected devices
    async fn broadcast_clipboard(&self, content: String) -> u32 {
        debug!("D-Bus: Broadcast clipboard ({} bytes)", content.len());
        let msg = Message::Clipboard(Clipboard {
            msg_type: MessageType::Clipboard,
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        });
        let devices = self.connection_manager.connected_devices().await;
        let count = devices.len() as u32;
        let _ = self.connection_manager.broadcast(msg).await;
        count
    }

    /// Send a ping to a device
    async fn ping(&self, device_id: String) -> bool {
        debug!("D-Bus: Ping {}", device_id);
        let msg = Message::Ping(Ping {
            msg_type: MessageType::Ping,
            message: None,
        });
        self.connection_manager.send_to(&device_id, msg).await.is_ok()
    }

    /// Ring/find a device
    async fn find_device(&self, device_id: String) -> bool {
        debug!("D-Bus: Find device {}", device_id);
        let msg = Message::FindDevice(FindDevice {
            msg_type: MessageType::FindDevice,
        });
        self.connection_manager.send_to(&device_id, msg).await.is_ok()
    }

    /// Share a URL with a device
    async fn share_url(&self, device_id: String, url: String) -> bool {
        debug!("D-Bus: Share URL with {}: {}", device_id, url);
        let msg = Message::ShareUrl(ShareUrl {
            msg_type: MessageType::ShareUrl,
            url,
        });
        self.connection_manager.send_to(&device_id, msg).await.is_ok()
    }

    /// Share text with a device
    async fn share_text(&self, device_id: String, text: String) -> bool {
        debug!("D-Bus: Share text with {} ({} bytes)", device_id, text.len());
        let msg = Message::ShareText(ShareText {
            msg_type: MessageType::ShareText,
            text,
        });
        self.connection_manager.send_to(&device_id, msg).await.is_ok()
    }

    /// Send a file to a device
    async fn send_file(&self, device_id: String, file_path: String) -> bool {
        debug!("D-Bus: Send file to {}: {}", device_id, file_path);
        // TODO: Implement file send (requires chunked transfer)
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
