//! D-Bus client for communicating with the Cosmic Konnect daemon
//!
//! This module provides a thin client layer that the tray app uses to
//! interact with the background daemon via D-Bus.

use std::sync::Arc;
use futures_util::StreamExt;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};
use zbus::{proxy, Connection};

/// D-Bus service name
pub const DBUS_NAME: &str = "io.github.reality2_roycdavies.CosmicKonnect";

/// D-Bus object path
pub const DBUS_PATH: &str = "/io/github/reality2_roycdavies/CosmicKonnect";

/// Device info from daemon
#[derive(Debug, Clone)]
pub struct DaemonDevice {
    pub device_id: String,
    pub name: String,
    pub device_type: String,
    pub state: String,
    pub paired: bool,
}

/// Events from the daemon
#[derive(Debug, Clone)]
pub enum DaemonEvent {
    DeviceDiscovered {
        device_id: String,
        name: String,
        device_type: String,
    },
    DeviceLost {
        device_id: String,
    },
    DeviceConnected {
        device_id: String,
        name: String,
    },
    DeviceDisconnected {
        device_id: String,
    },
    PairingRequested {
        device_id: String,
        name: String,
        verification_code: String,
    },
    DevicePaired {
        device_id: String,
        name: String,
    },
    ClipboardReceived {
        device_id: String,
        content: String,
    },
    NotificationReceived {
        device_id: String,
        app_name: String,
        title: String,
        text: String,
    },
    DaemonConnected,
    DaemonDisconnected,
}

/// D-Bus proxy for the daemon
#[proxy(
    interface = "io.github.reality2_roycdavies.CosmicKonnect",
    default_service = "io.github.reality2_roycdavies.CosmicKonnect",
    default_path = "/io/github/reality2_roycdavies/CosmicKonnect"
)]
trait CosmicKonnect {
    /// Get the daemon version
    fn version(&self) -> zbus::Result<String>;

    /// Get our device ID
    fn device_id(&self) -> zbus::Result<String>;

    /// Get our device name
    fn device_name(&self) -> zbus::Result<String>;

    /// Get list of all known devices
    fn list_devices(&self) -> zbus::Result<Vec<(String, String, String, String, bool)>>;

    /// Get list of paired devices
    fn list_paired_devices(&self) -> zbus::Result<Vec<(String, String, String)>>;

    /// Get list of connected devices
    fn list_connected_devices(&self) -> zbus::Result<Vec<(String, String)>>;

    /// Connect to a device by ID
    fn connect(&self, device_id: &str) -> zbus::Result<bool>;

    /// Disconnect from a device
    fn disconnect(&self, device_id: &str) -> zbus::Result<bool>;

    /// Request pairing with a device
    fn request_pairing(&self, device_id: &str) -> zbus::Result<bool>;

    /// Accept a pending pairing request
    fn accept_pairing(&self, device_id: &str) -> zbus::Result<bool>;

    /// Reject a pending pairing request
    fn reject_pairing(&self, device_id: &str) -> zbus::Result<bool>;

    /// Unpair a device
    fn unpair(&self, device_id: &str) -> zbus::Result<bool>;

    /// Send clipboard content to a device
    fn send_clipboard(&self, device_id: &str, content: &str) -> zbus::Result<bool>;

    /// Broadcast clipboard to all connected devices
    fn broadcast_clipboard(&self, content: &str) -> zbus::Result<u32>;

    /// Send a ping to a device
    fn ping(&self, device_id: &str) -> zbus::Result<bool>;

    /// Ring/find a device
    fn find_device(&self, device_id: &str) -> zbus::Result<bool>;

    /// Share a URL with a device
    fn share_url(&self, device_id: &str, url: &str) -> zbus::Result<bool>;

    /// Share text with a device
    fn share_text(&self, device_id: &str, text: &str) -> zbus::Result<bool>;

    /// Send a file to a device
    fn send_file(&self, device_id: &str, file_path: &str) -> zbus::Result<bool>;

    /// Enable or disable BLE discovery
    fn set_ble_enabled(&self, enabled: bool) -> zbus::Result<()>;

    /// Check if BLE discovery is enabled
    fn is_ble_enabled(&self) -> zbus::Result<bool>;

    /// Enable or disable mDNS discovery
    fn set_mdns_enabled(&self, enabled: bool) -> zbus::Result<()>;

    /// Check if mDNS discovery is enabled
    fn is_mdns_enabled(&self) -> zbus::Result<bool>;

    // Signals
    #[zbus(signal)]
    fn device_discovered(&self, device_id: &str, name: &str, device_type: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn device_lost(&self, device_id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn device_connected(&self, device_id: &str, name: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn device_disconnected(&self, device_id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn pairing_requested(&self, device_id: &str, name: &str, verification_code: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn device_paired(&self, device_id: &str, name: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn clipboard_received(&self, device_id: &str, content: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_received(&self, device_id: &str, app_name: &str, title: &str, text: &str) -> zbus::Result<()>;
}

/// Client for communicating with the daemon
pub struct DaemonClient {
    connection: Option<Connection>,
    event_tx: broadcast::Sender<DaemonEvent>,
    connected: Arc<RwLock<bool>>,
}

impl DaemonClient {
    /// Create a new daemon client
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            connection: None,
            event_tx,
            connected: Arc::new(RwLock::new(false)),
        }
    }

    /// Subscribe to daemon events
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonEvent> {
        self.event_tx.subscribe()
    }

    /// Check if connected to daemon
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Connect to the daemon
    pub async fn connect(&mut self) -> Result<(), DaemonClientError> {
        info!("Connecting to Cosmic Konnect daemon...");

        let connection = Connection::session().await?;

        // Try to create the proxy to check if daemon is running
        let proxy = CosmicKonnectProxy::new(&connection).await?;

        // Test connection by getting version
        match proxy.version().await {
            Ok(version) => {
                info!("Connected to daemon version {}", version);
                self.connection = Some(connection);
                *self.connected.write().await = true;
                let _ = self.event_tx.send(DaemonEvent::DaemonConnected);
                Ok(())
            }
            Err(e) => {
                warn!("Daemon not responding: {}", e);
                Err(DaemonClientError::DaemonNotRunning)
            }
        }
    }

    /// Start listening for signals from the daemon
    pub async fn start_signal_listener(&self) -> Result<(), DaemonClientError> {
        let connection = self.connection.as_ref()
            .ok_or(DaemonClientError::NotConnected)?;

        let proxy = CosmicKonnectProxy::new(connection).await?;
        let event_tx = self.event_tx.clone();
        let connected = self.connected.clone();

        // Device discovered signal
        let mut discovered_stream = proxy.receive_device_discovered().await?;
        let event_tx_discovered = event_tx.clone();
        tokio::spawn(async move {
            while let Some(signal) = discovered_stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = event_tx_discovered.send(DaemonEvent::DeviceDiscovered {
                        device_id: args.device_id.to_string(),
                        name: args.name.to_string(),
                        device_type: args.device_type.to_string(),
                    });
                }
            }
        });

        // Device connected signal
        let mut connected_stream = proxy.receive_device_connected().await?;
        let event_tx_connected = event_tx.clone();
        tokio::spawn(async move {
            while let Some(signal) = connected_stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = event_tx_connected.send(DaemonEvent::DeviceConnected {
                        device_id: args.device_id.to_string(),
                        name: args.name.to_string(),
                    });
                }
            }
        });

        // Device disconnected signal
        let mut disconnected_stream = proxy.receive_device_disconnected().await?;
        let event_tx_disconnected = event_tx.clone();
        tokio::spawn(async move {
            while let Some(signal) = disconnected_stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = event_tx_disconnected.send(DaemonEvent::DeviceDisconnected {
                        device_id: args.device_id.to_string(),
                    });
                }
            }
        });

        // Clipboard received signal
        let mut clipboard_stream = proxy.receive_clipboard_received().await?;
        let event_tx_clipboard = event_tx.clone();
        tokio::spawn(async move {
            while let Some(signal) = clipboard_stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = event_tx_clipboard.send(DaemonEvent::ClipboardReceived {
                        device_id: args.device_id.to_string(),
                        content: args.content.to_string(),
                    });
                }
            }
        });

        // Notification received signal
        let mut notification_stream = proxy.receive_notification_received().await?;
        let event_tx_notification = event_tx.clone();
        tokio::spawn(async move {
            while let Some(signal) = notification_stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = event_tx_notification.send(DaemonEvent::NotificationReceived {
                        device_id: args.device_id.to_string(),
                        app_name: args.app_name.to_string(),
                        title: args.title.to_string(),
                        text: args.text.to_string(),
                    });
                }
            }
        });

        Ok(())
    }

    /// Get proxy for making calls
    async fn proxy(&self) -> Result<CosmicKonnectProxy<'_>, DaemonClientError> {
        let connection = self.connection.as_ref()
            .ok_or(DaemonClientError::NotConnected)?;
        Ok(CosmicKonnectProxy::new(connection).await?)
    }

    /// Get all devices
    pub async fn list_devices(&self) -> Result<Vec<DaemonDevice>, DaemonClientError> {
        let proxy = self.proxy().await?;
        let devices = proxy.list_devices().await?;

        Ok(devices.into_iter().map(|(id, name, dtype, state, paired)| {
            DaemonDevice {
                device_id: id,
                name,
                device_type: dtype,
                state,
                paired,
            }
        }).collect())
    }

    /// Get connected devices
    pub async fn list_connected_devices(&self) -> Result<Vec<(String, String)>, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.list_connected_devices().await?)
    }

    /// Send ping to a device
    pub async fn ping(&self, device_id: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.ping(device_id).await?)
    }

    /// Find/ring a device
    pub async fn find_device(&self, device_id: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.find_device(device_id).await?)
    }

    /// Send clipboard
    pub async fn send_clipboard(&self, device_id: &str, content: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.send_clipboard(device_id, content).await?)
    }

    /// Broadcast clipboard to all
    pub async fn broadcast_clipboard(&self, content: &str) -> Result<u32, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.broadcast_clipboard(content).await?)
    }

    /// Request pairing
    pub async fn request_pairing(&self, device_id: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.request_pairing(device_id).await?)
    }

    /// Share URL
    pub async fn share_url(&self, device_id: &str, url: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.share_url(device_id, url).await?)
    }

    /// Share text
    pub async fn share_text(&self, device_id: &str, text: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.share_text(device_id, text).await?)
    }

    /// Send file
    pub async fn send_file(&self, device_id: &str, path: &str) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.send_file(device_id, path).await?)
    }

    /// Get daemon version
    pub async fn version(&self) -> Result<String, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.version().await?)
    }

    /// Get our device ID
    pub async fn device_id(&self) -> Result<String, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.device_id().await?)
    }

    /// Get our device name
    pub async fn device_name(&self) -> Result<String, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.device_name().await?)
    }

    /// Check if BLE is enabled
    pub async fn is_ble_enabled(&self) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.is_ble_enabled().await?)
    }

    /// Check if mDNS is enabled
    pub async fn is_mdns_enabled(&self) -> Result<bool, DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.is_mdns_enabled().await?)
    }

    /// Set BLE discovery enabled/disabled
    pub async fn set_ble_enabled(&self, enabled: bool) -> Result<(), DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.set_ble_enabled(enabled).await?)
    }

    /// Set mDNS discovery enabled/disabled
    pub async fn set_mdns_enabled(&self, enabled: bool) -> Result<(), DaemonClientError> {
        let proxy = self.proxy().await?;
        Ok(proxy.set_mdns_enabled(enabled).await?)
    }
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Daemon client errors
#[derive(Debug, thiserror::Error)]
pub enum DaemonClientError {
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    #[error("Not connected to daemon")]
    NotConnected,

    #[error("Daemon not running")]
    DaemonNotRunning,
}
