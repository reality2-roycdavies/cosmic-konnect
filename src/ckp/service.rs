//! CKP Service Manager
//!
//! Main entry point for the Cosmic Konnect Protocol service.
//! Coordinates discovery, connections, and message handling.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

use super::connection::{ConnectionEvent, ConnectionManager};
use super::crypto::PairingInfo;
use super::discovery::{DiscoveredDevice, DiscoveryEvent, UdpDiscovery};
use super::message::*;
use super::{TCP_PORT, PROTOCOL_VERSION};

/// Events from the CKP service for UI/tray consumption
#[derive(Debug, Clone)]
pub enum CkpServiceEvent {
    /// A device was discovered
    DeviceDiscovered {
        device_id: String,
        name: String,
        device_type: DeviceType,
    },
    /// A device was lost (timeout)
    DeviceLost {
        device_id: String,
    },
    /// Connected to a device
    Connected {
        device_id: String,
        name: String,
    },
    /// Disconnected from a device
    Disconnected {
        device_id: String,
    },
    /// Pairing requested - show verification code to user
    PairingRequested {
        device_id: String,
        name: String,
        verification_code: String,
    },
    /// Pairing completed
    Paired {
        device_id: String,
        name: String,
    },
    /// Pairing rejected
    PairingRejected {
        device_id: String,
        reason: String,
    },
    /// Ping received
    PingReceived {
        device_id: String,
        message: Option<String>,
    },
    /// Clipboard received
    ClipboardReceived {
        device_id: String,
        content: String,
    },
    /// Notification received
    NotificationReceived {
        device_id: String,
        notification: Notification,
    },
    /// File offer received
    FileOfferReceived {
        device_id: String,
        transfer_id: String,
        filename: String,
        size: u64,
    },
    /// Find device request received
    FindDeviceReceived {
        device_id: String,
    },
    /// URL shared
    UrlReceived {
        device_id: String,
        url: String,
    },
    /// Text shared
    TextReceived {
        device_id: String,
        text: String,
    },
}

/// Commands to send to the CKP service
#[derive(Debug)]
pub enum CkpServiceCommand {
    /// Connect to a discovered device
    Connect { device_id: String },
    /// Disconnect from a device
    Disconnect { device_id: String },
    /// Request pairing with a device
    RequestPairing { device_id: String },
    /// Accept a pairing request
    AcceptPairing { device_id: String },
    /// Reject a pairing request
    RejectPairing { device_id: String },
    /// Send a ping to a device
    SendPing { device_id: String, message: Option<String> },
    /// Send clipboard content to a device
    SendClipboard { device_id: String, content: String },
    /// Broadcast clipboard to all connected devices
    BroadcastClipboard { content: String },
    /// Send a file
    SendFile { device_id: String, path: PathBuf },
    /// Find device (ring phone)
    FindDevice { device_id: String },
    /// Share a URL
    ShareUrl { device_id: String, url: String },
    /// Share text
    ShareText { device_id: String, text: String },
    /// Dismiss a notification
    DismissNotification { device_id: String, notification_id: String },
    /// Shutdown the service
    Shutdown,
}

/// Device state for UI
#[derive(Debug, Clone)]
pub struct DeviceState {
    pub device_id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub paired: bool,
    pub connected: bool,
    pub last_seen: u64,
}

/// CKP Service Manager
pub struct CkpService {
    identity: Identity,
    discovery: Arc<UdpDiscovery>,
    connections: Arc<ConnectionManager>,
    devices: Arc<RwLock<HashMap<String, DeviceState>>>,
    event_tx: broadcast::Sender<CkpServiceEvent>,
    command_tx: mpsc::Sender<CkpServiceCommand>,
    command_rx: Option<mpsc::Receiver<CkpServiceCommand>>,
    config_dir: PathBuf,
}

impl CkpService {
    /// Create a new CKP service
    pub fn new(device_id: String, device_name: String, config_dir: PathBuf) -> Self {
        let identity = Identity::new(
            device_id,
            device_name,
            DeviceType::Desktop,
            TCP_PORT,
        );

        let discovery = Arc::new(UdpDiscovery::new(identity.clone()));
        let connections = Arc::new(ConnectionManager::new(identity.clone()));

        let (event_tx, _) = broadcast::channel(64);
        let (command_tx, command_rx) = mpsc::channel(64);

        Self {
            identity,
            discovery,
            connections,
            devices: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            command_tx,
            command_rx: Some(command_rx),
            config_dir,
        }
    }

    /// Get the device ID
    pub fn device_id(&self) -> &str {
        &self.identity.device_id
    }

    /// Get the device name
    pub fn device_name(&self) -> &str {
        &self.identity.name
    }

    /// Subscribe to service events
    pub fn subscribe(&self) -> broadcast::Receiver<CkpServiceEvent> {
        self.event_tx.subscribe()
    }

    /// Get a command sender for this service
    pub fn command_sender(&self) -> mpsc::Sender<CkpServiceCommand> {
        self.command_tx.clone()
    }

    /// Get the devices state for sharing with D-Bus
    pub fn devices_state(&self) -> Arc<RwLock<HashMap<String, DeviceState>>> {
        self.devices.clone()
    }

    /// Get list of all devices (excluding self)
    pub async fn get_devices(&self) -> Vec<DeviceState> {
        let own_id = self.device_id();
        self.devices
            .read()
            .await
            .values()
            .filter(|d| d.device_id != own_id)
            .cloned()
            .collect()
    }

    /// Get list of paired devices
    pub async fn get_paired_devices(&self) -> Vec<DeviceState> {
        self.devices
            .read()
            .await
            .values()
            .filter(|d| d.paired)
            .cloned()
            .collect()
    }

    /// Get list of connected devices
    pub async fn get_connected_devices(&self) -> Vec<DeviceState> {
        self.devices
            .read()
            .await
            .values()
            .filter(|d| d.connected)
            .cloned()
            .collect()
    }

    /// Start the CKP service
    pub async fn start(&mut self) -> Result<(), CkpServiceError> {
        info!("Starting CKP service as {} ({})", self.identity.name, self.identity.device_id);

        // Load paired devices
        self.load_paired_devices().await?;

        // Start event processing tasks FIRST so they don't miss any events
        // The handlers subscribe to channels, so they must start before
        // discovery/connections emit events
        self.start_connection_handler().await;
        self.start_command_handler().await;

        // Start discovery (this will emit device discovered events)
        self.discovery.start().await.map_err(|e| {
            CkpServiceError::Discovery(format!("Failed to start discovery: {}", e))
        })?;

        // Start connection listener
        self.connections.start_listener().await.map_err(|e| {
            CkpServiceError::Connection(format!("Failed to start listener: {}", e))
        })?;

        // Start discovery handler last (it processes discovery events and auto-connects)
        self.start_discovery_handler().await;

        info!("CKP service started");
        Ok(())
    }

    /// Load paired devices from storage
    async fn load_paired_devices(&self) -> Result<(), CkpServiceError> {
        let paired_file = self.config_dir.join("paired_devices.json");

        if paired_file.exists() {
            match std::fs::read_to_string(&paired_file) {
                Ok(content) => {
                    match serde_json::from_str::<Vec<StoredPairing>>(&content) {
                        Ok(pairings) => {
                            let mut devices = self.devices.write().await;
                            let mut pairing_infos = Vec::new();

                            for stored in pairings {
                                devices.insert(stored.device_id.clone(), DeviceState {
                                    device_id: stored.device_id.clone(),
                                    name: stored.device_name.clone(),
                                    device_type: DeviceType::Phone, // Default
                                    paired: true,
                                    connected: false,
                                    last_seen: stored.paired_at,
                                });

                                if let Ok(key) = hex::decode(&stored.pairing_key) {
                                    if key.len() == 32 {
                                        let mut key_array = [0u8; 32];
                                        key_array.copy_from_slice(&key);
                                        pairing_infos.push(PairingInfo {
                                            device_id: stored.device_id,
                                            device_name: stored.device_name,
                                            pairing_key: key_array,
                                            paired_at: stored.paired_at,
                                        });
                                    }
                                }
                            }

                            self.connections.load_paired_devices(pairing_infos).await;
                            info!("Loaded {} paired devices", devices.len());
                        }
                        Err(e) => {
                            warn!("Failed to parse paired devices: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read paired devices: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Save paired devices to storage
    async fn save_paired_devices(&self) -> Result<(), CkpServiceError> {
        let paired_file = self.config_dir.join("paired_devices.json");

        // Ensure config dir exists
        if let Some(parent) = paired_file.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let pairings = self.connections.get_paired_devices().await;
        let stored: Vec<StoredPairing> = pairings
            .into_iter()
            .map(|p| StoredPairing {
                device_id: p.device_id,
                device_name: p.device_name,
                pairing_key: hex::encode(p.pairing_key),
                paired_at: p.paired_at,
            })
            .collect();

        let content = serde_json::to_string_pretty(&stored)
            .map_err(|e| CkpServiceError::Storage(format!("Failed to serialize: {}", e)))?;

        std::fs::write(&paired_file, content)
            .map_err(|e| CkpServiceError::Storage(format!("Failed to write: {}", e)))?;

        info!("Saved {} paired devices", stored.len());
        Ok(())
    }

    /// Start discovery event handler
    async fn start_discovery_handler(&self) {
        let mut discovery_rx = self.discovery.subscribe();
        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();
        let connections = self.connections.clone();
        let own_device_id = self.identity.device_id.clone();

        tokio::spawn(async move {
            while let Ok(event) = discovery_rx.recv().await {
                match event {
                    DiscoveryEvent::DeviceDiscovered(discovered) => {
                        // Skip self-discovery
                        if discovered.device_id == own_device_id {
                            continue;
                        }

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        let mut devices_map = devices.write().await;

                        let is_new = !devices_map.contains_key(&discovered.device_id);

                        if is_new {
                            // New device - insert with connected=false
                            devices_map.insert(discovered.device_id.clone(), DeviceState {
                                device_id: discovered.device_id.clone(),
                                name: discovered.name.clone(),
                                device_type: discovered.device_type,
                                paired: false,
                                connected: false,
                                last_seen: now,
                            });
                        } else {
                            // Existing device - update last_seen but preserve connected/paired state
                            if let Some(device) = devices_map.get_mut(&discovered.device_id) {
                                device.last_seen = now;
                                device.name = discovered.name.clone();  // Name might change
                            }
                        }

                        drop(devices_map);

                        // Check if device is already connected
                        let is_connected = {
                            let devices_map = devices.read().await;
                            devices_map.get(&discovered.device_id)
                                .map(|d| d.connected)
                                .unwrap_or(false)
                        };

                        if is_new {
                            let _ = event_tx.send(CkpServiceEvent::DeviceDiscovered {
                                device_id: discovered.device_id.clone(),
                                name: discovered.name.clone(),
                                device_type: discovered.device_type,
                            });
                        }

                        // Auto-connect to discovered devices that aren't already connected
                        if !is_connected {
                            if let Some(addr) = discovered.addresses.first() {
                                let socket_addr = SocketAddr::new(*addr, discovered.tcp_port);
                                info!("Auto-connecting to {} at {}", discovered.name, socket_addr);
                                if let Err(e) = connections.connect(socket_addr).await {
                                    warn!("Failed to auto-connect to {}: {}", discovered.name, e);
                                }
                            }
                        }
                    }
                    DiscoveryEvent::DeviceLost(device_id) => {
                        let mut devices_map = devices.write().await;
                        if let Some(device) = devices_map.get_mut(&device_id) {
                            device.connected = false;
                        }
                        drop(devices_map);

                        let _ = event_tx.send(CkpServiceEvent::DeviceLost { device_id });
                    }
                }
            }
        });
    }

    /// Start connection event handler
    async fn start_connection_handler(&self) {
        let mut conn_rx = self.connections.subscribe();
        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();
        let config_dir = self.config_dir.clone();
        let connections = self.connections.clone();

        tokio::spawn(async move {
            while let Ok(event) = conn_rx.recv().await {
                match event {
                    ConnectionEvent::Connected { device_id, device_name, .. } => {
                        let mut devices_map = devices.write().await;
                        if let Some(device) = devices_map.get_mut(&device_id) {
                            device.connected = true;
                            device.name = device_name.clone();
                        } else {
                            // Device not in map yet (connection happened before discovery event)
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            devices_map.insert(device_id.clone(), DeviceState {
                                device_id: device_id.clone(),
                                name: device_name.clone(),
                                device_type: DeviceType::Phone, // Default
                                paired: false,
                                connected: true,
                                last_seen: now,
                            });
                        }
                        drop(devices_map);

                        let _ = event_tx.send(CkpServiceEvent::Connected {
                            device_id,
                            name: device_name,
                        });
                    }
                    ConnectionEvent::Disconnected { device_id, .. } => {
                        let mut devices_map = devices.write().await;
                        if let Some(device) = devices_map.get_mut(&device_id) {
                            device.connected = false;
                        }
                        drop(devices_map);

                        let _ = event_tx.send(CkpServiceEvent::Disconnected { device_id });
                    }
                    ConnectionEvent::PairingRequested { device_id, device_name, verification_code } => {
                        let _ = event_tx.send(CkpServiceEvent::PairingRequested {
                            device_id,
                            name: device_name,
                            verification_code,
                        });
                    }
                    ConnectionEvent::Paired { device_id, device_name } => {
                        let mut devices_map = devices.write().await;
                        if let Some(device) = devices_map.get_mut(&device_id) {
                            device.paired = true;
                            device.name = device_name.clone();
                        } else {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            devices_map.insert(device_id.clone(), DeviceState {
                                device_id: device_id.clone(),
                                name: device_name.clone(),
                                device_type: DeviceType::Phone,
                                paired: true,
                                connected: true,
                                last_seen: now,
                            });
                        }
                        drop(devices_map);

                        // Save paired devices
                        let pairings = connections.get_paired_devices().await;
                        let stored: Vec<StoredPairing> = pairings
                            .into_iter()
                            .map(|p| StoredPairing {
                                device_id: p.device_id,
                                device_name: p.device_name,
                                pairing_key: hex::encode(p.pairing_key),
                                paired_at: p.paired_at,
                            })
                            .collect();

                        let paired_file = config_dir.join("paired_devices.json");
                        if let Ok(content) = serde_json::to_string_pretty(&stored) {
                            let _ = std::fs::write(&paired_file, content);
                        }

                        let _ = event_tx.send(CkpServiceEvent::Paired {
                            device_id,
                            name: device_name,
                        });
                    }
                    ConnectionEvent::PairingRejected { device_id, reason } => {
                        let _ = event_tx.send(CkpServiceEvent::PairingRejected { device_id, reason });
                    }
                    ConnectionEvent::MessageReceived { device_id, message } => {
                        handle_message(&device_id, message, &event_tx);
                    }
                    _ => {}
                }
            }
        });
    }

    /// Start command handler
    async fn start_command_handler(&mut self) {
        let mut command_rx = self.command_rx.take().expect("command_rx already taken");
        let connections = self.connections.clone();
        let discovery = self.discovery.clone();

        tokio::spawn(async move {
            while let Some(cmd) = command_rx.recv().await {
                match cmd {
                    CkpServiceCommand::Connect { device_id } => {
                        let devices = discovery.get_devices().await;
                        if let Some(device) = devices.iter().find(|d| d.device_id == device_id) {
                            if let Some(addr) = device.addresses.first() {
                                let socket_addr = SocketAddr::new(*addr, device.tcp_port);
                                if let Err(e) = connections.connect(socket_addr).await {
                                    error!("Failed to connect to {}: {}", device_id, e);
                                }
                            }
                        }
                    }
                    CkpServiceCommand::Disconnect { device_id } => {
                        if let Err(e) = connections.disconnect(&device_id).await {
                            debug!("Failed to disconnect from {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::RequestPairing { device_id } => {
                        if let Err(e) = connections.request_pairing(&device_id).await {
                            error!("Failed to request pairing with {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::AcceptPairing { device_id } => {
                        // The connection handler manages this
                        debug!("Accept pairing for {}", device_id);
                    }
                    CkpServiceCommand::RejectPairing { device_id } => {
                        debug!("Reject pairing for {}", device_id);
                    }
                    CkpServiceCommand::SendPing { device_id, message } => {
                        let msg = Message::Ping(Ping {
                            msg_type: MessageType::Ping,
                            message,
                        });
                        if let Err(e) = connections.send_to(&device_id, msg).await {
                            debug!("Failed to send ping to {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::SendClipboard { device_id, content } => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let msg = Message::Clipboard(Clipboard {
                            msg_type: MessageType::Clipboard,
                            content,
                            timestamp: now,
                        });
                        if let Err(e) = connections.send_to(&device_id, msg).await {
                            debug!("Failed to send clipboard to {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::BroadcastClipboard { content } => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let msg = Message::Clipboard(Clipboard {
                            msg_type: MessageType::Clipboard,
                            content,
                            timestamp: now,
                        });
                        if let Err(e) = connections.broadcast(msg).await {
                            debug!("Failed to broadcast clipboard: {}", e);
                        }
                    }
                    CkpServiceCommand::FindDevice { device_id } => {
                        let msg = Message::FindDevice(FindDevice {
                            msg_type: MessageType::FindDevice,
                        });
                        if let Err(e) = connections.send_to(&device_id, msg).await {
                            debug!("Failed to send find device to {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::ShareUrl { device_id, url } => {
                        let msg = Message::ShareUrl(ShareUrl {
                            msg_type: MessageType::ShareUrl,
                            url,
                        });
                        if let Err(e) = connections.send_to(&device_id, msg).await {
                            debug!("Failed to share URL with {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::ShareText { device_id, text } => {
                        let msg = Message::ShareText(ShareText {
                            msg_type: MessageType::ShareText,
                            text,
                        });
                        if let Err(e) = connections.send_to(&device_id, msg).await {
                            debug!("Failed to share text with {}: {}", device_id, e);
                        }
                    }
                    CkpServiceCommand::DismissNotification { device_id, notification_id } => {
                        let msg = Message::NotificationAction(NotificationAction {
                            msg_type: MessageType::NotificationAction,
                            id: notification_id,
                            action: "dismiss".to_string(),
                            reply_text: None,
                        });
                        if let Err(e) = connections.send_to(&device_id, msg).await {
                            debug!("Failed to dismiss notification: {}", e);
                        }
                    }
                    CkpServiceCommand::SendFile { device_id, path } => {
                        // TODO: Implement file transfer
                        info!("File transfer not yet implemented: {:?} -> {}", path, device_id);
                    }
                    CkpServiceCommand::Shutdown => {
                        info!("Shutting down CKP service");
                        break;
                    }
                }
            }
        });
    }
}

/// Handle incoming messages
fn handle_message(
    device_id: &str,
    message: Message,
    event_tx: &broadcast::Sender<CkpServiceEvent>,
) {
    match message {
        Message::Ping(ping) => {
            let _ = event_tx.send(CkpServiceEvent::PingReceived {
                device_id: device_id.to_string(),
                message: ping.message,
            });
        }
        Message::Clipboard(clipboard) => {
            let _ = event_tx.send(CkpServiceEvent::ClipboardReceived {
                device_id: device_id.to_string(),
                content: clipboard.content,
            });
        }
        Message::Notification(notification) => {
            let _ = event_tx.send(CkpServiceEvent::NotificationReceived {
                device_id: device_id.to_string(),
                notification,
            });
        }
        Message::FileOffer(offer) => {
            let _ = event_tx.send(CkpServiceEvent::FileOfferReceived {
                device_id: device_id.to_string(),
                transfer_id: offer.transfer_id,
                filename: offer.filename,
                size: offer.size,
            });
        }
        Message::FindDevice(_) => {
            let _ = event_tx.send(CkpServiceEvent::FindDeviceReceived {
                device_id: device_id.to_string(),
            });
        }
        Message::ShareUrl(share) => {
            let _ = event_tx.send(CkpServiceEvent::UrlReceived {
                device_id: device_id.to_string(),
                url: share.url,
            });
        }
        Message::ShareText(share) => {
            let _ = event_tx.send(CkpServiceEvent::TextReceived {
                device_id: device_id.to_string(),
                text: share.text,
            });
        }
        _ => {
            debug!("Unhandled message type from {}: {:?}", device_id, message.message_type());
        }
    }
}

/// Stored pairing for JSON serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredPairing {
    device_id: String,
    device_name: String,
    pairing_key: String, // Hex encoded
    paired_at: u64,
}

/// CKP service errors
#[derive(Debug, thiserror::Error)]
pub enum CkpServiceError {
    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Storage error: {0}")]
    Storage(String),
}
