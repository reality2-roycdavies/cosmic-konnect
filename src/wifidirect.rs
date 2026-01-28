#![allow(dead_code)]
//! Wi-Fi Direct (P2P) support for Linux
//!
//! Supports two backends:
//! 1. NetworkManager D-Bus (preferred, works without root)
//! 2. wpa_supplicant D-Bus (requires root or special permissions)
//!
//! Note: Wi-Fi Direct on Linux requires:
//! - A Wi-Fi adapter that supports P2P
//! - Either NetworkManager or wpa_supplicant with P2P support

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};
use zbus::{proxy, Connection};

// ============================================================================
// NetworkManager D-Bus interfaces (preferred, no root required)
// ============================================================================

/// NetworkManager D-Bus service
const NM_SERVICE: &str = "org.freedesktop.NetworkManager";

/// D-Bus proxy for NetworkManager main interface
#[proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    /// Get all devices
    #[zbus(property)]
    fn devices(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;
}

/// D-Bus proxy for NetworkManager Device
#[proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
trait NmDevice {
    /// Device type (30 = NM_DEVICE_TYPE_WIFI_P2P)
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;

    /// Interface name
    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;
}

/// D-Bus proxy for NetworkManager WiFi P2P Device
#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.WifiP2P",
    default_service = "org.freedesktop.NetworkManager"
)]
trait NmWifiP2P {
    /// Start finding P2P peers
    fn start_find(&self, options: HashMap<&str, zbus::zvariant::Value<'_>>) -> zbus::Result<()>;

    /// Stop finding P2P peers
    fn stop_find(&self) -> zbus::Result<()>;

    /// List of discovered peers
    #[zbus(property)]
    fn peers(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;

    /// Peer added signal
    #[zbus(signal)]
    fn peer_added(&self, peer: zbus::zvariant::OwnedObjectPath) -> zbus::Result<()>;

    /// Peer removed signal
    #[zbus(signal)]
    fn peer_removed(&self, peer: zbus::zvariant::OwnedObjectPath) -> zbus::Result<()>;
}

/// D-Bus proxy for NetworkManager WiFi P2P Peer
#[proxy(
    interface = "org.freedesktop.NetworkManager.WifiP2PPeer",
    default_service = "org.freedesktop.NetworkManager"
)]
trait NmP2PPeer {
    /// Peer name
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;

    /// Hardware address
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// Manufacturer
    #[zbus(property)]
    fn manufacturer(&self) -> zbus::Result<String>;

    /// Model
    #[zbus(property)]
    fn model(&self) -> zbus::Result<String>;
}

// ============================================================================
// wpa_supplicant D-Bus interfaces (fallback, requires root)
// ============================================================================

/// wpa_supplicant D-Bus service name
const WPA_SUPPLICANT_SERVICE: &str = "fi.w1.wpa_supplicant1";
/// wpa_supplicant D-Bus object path
const WPA_SUPPLICANT_PATH: &str = "/fi/w1/wpa_supplicant1";

/// D-Bus proxy for wpa_supplicant1 main interface
#[proxy(
    interface = "fi.w1.wpa_supplicant1",
    default_service = "fi.w1.wpa_supplicant1",
    default_path = "/fi/w1/wpa_supplicant1"
)]
trait WpaSupplicant {
    /// Get an interface by name
    fn get_interface(&self, ifname: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

    /// List all interfaces
    #[zbus(property)]
    fn interfaces(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;
}

/// D-Bus proxy for P2P operations on an interface
#[proxy(
    interface = "fi.w1.wpa_supplicant1.Interface.P2PDevice",
    default_service = "fi.w1.wpa_supplicant1"
)]
trait P2PDevice {
    /// Start P2P device discovery
    fn find(&self, args: HashMap<&str, zbus::zvariant::Value<'_>>) -> zbus::Result<()>;

    /// Stop P2P device discovery
    fn stop_find(&self) -> zbus::Result<()>;

    /// Connect to a P2P peer
    fn connect(
        &self,
        args: HashMap<&str, zbus::zvariant::Value<'_>>,
    ) -> zbus::Result<String>;

    /// Create a P2P group
    fn group_add(&self, args: HashMap<&str, zbus::zvariant::Value<'_>>) -> zbus::Result<()>;

    /// Remove a P2P group
    fn disconnect(&self) -> zbus::Result<()>;

    /// P2P device found signal
    #[zbus(signal)]
    fn device_found(&self, path: zbus::zvariant::OwnedObjectPath) -> zbus::Result<()>;

    /// P2P device lost signal
    #[zbus(signal)]
    fn device_lost(&self, path: zbus::zvariant::OwnedObjectPath) -> zbus::Result<()>;

    /// P2P group started signal
    #[zbus(signal)]
    fn group_started(
        &self,
        properties: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::Result<()>;

    /// P2P group finished signal
    #[zbus(signal)]
    fn group_finished(
        &self,
        properties: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::Result<()>;

    /// P2P peers property
    #[zbus(property)]
    fn peers(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;

    /// P2P group property
    #[zbus(property)]
    fn group(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

/// D-Bus proxy for P2P peer information
#[proxy(
    interface = "fi.w1.wpa_supplicant1.Peer",
    default_service = "fi.w1.wpa_supplicant1"
)]
trait Peer {
    /// Device name
    #[zbus(property)]
    fn device_name(&self) -> zbus::Result<String>;

    /// Device address
    #[zbus(property)]
    fn device_address(&self) -> zbus::Result<Vec<u8>>;

    /// Primary device type
    #[zbus(property)]
    fn primary_device_type(&self) -> zbus::Result<Vec<u8>>;

    /// Config methods
    #[zbus(property)]
    fn config_method(&self) -> zbus::Result<u16>;

    /// Device capability
    #[zbus(property)]
    fn device_capability(&self) -> zbus::Result<u8>;

    /// Group capability
    #[zbus(property)]
    fn group_capability(&self) -> zbus::Result<u8>;
}

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

/// Backend used for P2P operations
#[derive(Debug, Clone, Copy, PartialEq)]
enum P2pBackend {
    /// NetworkManager (preferred, no root needed)
    NetworkManager,
    /// wpa_supplicant (requires root or special permissions)
    WpaSupplicant,
}

/// Wi-Fi Direct manager for Linux
pub struct WifiDirectManager {
    interface: String,
    event_tx: broadcast::Sender<P2pEvent>,
    discovered_devices: Arc<RwLock<HashMap<String, P2pDevice>>>,
    group_info: Arc<RwLock<Option<P2pGroupInfo>>>,
    stop_tx: Option<mpsc::Sender<()>>,
    backend: Arc<RwLock<Option<P2pBackend>>>,
    nm_p2p_path: Arc<RwLock<Option<zbus::zvariant::OwnedObjectPath>>>,
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
            stop_tx: None,
            backend: Arc::new(RwLock::new(None)),
            nm_p2p_path: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to P2P events
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    /// Check if Wi-Fi Direct is available via D-Bus
    /// Tries NetworkManager first (no root needed), then falls back to wpa_supplicant
    pub async fn is_available(&self) -> bool {
        // Try NetworkManager first (preferred, no root required)
        if let Some(path) = self.find_nm_p2p_device().await {
            info!("Wi-Fi P2P available via NetworkManager");
            *self.backend.write().await = Some(P2pBackend::NetworkManager);
            *self.nm_p2p_path.write().await = Some(path);
            return true;
        }

        // Fall back to wpa_supplicant (requires root)
        match Connection::system().await {
            Ok(conn) => {
                let proxy = WpaSupplicantProxy::new(&conn).await;
                match proxy {
                    Ok(p) => {
                        // Try to get our interface
                        match p.get_interface(&self.interface).await {
                            Ok(path) => {
                                // Check if P2P is supported by trying to access P2PDevice interface
                                match P2PDeviceProxy::builder(&conn).path(path) {
                                    Ok(builder) => {
                                        match builder.build().await {
                                            Ok(_) => {
                                                info!("Wi-Fi P2P available via wpa_supplicant");
                                                *self.backend.write().await = Some(P2pBackend::WpaSupplicant);
                                                return true;
                                            }
                                            Err(e) => debug!("P2P interface not available: {}", e),
                                        }
                                    }
                                    Err(e) => debug!("Failed to build P2P proxy: {}", e),
                                }
                            }
                            Err(e) => {
                                debug!("Interface {} not found in wpa_supplicant: {}", self.interface, e);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to create wpa_supplicant proxy: {}", e);
                    }
                }
            }
            Err(e) => {
                debug!("Failed to connect to system D-Bus: {}", e);
            }
        }
        warn!("Wi-Fi P2P not available (neither NetworkManager nor wpa_supplicant)");
        false
    }

    /// Find the NetworkManager WiFi P2P device
    async fn find_nm_p2p_device(&self) -> Option<zbus::zvariant::OwnedObjectPath> {
        let conn = Connection::system().await.ok()?;
        let nm = NetworkManagerProxy::new(&conn).await.ok()?;

        let devices = nm.devices().await.ok()?;

        for device_path in devices {
            let device = NmDeviceProxy::builder(&conn)
                .path(device_path.clone())
                .ok()?
                .build()
                .await
                .ok()?;

            // DeviceType 30 = NM_DEVICE_TYPE_WIFI_P2P
            if device.device_type().await.ok()? == 30 {
                // Verify we can access the WifiP2P interface
                if NmWifiP2PProxy::builder(&conn)
                    .path(device_path.clone())
                    .ok()?
                    .build()
                    .await
                    .is_ok()
                {
                    debug!("Found NetworkManager P2P device: {:?}", device_path);
                    return Some(device_path);
                }
            }
        }
        None
    }

    /// Get the D-Bus connection and P2P proxy
    async fn get_p2p_proxy(&self) -> Result<(Connection, P2PDeviceProxy<'static>), P2pError> {
        let conn = Connection::system()
            .await
            .map_err(|e| P2pError::Dbus(format!("Failed to connect to system D-Bus: {}", e)))?;

        let wpa = WpaSupplicantProxy::new(&conn)
            .await
            .map_err(|e| P2pError::Dbus(format!("Failed to create wpa_supplicant proxy: {}", e)))?;

        let iface_path = wpa
            .get_interface(&self.interface)
            .await
            .map_err(|e| P2pError::NotAvailable(format!("Interface {} not found: {}", self.interface, e)))?;

        let p2p = P2PDeviceProxy::builder(&conn)
            .path(iface_path)
            .map_err(|e| P2pError::Dbus(format!("Failed to build P2P proxy: {}", e)))?
            .build()
            .await
            .map_err(|e| P2pError::Dbus(format!("Failed to create P2P proxy: {}", e)))?;

        Ok((conn, p2p))
    }

    /// Start P2P device discovery
    pub async fn start_discovery(&self) -> Result<(), P2pError> {
        info!("Starting Wi-Fi Direct discovery on {}", self.interface);

        let backend = *self.backend.read().await;

        match backend {
            Some(P2pBackend::NetworkManager) => self.start_nm_discovery().await,
            Some(P2pBackend::WpaSupplicant) => self.start_wpa_discovery().await,
            None => {
                // Backend not set - caller should call is_available() first
                Err(P2pError::NotAvailable("No P2P backend available. Call is_available() first.".to_string()))
            }
        }
    }

    /// Start discovery using NetworkManager
    async fn start_nm_discovery(&self) -> Result<(), P2pError> {
        let path = self.nm_p2p_path.read().await.clone()
            .ok_or_else(|| P2pError::NotAvailable("NetworkManager P2P device not found".to_string()))?;

        let conn = Connection::system()
            .await
            .map_err(|e| P2pError::Dbus(format!("Failed to connect to D-Bus: {}", e)))?;

        let p2p = NmWifiP2PProxy::builder(&conn)
            .path(path.clone())
            .map_err(|e| P2pError::Dbus(format!("Failed to build NM P2P proxy: {}", e)))?
            .build()
            .await
            .map_err(|e| P2pError::Dbus(format!("Failed to create NM P2P proxy: {}", e)))?;

        // Start discovery
        let args: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
        p2p.start_find(args)
            .await
            .map_err(|e| P2pError::Discovery(format!("Failed to start NM P2P find: {}", e)))?;

        info!("NetworkManager P2P discovery started");

        // Start monitoring for peer signals
        let event_tx = self.event_tx.clone();
        let discovered_devices = self.discovered_devices.clone();
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

        tokio::spawn(async move {
            if let Err(e) = monitor_nm_p2p_signals(
                conn,
                path,
                event_tx.clone(),
                discovered_devices,
                &mut stop_rx,
            ).await {
                error!("NM P2P signal monitor error: {}", e);
                let _ = event_tx.send(P2pEvent::Error(e.to_string()));
            }
        });

        Ok(())
    }

    /// Start discovery using wpa_supplicant
    async fn start_wpa_discovery(&self) -> Result<(), P2pError> {
        let (conn, p2p) = self.get_p2p_proxy().await?;

        // Start discovery with default arguments
        let args: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
        p2p.find(args)
            .await
            .map_err(|e| P2pError::Discovery(format!("Failed to start P2P find: {}", e)))?;

        info!("wpa_supplicant P2P discovery started");

        // Start monitoring for device signals
        let event_tx = self.event_tx.clone();
        let discovered_devices = self.discovered_devices.clone();
        let group_info = self.group_info.clone();
        let interface = self.interface.clone();

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

        tokio::spawn(async move {
            if let Err(e) = monitor_p2p_signals(
                conn,
                interface,
                event_tx.clone(),
                discovered_devices,
                group_info,
                &mut stop_rx,
            ).await {
                error!("P2P signal monitor error: {}", e);
                let _ = event_tx.send(P2pEvent::Error(e.to_string()));
            }
        });

        Ok(())
    }

    /// Stop P2P discovery
    pub async fn stop_discovery(&self) -> Result<(), P2pError> {
        info!("Stopping Wi-Fi Direct discovery");

        let (_, p2p) = self.get_p2p_proxy().await?;

        p2p.stop_find()
            .await
            .map_err(|e| P2pError::Discovery(format!("Failed to stop P2P find: {}", e)))?;

        if let Some(tx) = &self.stop_tx {
            let _ = tx.send(()).await;
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

        let (_, p2p) = self.get_p2p_proxy().await?;

        let mut args: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();

        // Convert MAC address to byte array
        let addr_bytes: Vec<u8> = device_address
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if addr_bytes.len() != 6 {
            return Err(P2pError::Connection("Invalid MAC address format".to_string()));
        }

        args.insert("peer", zbus::zvariant::Value::from(addr_bytes));
        args.insert("wps_method", zbus::zvariant::Value::from("pbc"));
        args.insert("go_intent", zbus::zvariant::Value::from(go_intent.min(15) as u32));

        p2p.connect(args)
            .await
            .map_err(|e| P2pError::Connection(format!("Failed to connect: {}", e)))?;

        Ok(())
    }

    /// Create a P2P group (become Group Owner)
    pub async fn create_group(&self) -> Result<(), P2pError> {
        info!("Creating P2P group on {}", self.interface);

        let (_, p2p) = self.get_p2p_proxy().await?;

        let args: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
        p2p.group_add(args)
            .await
            .map_err(|e| P2pError::Group(format!("Failed to create group: {}", e)))?;

        Ok(())
    }

    /// Remove current P2P group
    pub async fn remove_group(&self) -> Result<(), P2pError> {
        info!("Removing P2P group");

        let (_, p2p) = self.get_p2p_proxy().await?;

        p2p.disconnect()
            .await
            .map_err(|e| P2pError::Group(format!("Failed to remove group: {}", e)))?;

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

/// Monitor NetworkManager P2P signals for peer discovery
async fn monitor_nm_p2p_signals(
    conn: Connection,
    device_path: zbus::zvariant::OwnedObjectPath,
    event_tx: broadcast::Sender<P2pEvent>,
    discovered_devices: Arc<RwLock<HashMap<String, P2pDevice>>>,
    stop_rx: &mut mpsc::Receiver<()>,
) -> Result<(), P2pError> {
    use futures_util::StreamExt;

    let p2p = NmWifiP2PProxy::builder(&conn)
        .path(device_path)
        .map_err(|e| P2pError::Dbus(e.to_string()))?
        .build()
        .await
        .map_err(|e| P2pError::Dbus(e.to_string()))?;

    // Subscribe to signals
    let mut peer_added = p2p.receive_peer_added().await?;
    let mut peer_removed = p2p.receive_peer_removed().await?;

    // Also poll existing peers periodically
    let mut poll_interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            Some(signal) = peer_added.next() => {
                if let Ok(args) = signal.args() {
                    let peer_path = &args.peer;
                    if let Ok(device) = get_nm_peer_info(&conn, peer_path).await {
                        let is_new = {
                            let mut devices = discovered_devices.write().await;
                            let was_present = devices.contains_key(&device.address);
                            devices.insert(device.address.clone(), device.clone());
                            !was_present
                        };

                        if is_new {
                            info!("P2P peer found via NM: {} ({})", device.name, device.address);
                            let _ = event_tx.send(P2pEvent::DeviceFound(device));
                        }
                    }
                }
            }

            Some(signal) = peer_removed.next() => {
                if let Ok(args) = signal.args() {
                    let peer_path = args.peer.as_str();
                    // Extract address from path (last component)
                    if let Some(addr) = peer_path.rsplit('/').next() {
                        let address = addr.replace('_', ":");
                        let mut devices = discovered_devices.write().await;
                        if devices.remove(&address).is_some() {
                            info!("P2P peer lost via NM: {}", address);
                            let _ = event_tx.send(P2pEvent::DeviceLost(address));
                        }
                    }
                }
            }

            _ = poll_interval.tick() => {
                // Poll for current peers
                if let Ok(peers) = p2p.peers().await {
                    for peer_path in peers {
                        if let Ok(device) = get_nm_peer_info(&conn, &peer_path).await {
                            let mut devices = discovered_devices.write().await;
                            if !devices.contains_key(&device.address) {
                                info!("P2P peer found via NM poll: {} ({})", device.name, device.address);
                                devices.insert(device.address.clone(), device.clone());
                                let _ = event_tx.send(P2pEvent::DeviceFound(device.clone()));
                            }
                        }
                    }
                }
            }

            _ = stop_rx.recv() => {
                info!("NM P2P signal monitor stopped");
                break;
            }
        }
    }

    Ok(())
}

/// Get peer info from NetworkManager
async fn get_nm_peer_info(
    conn: &Connection,
    peer_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<P2pDevice, P2pError> {
    let peer = NmP2PPeerProxy::builder(conn)
        .path(peer_path.clone())
        .map_err(|e| P2pError::Dbus(e.to_string()))?
        .build()
        .await
        .map_err(|e| P2pError::Dbus(e.to_string()))?;

    let name = peer.name().await.unwrap_or_default();
    let address = peer.hw_address().await.unwrap_or_default();
    let manufacturer = peer.manufacturer().await.unwrap_or_default();
    let model = peer.model().await.unwrap_or_default();

    let device_type = if !manufacturer.is_empty() || !model.is_empty() {
        format!("{} {}", manufacturer, model).trim().to_string()
    } else {
        "Unknown".to_string()
    };

    Ok(P2pDevice {
        address,
        name,
        device_type,
        config_methods: 0,
        device_capability: 0,
        group_capability: 0,
    })
}

/// Monitor P2P D-Bus signals for device discovery (wpa_supplicant)
async fn monitor_p2p_signals(
    conn: Connection,
    interface: String,
    event_tx: broadcast::Sender<P2pEvent>,
    discovered_devices: Arc<RwLock<HashMap<String, P2pDevice>>>,
    group_info: Arc<RwLock<Option<P2pGroupInfo>>>,
    stop_rx: &mut mpsc::Receiver<()>,
) -> Result<(), P2pError> {
    use futures_util::StreamExt;

    let wpa = WpaSupplicantProxy::new(&conn)
        .await
        .map_err(|e| P2pError::Dbus(e.to_string()))?;

    let iface_path = wpa
        .get_interface(&interface)
        .await
        .map_err(|e| P2pError::NotAvailable(e.to_string()))?;

    let p2p = P2PDeviceProxy::builder(&conn)
        .path(iface_path.clone())
        .map_err(|e| P2pError::Dbus(e.to_string()))?
        .build()
        .await
        .map_err(|e| P2pError::Dbus(e.to_string()))?;

    // Subscribe to signals
    let mut device_found = p2p.receive_device_found().await?;
    let mut device_lost = p2p.receive_device_lost().await?;
    let mut group_started = p2p.receive_group_started().await?;
    let mut group_finished = p2p.receive_group_finished().await?;

    // Also poll existing peers periodically
    let mut poll_interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            Some(signal) = device_found.next() => {
                if let Ok(args) = signal.args() {
                    let peer_path = &args.path;
                    if let Ok(device) = get_peer_info(&conn, peer_path).await {
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

            Some(signal) = device_lost.next() => {
                if let Ok(args) = signal.args() {
                    let peer_path = args.path.as_str();
                    // Extract address from path (last component)
                    if let Some(addr) = peer_path.rsplit('/').next() {
                        let address = addr.replace('_', ":");
                        let mut devices = discovered_devices.write().await;
                        if devices.remove(&address).is_some() {
                            info!("P2P device lost: {}", address);
                            let _ = event_tx.send(P2pEvent::DeviceLost(address));
                        }
                    }
                }
            }

            Some(signal) = group_started.next() => {
                if let Ok(args) = signal.args() {
                    let props = args.properties;

                    let iface = props.get("interface")
                        .and_then(|v| v.try_clone().ok())
                        .and_then(|v| TryInto::<String>::try_into(v).ok())
                        .unwrap_or_default();

                    let ssid = props.get("SSID")
                        .and_then(|v| v.try_clone().ok())
                        .and_then(|v| TryInto::<Vec<u8>>::try_into(v).ok())
                        .map(|b| String::from_utf8_lossy(&b).to_string())
                        .unwrap_or_default();

                    let role = props.get("role")
                        .and_then(|v| v.try_clone().ok())
                        .and_then(|v| TryInto::<String>::try_into(v).ok())
                        .map(|r| if r == "GO" { P2pRole::GroupOwner } else { P2pRole::Client })
                        .unwrap_or(P2pRole::Client);

                    let freq = props.get("frequency")
                        .and_then(|v| v.try_clone().ok())
                        .and_then(|v| TryInto::<u32>::try_into(v).ok())
                        .unwrap_or(0);

                    let passphrase = props.get("passphrase")
                        .and_then(|v| v.try_clone().ok())
                        .and_then(|v| TryInto::<String>::try_into(v).ok());

                    let info = P2pGroupInfo {
                        interface: iface.clone(),
                        ssid,
                        role,
                        frequency: freq,
                        passphrase,
                    };

                    info!("P2P group started: {} ({:?})", info.interface, info.role);
                    *group_info.write().await = Some(info.clone());
                    let _ = event_tx.send(P2pEvent::GroupStarted(info));
                }
            }

            Some(_signal) = group_finished.next() => {
                info!("P2P group finished");
                *group_info.write().await = None;
                let _ = event_tx.send(P2pEvent::GroupFinished);
            }

            _ = poll_interval.tick() => {
                // Poll existing peers
                if let Ok(peers) = p2p.peers().await {
                    for peer_path in peers {
                        if let Ok(device) = get_peer_info(&conn, &peer_path).await {
                            let mut devices = discovered_devices.write().await;
                            if !devices.contains_key(&device.address) {
                                info!("P2P device found (poll): {} ({})", device.name, device.address);
                                devices.insert(device.address.clone(), device.clone());
                                let _ = event_tx.send(P2pEvent::DeviceFound(device));
                            }
                        }
                    }
                }
            }

            _ = stop_rx.recv() => {
                info!("P2P monitor stopping");
                break;
            }
        }
    }

    Ok(())
}

/// Get peer information from D-Bus
async fn get_peer_info(
    conn: &Connection,
    peer_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<P2pDevice, P2pError> {
    let peer = PeerProxy::builder(conn)
        .path(peer_path.clone())
        .map_err(|e| P2pError::Dbus(e.to_string()))?
        .build()
        .await
        .map_err(|e| P2pError::Dbus(e.to_string()))?;

    let name = peer.device_name().await.unwrap_or_default();
    let addr_bytes = peer.device_address().await.unwrap_or_default();
    let address = addr_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    let device_type_bytes = peer.primary_device_type().await.unwrap_or_default();
    let device_type = if device_type_bytes.len() >= 2 {
        format!("{}-{}", device_type_bytes[0], device_type_bytes[1])
    } else {
        "unknown".to_string()
    };

    let config_methods = peer.config_method().await.unwrap_or(0);
    let device_capability = peer.device_capability().await.unwrap_or(0);
    let group_capability = peer.group_capability().await.unwrap_or(0);

    Ok(P2pDevice {
        address,
        name,
        device_type,
        config_methods,
        device_capability,
        group_capability,
    })
}

/// Get IP address of an interface using pnet_datalink
fn get_interface_ip(interface: &str) -> Option<IpAddr> {
    for iface in pnet_datalink::interfaces() {
        if iface.name == interface {
            for ip in iface.ips {
                match ip.ip() {
                    IpAddr::V4(addr) if !addr.is_loopback() && !addr.is_link_local() => {
                        return Some(IpAddr::V4(addr));
                    }
                    _ => continue,
                }
            }
        }
    }
    None
}

/// P2P-related errors
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("D-Bus error: {0}")]
    Dbus(String),

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Group error: {0}")]
    Group(String),

    #[error("Not available: {0}")]
    NotAvailable(String),
}

impl From<zbus::Error> for P2pError {
    fn from(e: zbus::Error) -> Self {
        P2pError::Dbus(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_format() {
        let addr_bytes: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let address = addr_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(address, "aa:bb:cc:dd:ee:ff");
    }
}
