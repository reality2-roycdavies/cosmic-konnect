#![allow(dead_code)]
//! Unified Discovery Manager for Cosmic Konnect
//!
//! Coordinates multiple discovery mechanisms:
//! - UDP broadcast (traditional KDE Connect discovery)
//! - BLE scanning (discovers nearby devices via Bluetooth)
//! - Wi-Fi Direct/P2P (creates direct connections)

use crate::ble::{BleAdvertiser, BleAdvertiserEvent, BleDeviceIdentity, BleEvent, BleScanner};
use crate::discovery::{DiscoveryConfig, DiscoveryEvent, DiscoveryService};
use crate::protocol::IdentityPacketBody;
use crate::wifidirect::{P2pEvent, WifiDirectManager};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

/// Discovery method that found the device
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiscoveryMethod {
    UdpBroadcast,
    Ble,
    WifiDirect,
}

/// Unified discovered device information
#[derive(Debug, Clone)]
pub struct UnifiedDevice {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub ip_addresses: Vec<IpAddr>,
    pub tcp_port: u16,
    pub discovery_method: DiscoveryMethod,
    pub last_seen: Instant,
    /// BLE-specific info
    pub ble_address: Option<String>,
    pub rssi: Option<i16>,
    /// Wi-Fi Direct specific info
    pub p2p_address: Option<String>,
}

/// Events from unified discovery
#[derive(Debug, Clone)]
pub enum UnifiedDiscoveryEvent {
    /// A device was discovered or updated
    DeviceDiscovered(UnifiedDevice),
    /// A device was lost (timeout)
    DeviceLost(String),
    /// Connection to a device is available
    ConnectionAvailable {
        device_id: String,
        ip_address: IpAddr,
        tcp_port: u16,
    },
}

/// Configuration for unified discovery
#[derive(Debug, Clone)]
pub struct UnifiedDiscoveryConfig {
    /// Enable UDP broadcast discovery
    pub enable_udp: bool,
    /// Enable BLE discovery (scanning)
    pub enable_ble: bool,
    /// Enable BLE advertising (so others can discover us)
    pub enable_ble_advertise: bool,
    /// Enable Wi-Fi Direct discovery
    pub enable_wifi_direct: bool,
    /// Wi-Fi interface for P2P (e.g., "wlan0")
    pub wifi_interface: String,
    /// Device timeout for considering a device lost
    pub device_timeout: Duration,
    /// Our device identity for advertising
    pub device_id: String,
    /// Our device name for advertising
    pub device_name: String,
    /// Our device type for advertising
    pub device_type: String,
    /// TCP port for connections
    pub tcp_port: u16,
}

impl Default for UnifiedDiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_udp: true,
            enable_ble: true,
            enable_ble_advertise: true,
            enable_wifi_direct: false, // Disabled by default as it requires setup
            wifi_interface: "wlan0".to_string(),
            device_timeout: Duration::from_secs(60),
            device_id: String::new(),
            device_name: String::new(),
            device_type: "desktop".to_string(),
            tcp_port: 17161, // CKP default port
        }
    }
}

/// Unified Discovery Manager
pub struct UnifiedDiscoveryManager {
    config: UnifiedDiscoveryConfig,
    identity: IdentityPacketBody,
    devices: Arc<RwLock<HashMap<String, UnifiedDevice>>>,
    event_tx: broadcast::Sender<UnifiedDiscoveryEvent>,
    /// Keep BLE advertiser alive to maintain advertising
    ble_advertiser: Arc<RwLock<Option<BleAdvertiser>>>,
}

impl UnifiedDiscoveryManager {
    /// Create a new unified discovery manager
    pub fn new(identity: IdentityPacketBody, config: UnifiedDiscoveryConfig) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            config,
            identity,
            devices: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            ble_advertiser: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to discovery events
    pub fn subscribe(&self) -> broadcast::Receiver<UnifiedDiscoveryEvent> {
        self.event_tx.subscribe()
    }

    /// Get list of all discovered devices
    pub async fn get_devices(&self) -> Vec<UnifiedDevice> {
        self.devices.read().await.values().cloned().collect()
    }

    /// Start all enabled discovery mechanisms
    pub async fn start(&self) -> Result<(), UnifiedDiscoveryError> {
        info!("Starting unified discovery");

        // Start UDP discovery
        if self.config.enable_udp {
            self.start_udp_discovery().await?;
        }

        // Start BLE discovery
        if self.config.enable_ble {
            if let Err(e) = self.start_ble_discovery().await {
                warn!("BLE discovery not available: {}", e);
            }
        }

        // Start Wi-Fi Direct discovery
        if self.config.enable_wifi_direct {
            if let Err(e) = self.start_wifi_direct().await {
                warn!("Wi-Fi Direct not available: {}", e);
            }
        }

        // Start device cleanup task
        self.start_cleanup_task().await;

        Ok(())
    }

    async fn start_udp_discovery(&self) -> Result<(), UnifiedDiscoveryError> {
        info!("Starting UDP broadcast discovery");

        let udp_config = DiscoveryConfig::default();
        let mut udp_service = DiscoveryService::new(self.identity.clone(), udp_config);
        let mut udp_events = udp_service.subscribe();

        udp_service.start().await.map_err(|e| {
            UnifiedDiscoveryError::Udp(format!("Failed to start UDP discovery: {}", e))
        })?;

        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = udp_events.recv().await {
                match event {
                    DiscoveryEvent::DeviceDiscovered(device)
                    | DiscoveryEvent::DeviceUpdated(device) => {
                        let unified = UnifiedDevice {
                            device_id: device.identity.device_id.clone(),
                            device_name: device.identity.device_name.clone(),
                            device_type: device.identity.device_type.to_string(),
                            ip_addresses: vec![device.address],
                            tcp_port: device.tcp_port,
                            discovery_method: DiscoveryMethod::UdpBroadcast,
                            last_seen: Instant::now(),
                            ble_address: None,
                            rssi: None,
                            p2p_address: None,
                        };

                        add_or_update_device(&devices, &event_tx, unified).await;
                    }
                    DiscoveryEvent::DeviceLost(device_id) => {
                        let _ = event_tx.send(UnifiedDiscoveryEvent::DeviceLost(device_id));
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_ble_discovery(&self) -> Result<(), UnifiedDiscoveryError> {
        info!("Starting BLE discovery");

        // Start BLE scanner
        let scanner = BleScanner::new();
        let mut ble_events = scanner.subscribe();

        scanner
            .start_scan()
            .await
            .map_err(|e| UnifiedDiscoveryError::Ble(format!("Failed to start BLE scanner: {}", e)))?;

        // Start BLE advertiser if enabled and we have device identity
        if self.config.enable_ble_advertise && !self.config.device_id.is_empty() {
            let ble_identity = BleDeviceIdentity {
                device_id: self.config.device_id.clone(),
                device_name: self.config.device_name.clone(),
                device_type: self.config.device_type.clone(),
                tcp_port: self.config.tcp_port,
                protocol_version: 1, // CKP version 1
            };

            let mut advertiser = BleAdvertiser::new(ble_identity);
            let mut adv_events = advertiser.subscribe();

            match advertiser.start().await {
                Ok(()) => {
                    info!("BLE advertising started");

                    // Store advertiser to keep it alive (prevents stop signal from being sent)
                    *self.ble_advertiser.write().await = Some(advertiser);

                    // Handle advertiser events in background
                    tokio::spawn(async move {
                        while let Ok(event) = adv_events.recv().await {
                            match event {
                                BleAdvertiserEvent::ConnectionRequested {
                                    requester_id,
                                    requester_name,
                                } => {
                                    info!(
                                        "BLE connection request from: {} ({})",
                                        requester_name, requester_id
                                    );
                                }
                                BleAdvertiserEvent::Error(e) => {
                                    warn!("BLE advertiser error: {}", e);
                                }
                                _ => {}
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to start BLE advertising: {}", e);
                }
            }
        }

        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = ble_events.recv().await {
                if let BleEvent::DeviceDiscovered(ble_device) = event {
                    let ip_addresses: Vec<IpAddr> = ble_device
                        .ip_addresses
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect();

                    let unified = UnifiedDevice {
                        device_id: ble_device.device_id.clone(),
                        device_name: ble_device.device_name.clone(),
                        device_type: ble_device.device_type.clone(),
                        ip_addresses: ip_addresses.clone(),
                        tcp_port: ble_device.tcp_port,
                        discovery_method: DiscoveryMethod::Ble,
                        last_seen: Instant::now(),
                        ble_address: Some(ble_device.ble_address.to_string()),
                        rssi: ble_device.rssi,
                        p2p_address: None,
                    };

                    add_or_update_device(&devices, &event_tx, unified).await;

                    // Notify connection available if we have IPs
                    if let Some(ip) = ip_addresses.first() {
                        let _ = event_tx.send(UnifiedDiscoveryEvent::ConnectionAvailable {
                            device_id: ble_device.device_id,
                            ip_address: *ip,
                            tcp_port: ble_device.tcp_port,
                        });
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_wifi_direct(&self) -> Result<(), UnifiedDiscoveryError> {
        info!("Starting Wi-Fi Direct discovery");

        let manager = WifiDirectManager::new(&self.config.wifi_interface);

        if !manager.is_available().await {
            return Err(UnifiedDiscoveryError::WifiDirect(
                "Wi-Fi Direct not available".to_string(),
            ));
        }

        let mut p2p_events = manager.subscribe();

        manager
            .start_discovery()
            .await
            .map_err(|e| UnifiedDiscoveryError::WifiDirect(format!("Failed to start P2P: {}", e)))?;

        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = p2p_events.recv().await {
                match event {
                    P2pEvent::DeviceFound(p2p_device) => {
                        // P2P devices don't have connection info until connected
                        let unified = UnifiedDevice {
                            device_id: format!("p2p-{}", p2p_device.address.replace(':', "")),
                            device_name: p2p_device.name.clone(),
                            device_type: p2p_device.device_type.clone(),
                            ip_addresses: vec![],
                            tcp_port: 1716,
                            discovery_method: DiscoveryMethod::WifiDirect,
                            last_seen: Instant::now(),
                            ble_address: None,
                            rssi: None,
                            p2p_address: Some(p2p_device.address),
                        };

                        add_or_update_device(&devices, &event_tx, unified).await;
                    }
                    P2pEvent::Connected { ip_address, .. } => {
                        if let Some(ip) = ip_address {
                            // Update P2P devices with the new IP
                            let mut devices_map = devices.write().await;
                            for device in devices_map.values_mut() {
                                if device.discovery_method == DiscoveryMethod::WifiDirect
                                    && device.ip_addresses.is_empty()
                                {
                                    device.ip_addresses.push(ip);
                                    device.last_seen = Instant::now();

                                    let _ =
                                        event_tx.send(UnifiedDiscoveryEvent::ConnectionAvailable {
                                            device_id: device.device_id.clone(),
                                            ip_address: ip,
                                            tcp_port: device.tcp_port,
                                        });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    async fn start_cleanup_task(&self) {
        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();
        let timeout = self.config.device_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let mut devices_map = devices.write().await;
                let stale: Vec<String> = devices_map
                    .iter()
                    .filter(|(_, d)| d.last_seen.elapsed() > timeout)
                    .map(|(id, _)| id.clone())
                    .collect();

                for id in stale {
                    if let Some(device) = devices_map.remove(&id) {
                        info!("Device timeout: {}", device.device_name);
                        let _ = event_tx.send(UnifiedDiscoveryEvent::DeviceLost(id));
                    }
                }
            }
        });
    }
}

/// Add or update a device in the device map
async fn add_or_update_device(
    devices: &Arc<RwLock<HashMap<String, UnifiedDevice>>>,
    event_tx: &broadcast::Sender<UnifiedDiscoveryEvent>,
    new_device: UnifiedDevice,
) {
    let mut devices_map = devices.write().await;

    if let Some(existing) = devices_map.get_mut(&new_device.device_id) {
        // Merge IPs
        for ip in &new_device.ip_addresses {
            if !existing.ip_addresses.contains(ip) {
                existing.ip_addresses.push(*ip);
            }
        }

        // Update optional fields if new device has them
        if existing.ble_address.is_none() && new_device.ble_address.is_some() {
            existing.ble_address = new_device.ble_address;
        }
        if existing.p2p_address.is_none() && new_device.p2p_address.is_some() {
            existing.p2p_address = new_device.p2p_address;
        }
        if new_device.rssi.is_some() {
            existing.rssi = new_device.rssi;
        }

        existing.last_seen = Instant::now();

        let _ = event_tx.send(UnifiedDiscoveryEvent::DeviceDiscovered(existing.clone()));
    } else {
        info!(
            "New device discovered via {:?}: {} ({})",
            new_device.discovery_method, new_device.device_name, new_device.device_id
        );
        let _ = event_tx.send(UnifiedDiscoveryEvent::DeviceDiscovered(new_device.clone()));
        devices_map.insert(new_device.device_id.clone(), new_device);
    }
}

/// Unified discovery errors
#[derive(Debug, thiserror::Error)]
pub enum UnifiedDiscoveryError {
    #[error("UDP discovery error: {0}")]
    Udp(String),

    #[error("BLE error: {0}")]
    Ble(String),

    #[error("Wi-Fi Direct error: {0}")]
    WifiDirect(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DeviceType;

    #[test]
    fn test_config_default() {
        let config = UnifiedDiscoveryConfig::default();
        assert!(config.enable_udp);
        assert!(config.enable_ble);
        assert!(!config.enable_wifi_direct);
    }
}
