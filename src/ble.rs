#![allow(dead_code)]
//! BLE discovery for Cosmic Konnect
//!
//! Uses BlueZ via D-Bus (bluer crate) to:
//! - Scan for other Cosmic Konnect devices
//! - Read device info from GATT characteristics
//!
//! Note: GATT server (advertising) is handled separately as it requires
//! more complex setup with BlueZ.

use bluer::{Adapter, AdapterEvent, Address, Device};
use tokio_stream::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Cosmic Konnect BLE UUIDs (must match Android implementation)
// Pattern: c05a1c00-a0aa-3c70-XXXX-000000000001

/// Service UUID: c05a1c00-a0aa-3c70-0000-000000000001
pub const GATT_SERVICE_UUID: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700000000000000001);

/// Device ID characteristic
pub const CHAR_DEVICE_ID: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700001000000000001);

/// Device Name characteristic
pub const CHAR_DEVICE_NAME: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700002000000000001);

/// Device Type characteristic
pub const CHAR_DEVICE_TYPE: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700003000000000001);

/// IP Address characteristic
pub const CHAR_IP_ADDRESS: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700004000000000001);

/// TCP Port characteristic
pub const CHAR_TCP_PORT: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700005000000000001);

/// Protocol Version characteristic
pub const CHAR_PROTOCOL_VERSION: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700006000000000001);

/// Connection Request characteristic
pub const CHAR_CONNECTION_REQUEST: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700007000000000001);

/// Scan timeout
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

/// Device discovered via BLE
#[derive(Debug, Clone)]
pub struct BleDiscoveredDevice {
    pub ble_address: Address,
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub ip_addresses: Vec<String>,
    pub tcp_port: u16,
    pub protocol_version: u8,
    pub rssi: Option<i16>,
}

/// Events from BLE discovery
#[derive(Debug, Clone)]
pub enum BleEvent {
    /// A new device was discovered via BLE
    DeviceDiscovered(BleDiscoveredDevice),
    /// BLE scan started
    ScanStarted,
    /// BLE scan stopped
    ScanStopped,
    /// Error during BLE operation
    Error(String),
}

/// BLE scanner for discovering Cosmic Konnect devices
pub struct BleScanner {
    event_tx: broadcast::Sender<BleEvent>,
    discovered_devices: Arc<RwLock<HashMap<Address, BleDiscoveredDevice>>>,
}

impl BleScanner {
    /// Create a new BLE scanner
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            event_tx,
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to BLE events
    pub fn subscribe(&self) -> broadcast::Receiver<BleEvent> {
        self.event_tx.subscribe()
    }

    /// Start scanning for devices
    pub async fn start_scan(&self) -> Result<(), BleError> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;

        info!(
            "BLE adapter: {} ({})",
            adapter.name(),
            adapter.address().await?
        );

        // Ensure adapter is powered on
        if !adapter.is_powered().await? {
            info!("Powering on BLE adapter...");
            adapter.set_powered(true).await?;
        }

        let event_tx = self.event_tx.clone();
        let discovered_devices = self.discovered_devices.clone();

        tokio::spawn(async move {
            let _ = event_tx.send(BleEvent::ScanStarted);

            if let Err(e) = run_scanner(&adapter, &event_tx, &discovered_devices).await {
                error!("BLE scanner error: {}", e);
                let _ = event_tx.send(BleEvent::Error(e.to_string()));
            }

            let _ = event_tx.send(BleEvent::ScanStopped);
        });

        Ok(())
    }

    /// Get list of discovered devices
    pub async fn get_discovered_devices(&self) -> Vec<BleDiscoveredDevice> {
        self.discovered_devices
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }
}

impl Default for BleScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the BLE scanner
async fn run_scanner(
    adapter: &Adapter,
    event_tx: &broadcast::Sender<BleEvent>,
    discovered_devices: &Arc<RwLock<HashMap<Address, BleDiscoveredDevice>>>,
) -> Result<(), BleError> {
    info!("Starting BLE scan...");

    // Set discovery filter to look for our service
    let filter = bluer::DiscoveryFilter {
        uuids: std::collections::HashSet::from([GATT_SERVICE_UUID]),
        ..Default::default()
    };
    adapter.set_discovery_filter(filter).await?;

    let events = adapter.discover_devices().await?;
    tokio::pin!(events);

    let timeout = tokio::time::sleep(SCAN_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(event) = events.next() => {
                match event {
                    AdapterEvent::DeviceAdded(addr) => {
                        if let Err(e) = handle_device_discovered(
                            adapter, addr, event_tx, discovered_devices
                        ).await {
                            debug!("Failed to handle device {}: {}", addr, e);
                        }
                    }
                    AdapterEvent::DeviceRemoved(addr) => {
                        debug!("BLE device removed: {}", addr);
                    }
                    _ => {}
                }
            }
            _ = &mut timeout => {
                info!("BLE scan timeout");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a discovered BLE device
async fn handle_device_discovered(
    adapter: &Adapter,
    addr: Address,
    event_tx: &broadcast::Sender<BleEvent>,
    discovered_devices: &Arc<RwLock<HashMap<Address, BleDiscoveredDevice>>>,
) -> Result<(), BleError> {
    let device = adapter.device(addr)?;

    // Check if device advertises our service UUID
    let uuids = device.uuids().await?.unwrap_or_default();
    if !uuids.contains(&GATT_SERVICE_UUID) {
        return Ok(()); // Not a Cosmic Konnect device
    }

    info!("Found Cosmic Konnect device: {}", addr);

    // Get RSSI
    let rssi = device.rssi().await.ok().flatten();

    // Connect to read characteristics
    if !device.is_connected().await? {
        info!("Connecting to {} to read device info...", addr);
        match tokio::time::timeout(Duration::from_secs(10), device.connect()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!("Failed to connect to {}: {}", addr, e);
                return Ok(());
            }
            Err(_) => {
                warn!("Connection to {} timed out", addr);
                return Ok(());
            }
        }
    }

    // Wait for services to be resolved
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Read characteristics
    match read_device_characteristics(&device).await {
        Ok(device_info) => {
            let ble_device = BleDiscoveredDevice {
                ble_address: addr,
                device_id: device_info.device_id,
                device_name: device_info.device_name,
                device_type: device_info.device_type,
                ip_addresses: device_info.ip_addresses,
                tcp_port: device_info.tcp_port,
                protocol_version: device_info.protocol_version,
                rssi,
            };

            info!(
                "BLE device info: {} ({}) IPs: {:?}",
                ble_device.device_name, ble_device.device_id, ble_device.ip_addresses
            );

            // Store and emit event
            discovered_devices
                .write()
                .await
                .insert(addr, ble_device.clone());
            let _ = event_tx.send(BleEvent::DeviceDiscovered(ble_device));
        }
        Err(e) => {
            warn!("Failed to read characteristics from {}: {}", addr, e);
        }
    }

    // Disconnect after reading
    device.disconnect().await.ok();

    Ok(())
}

/// Device info read from characteristics
struct DeviceInfo {
    device_id: String,
    device_name: String,
    device_type: String,
    ip_addresses: Vec<String>,
    tcp_port: u16,
    protocol_version: u8,
}

/// Read device characteristics
async fn read_device_characteristics(device: &Device) -> Result<DeviceInfo, BleError> {
    let services = device.services().await?;

    // Find our service
    for service in services {
        if service.uuid().await? != GATT_SERVICE_UUID {
            continue;
        }

        let mut device_id = String::new();
        let mut device_name = String::new();
        let mut device_type = String::new();
        let mut ip_addresses = Vec::new();
        let mut tcp_port = 1716u16;
        let mut protocol_version = 7u8;

        for char in service.characteristics().await? {
            let uuid = char.uuid().await?;

            // Try to read the characteristic
            let value = match char.read().await {
                Ok(v) => v,
                Err(e) => {
                    debug!("Failed to read characteristic {}: {}", uuid, e);
                    continue;
                }
            };

            let value_str = String::from_utf8_lossy(&value).to_string();

            if uuid == CHAR_DEVICE_ID {
                device_id = value_str;
            } else if uuid == CHAR_DEVICE_NAME {
                device_name = value_str;
            } else if uuid == CHAR_DEVICE_TYPE {
                device_type = value_str;
            } else if uuid == CHAR_IP_ADDRESS {
                ip_addresses = value_str
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
            } else if uuid == CHAR_TCP_PORT {
                tcp_port = value_str.parse().unwrap_or(1716);
            } else if uuid == CHAR_PROTOCOL_VERSION {
                protocol_version = value_str.parse().unwrap_or(7);
            }
        }

        if !device_id.is_empty() && !device_name.is_empty() {
            return Ok(DeviceInfo {
                device_id,
                device_name,
                device_type,
                ip_addresses,
                tcp_port,
                protocol_version,
            });
        }
    }

    Err(BleError::ServiceNotFound)
}

/// BLE-related errors
#[derive(Debug, thiserror::Error)]
pub enum BleError {
    #[error("BLE error: {0}")]
    Bluer(#[from] bluer::Error),

    #[error("Cosmic Konnect service not found on device")]
    ServiceNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_format() {
        // Verify UUIDs are valid
        assert!(!GATT_SERVICE_UUID.is_nil());
        assert!(!CHAR_DEVICE_ID.is_nil());
        // Check that UUID string matches expected format
        let uuid_str = GATT_SERVICE_UUID.to_string();
        assert!(uuid_str.starts_with("c05a1c00-a0aa-3c70-0000"));
    }
}
