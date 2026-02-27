//! GATT server and client for BLE communication
//!
//! Defines the Cosmic Konnect BLE service with characteristics for
//! device discovery and connection establishment.

use bluer::adv::Advertisement;
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicRead, CharacteristicWrite,
    CharacteristicWriteMethod, Service,
};
use bluer::{Adapter, AdapterEvent, Address, Device};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_stream::StreamExt;
use tracing::{debug, error, info};
use uuid::Uuid;

// Cosmic Konnect BLE UUIDs (must match Android implementation)
// Pattern: c05a1c00-a0aa-3c70-XXXX-000000000001

/// Service UUID
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

/// Hotspot SSID characteristic
pub const CHAR_HOTSPOT_SSID: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700008000000000001);

/// Hotspot Password characteristic
pub const CHAR_HOTSPOT_PASSWORD: Uuid = Uuid::from_u128(0xc05a1c00a0aa3c700009000000000001);

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

/// Events from BLE operations
#[derive(Debug, Clone)]
pub enum BleEvent {
    DeviceDiscovered(BleDiscoveredDevice),
    ScanStarted,
    ScanStopped,
    Error(String),
}

/// Device identity for BLE advertising
#[derive(Debug, Clone)]
pub struct BleDeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub tcp_port: u16,
    pub protocol_version: u8,
    pub hotspot_ssid: Option<String>,
    pub hotspot_password: Option<String>,
}

/// BLE Scanner
pub struct BleScanner {
    event_tx: broadcast::Sender<BleEvent>,
    discovered: Arc<RwLock<HashMap<Address, BleDiscoveredDevice>>>,
}

impl BleScanner {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            event_tx,
            discovered: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BleEvent> {
        self.event_tx.subscribe()
    }

    pub async fn start_scan(&self) -> Result<(), BleError> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;

        info!("BLE scanner using: {} ({})", adapter.name(), adapter.address().await?);

        if !adapter.is_powered().await? {
            adapter.set_powered(true).await?;
        }

        let event_tx = self.event_tx.clone();
        let discovered = self.discovered.clone();

        tokio::spawn(async move {
            let _ = event_tx.send(BleEvent::ScanStarted);

            if let Err(e) = run_scan(&adapter, &event_tx, &discovered).await {
                error!("BLE scan error: {}", e);
                let _ = event_tx.send(BleEvent::Error(e.to_string()));
            }

            let _ = event_tx.send(BleEvent::ScanStopped);
        });

        Ok(())
    }

    pub async fn get_discovered(&self) -> Vec<BleDiscoveredDevice> {
        self.discovered.read().await.values().cloned().collect()
    }
}

impl Default for BleScanner {
    fn default() -> Self {
        Self::new()
    }
}

async fn run_scan(
    adapter: &Adapter,
    event_tx: &broadcast::Sender<BleEvent>,
    discovered: &Arc<RwLock<HashMap<Address, BleDiscoveredDevice>>>,
) -> Result<(), BleError> {
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
                if let AdapterEvent::DeviceAdded(addr) = event {
                    if let Err(e) = handle_device(adapter, addr, event_tx, discovered).await {
                        debug!("Device {} error: {}", addr, e);
                    }
                }
            }
            _ = &mut timeout => break,
        }
    }

    Ok(())
}

async fn handle_device(
    adapter: &Adapter,
    addr: Address,
    event_tx: &broadcast::Sender<BleEvent>,
    discovered: &Arc<RwLock<HashMap<Address, BleDiscoveredDevice>>>,
) -> Result<(), BleError> {
    let device = adapter.device(addr)?;

    let uuids = device.uuids().await?.unwrap_or_default();
    if !uuids.contains(&GATT_SERVICE_UUID) {
        return Ok(());
    }

    info!("Found Cosmic Konnect device: {}", addr);
    let rssi = device.rssi().await.ok().flatten();

    if !device.is_connected().await? {
        match tokio::time::timeout(Duration::from_secs(10), device.connect()).await {
            Ok(Ok(())) => {}
            _ => return Ok(()),
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    if let Ok(info) = read_characteristics(&device).await {
        let ble_device = BleDiscoveredDevice {
            ble_address: addr,
            device_id: info.device_id,
            device_name: info.device_name,
            device_type: info.device_type,
            ip_addresses: info.ip_addresses,
            tcp_port: info.tcp_port,
            protocol_version: info.protocol_version,
            rssi,
        };

        discovered.write().await.insert(addr, ble_device.clone());
        let _ = event_tx.send(BleEvent::DeviceDiscovered(ble_device));
    }

    device.disconnect().await.ok();
    Ok(())
}

struct DeviceInfo {
    device_id: String,
    device_name: String,
    device_type: String,
    ip_addresses: Vec<String>,
    tcp_port: u16,
    protocol_version: u8,
}

async fn read_characteristics(device: &Device) -> Result<DeviceInfo, BleError> {
    let services = device.services().await?;

    for service in services {
        if service.uuid().await? != GATT_SERVICE_UUID {
            continue;
        }

        let mut info = DeviceInfo {
            device_id: String::new(),
            device_name: String::new(),
            device_type: String::new(),
            ip_addresses: Vec::new(),
            tcp_port: 51716,
            protocol_version: 1,
        };

        for char in service.characteristics().await? {
            let uuid = char.uuid().await?;
            let value = match char.read().await {
                Ok(v) => String::from_utf8_lossy(&v).to_string(),
                Err(_) => continue,
            };

            match uuid {
                u if u == CHAR_DEVICE_ID => info.device_id = value,
                u if u == CHAR_DEVICE_NAME => info.device_name = value,
                u if u == CHAR_DEVICE_TYPE => info.device_type = value,
                u if u == CHAR_IP_ADDRESS => {
                    info.ip_addresses = value.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
                }
                u if u == CHAR_TCP_PORT => info.tcp_port = value.parse().unwrap_or(51716),
                u if u == CHAR_PROTOCOL_VERSION => info.protocol_version = value.parse().unwrap_or(1),
                _ => {}
            }
        }

        if !info.device_id.is_empty() && !info.device_name.is_empty() {
            return Ok(info);
        }
    }

    Err(BleError::ServiceNotFound)
}

/// BLE Advertiser (GATT Server)
pub struct BleAdvertiser {
    identity: BleDeviceIdentity,
    event_tx: broadcast::Sender<BleAdvertiserEvent>,
    stop_tx: Option<mpsc::Sender<()>>,
}

#[derive(Debug, Clone)]
pub enum BleAdvertiserEvent {
    Started,
    Stopped,
    ConnectionRequested { requester_id: String, requester_name: String },
    Error(String),
}

impl BleAdvertiser {
    pub fn new(identity: BleDeviceIdentity) -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            identity,
            event_tx,
            stop_tx: None,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BleAdvertiserEvent> {
        self.event_tx.subscribe()
    }

    fn get_ip_addresses() -> Vec<String> {
        let mut addrs = Vec::new();

        // Use std::net to get local addresses
        if let Ok(interfaces) = std::fs::read_dir("/sys/class/net") {
            for entry in interfaces.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" {
                    continue;
                }

                // Try to get IP from /proc
                if let Ok(output) = std::process::Command::new("ip")
                    .args(["-4", "addr", "show", &name])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.contains("inet ") {
                            if let Some(addr) = line.split_whitespace().nth(1) {
                                if let Some(ip) = addr.split('/').next() {
                                    if !ip.starts_with("127.") {
                                        addrs.push(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        addrs
    }

    pub async fn start(&mut self) -> Result<(), BleError> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;

        info!("BLE advertiser using: {} ({})", adapter.name(), adapter.address().await?);

        if !adapter.is_powered().await? {
            adapter.set_powered(true).await?;
        }

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        self.stop_tx = Some(stop_tx);

        let identity = self.identity.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = run_gatt_server(&adapter, identity, &event_tx, &mut stop_rx).await {
                error!("GATT server error: {}", e);
                let _ = event_tx.send(BleAdvertiserEvent::Error(e.to_string()));
            }
            let _ = event_tx.send(BleAdvertiserEvent::Stopped);
        });

        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(()).await;
        }
    }
}

async fn run_gatt_server(
    adapter: &Adapter,
    identity: BleDeviceIdentity,
    event_tx: &broadcast::Sender<BleAdvertiserEvent>,
    stop_rx: &mut mpsc::Receiver<()>,
) -> Result<(), BleError> {
    info!("Starting GATT server...");

    // Create characteristic values
    let device_id = Arc::new(RwLock::new(identity.device_id.clone()));
    let device_name = Arc::new(RwLock::new(identity.device_name.clone()));
    let device_type = Arc::new(RwLock::new(identity.device_type.clone()));
    let tcp_port = Arc::new(RwLock::new(identity.tcp_port.to_string()));
    let protocol_version = Arc::new(RwLock::new(identity.protocol_version.to_string()));

    // Create read handlers
    let device_id_r = device_id.clone();
    let device_name_r = device_name.clone();
    let device_type_r = device_type.clone();
    let tcp_port_r = tcp_port.clone();
    let protocol_version_r = protocol_version.clone();
    let event_tx_w = event_tx.clone();

    // Build characteristics
    let mut chars = vec![
        Characteristic {
            uuid: CHAR_DEVICE_ID,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = device_id_r.clone();
                    Box::pin(async move { Ok(v.read().await.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        Characteristic {
            uuid: CHAR_DEVICE_NAME,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = device_name_r.clone();
                    Box::pin(async move { Ok(v.read().await.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        Characteristic {
            uuid: CHAR_DEVICE_TYPE,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = device_type_r.clone();
                    Box::pin(async move { Ok(v.read().await.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        Characteristic {
            uuid: CHAR_IP_ADDRESS,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    Box::pin(async move {
                        let ips = BleAdvertiser::get_ip_addresses().join(",");
                        Ok(ips.as_bytes().to_vec())
                    })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        Characteristic {
            uuid: CHAR_TCP_PORT,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = tcp_port_r.clone();
                    Box::pin(async move { Ok(v.read().await.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        Characteristic {
            uuid: CHAR_PROTOCOL_VERSION,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = protocol_version_r.clone();
                    Box::pin(async move { Ok(v.read().await.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        Characteristic {
            uuid: CHAR_CONNECTION_REQUEST,
            write: Some(CharacteristicWrite {
                write: true,
                method: CharacteristicWriteMethod::Fun(Box::new(move |data, _| {
                    let tx = event_tx_w.clone();
                    Box::pin(async move {
                        if let Ok(json) = String::from_utf8(data) {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                                // Accept both camelCase (Android) and snake_case keys
                                let id = v["deviceId"].as_str()
                                    .or_else(|| v["device_id"].as_str())
                                    .unwrap_or("unknown").to_string();
                                let name = v["deviceName"].as_str()
                                    .or_else(|| v["device_name"].as_str())
                                    .unwrap_or("Unknown").to_string();
                                let _ = tx.send(BleAdvertiserEvent::ConnectionRequested {
                                    requester_id: id,
                                    requester_name: name,
                                });
                            }
                        }
                        Ok(())
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    // Add hotspot SSID characteristic if available
    if let Some(ref ssid) = identity.hotspot_ssid {
        let ssid_val = ssid.clone();
        chars.push(Characteristic {
            uuid: CHAR_HOTSPOT_SSID,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = ssid_val.clone();
                    Box::pin(async move { Ok(v.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    // Add hotspot password characteristic if available
    if let Some(ref password) = identity.hotspot_password {
        let password_val = password.clone();
        chars.push(Characteristic {
            uuid: CHAR_HOTSPOT_PASSWORD,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_| {
                    let v = password_val.clone();
                    Box::pin(async move { Ok(v.as_bytes().to_vec()) })
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    let service = Service {
        uuid: GATT_SERVICE_UUID,
        primary: true,
        characteristics: chars,
        ..Default::default()
    };

    let app = Application {
        services: vec![service],
        ..Default::default()
    };

    let app_handle = adapter.serve_gatt_application(app).await?;
    info!("GATT application registered");

    // Create advertisement
    let adv_name = format!("CK-{}", &identity.device_name[..identity.device_name.len().min(16)]);
    let le_adv = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![GATT_SERVICE_UUID].into_iter().collect(),
        local_name: Some(adv_name.clone()),
        discoverable: Some(true),
        ..Default::default()
    };

    let adv_handle = adapter.advertise(le_adv).await?;
    info!("BLE advertising as: {}", adv_name);

    let _ = event_tx.send(BleAdvertiserEvent::Started);

    // Wait for stop
    stop_rx.recv().await;

    info!("Stopping BLE advertising...");
    drop(adv_handle);
    drop(app_handle);

    Ok(())
}

/// BLE errors
#[derive(Debug, thiserror::Error)]
pub enum BleError {
    #[error("BLE error: {0}")]
    Bluer(#[from] bluer::Error),

    #[error("Service not found")]
    ServiceNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
