//! BLE discovery and advertising
//!
//! Uses BlueZ via D-Bus (bluer crate) to discover and advertise
//! Cosmic Konnect devices via Bluetooth Low Energy.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::DaemonError;
use crate::protocol::connection::ConnectionManager;
use crate::AppState;
use crate::gatt::{BleAdvertiser, BleScanner, BleDeviceIdentity, BleEvent};

/// Run the BLE subsystem
pub async fn run(state: Arc<RwLock<AppState>>, connection_manager: Arc<ConnectionManager>) -> Result<(), DaemonError> {
    info!("Starting BLE subsystem...");

    // Check if BLE is enabled
    {
        let state_guard = state.read().await;
        if !state_guard.config.ble_enabled {
            info!("BLE is disabled in configuration");
            return Ok(());
        }
    }

    // Create scanner and advertiser
    let scanner = Arc::new(BleScanner::new());
    let mut scanner_rx = scanner.subscribe();

    // Try to start a WiFi hotspot so Android can connect on isolated networks
    let hotspot_config = crate::wifi_hotspot::HotspotConfig::default();
    let (hotspot_ssid, hotspot_password) = match crate::wifi_hotspot::start_hotspot(&hotspot_config) {
        Ok(info) => {
            info!("WiFi hotspot active: SSID={}, IP={:?}", info.ssid, info.ip_address);
            (Some(info.ssid), Some(info.password))
        }
        Err(e) => {
            warn!("WiFi hotspot not available: {} (will advertise without hotspot)", e);
            (None, None)
        }
    };

    // Get identity for advertising
    let identity = {
        let state_guard = state.read().await;
        BleDeviceIdentity {
            device_id: state_guard.config.identity.device_id.clone(),
            device_name: state_guard.config.identity.device_name.clone(),
            device_type: state_guard.config.identity.device_type.to_string(),
            tcp_port: state_guard.config.tcp_port,
            protocol_version: crate::config::PROTOCOL_VERSION,
            hotspot_ssid,
            hotspot_password,
        }
    };

    let mut advertiser = BleAdvertiser::new(identity);

    // Start advertising
    if let Err(e) = advertiser.start().await {
        warn!("Failed to start BLE advertising: {}", e);
        // Continue anyway - scanning might still work
    }

    // Start scanning
    if let Err(e) = scanner.start_scan().await {
        warn!("Failed to start BLE scanning: {}", e);
    }

    // Process BLE events
    loop {
        tokio::select! {
            event = scanner_rx.recv() => {
                match event {
                    Ok(BleEvent::DeviceDiscovered(device)) => {
                        info!("BLE discovered: {} ({}) at {:?}",
                            device.device_name,
                            device.device_id,
                            device.ip_addresses
                        );

                        // Add to device manager
                        let addresses: Vec<std::net::IpAddr> = device.ip_addresses
                            .iter()
                            .filter_map(|s| s.parse().ok())
                            .collect();

                        let device_type = match device.device_type.as_str() {
                            "phone" => crate::config::DeviceType::Phone,
                            "tablet" => crate::config::DeviceType::Tablet,
                            "laptop" => crate::config::DeviceType::Laptop,
                            "tv" => crate::config::DeviceType::Tv,
                            _ => crate::config::DeviceType::Desktop,
                        };

                        {
                            let state_guard = state.read().await;
                            state_guard.device_manager.device_discovered(
                                device.device_id.clone(),
                                device.device_name.clone(),
                                device_type,
                                addresses.clone(),
                                device.tcp_port,
                            ).await;
                        }

                        // Auto-connect if not already connected
                        let already_connected = connection_manager.connected_devices().await
                            .contains(&device.device_id);

                        if !already_connected && !addresses.is_empty() {
                            let cm = connection_manager.clone();
                            let tcp_port = device.tcp_port;
                            let device_name = device.device_name.clone();
                            let addrs = addresses.clone();
                            tokio::spawn(async move {
                                // Try each address
                                for addr in &addrs {
                                    let sock_addr = std::net::SocketAddr::new(*addr, tcp_port);
                                    info!("Auto-connecting to {} at {}", device_name, sock_addr);
                                    match cm.connect(sock_addr).await {
                                        Ok(()) => {
                                            info!("Auto-connected to {} at {}", device_name, sock_addr);
                                            return;
                                        }
                                        Err(e) => {
                                            warn!("Auto-connect to {} failed: {}", sock_addr, e);
                                        }
                                    }
                                }
                            });
                        }
                    }
                    Ok(BleEvent::ScanStarted) => {
                        info!("BLE scan started");
                    }
                    Ok(BleEvent::ScanStopped) => {
                        info!("BLE scan stopped, restarting in 30s...");
                        tokio::time::sleep(Duration::from_secs(30)).await;

                        // Restart scan
                        if let Err(e) = scanner.start_scan().await {
                            warn!("Failed to restart BLE scan: {}", e);
                        }
                    }
                    Ok(BleEvent::Error(e)) => {
                        error!("BLE error: {}", e);
                    }
                    Err(e) => {
                        debug!("BLE event channel error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    advertiser.stop().await;

    Ok(())
}
