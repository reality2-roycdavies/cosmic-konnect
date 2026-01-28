//! BLE discovery and advertising
//!
//! Uses BlueZ via D-Bus (bluer crate) to discover and advertise
//! Cosmic Konnect devices via Bluetooth Low Energy.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::DaemonError;
use crate::AppState;
use crate::gatt::{BleAdvertiser, BleScanner, BleDeviceIdentity, BleEvent};

/// Run the BLE subsystem
pub async fn run(state: Arc<RwLock<AppState>>) -> Result<(), DaemonError> {
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

    // Get identity for advertising
    let identity = {
        let state_guard = state.read().await;
        BleDeviceIdentity {
            device_id: state_guard.config.identity.device_id.clone(),
            device_name: state_guard.config.identity.device_name.clone(),
            device_type: state_guard.config.identity.device_type.to_string(),
            tcp_port: state_guard.config.tcp_port,
            protocol_version: crate::config::PROTOCOL_VERSION,
            hotspot_ssid: None,
            hotspot_password: None,
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
                        let state_guard = state.read().await;
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

                        state_guard.device_manager.device_discovered(
                            device.device_id,
                            device.device_name,
                            device_type,
                            addresses,
                            device.tcp_port,
                        ).await;
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
