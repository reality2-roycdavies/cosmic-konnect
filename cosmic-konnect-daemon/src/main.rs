//! Cosmic Konnect Daemon
//!
//! Background service for device connectivity. Handles:
//! - BLE discovery and advertising
//! - GATT server/client for device rendezvous
//! - WiFi transport for data sync
//! - D-Bus API for UI clients

mod ble;
mod config;
mod dbus_api;
mod device;
mod error;
mod gatt;
mod protocol;
mod sync_engine;
mod transport;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::Config;
use crate::device::DeviceManager;
use crate::dbus_api::DbusService;
use crate::error::DaemonError;

/// Application state shared across components
pub struct AppState {
    pub config: Config,
    pub device_manager: DeviceManager,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            device_manager: DeviceManager::new(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), DaemonError> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(true)
        .init();

    info!("Cosmic Konnect Daemon starting...");

    // Load configuration
    let config = Config::load().await?;
    info!("Configuration loaded from {:?}", config.config_path());

    // Create shared application state
    let state = Arc::new(RwLock::new(AppState::new(config)));

    // Start D-Bus service
    let dbus_service = DbusService::new(state.clone());
    let dbus_handle = tokio::spawn(async move {
        if let Err(e) = dbus_service.run().await {
            error!("D-Bus service error: {}", e);
        }
    });

    // Start BLE subsystem
    let ble_state = state.clone();
    let ble_handle = tokio::spawn(async move {
        if let Err(e) = ble::run(ble_state).await {
            error!("BLE subsystem error: {}", e);
        }
    });

    // Start mDNS discovery for LAN devices
    let mdns_state = state.clone();
    let mdns_handle = tokio::spawn(async move {
        if let Err(e) = transport::mdns::run(mdns_state).await {
            error!("mDNS discovery error: {}", e);
        }
    });

    // Start transport listener (for incoming connections)
    let transport_state = state.clone();
    let transport_handle = tokio::spawn(async move {
        if let Err(e) = transport::listener::run(transport_state).await {
            error!("Transport listener error: {}", e);
        }
    });

    info!("Cosmic Konnect Daemon started successfully");
    info!("D-Bus: io.github.reality2_roycdavies.CosmicKonnect");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping...");

    // Clean shutdown
    dbus_handle.abort();
    ble_handle.abort();
    mdns_handle.abort();
    transport_handle.abort();

    info!("Cosmic Konnect Daemon stopped");
    Ok(())
}
