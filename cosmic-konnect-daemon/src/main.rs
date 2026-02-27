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
mod wifi_hotspot;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::Config;
use crate::device::DeviceManager;
use crate::dbus_api::{DbusService, DbusSignals};
use crate::error::DaemonError;
use crate::protocol::connection::{ConnectionEvent, ConnectionManager};
use crate::protocol::message::{Identity, DeviceType as ProtoDeviceType, Message};

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
    let state = Arc::new(RwLock::new(AppState::new(config.clone())));

    // Load paired devices from disk
    {
        let state_guard = state.read().await;
        if let Ok(data_dir) = state_guard.config.data_dir() {
            if let Err(e) = state_guard.device_manager.load_paired_devices(&data_dir).await {
                warn!("Failed to load paired devices: {}", e);
            }
        }
    }

    // Build protocol Identity from config
    let device_type = match config.identity.device_type {
        crate::config::DeviceType::Desktop => ProtoDeviceType::Desktop,
        crate::config::DeviceType::Laptop => ProtoDeviceType::Laptop,
        crate::config::DeviceType::Phone => ProtoDeviceType::Phone,
        crate::config::DeviceType::Tablet => ProtoDeviceType::Tablet,
        crate::config::DeviceType::Tv => ProtoDeviceType::Tv,
    };

    let identity = Identity::new(
        config.identity.device_id.clone(),
        config.identity.device_name.clone(),
        device_type,
        config.tcp_port,
    );

    // Create ConnectionManager and start the TCP listener
    let connection_manager = Arc::new(ConnectionManager::new(identity));
    if let Err(e) = connection_manager.start_listener().await {
        error!("Failed to start TCP listener: {}", e);
    } else {
        info!("TCP listener started via ConnectionManager");
    }

    // Start D-Bus service and get connection for signal emission
    let dbus_service = DbusService::new(state.clone(), connection_manager.clone());
    let dbus_connection = match dbus_service.start().await {
        Ok(conn) => {
            info!("D-Bus service started");
            Arc::new(conn)
        }
        Err(e) => {
            error!("Failed to start D-Bus service: {}", e);
            return Err(e);
        }
    };

    // Spawn event handler loop that routes ConnectionEvents to:
    // 1. DeviceManager state updates
    // 2. D-Bus signals for the GUI
    // 3. System integration (clipboard, notifications, find-device sound)
    let event_state = state.clone();
    let event_dbus = dbus_connection.clone();
    let mut event_rx = connection_manager.subscribe();
    let event_handle = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    handle_connection_event(event, &event_state, &event_dbus).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Event handler lagged, missed {} events", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    // Start clipboard watcher — monitors system clipboard and broadcasts changes to connected devices
    let clip_cm = connection_manager.clone();
    let clip_config = config.clone();
    let clipboard_handle = tokio::spawn(async move {
        if !clip_config.clipboard_sync {
            info!("Clipboard sync is disabled in configuration");
            return;
        }
        info!("Starting clipboard watcher...");
        clipboard_watcher(clip_cm).await;
    });

    // Start BLE subsystem
    let ble_state = state.clone();
    let ble_cm = connection_manager.clone();
    let ble_handle = tokio::spawn(async move {
        if let Err(e) = ble::run(ble_state, ble_cm).await {
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

    info!("Cosmic Konnect Daemon started successfully");
    info!("D-Bus: io.github.reality2_roycdavies.CosmicKonnect");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping...");

    // Clean shutdown
    clipboard_handle.abort();
    ble_handle.abort();
    mdns_handle.abort();
    event_handle.abort();

    // D-Bus connection drops automatically when dbus_connection Arc is dropped

    info!("Cosmic Konnect Daemon stopped");
    Ok(())
}

/// Handle a single connection event: update state, emit D-Bus signals, integrate with system
async fn handle_connection_event(
    event: ConnectionEvent,
    state: &Arc<RwLock<AppState>>,
    dbus_conn: &zbus::Connection,
) {
    let state_guard = state.read().await;

    match event {
        ConnectionEvent::Connected { device_id, device_name, address } => {
            info!("Device connected: {} ({}) at {}", device_name, device_id, address);
            state_guard.device_manager.device_connected(&device_id).await;
            DbusSignals::device_connected(dbus_conn, &device_id, &device_name).await;
        }

        ConnectionEvent::Identified { device_id, identity } => {
            let dt = match identity.device_type {
                ProtoDeviceType::Desktop => crate::config::DeviceType::Desktop,
                ProtoDeviceType::Laptop => crate::config::DeviceType::Laptop,
                ProtoDeviceType::Phone => crate::config::DeviceType::Phone,
                ProtoDeviceType::Tablet => crate::config::DeviceType::Tablet,
                ProtoDeviceType::Tv => crate::config::DeviceType::Tv,
            };
            state_guard.device_manager.device_discovered(
                device_id.clone(),
                identity.name.clone(),
                dt,
                vec![],
                identity.tcp_port,
            ).await;
            DbusSignals::device_discovered(dbus_conn, &device_id, &identity.name, &dt.to_string()).await;
        }

        ConnectionEvent::PairingRequested { device_id, device_name, verification_code } => {
            info!("Pairing requested from {} ({}), code: {}", device_name, device_id, verification_code);
            DbusSignals::pairing_requested(dbus_conn, &device_id, &device_name, &verification_code).await;
        }

        ConnectionEvent::Paired { device_id, device_name } => {
            info!("Paired with {} ({})", device_name, device_id);
            DbusSignals::device_paired(dbus_conn, &device_id, &device_name).await;
        }

        ConnectionEvent::PairingRejected { device_id, reason } => {
            warn!("Pairing rejected by {}: {}", device_id, reason);
        }

        ConnectionEvent::MessageReceived { device_id, message } => {
            handle_message(&device_id, message, dbus_conn).await;
        }

        ConnectionEvent::Disconnected { device_id, reason } => {
            info!("Device disconnected: {} (reason: {:?})", device_id, reason);
            state_guard.device_manager.device_disconnected(&device_id).await;
            DbusSignals::device_disconnected(dbus_conn, &device_id).await;
        }
    }
}

/// Flag to suppress clipboard watcher from re-broadcasting content just received from a remote device
static CLIPBOARD_FROM_REMOTE: AtomicBool = AtomicBool::new(false);

/// Handle a received message: integrate with system clipboard, notifications, etc.
async fn handle_message(device_id: &str, message: Message, dbus_conn: &zbus::Connection) {
    match message {
        Message::Clipboard(clip) => {
            info!("Clipboard from {} ({} bytes)", device_id, clip.content.len());

            // Set flag so the clipboard watcher doesn't echo this back
            CLIPBOARD_FROM_REMOTE.store(true, Ordering::SeqCst);

            // Set system clipboard via wl-copy (Wayland)
            let content = clip.content.clone();
            match set_clipboard(&content).await {
                Ok(()) => info!("System clipboard updated from {}", device_id),
                Err(e) => warn!("Failed to set system clipboard: {}", e),
            }

            // Show desktop notification with preview
            let preview = if clip.content.len() > 80 {
                format!("{}...", &clip.content[..80])
            } else {
                clip.content.clone()
            };
            let _ = notify_rust::Notification::new()
                .summary("Clipboard Received")
                .body(&preview)
                .icon("edit-paste")
                .appname("Cosmic Konnect")
                .show();

            // Emit D-Bus signal for GUI
            DbusSignals::clipboard_received(dbus_conn, device_id, &clip.content).await;
        }

        Message::Notification(notif) => {
            info!("Notification from {}: {} - {}", device_id, notif.app, notif.title);

            // Show desktop notification
            if let Err(e) = notify_rust::Notification::new()
                .summary(&format!("{}: {}", notif.app, notif.title))
                .body(&notif.text)
                .icon("cosmic-konnect")
                .appname("Cosmic Konnect")
                .show()
            {
                warn!("Failed to show notification: {}", e);
            }

            // Emit D-Bus signal for GUI
            DbusSignals::notification_received(dbus_conn, device_id, &notif.app, &notif.title, &notif.text).await;
        }

        Message::FindDevice(_) => {
            info!("Find device request from {}", device_id);

            // Play alert sound via canberra (available on most Linux desktops)
            tokio::task::spawn_blocking(|| {
                let _ = std::process::Command::new("canberra-gtk-play")
                    .args(["-i", "phone-incoming-call", "-d", "Cosmic Konnect: Find Device"])
                    .status()
                    .or_else(|_| {
                        // Fallback to paplay
                        std::process::Command::new("paplay")
                            .arg("/usr/share/sounds/freedesktop/stereo/phone-incoming-call.oga")
                            .status()
                    });
            });

            // Show notification
            let _ = notify_rust::Notification::new()
                .summary("Find My Device")
                .body("A connected device is looking for this computer")
                .icon("find-location")
                .appname("Cosmic Konnect")
                .urgency(notify_rust::Urgency::Critical)
                .show();
        }

        Message::Ping(ping) => {
            info!("Ping from {}: {:?}", device_id, ping.message);

            // Play a short notification sound
            tokio::task::spawn_blocking(|| {
                let _ = std::process::Command::new("canberra-gtk-play")
                    .args(["-i", "message-new-instant", "-d", "Cosmic Konnect: Ping"])
                    .status()
                    .or_else(|_| {
                        std::process::Command::new("paplay")
                            .arg("/usr/share/sounds/freedesktop/stereo/message-new-instant.oga")
                            .status()
                    });
            });

            // Show notification
            let body = ping.message.as_deref().unwrap_or("Ping!");
            let _ = notify_rust::Notification::new()
                .summary("Cosmic Konnect — Ping")
                .body(body)
                .icon("dialog-information")
                .appname("Cosmic Konnect")
                .show();
        }

        Message::ShareUrl(url) => {
            info!("URL from {}: {}", device_id, url.url);

            // Show notification with the URL
            let _ = notify_rust::Notification::new()
                .summary("URL Shared")
                .body(&url.url)
                .icon("web-browser")
                .appname("Cosmic Konnect")
                .show();

            // Open in default browser
            tokio::task::spawn_blocking(move || {
                let _ = std::process::Command::new("xdg-open")
                    .arg(&url.url)
                    .status();
            });
        }

        Message::ShareText(text) => {
            info!("Text from {} ({} bytes)", device_id, text.text.len());

            // Set clipboard via wl-copy
            if let Err(e) = set_clipboard(&text.text).await {
                warn!("Failed to set clipboard from shared text: {}", e);
            }
        }

        Message::FileOffer(offer) => {
            info!("File offer from {}: {} ({} bytes)", device_id, offer.filename, offer.size);
            DbusSignals::file_offer_received(dbus_conn, device_id, &offer.transfer_id, &offer.filename, offer.size).await;

            let _ = notify_rust::Notification::new()
                .summary("File Offer")
                .body(&format!("{} ({} bytes)", offer.filename, offer.size))
                .icon("document-save")
                .appname("Cosmic Konnect")
                .show();
        }

        other => {
            info!("Message {:?} from {}", other.message_type(), device_id);
        }
    }
}

/// Get system clipboard content via wl-paste (Wayland)
async fn get_clipboard() -> Result<String, String> {
    let output = tokio::process::Command::new("wl-paste")
        .args(["--no-newline", "-t", "text/plain"])
        .output()
        .await
        .map_err(|e| format!("wl-paste failed: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err("wl-paste returned non-zero".to_string())
    }
}

/// Set system clipboard content via wl-copy (Wayland)
async fn set_clipboard(content: &str) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new("wl-copy")
        .arg("--type")
        .arg("text/plain")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("wl-copy failed to start: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(content.as_bytes()).await
            .map_err(|e| format!("Failed to write to wl-copy: {}", e))?;
    }

    let status = child.wait().await
        .map_err(|e| format!("wl-copy wait failed: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("wl-copy returned non-zero".to_string())
    }
}

/// Watch the system clipboard for changes and broadcast to all connected devices
async fn clipboard_watcher(connection_manager: Arc<ConnectionManager>) {
    let mut last_content = get_clipboard().await.unwrap_or_default();

    info!("Clipboard watcher running (polling every 1s)");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Check if we should skip this cycle (content was just set by a remote device)
        if CLIPBOARD_FROM_REMOTE.swap(false, Ordering::SeqCst) {
            // Update last_content to the remotely-set value so we don't re-broadcast it
            if let Ok(text) = get_clipboard().await {
                last_content = text;
            }
            continue;
        }

        let current = match get_clipboard().await {
            Ok(text) => text,
            Err(_) => continue,
        };

        if current != last_content && !current.is_empty() {
            let connected = connection_manager.connected_devices().await;
            if !connected.is_empty() {
                info!("Clipboard changed ({} bytes), broadcasting to {} device(s)", current.len(), connected.len());
                let msg = Message::Clipboard(protocol::message::Clipboard {
                    msg_type: protocol::message::MessageType::Clipboard,
                    content: current.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                });
                if let Err(e) = connection_manager.broadcast(msg).await {
                    warn!("Failed to broadcast clipboard: {}", e);
                }
            }
            last_content = current;
        }
    }
}
