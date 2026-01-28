//! cosmic-konnect - KDE Connect protocol implementation for COSMIC desktop
//!
//! This application implements the KDE Connect protocol, allowing COSMIC desktop
//! users to connect their phones, tablets, and other devices.
//!
//! ## Modes
//!
//! - No arguments: Opens GUI (starts tray first if not already running)
//! - `--tray` or `-t`: Run the system tray icon (for autostart)
//! - `--discover` or `-d`: Run device discovery (CLI mode)
//! - `--pair` or `-p`: Discover and attempt to pair with devices (CLI mode)
//! - `--list` or `-l`: List discovered devices and exit

mod app;
mod ble;  // WIP: BLE discovery
mod ckp;  // Cosmic Konnect Protocol (new simplified protocol)
mod clipboard;
mod connection;
mod crypto;
mod dbus_client;
mod discovery;
mod filetransfer;
mod identity;
mod notifications;
mod protocol;
mod service;
mod tray;
mod unified_discovery;  // WIP: Unified discovery manager
mod wifidirect;  // WIP: Wi-Fi Direct support

use connection::{ConnectionEvent, ConnectionService};
use discovery::{DiscoveryConfig, DiscoveryEvent, DiscoveryService};
use identity::load_or_create_identity;
use protocol::{DEFAULT_TCP_PORT, NetworkPacket};
use service::{KonnectService, ServiceState, SERVICE_NAME, OBJECT_PATH};
use std::fs;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use tray::{TrayCommand, TrayDevice};
use zbus::connection::Builder as ConnectionBuilder;

/// Check if running inside a Flatpak sandbox
fn is_flatpak() -> bool {
    std::path::Path::new("/.flatpak-info").exists()
}

/// Get the app config directory
fn app_config_dir() -> std::path::PathBuf {
    if is_flatpak() {
        dirs::home_dir()
            .map(|h| h.join(".config/cosmic-konnect"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/cosmic-konnect"))
    } else {
        dirs::config_dir()
            .map(|d| d.join("cosmic-konnect"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/cosmic-konnect"))
    }
}

/// Get the path to the tray lockfile
fn tray_lockfile_path() -> std::path::PathBuf {
    app_config_dir().join("tray.lock")
}

/// Get the path to the GUI lockfile
fn gui_lockfile_path() -> std::path::PathBuf {
    app_config_dir().join("gui.lock")
}

fn print_help() {
    println!(
        r#"cosmic-konnect - Device connectivity for COSMIC Desktop

Usage: cosmic-konnect [OPTIONS]

Options:
    (none)           Open GUI (starts tray first if not running)
    -t, --tray       Run with system tray icon (for autostart)
    -d, --discover   Run device discovery (listen for devices)
    -l, --list       List discovered devices and exit
    -v, --verbose    Enable verbose logging
    -h, --help       Show this help message
    --version        Show version information
    --kdeconnect     Use legacy KDE Connect protocol (default: Cosmic Konnect Protocol)

Features:
  - Clipboard synchronization
  - Notification mirroring
  - File transfer
  - Find my phone
  - URL and text sharing
  - And more...

Uses the Cosmic Konnect Protocol (CKP) by default. Use --kdeconnect for
compatibility with KDE Connect, GSConnect, and other implementations."#
    );
}

fn print_version() {
    println!("cosmic-konnect {}", env!("CARGO_PKG_VERSION"));
}

/// Check if tray is already running using a lockfile
fn is_tray_running() -> bool {
    let lockfile = tray_lockfile_path();

    if let Ok(metadata) = fs::metadata(&lockfile) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() < 60;
            }
        }
        return false;
    }
    false
}

/// Create a lockfile to indicate the tray is running
pub fn create_tray_lockfile() {
    let lockfile = tray_lockfile_path();
    if let Some(parent) = lockfile.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = fs::File::create(&lockfile) {
        let _ = write!(file, "{}", std::process::id());
    }
}

/// Remove the lockfile when tray exits
pub fn remove_tray_lockfile() {
    let _ = fs::remove_file(tray_lockfile_path());
}

/// Check if the GUI is already running
fn is_gui_running() -> bool {
    let lockfile = gui_lockfile_path();

    if let Ok(metadata) = fs::metadata(&lockfile) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() < 60;
            }
        }
        return false;
    }
    false
}

/// Create a lockfile to indicate the GUI is running
pub fn create_gui_lockfile() {
    let lockfile = gui_lockfile_path();
    if let Some(parent) = lockfile.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = fs::File::create(&lockfile) {
        let _ = write!(file, "{}", std::process::id());
    }
}

/// Remove the GUI lockfile when app exits
pub fn remove_gui_lockfile() {
    let _ = fs::remove_file(gui_lockfile_path());
}

/// Get system boot time
fn get_boot_time() -> Option<u64> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    for line in stat.lines() {
        if line.starts_with("btime ") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// Clean up stale lockfiles from previous sessions
fn cleanup_stale_lockfiles() {
    cleanup_single_lockfile(&gui_lockfile_path(), "GUI");
    cleanup_single_lockfile(&tray_lockfile_path(), "tray");
}

/// Helper to clean up a single stale lockfile
fn cleanup_single_lockfile(lockfile: &std::path::Path, name: &str) {
    if let Ok(metadata) = fs::metadata(lockfile) {
        if let Ok(modified) = metadata.modified() {
            if let Some(boot_time) = get_boot_time() {
                if let Ok(modified_unix) = modified.duration_since(std::time::UNIX_EPOCH) {
                    if modified_unix.as_secs() < boot_time {
                        let _ = fs::remove_file(lockfile);
                        eprintln!("Cleaned up {} lockfile from previous boot", name);
                        return;
                    }
                }
            }
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() >= 60 {
                    let _ = fs::remove_file(lockfile);
                    eprintln!("Cleaned up stale {} lockfile", name);
                }
            }
        } else {
            let _ = fs::remove_file(lockfile);
            eprintln!("Removed {} lockfile with unreadable metadata", name);
        }
    }
}

/// Ensure autostart entry exists for the tray
fn ensure_autostart() {
    let autostart_dir = if is_flatpak() {
        dirs::home_dir().map(|h| h.join(".config/autostart"))
    } else {
        dirs::config_dir().map(|d| d.join("autostart"))
    };

    let Some(autostart_dir) = autostart_dir else {
        return;
    };

    let desktop_file = autostart_dir.join("io.github.reality2_roycdavies.cosmic-konnect.desktop");

    if desktop_file.exists() {
        return;
    }

    let _ = fs::create_dir_all(&autostart_dir);

    let exec_cmd = if is_flatpak() {
        "flatpak run io.github.reality2_roycdavies.cosmic-konnect --tray"
    } else {
        "cosmic-konnect --tray"
    };

    let content = format!(
        r#"[Desktop Entry]
Type=Application
Name=Cosmic Konnect
Comment=KDE Connect for COSMIC desktop
Exec={exec_cmd}
Icon=io.github.reality2_roycdavies.cosmic-konnect
Terminal=false
Categories=Utility;Network;
X-GNOME-Autostart-enabled=true
"#
    );

    let _ = fs::write(&desktop_file, content);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse arguments
    let mut verbose = false;
    let mut mode = None; // None = GUI mode (default)
    let mut use_kdeconnect = false;

    for arg in &args[1..] {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--version" => {
                print_version();
                return Ok(());
            }
            "-v" | "--verbose" => verbose = true,
            "-t" | "--tray" => mode = Some("tray"),
            "-d" | "--discover" => mode = Some("discover"),
            "-l" | "--list" => mode = Some("list"),
            "--kdeconnect" => use_kdeconnect = true,
            _ => {
                eprintln!("Unknown argument: {}", arg);
                eprintln!("Use --help for usage information");
                std::process::exit(1);
            }
        }
    }

    // Clean up stale lockfiles
    cleanup_stale_lockfiles();

    match mode {
        None => {
            // Default: GUI mode - start tray if not running, then launch GUI
            if is_gui_running() {
                println!("Cosmic Konnect is already open.");
                return Ok(());
            }

            if !is_tray_running() {
                println!("Starting cosmic-konnect tray in background...");
                if let Err(e) = Command::new(
                    std::env::current_exe().unwrap_or_else(|_| "cosmic-konnect".into()),
                )
                .arg("--tray")
                .spawn()
                {
                    eprintln!("Warning: Failed to start tray: {}", e);
                }
                std::thread::sleep(Duration::from_millis(1000));
            }

            // Launch GUI
            println!("Opening Cosmic Konnect...");
            create_gui_lockfile();
            let result = app::run_app();
            remove_gui_lockfile();
            result.map_err(|e| e.into())
        }
        Some("tray") => {
            // Tray mode
            if is_tray_running() {
                println!("Cosmic Konnect tray is already running.");
                return Ok(());
            }

            if use_kdeconnect {
                run_kdeconnect_tray_mode(verbose)
            } else {
                run_ckp_tray_mode(verbose)
            }
        }
        Some(cli_mode) => {
            // CLI modes (discover, pair, etc.)
            run_cli_mode(cli_mode, verbose)
        }
    }
}

/// Run in tray mode with Cosmic Konnect Protocol (CKP)
fn run_ckp_tray_mode(verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();

    // Set up autostart
    ensure_autostart();
    create_tray_lockfile();

    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;

    let result = rt.block_on(async {
        // Load or create device identity
        let stored_identity = load_or_create_identity()?;

        info!(
            "Device: {} (CKP mode)",
            stored_identity.device_name
        );
        info!("Device ID: {}", stored_identity.device_id);

        // Create CKP service
        let config_dir = app_config_dir();
        let mut ckp_service = ckp::CkpService::new(
            stored_identity.device_id.clone(),
            stored_identity.device_name.clone(),
            config_dir.clone(),
        );

        // Subscribe to events
        let mut ckp_events = ckp_service.subscribe();
        let command_tx = ckp_service.command_sender();
        let devices_state = ckp_service.devices_state();

        // Start the CKP service
        ckp_service.start().await.map_err(|e| format!("Failed to start CKP service: {}", e))?;

        // Start D-Bus service for GUI communication
        let dbus_service = ckp::CkpDbusService::new(
            command_tx.clone(),
            devices_state,
            stored_identity.device_id.clone(),
            stored_identity.device_name.clone(),
        );
        let _dbus_connection = zbus::connection::Builder::session()?
            .name(ckp::DBUS_SERVICE_NAME)?
            .serve_at(ckp::DBUS_OBJECT_PATH, dbus_service)?
            .build()
            .await?;
        info!("D-Bus service started: {}", ckp::DBUS_SERVICE_NAME);

        // Start the tray
        let (tray_handle, tray_rx) =
            tray::start_tray().map_err(|e| format!("Failed to start tray: {}", e))?;
        info!("System tray started");

        info!("CKP service started on port {}", ckp::TCP_PORT);

        // Download directory for received files
        let download_dir = dirs::download_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

        // Start clipboard monitoring for CKP (using wl-paste for Wayland)
        let clipboard_command_tx = command_tx.clone();
        tokio::spawn(async move {
            let mut last_content = String::new();

            info!("Starting CKP clipboard monitor");

            // Helper to read clipboard using wl-paste (Wayland) or xclip (X11)
            fn read_clipboard() -> Option<String> {
                // Try wl-paste first (Wayland)
                if let Ok(output) = std::process::Command::new("wl-paste")
                    .args(["--no-newline"])
                    .output()
                {
                    if output.status.success() {
                        return Some(String::from_utf8_lossy(&output.stdout).to_string());
                    }
                }
                // Fall back to xclip (X11)
                if let Ok(output) = std::process::Command::new("xclip")
                    .args(["-selection", "clipboard", "-o"])
                    .output()
                {
                    if output.status.success() {
                        return Some(String::from_utf8_lossy(&output.stdout).to_string());
                    }
                }
                None
            }

            // Initialize with current clipboard
            if let Some(content) = read_clipboard() {
                last_content = content;
                info!("Initial clipboard: {} chars", last_content.len());
            }

            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                if let Some(content) = read_clipboard() {
                    if content != last_content && !content.is_empty() {
                        info!("Clipboard changed: {} chars, broadcasting", content.len());
                        last_content = content.clone();

                        // Broadcast to all connected devices
                        if let Err(e) = clipboard_command_tx.send(ckp::CkpServiceCommand::BroadcastClipboard {
                            content,
                        }).await {
                            warn!("Failed to send clipboard broadcast: {}", e);
                        }
                    }
                }
            }
        });

        // Main event loop
        loop {
            // Check for tray commands (non-blocking)
            match tray_rx.try_recv() {
                Ok(TrayCommand::Quit) => {
                    info!("Quit requested from tray");
                    let _ = command_tx.send(ckp::CkpServiceCommand::Shutdown).await;
                    break;
                }
                Ok(TrayCommand::RefreshDevices) => {
                    info!("Refreshing devices...");
                    // Discovery runs automatically
                }
                Ok(TrayCommand::PingDevice(device_id)) => {
                    info!("Ping requested for device: {}", device_id);
                    let _ = command_tx.send(ckp::CkpServiceCommand::SendPing {
                        device_id,
                        message: Some("Ping from Cosmic Konnect".to_string()),
                    }).await;
                }
                Ok(TrayCommand::FindPhone(device_id)) => {
                    info!("Find phone requested for device: {}", device_id);
                    let _ = command_tx.send(ckp::CkpServiceCommand::FindDevice { device_id }).await;
                }
                Ok(TrayCommand::OpenSettings) => {
                    info!("Opening settings window...");
                    let _ = Command::new(
                        std::env::current_exe().unwrap_or_else(|_| "cosmic-konnect".into()),
                    )
                    .spawn();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    warn!("Tray disconnected");
                    break;
                }
            }

            tokio::select! {
                // CKP service events
                Ok(event) = ckp_events.recv() => {
                    match event {
                        ckp::CkpServiceEvent::DeviceDiscovered { device_id, name, device_type } => {
                            info!("Discovered: {} ({:?})", name, device_type);
                            tray_handle.add_device(TrayDevice {
                                id: device_id,
                                name,
                                device_type: format!("{:?}", device_type).to_lowercase(),
                                battery: None,
                            });
                        }
                        ckp::CkpServiceEvent::DeviceLost { device_id } => {
                            info!("Lost device: {}", device_id);
                            tray_handle.remove_device(&device_id);
                        }
                        ckp::CkpServiceEvent::Connected { device_id, name } => {
                            info!("Connected to: {}", name);
                            tray_handle.add_device(TrayDevice {
                                id: device_id,
                                name,
                                device_type: "phone".to_string(),
                                battery: None,
                            });
                        }
                        ckp::CkpServiceEvent::Disconnected { device_id } => {
                            info!("Disconnected: {}", device_id);
                            tray_handle.remove_device(&device_id);
                        }
                        ckp::CkpServiceEvent::PairingRequested { device_id, name, verification_code } => {
                            info!("Pairing request from {}: code = {}", name, verification_code);
                            let body = format!("{} wants to pair.\nVerification code: {}", name, verification_code);
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = notify_rust::Notification::new()
                                    .summary("Pairing Request")
                                    .body(&body)
                                    .icon("dialog-password")
                                    .timeout(notify_rust::Timeout::Never)
                                    .show()
                                {
                                    tracing::warn!("Failed to show pairing notification: {}", e);
                                }
                            });
                        }
                        ckp::CkpServiceEvent::Paired { device_id, name } => {
                            info!("Paired with: {}", name);
                            let body = format!("Successfully paired with {}", name);
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = notify_rust::Notification::new()
                                    .summary("Device Paired")
                                    .body(&body)
                                    .icon("dialog-ok")
                                    .show()
                                {
                                    tracing::warn!("Failed to show paired notification: {}", e);
                                }
                            });
                        }
                        ckp::CkpServiceEvent::PairingRejected { device_id, reason } => {
                            info!("Pairing rejected for {}: {}", device_id, reason);
                        }
                        ckp::CkpServiceEvent::PingReceived { device_id, message } => {
                            let msg = message.unwrap_or_else(|| "Ping!".to_string());
                            info!("Ping from {}: {}", device_id, msg);
                            // Spawn blocking to avoid runtime-in-runtime panic
                            let msg_clone = msg.clone();
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = notify_rust::Notification::new()
                                    .summary("Ping Received")
                                    .body(&msg_clone)
                                    .icon("dialog-information")
                                    .show()
                                {
                                    tracing::warn!("Failed to show ping notification: {}", e);
                                }
                            });
                        }
                        ckp::CkpServiceEvent::ClipboardReceived { device_id, content } => {
                            info!("Clipboard from {}: {} chars", device_id, content.len());
                            // Update system clipboard using wl-copy
                            if let Err(e) = clipboard::set_clipboard(&content) {
                                warn!("Failed to set clipboard: {}", e);
                            }
                            // Show notification with clipboard preview
                            let preview = if content.len() > 50 {
                                format!("{}...", &content[..50])
                            } else {
                                content.clone()
                            };
                            let char_count = content.len();
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = notify_rust::Notification::new()
                                    .summary("Clipboard Received")
                                    .body(&format!("{} chars: {}", char_count, preview))
                                    .icon("edit-paste")
                                    .timeout(3000)
                                    .show()
                                {
                                    tracing::warn!("Failed to show clipboard notification: {}", e);
                                }
                            });
                        }
                        ckp::CkpServiceEvent::NotificationReceived { device_id, notification } => {
                            info!("Notification from {}: {} - {}", device_id, notification.app, notification.title);
                            let summary = format!("{}: {}", notification.app, notification.title);
                            let body = notification.text.clone();
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = notify_rust::Notification::new()
                                    .summary(&summary)
                                    .body(&body)
                                    .icon("dialog-information")
                                    .show()
                                {
                                    tracing::warn!("Failed to show notification: {}", e);
                                }
                            });
                        }
                        ckp::CkpServiceEvent::FileOfferReceived { device_id, transfer_id, filename, size } => {
                            info!("File offer from {}: {} ({} bytes)", device_id, filename, size);
                            let body = format!("{} ({} bytes)", filename, size);
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = notify_rust::Notification::new()
                                    .summary("File Offered")
                                    .body(&body)
                                    .icon("document-save")
                                    .show()
                                {
                                    tracing::warn!("Failed to show file notification: {}", e);
                                }
                            });
                            // TODO: Auto-accept or prompt user
                        }
                        ckp::CkpServiceEvent::FindDeviceReceived { device_id } => {
                            info!("Find device request from {}", device_id);
                            // Play a sound or flash the screen
                            let _ = std::process::Command::new("paplay")
                                .arg("/usr/share/sounds/freedesktop/stereo/complete.oga")
                                .spawn();
                        }
                        ckp::CkpServiceEvent::UrlReceived { device_id, url } => {
                            info!("URL from {}: {}", device_id, url);
                            let _ = std::process::Command::new("xdg-open")
                                .arg(&url)
                                .spawn();
                        }
                        ckp::CkpServiceEvent::TextReceived { device_id, text } => {
                            info!("Text from {}: {} chars", device_id, text.len());
                            // Copy to clipboard using wl-copy
                            if let Err(e) = clipboard::set_clipboard(&text) {
                                warn!("Failed to set clipboard: {}", e);
                            }
                        }
                    }
                }

                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Periodic: refresh tray lockfile
                    static TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                    let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if tick % 300 == 0 {
                        create_tray_lockfile();
                    }
                }
            }
        }

        info!("Stopping CKP service...");
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    remove_tray_lockfile();
    result
}

/// Run in tray mode with legacy KDE Connect protocol
fn run_kdeconnect_tray_mode(verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();

    // Set up autostart
    ensure_autostart();
    create_tray_lockfile();

    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;

    let result = rt.block_on(async {
        // Load or create device identity
        let stored_identity = load_or_create_identity()?;

        info!(
            "Device: {} ({:?})",
            stored_identity.device_name, stored_identity.device_type
        );
        info!("Device ID: {}", stored_identity.device_id);

        // Define our capabilities
        let capabilities = (
            vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
            ],
            vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
            ],
        );

        let identity = stored_identity.clone().to_identity_packet(capabilities);

        // Start connection service (TCP listener) - need this first for device_senders
        let conn_service = ConnectionService::new(stored_identity.clone(), DEFAULT_TCP_PORT)?;
        let mut conn_events = conn_service.subscribe();
        let device_senders = conn_service.get_device_senders();

        // Create shared service state for D-Bus
        let service_state = Arc::new(RwLock::new(ServiceState::default()));

        // Set our own device ID so we can filter it from device list
        {
            let mut state = service_state.write().await;
            state.own_device_id = stored_identity.device_id.clone();
        }

        // Start D-Bus service (needs device_senders for sending packets)
        let dbus_service = KonnectService::new(service_state.clone(), device_senders);
        let _dbus_connection = ConnectionBuilder::session()?
            .name(SERVICE_NAME)?
            .serve_at(OBJECT_PATH, dbus_service)?
            .build()
            .await?;
        info!("D-Bus service started: {}", SERVICE_NAME);

        info!("Starting with system tray...");

        // Start the tray
        let (tray_handle, tray_rx) =
            tray::start_tray().map_err(|e| format!("Failed to start tray: {}", e))?;

        // Start TCP listener
        conn_service.start_listener().await?;

        // Start discovery
        let config = DiscoveryConfig::default();
        let mut discovery_service = DiscoveryService::new(identity, config);
        let mut discovery_events = discovery_service.subscribe();
        discovery_service.start().await?;

        info!("Listening for connections on TCP port {}", DEFAULT_TCP_PORT);

        // Start clipboard sync
        let clipboard_state = Arc::new(RwLock::new(clipboard::ClipboardState::default()));
        let _clipboard_stop = clipboard::start_clipboard_monitor(
            clipboard_state.clone(),
            conn_service.get_device_senders(),
        );
        info!("Clipboard sync started");

        // Notification manager
        let notification_manager = Arc::new(RwLock::new(notifications::NotificationManager::new()));

        // Track discovered devices for auto-connect
        let mut pending_connections: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Track device addresses for file transfer
        let mut device_addresses: std::collections::HashMap<String, std::net::IpAddr> =
            std::collections::HashMap::new();

        // Download directory for received files
        let download_dir = dirs::download_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

        // Main event loop
        loop {
            // Check for tray commands (non-blocking)
            match tray_rx.try_recv() {
                Ok(TrayCommand::Quit) => {
                    info!("Quit requested from tray");
                    break;
                }
                Ok(TrayCommand::RefreshDevices) => {
                    info!("Refreshing devices...");
                    discovery_service.broadcast_identity().await.ok();
                }
                Ok(TrayCommand::PingDevice(device_id)) => {
                    info!("Ping requested for device: {}", device_id);
                    let ping = NetworkPacket::new("kdeconnect.ping", serde_json::json!({}));
                    if let Err(e) = conn_service.send_packet(&device_id, ping).await {
                        warn!("Failed to send ping: {}", e);
                    }
                }
                Ok(TrayCommand::FindPhone(device_id)) => {
                    info!("Find phone requested for device: {}", device_id);
                    let packet = NetworkPacket::new("kdeconnect.findmyphone.request", serde_json::json!({}));
                    if let Err(e) = conn_service.send_packet(&device_id, packet).await {
                        warn!("Failed to send find phone request: {}", e);
                    }
                }
                Ok(TrayCommand::OpenSettings) => {
                    info!("Opening settings window...");
                    // Launch GUI in separate process
                    let _ = Command::new(
                        std::env::current_exe().unwrap_or_else(|_| "cosmic-konnect".into()),
                    )
                    .spawn();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    warn!("Tray disconnected");
                    break;
                }
            }

            tokio::select! {
                // Discovery events
                Ok(event) = discovery_events.recv() => {
                    match event {
                        DiscoveryEvent::DeviceDiscovered(device) => {
                            info!(
                                "Discovered: {} ({:?}) at {}:{}",
                                device.identity.device_name,
                                device.identity.device_type,
                                device.address,
                                device.tcp_port
                            );

                            // Auto-connect to discovered devices
                            if !pending_connections.contains(&device.identity.device_id) {
                                pending_connections.insert(device.identity.device_id.clone());
                                let connect_addr = std::net::SocketAddr::new(device.address, device.tcp_port);
                                if let Err(e) = conn_service.connect_to(connect_addr, Some(device.identity.clone())).await {
                                    error!("Failed to connect: {}", e);
                                    pending_connections.remove(&device.identity.device_id);
                                }
                            }
                        }
                        DiscoveryEvent::DeviceLost(device_id) => {
                            info!("Discovery lost device: {}", device_id);
                            // Only clear from pending_connections so we can reconnect if rediscovered
                            // Don't remove from D-Bus state or tray - the TCP connection may still be active
                            pending_connections.remove(&device_id);
                        }
                        _ => {}
                    }
                }

                // Connection events
                Ok(event) = conn_events.recv() => {
                    match event {
                        ConnectionEvent::IncomingConnection { device_id, device_name, address } => {
                            info!("Connection from {} at {}", device_name, address);

                            // Store device address for file transfers
                            device_addresses.insert(device_id.clone(), address.ip());

                            // Update D-Bus state
                            {
                                let mut state = service_state.write().await;
                                state.add_device(device_id.clone(), device_name.clone(), "phone".to_string());
                            }
                            tray_handle.add_device(TrayDevice {
                                id: device_id.clone(),
                                name: device_name,
                                device_type: "phone".to_string(),
                                battery: None,
                            });

                            // Request notifications from the device
                            let notif_request = notifications::create_notification_request_packet();
                            if let Err(e) = conn_service.send_packet(&device_id, notif_request).await {
                                debug!("Failed to request notifications: {}", e);
                            }
                        }
                        ConnectionEvent::PairRequest { device_name, .. } => {
                            info!("Pairing request from {}", device_name);
                        }
                        ConnectionEvent::Paired { device_id, device_name } => {
                            info!("Paired with {}", device_name);
                            // Update D-Bus state
                            {
                                let mut state = service_state.write().await;
                                state.add_device(device_id.clone(), device_name.clone(), "phone".to_string());
                                state.set_paired(&device_id, true);
                            }
                            tray_handle.add_device(TrayDevice {
                                id: device_id,
                                name: device_name,
                                device_type: "phone".to_string(),
                                battery: None,
                            });
                        }
                        ConnectionEvent::PairRejected { device_id } => {
                            info!("Pairing rejected: {}", device_id);
                        }
                        ConnectionEvent::Disconnected { device_id } => {
                            info!("Disconnected: {}", device_id);
                            // Update D-Bus state
                            {
                                let mut state = service_state.write().await;
                                state.remove_device(&device_id);
                            }
                            pending_connections.remove(&device_id);
                            tray_handle.remove_device(&device_id);
                        }
                        ConnectionEvent::PacketReceived { device_id, packet } => {
                            match packet.packet_type.as_str() {
                                "kdeconnect.battery" => {
                                    if let Ok(body) = serde_json::from_value::<serde_json::Value>(packet.body) {
                                        if let Some(charge) = body.get("currentCharge").and_then(|c| c.as_i64()) {
                                            // Update D-Bus state
                                            {
                                                let mut state = service_state.write().await;
                                                state.update_battery(&device_id, charge as i32);
                                            }
                                            tray_handle.update_device_battery(&device_id, charge as i32);
                                        }
                                    }
                                }
                                "kdeconnect.clipboard" => {
                                    let mut state = clipboard_state.write().await;
                                    clipboard::handle_clipboard_packet(&packet, &mut state);
                                }
                                "kdeconnect.clipboard.connect" => {
                                    let mut state = clipboard_state.write().await;
                                    clipboard::handle_clipboard_connect_packet(&packet, &mut state);
                                }
                                "kdeconnect.notification" => {
                                    // Get device name for notification display
                                    let device_name = {
                                        let state = service_state.read().await;
                                        state.devices.get(&device_id)
                                            .map(|d| d.name.clone())
                                            .unwrap_or_else(|| device_id.clone())
                                    };
                                    let mut manager = notification_manager.write().await;
                                    notifications::handle_notification_packet(&packet, &mut manager, &device_name);
                                }
                                "kdeconnect.share.request" => {
                                    // Get device info for file transfer
                                    let (device_name, device_addr) = {
                                        let state = service_state.read().await;
                                        let name = state.devices.get(&device_id)
                                            .map(|d| d.name.clone())
                                            .unwrap_or_else(|| device_id.clone());
                                        let addr = device_addresses.get(&device_id).copied();
                                        (name, addr)
                                    };

                                    if let Some(addr) = device_addr {
                                        filetransfer::handle_share_request(
                                            &packet,
                                            addr,
                                            &download_dir,
                                            &device_name,
                                        ).await;
                                    } else {
                                        warn!("No address for device {} to receive file", device_id);
                                    }
                                }
                                _ => {
                                    debug!("Unhandled packet from {}: {}", device_id, packet.packet_type);
                                }
                            }
                        }
                    }
                }

                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Periodic: refresh tray lockfile
                    static TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                    let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if tick % 300 == 0 {  // Every 30 seconds (300 * 100ms)
                        create_tray_lockfile();
                    }
                }
            }
        }

        info!("Stopping...");
        discovery_service.stop();
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    remove_tray_lockfile();
    result
}

/// Run in CLI mode (discover, pair, etc.)
fn run_cli_mode(mode: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        // Load or create device identity
        let stored_identity = load_or_create_identity()?;

        info!(
            "Device: {} ({:?})",
            stored_identity.device_name, stored_identity.device_type
        );
        info!("Device ID: {}", stored_identity.device_id);

        // Define our capabilities
        let capabilities = (
            vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
            ],
            vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
            ],
        );

        let identity = stored_identity.clone().to_identity_packet(capabilities);

        match mode {
            "pair" => run_pair_mode(stored_identity, identity).await,
            "broadcast" => run_broadcast_mode(identity).await,
            "list" => run_list_mode(identity).await,
            "discover" | _ => run_discover_mode(identity, verbose).await,
        }
    })
}

async fn run_pair_mode(
    stored_identity: identity::StoredIdentity,
    identity: protocol::IdentityPacketBody,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting pairing mode...");

    let conn_service = ConnectionService::new(stored_identity, DEFAULT_TCP_PORT)?;
    let mut conn_events = conn_service.subscribe();
    conn_service.start_listener().await?;

    let config = DiscoveryConfig::default();
    let mut discovery_service = DiscoveryService::new(identity, config);
    let mut discovery_events = discovery_service.subscribe();
    discovery_service.start().await?;

    info!("Listening for connections on TCP port {}", DEFAULT_TCP_PORT);
    info!("Press Ctrl+C to stop");
    println!();

    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    ctrlc_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    let mut pending_connections: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = discovery_events.recv() => {
                match event {
                    DiscoveryEvent::DeviceDiscovered(device) => {
                        println!(
                            "[+] Discovered: {} ({:?}) at {}:{}",
                            device.identity.device_name,
                            device.identity.device_type,
                            device.address,
                            device.tcp_port
                        );

                        if !pending_connections.contains(&device.identity.device_id) {
                            pending_connections.insert(device.identity.device_id.clone());
                            let connect_addr = std::net::SocketAddr::new(device.address, device.tcp_port);
                            info!("Connecting to {}...", device.identity.device_name);
                            if let Err(e) = conn_service.connect_to(connect_addr, Some(device.identity.clone())).await {
                                error!("Failed to connect: {}", e);
                                pending_connections.remove(&device.identity.device_id);
                            }
                        }
                    }
                    DiscoveryEvent::DeviceLost(device_id) => {
                        println!("[-] Lost device: {}", device_id);
                        pending_connections.remove(&device_id);
                    }
                    _ => {}
                }
            }

            Ok(event) = conn_events.recv() => {
                match event {
                    ConnectionEvent::IncomingConnection { device_name, address, .. } => {
                        println!("[*] Connection from {} at {}", device_name, address);
                    }
                    ConnectionEvent::PairRequest { device_name, .. } => {
                        println!("[?] Pairing request from {}", device_name);
                        println!("    (Auto-accepting for testing)");
                    }
                    ConnectionEvent::Paired { device_name, .. } => {
                        println!("[✓] Paired with {}", device_name);
                    }
                    ConnectionEvent::PairRejected { device_id } => {
                        println!("[✗] Pairing rejected: {}", device_id);
                    }
                    ConnectionEvent::Disconnected { device_id } => {
                        println!("[-] Disconnected: {}", device_id);
                        pending_connections.remove(&device_id);
                    }
                    ConnectionEvent::PacketReceived { device_id, packet } => {
                        println!("[<] Packet from {}: {}", device_id, packet.packet_type);
                    }
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        }
    }

    println!();
    info!("Stopping...");
    discovery_service.stop();
    Ok(())
}

async fn run_broadcast_mode(
    identity: protocol::IdentityPacketBody,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DiscoveryConfig::default();
    let mut service = DiscoveryService::new(identity, config);

    info!("Broadcasting identity...");
    service.start().await?;

    tokio::time::sleep(Duration::from_secs(1)).await;
    service.stop();

    info!("Broadcast complete");
    Ok(())
}

async fn run_list_mode(
    identity: protocol::IdentityPacketBody,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DiscoveryConfig {
        broadcast_interval: Duration::from_secs(2),
        device_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    let mut service = DiscoveryService::new(identity, config);
    let mut events = service.subscribe();

    info!("Scanning for devices (5 seconds)...");
    service.start().await?;

    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => break,
            Ok(event) = events.recv() => {
                if let DiscoveryEvent::DeviceDiscovered(device) = event {
                    println!(
                        "  {} ({:?}) at {}:{}",
                        device.identity.device_name,
                        device.identity.device_type,
                        device.address,
                        device.tcp_port
                    );
                }
            }
        }
    }

    service.stop();

    let devices = service.get_devices().await;
    println!("\nFound {} device(s)", devices.len());

    if devices.is_empty() {
        println!("\nNo devices found. Make sure:");
        println!("  - KDE Connect is running on your phone/other device");
        println!("  - Both devices are on the same network");
        println!("  - No firewall is blocking UDP port 1716");
    }

    Ok(())
}

async fn run_discover_mode(
    identity: protocol::IdentityPacketBody,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DiscoveryConfig::default();
    let mut service = DiscoveryService::new(identity, config);
    let mut events = service.subscribe();

    info!("Starting discovery service...");
    info!("Press Ctrl+C to stop");
    println!();

    service.start().await?;

    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();

    ctrlc_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        tokio::select! {
            Ok(event) = events.recv() => {
                match event {
                    DiscoveryEvent::DeviceDiscovered(device) => {
                        println!(
                            "[+] Discovered: {} ({:?}) at {}:{}",
                            device.identity.device_name,
                            device.identity.device_type,
                            device.address,
                            device.tcp_port
                        );
                        println!("    Capabilities: {:?}", device.identity.incoming_capabilities);
                    }
                    DiscoveryEvent::DeviceUpdated(device) => {
                        if verbose {
                            println!(
                                "[~] Updated: {} at {}",
                                device.identity.device_name,
                                device.address
                            );
                        }
                    }
                    DiscoveryEvent::DeviceLost(device_id) => {
                        println!("[-] Lost device: {}", device_id);
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        }
    }

    println!();
    info!("Stopping discovery service...");
    service.stop();

    let devices = service.get_devices().await;
    info!("Session ended with {} known device(s)", devices.len());

    Ok(())
}

/// Set up Ctrl+C handler
fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) {
    let handler = std::sync::Mutex::new(Some(handler));

    ctrlc::set_handler(move || {
        if let Some(h) = handler.lock().unwrap().take() {
            h();
        }
    })
    .expect("Failed to set Ctrl+C handler");
}
