//! cosmic-konnect - KDE Connect protocol implementation for COSMIC desktop
//!
//! This application implements the KDE Connect protocol, allowing COSMIC desktop
//! users to connect their phones, tablets, and other devices.

mod discovery;
mod identity;
mod protocol;

use discovery::{DiscoveryConfig, DiscoveryEvent, DiscoveryService};
use identity::load_or_create_identity;
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

fn print_help() {
    println!(
        r#"cosmic-konnect - KDE Connect for COSMIC Desktop

Usage: cosmic-konnect [OPTIONS]

Options:
    -d, --discover   Run device discovery (listen for devices)
    -b, --broadcast  Broadcast our identity once and exit
    -l, --list       List discovered devices and exit
    -v, --verbose    Enable verbose logging
    -h, --help       Show this help message
    --version        Show version information

Without arguments, runs in discovery mode continuously.

The KDE Connect protocol allows connecting phones, tablets, and other
devices to your desktop for features like:
  - Clipboard synchronization
  - Notification mirroring
  - File transfer
  - Remote input control
  - Media playback control
  - SMS messaging
  - And more...

Compatible with KDE Connect, GSConnect, and other implementations."#
    );
}

fn print_version() {
    println!("cosmic-konnect {}", env!("CARGO_PKG_VERSION"));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse arguments
    let mut verbose = false;
    let mut mode = "discover"; // default mode

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
            "-d" | "--discover" => mode = "discover",
            "-b" | "--broadcast" => mode = "broadcast",
            "-l" | "--list" => mode = "list",
            _ => {
                eprintln!("Unknown argument: {}", arg);
                eprintln!("Use --help for usage information");
                std::process::exit(1);
            }
        }
    }

    // Initialize logging
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();

    // Load or create device identity
    let stored_identity = load_or_create_identity()?;

    info!(
        "Device: {} ({:?})",
        stored_identity.device_name, stored_identity.device_type
    );
    info!("Device ID: {}", stored_identity.device_id);

    // Define our capabilities (empty for now, will add plugins later)
    let capabilities = (
        vec!["kdeconnect.ping".to_string()],
        vec!["kdeconnect.ping".to_string()],
    );

    let identity = stored_identity.to_identity_packet(capabilities);

    match mode {
        "broadcast" => {
            // Just broadcast once
            let config = DiscoveryConfig::default();
            let mut service = DiscoveryService::new(identity, config);

            info!("Broadcasting identity...");
            service.start().await?;

            // Wait a moment for the broadcast
            tokio::time::sleep(Duration::from_secs(1)).await;
            service.stop();

            info!("Broadcast complete");
        }

        "list" => {
            // Discover for a few seconds and list devices
            let config = DiscoveryConfig {
                broadcast_interval: Duration::from_secs(2),
                device_timeout: Duration::from_secs(30),
                ..Default::default()
            };

            let mut service = DiscoveryService::new(identity, config);
            let mut events = service.subscribe();

            info!("Scanning for devices (5 seconds)...");
            service.start().await?;

            // Listen for 5 seconds
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
        }

        "discover" | _ => {
            // Continuous discovery mode
            let config = DiscoveryConfig::default();
            let mut service = DiscoveryService::new(identity, config);
            let mut events = service.subscribe();

            info!("Starting discovery service...");
            info!("Press Ctrl+C to stop");
            println!();

            service.start().await?;

            // Handle Ctrl+C
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();

            ctrlc_handler(move || {
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            });

            // Main event loop
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
                                // Only log in verbose mode
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
                        // Check running flag
                        if !running.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                    }
                }
            }

            println!();
            info!("Stopping discovery service...");
            service.stop();

            // List final device count
            let devices = service.get_devices().await;
            info!("Session ended with {} known device(s)", devices.len());
        }
    }

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
