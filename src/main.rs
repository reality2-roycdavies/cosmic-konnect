//! cosmic-konnect - KDE Connect protocol implementation for COSMIC desktop
//!
//! This application implements the KDE Connect protocol, allowing COSMIC desktop
//! users to connect their phones, tablets, and other devices.
//!
//! ## Modes
//!
//! - No arguments: Run as COSMIC panel applet
//! - `--settings` or `-s`: Open the settings window
//! - `--list` or `-l`: List discovered devices and exit
//! - `--discover` or `-d`: Run device discovery (CLI mode)
//! - `--help` or `-h`: Show help message
//! - `--version`: Show version information

mod app;
mod applet;
mod ble;  // WIP: BLE discovery
mod ckp;  // Cosmic Konnect Protocol (new simplified protocol)
mod clipboard;
mod connection;
mod crypto;
mod daemon_client;  // D-Bus client for daemon communication
mod dbus_client;
mod discovery;
mod filetransfer;
mod identity;
mod notifications;
mod protocol;
mod service;
mod settings;
mod settings_page;
mod unified_discovery;  // WIP: Unified discovery manager
mod wifidirect;  // WIP: Wi-Fi Direct support

use daemon_client::DaemonClient;
use discovery::{DiscoveryConfig, DiscoveryEvent, DiscoveryService};
use identity::load_or_create_identity;
use std::time::Duration;

const APPLET_ID: &str = "io.github.reality2_roycdavies.cosmic-konnect";

fn main() -> cosmic::iced::Result {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--settings" | "-s" => open_settings(),
            "--settings-standalone" => settings::run_settings(),
            "--list" | "-l" => {
                run_cli_list();
                Ok(())
            }
            "--discover" | "-d" => {
                run_cli_discover();
                Ok(())
            }
            "--help" | "-h" => {
                print_help(&args[0]);
                Ok(())
            }
            "--version" | "-v" => {
                println!("cosmic-konnect {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            _ => {
                eprintln!("Unknown argument: {}", args[1]);
                eprintln!("Use --help for usage information");
                std::process::exit(1);
            }
        }
    } else {
        applet::run_applet()
    }
}

fn print_help(program: &str) {
    println!("Cosmic Konnect - Device connectivity for COSMIC Desktop\n");
    println!("Usage: {} [OPTIONS]\n", program);
    println!("Options:");
    println!("  (none)             Run as COSMIC panel applet");
    println!("  --settings, -s     Open settings (via hub or standalone)");
    println!("  --settings-standalone  Open standalone settings window");
    println!("  --list, -l         List discovered devices and exit");
    println!("  --discover, -d     Run device discovery (interactive)");
    println!("  --version, -v      Show version information");
    println!("  --help, -h         Show this help message");
}

/// Try to open settings via cosmic-applet-settings hub; fall back to standalone.
fn open_settings() -> cosmic::iced::Result {
    use std::process::Command;
    if Command::new("cosmic-applet-settings")
        .arg(APPLET_ID)
        .spawn()
        .is_ok()
    {
        Ok(())
    } else {
        settings::run_settings()
    }
}

/// CLI mode: list devices via daemon D-Bus
fn run_cli_list() {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {e}");
            return;
        }
    };

    rt.block_on(async {
        let mut client = DaemonClient::new();
        if let Err(e) = client.connect().await {
            eprintln!("Failed to connect to daemon: {e}");
            eprintln!("Is the daemon running? Try: systemctl --user start cosmic-konnect");
            return;
        }

        match client.list_devices().await {
            Ok(devices) => {
                if devices.is_empty() {
                    println!("No devices found.");
                    println!("Make sure the daemon is running and devices are on the same network.");
                } else {
                    println!("Discovered devices:");
                    for device in &devices {
                        let paired = if device.paired { "paired" } else { "not paired" };
                        println!(
                            "  {} ({}) - {} [{}]",
                            device.name, device.device_type, device.state, paired
                        );
                    }
                    println!("\n{} device(s) total", devices.len());
                }
            }
            Err(e) => eprintln!("Failed to list devices: {e}"),
        }
    });
}

/// CLI mode: discover devices using local discovery
fn run_cli_discover() {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {e}");
            return;
        }
    };

    rt.block_on(async {
        let stored_identity = match load_or_create_identity() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("Failed to load identity: {e}");
                return;
            }
        };

        let identity = stored_identity.to_identity_packet((vec![], vec![]));

        let config = DiscoveryConfig {
            broadcast_interval: Duration::from_secs(2),
            device_timeout: Duration::from_secs(30),
            ..Default::default()
        };

        let mut service = DiscoveryService::new(identity, config);
        let mut events = service.subscribe();

        println!("Scanning for devices (5 seconds)...");
        if let Err(e) = service.start().await {
            eprintln!("Failed to start discovery: {e}");
            return;
        }

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
            println!("  - Cosmic Konnect is running on your phone/other device");
            println!("  - Both devices are on the same network");
            println!("  - No firewall is blocking the required ports");
        }
    });
}
