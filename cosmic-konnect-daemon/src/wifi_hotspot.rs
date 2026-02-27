//! WiFi hotspot support for the daemon.
//!
//! Creates a WiFi hotspot using NetworkManager (`nmcli`) so that Android
//! devices on isolated networks can connect via the hotspot after discovering
//! the desktop via BLE. The hotspot SSID and password are advertised via
//! BLE GATT characteristics.

use std::process::Command;
use tracing::{info, warn, error};

/// Hotspot connection name in NetworkManager
const HOTSPOT_CON_NAME: &str = "CosmicKonnect-Hotspot";

/// Default hotspot SSID
const HOTSPOT_SSID: &str = "CosmicKonnect";

/// Default hotspot password (8+ chars required for WPA)
const HOTSPOT_PASSWORD: &str = "cosmic123";

/// Hotspot configuration
#[derive(Debug, Clone)]
pub struct HotspotConfig {
    pub ssid: String,
    pub password: String,
    pub interface: Option<String>,
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self {
            ssid: HOTSPOT_SSID.to_string(),
            password: HOTSPOT_PASSWORD.to_string(),
            interface: None,
        }
    }
}

/// Active hotspot info
#[derive(Debug, Clone)]
pub struct HotspotInfo {
    pub ssid: String,
    pub password: String,
    pub interface: String,
    pub ip_address: Option<String>,
}

/// Start a WiFi hotspot using nmcli.
///
/// Tries to find a disconnected WiFi interface first (to avoid disrupting the
/// primary connection). Falls back to the primary WiFi interface if no
/// disconnected one is available.
pub fn start_hotspot(config: &HotspotConfig) -> Result<HotspotInfo, String> {
    // Check if hotspot is already active
    let status = Command::new("nmcli")
        .args(["connection", "show", "--active"])
        .output()
        .map_err(|e| format!("Failed to check connections: {}", e))?;

    let output = String::from_utf8_lossy(&status.stdout);
    if output.contains(HOTSPOT_CON_NAME) || output.contains("Hotspot") {
        info!("WiFi hotspot already active");
        // Get the interface it's running on
        let iface = find_hotspot_interface().unwrap_or_default();
        let ip = get_interface_ip(&iface);
        return Ok(HotspotInfo {
            ssid: config.ssid.clone(),
            password: config.password.clone(),
            interface: iface,
            ip_address: ip,
        });
    }

    // Find a suitable WiFi interface
    let iface = if let Some(ref iface) = config.interface {
        iface.clone()
    } else {
        find_wifi_interface()?
    };

    info!("Starting WiFi hotspot on interface: {}", iface);

    let result = Command::new("nmcli")
        .args([
            "device", "wifi", "hotspot",
            "ifname", &iface,
            "con-name", HOTSPOT_CON_NAME,
            "ssid", &config.ssid,
            "password", &config.password,
        ])
        .output()
        .map_err(|e| format!("Failed to create hotspot: {}", e))?;

    if result.status.success() {
        info!("WiFi hotspot '{}' started on {}", config.ssid, iface);
        let ip = get_interface_ip(&iface);
        Ok(HotspotInfo {
            ssid: config.ssid.clone(),
            password: config.password.clone(),
            interface: iface,
            ip_address: ip,
        })
    } else {
        let stderr = String::from_utf8_lossy(&result.stderr);
        Err(format!("Failed to start hotspot: {}", stderr))
    }
}

/// Stop the WiFi hotspot.
pub fn stop_hotspot() {
    let _ = Command::new("nmcli")
        .args(["connection", "down", HOTSPOT_CON_NAME])
        .output();
    info!("WiFi hotspot stopped");
}

/// Find a suitable WiFi interface for the hotspot.
/// Prefers a disconnected interface to avoid disrupting the primary connection.
fn find_wifi_interface() -> Result<String, String> {
    let output = Command::new("nmcli")
        .args(["device", "status"])
        .output()
        .map_err(|e| format!("Failed to list devices: {}", e))?;

    let iface_output = String::from_utf8_lossy(&output.stdout);
    let mut disconnected_wifi: Option<String> = None;
    let mut primary_wifi: Option<String> = None;

    for line in iface_output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "wifi" {
            let iface = parts[0].to_string();
            if parts[2] == "disconnected" {
                disconnected_wifi = Some(iface);
                break;
            } else if primary_wifi.is_none() {
                primary_wifi = Some(iface);
            }
        }
    }

    disconnected_wifi.or(primary_wifi)
        .ok_or_else(|| "No WiFi interface available for hotspot".to_string())
}

/// Find which interface is running the hotspot.
fn find_hotspot_interface() -> Option<String> {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "DEVICE,NAME", "connection", "show", "--active"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains(HOTSPOT_CON_NAME) || line.contains("Hotspot") {
            return line.split(':').next().map(|s| s.to_string());
        }
    }
    None
}

/// Get the IPv4 address of a network interface.
fn get_interface_ip(interface: &str) -> Option<String> {
    if interface.is_empty() {
        return None;
    }

    let output = Command::new("ip")
        .args(["-4", "addr", "show", interface])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            if let Some(addr) = trimmed.split_whitespace().nth(1) {
                if let Some(ip) = addr.split('/').next() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}
