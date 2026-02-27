//! mDNS/DNS-SD discovery and advertising
//!
//! Uses mdns-sd crate to:
//! - Advertise this device on the local network
//! - Discover other Cosmic Konnect devices

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::DeviceType;
use crate::error::DaemonError;
use crate::AppState;

/// mDNS service type for Cosmic Konnect
const SERVICE_TYPE: &str = "_cosmic-konnect._tcp.local.";

/// Run the mDNS subsystem
pub async fn run(state: Arc<RwLock<AppState>>) -> Result<(), DaemonError> {
    info!("Starting mDNS subsystem...");

    // Check if mDNS is enabled
    {
        let state_guard = state.read().await;
        if !state_guard.config.mdns_enabled {
            info!("mDNS is disabled in configuration");
            return Ok(());
        }
    }

    // Create mDNS daemon
    let mdns = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to create mDNS daemon: {}", e);
            return Err(DaemonError::Transport(format!("mDNS init failed: {}", e)));
        }
    };

    // Register our service
    let (device_id, device_name, device_type, tcp_port) = {
        let state_guard = state.read().await;
        (
            state_guard.config.identity.device_id.clone(),
            state_guard.config.identity.device_name.clone(),
            state_guard.config.identity.device_type,
            state_guard.config.tcp_port,
        )
    };

    // Build service info
    let hostname = format!("{}.local.", device_id.replace('_', "-"));
    let instance_name = format!("{}@{}", device_name, device_id);

    let mut properties = HashMap::new();
    properties.insert("id".to_string(), device_id.clone());
    properties.insert("name".to_string(), device_name.clone());
    properties.insert("type".to_string(), device_type.to_string());
    properties.insert("protocol".to_string(), "1".to_string());

    // Collect all non-loopback IPv4 addresses via `ip` command so we advertise
    // on every interface (main WiFi + hotspot). This ensures the phone on the
    // hotspot subnet can discover us via mDNS.
    let all_addrs = get_local_ipv4_addresses();
    info!("mDNS advertising on addresses: {:?}", all_addrs);

    let service_info = if all_addrs.is_empty() {
        ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &hostname,
            "",  // Auto-detect
            tcp_port,
            properties,
        )
    } else {
        let addr_strs: Vec<String> = all_addrs.iter().map(|a| a.to_string()).collect();
        let addr_refs: Vec<&str> = addr_strs.iter().map(|s| s.as_str()).collect();
        ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &hostname,
            addr_refs.as_slice(),
            tcp_port,
            properties,
        )
    };

    let service_info = match service_info {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to create service info: {}", e);
            return Err(DaemonError::Transport(format!("Service info error: {}", e)));
        }
    };

    // Register service
    if let Err(e) = mdns.register(service_info) {
        error!("Failed to register mDNS service: {}", e);
        return Err(DaemonError::Transport(format!("mDNS register failed: {}", e)));
    }

    info!("mDNS service registered: {}", instance_name);

    // Browse for other services
    let receiver = match mdns.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to start mDNS browse: {}", e);
            return Err(DaemonError::Transport(format!("mDNS browse failed: {}", e)));
        }
    };

    info!("mDNS browsing for {}", SERVICE_TYPE);

    // Process events
    loop {
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(event) => {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        // Skip our own service
                        let found_id = info.get_property_val_str("id").unwrap_or_default();
                        if found_id == device_id {
                            continue;
                        }

                        let found_name = info.get_property_val_str("name")
                            .unwrap_or(info.get_fullname());
                        let found_type_str = info.get_property_val_str("type").unwrap_or("desktop");
                        let found_port = info.get_port();

                        // Parse device type
                        let found_type = match found_type_str {
                            "phone" => DeviceType::Phone,
                            "tablet" => DeviceType::Tablet,
                            "laptop" => DeviceType::Laptop,
                            "tv" => DeviceType::Tv,
                            _ => DeviceType::Desktop,
                        };

                        // Get addresses
                        let addresses: Vec<IpAddr> = info.get_addresses()
                            .iter()
                            .copied()
                            .collect();

                        if addresses.is_empty() {
                            debug!("Discovered {} but no addresses", found_name);
                            continue;
                        }

                        info!("mDNS discovered: {} ({}) at {:?}:{}",
                            found_name, found_id, addresses, found_port);

                        // Add to device manager
                        let state_guard = state.read().await;
                        state_guard.device_manager.device_discovered(
                            found_id.to_string(),
                            found_name.to_string(),
                            found_type,
                            addresses,
                            found_port,
                        ).await;
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        debug!("mDNS service removed: {}", fullname);
                    }
                    ServiceEvent::SearchStarted(_) => {
                        debug!("mDNS search started");
                    }
                    ServiceEvent::SearchStopped(_) => {
                        debug!("mDNS search stopped");
                    }
                    _ => {}
                }
            }
            Err(flume::RecvTimeoutError::Timeout) => {
                // Normal timeout, continue
            }
            Err(flume::RecvTimeoutError::Disconnected) => {
                warn!("mDNS receiver disconnected");
                break;
            }
        }

        // Check if we should continue
        let state_guard = state.read().await;
        if !state_guard.config.mdns_enabled {
            info!("mDNS disabled, stopping");
            break;
        }
    }

    // Shutdown
    if let Err(e) = mdns.shutdown() {
        warn!("mDNS shutdown error: {}", e);
    }

    info!("mDNS subsystem stopped");
    Ok(())
}

/// Get all non-loopback IPv4 addresses on this machine via the `ip` command.
fn get_local_ipv4_addresses() -> Vec<std::net::Ipv4Addr> {
    let mut addrs = Vec::new();

    if let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Format: "N: ifname    inet A.B.C.D/prefix ..."
            if let Some(inet_pos) = line.find("inet ") {
                let rest = &line[inet_pos + 5..];
                if let Some(slash) = rest.find('/') {
                    if let Ok(v4) = rest[..slash].parse::<std::net::Ipv4Addr>() {
                        if !v4.is_loopback() {
                            addrs.push(v4);
                        }
                    }
                }
            }
        }
    }

    addrs
}
