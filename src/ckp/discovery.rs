//! CKP Discovery mechanisms
//!
//! Handles device discovery via:
//! - UDP broadcast
//! - BLE advertising/scanning
//! - Wi-Fi Direct

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::message::{Capability, DeviceType, Identity, Message, MessageFlags, MessageType};
use super::{DISCOVERY_INTERVAL_SECS, PROTOCOL_VERSION, TCP_PORT, UDP_DISCOVERY_PORT};

/// Discovered device information
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub addresses: Vec<IpAddr>,
    pub tcp_port: u16,
    pub capabilities: Vec<Capability>,
    pub last_seen: Instant,
    pub discovery_method: DiscoveryMethod,
}

/// How the device was discovered
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    UdpBroadcast,
    Ble,
    WifiDirect,
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A device was discovered or updated
    DeviceDiscovered(DiscoveredDevice),
    /// A device timed out and was removed
    DeviceLost(String),
}

/// UDP broadcast discovery service
pub struct UdpDiscovery {
    identity: Identity,
    devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    event_tx: broadcast::Sender<DiscoveryEvent>,
    device_timeout: Duration,
}

impl UdpDiscovery {
    /// Create a new UDP discovery service
    pub fn new(identity: Identity) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            identity,
            devices: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            device_timeout: Duration::from_secs(60),
        }
    }

    /// Subscribe to discovery events
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.event_tx.subscribe()
    }

    /// Get list of discovered devices
    pub async fn get_devices(&self) -> Vec<DiscoveredDevice> {
        self.devices.read().await.values().cloned().collect()
    }

    /// Start discovery
    pub async fn start(&self) -> Result<(), DiscoveryError> {
        info!("Starting UDP discovery on port {}", UDP_DISCOVERY_PORT);

        // Create broadcast socket
        let socket = UdpSocket::bind(("0.0.0.0", UDP_DISCOVERY_PORT)).await?;
        socket.set_broadcast(true)?;

        let socket = Arc::new(socket);
        let identity = self.identity.clone();
        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();
        let device_timeout = self.device_timeout;

        // Receiver task
        let recv_socket = socket.clone();
        let recv_devices = devices.clone();
        let recv_event_tx = event_tx.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];

            loop {
                match recv_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        info!("Received UDP packet from {} ({} bytes)", addr, len);
                        if let Err(e) =
                            handle_discovery_packet(&buf[..len], addr, &recv_devices, &recv_event_tx)
                                .await
                        {
                            warn!("Failed to handle discovery packet from {}: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        error!("UDP receive error: {}", e);
                    }
                }
            }
        });

        // Sender task
        let send_socket = socket.clone();
        let send_identity = identity.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(DISCOVERY_INTERVAL_SECS));

            loop {
                interval.tick().await;

                if let Err(e) = send_discovery_packet(&send_socket, &send_identity).await {
                    warn!("Failed to send discovery packet: {}", e);
                }
            }
        });

        // Cleanup task
        let cleanup_devices = devices.clone();
        let cleanup_event_tx = event_tx.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let mut devices = cleanup_devices.write().await;
                let now = Instant::now();

                let stale: Vec<String> = devices
                    .iter()
                    .filter(|(_, d)| now.duration_since(d.last_seen) > device_timeout)
                    .map(|(id, _)| id.clone())
                    .collect();

                for id in stale {
                    if devices.remove(&id).is_some() {
                        info!("Device timeout: {}", id);
                        let _ = cleanup_event_tx.send(DiscoveryEvent::DeviceLost(id));
                    }
                }
            }
        });

        // Send initial discovery
        send_discovery_packet(&socket, &identity).await?;

        Ok(())
    }
}

/// Send a discovery broadcast packet
async fn send_discovery_packet(socket: &UdpSocket, identity: &Identity) -> Result<(), DiscoveryError> {
    let message = Message::Identity(identity.clone());
    let encoded = message.encode(MessageFlags::default())?;

    // Get all broadcast addresses
    let broadcast_addrs = get_broadcast_addresses();

    // Send to all broadcast addresses
    for addr in &broadcast_addrs {
        let broadcast_addr = SocketAddr::new(IpAddr::V4(*addr), UDP_DISCOVERY_PORT);
        if let Err(e) = socket.send_to(&encoded, broadcast_addr).await {
            warn!("Failed to send to {}: {}", addr, e);
        } else {
            debug!("Sent discovery to {}:{}", addr, UDP_DISCOVERY_PORT);
        }
    }

    info!("Sent discovery broadcast to {} addresses", broadcast_addrs.len());

    Ok(())
}

/// Get all broadcast addresses for network interfaces
fn get_broadcast_addresses() -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();

    // Get interface broadcast addresses
    for iface in pnet_datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback() && iface.is_broadcast() {
            for ip in &iface.ips {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    // Calculate broadcast address from IP and prefix
                    let prefix = ip.prefix();
                    if prefix > 0 && prefix < 32 {
                        let mask = !((1u32 << (32 - prefix)) - 1);
                        let ip_int = u32::from(ipv4);
                        let broadcast_int = (ip_int & mask) | !mask;
                        let broadcast = Ipv4Addr::from(broadcast_int);
                        if !addresses.contains(&broadcast) {
                            addresses.push(broadcast);
                        }
                    }
                }
            }
        }
    }

    // Always include the limited broadcast address
    let limited = Ipv4Addr::new(255, 255, 255, 255);
    if !addresses.contains(&limited) {
        addresses.push(limited);
    }

    addresses
}

/// Handle a received discovery packet
async fn handle_discovery_packet(
    data: &[u8],
    addr: SocketAddr,
    devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    event_tx: &broadcast::Sender<DiscoveryEvent>,
) -> Result<(), DiscoveryError> {
    // Log first few bytes for debugging
    let header_preview: Vec<u8> = data.iter().take(20).cloned().collect();
    debug!("Packet header from {}: {:02x?}", addr, header_preview);

    // Parse the message
    let (message, _flags) = Message::decode(data)?;

    if let Message::Identity(identity) = message {
        info!(
            "Received Identity from {} ({}) at {}",
            identity.name, identity.device_id, addr
        );

        let device = DiscoveredDevice {
            device_id: identity.device_id.clone(),
            name: identity.name.clone(),
            device_type: identity.device_type,
            addresses: vec![addr.ip()],
            tcp_port: identity.tcp_port,
            capabilities: identity.capabilities.clone(),
            last_seen: Instant::now(),
            discovery_method: DiscoveryMethod::UdpBroadcast,
        };

        let mut devices_map = devices.write().await;

        if let Some(existing) = devices_map.get_mut(&identity.device_id) {
            // Update existing device
            if !existing.addresses.contains(&addr.ip()) {
                existing.addresses.push(addr.ip());
            }
            existing.last_seen = Instant::now();
            existing.name = identity.name.clone();
            existing.tcp_port = identity.tcp_port;
            existing.capabilities = identity.capabilities.clone();

            let _ = event_tx.send(DiscoveryEvent::DeviceDiscovered(existing.clone()));
        } else {
            // New device
            info!(
                "New device discovered: {} ({}) at {}",
                device.name, device.device_id, addr
            );
            let _ = event_tx.send(DiscoveryEvent::DeviceDiscovered(device.clone()));
            devices_map.insert(identity.device_id, device);
        }
    } else {
        warn!("Received non-Identity message in discovery: {:?}", message);
    }

    Ok(())
}

/// Discovery errors
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Message error: {0}")]
    Message(#[from] super::message::MessageError),
}

/// BLE connection info for advertisement
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BleConnectionInfo {
    pub addresses: Vec<String>,
    pub port: u16,
}

impl BleConnectionInfo {
    /// Create connection info from local addresses
    pub fn from_local(port: u16) -> Self {
        let addresses = get_local_addresses()
            .into_iter()
            .map(|a| a.to_string())
            .collect();

        Self { addresses, port }
    }

    /// Encode for BLE characteristic
    pub fn encode(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).unwrap_or_default()
    }

    /// Decode from BLE characteristic
    pub fn decode(data: &[u8]) -> Option<Self> {
        rmp_serde::from_slice(data).ok()
    }
}

/// Get local IP addresses
pub fn get_local_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();

    // Get addresses from network interfaces
    for iface in pnet_datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback() {
            for ip in iface.ips {
                let addr = ip.ip();
                if !addr.is_loopback() {
                    addresses.push(addr);
                }
            }
        }
    }

    // Fallback: try to get addresses via hostname lookup
    if addresses.is_empty() {
        if let Ok(hostname) = hostname::get() {
            if let Ok(hostname_str) = hostname.into_string() {
                if let Ok(addrs) = dns_lookup::lookup_host(&hostname_str) {
                    for addr in addrs {
                        if !addr.is_loopback() {
                            addresses.push(addr);
                        }
                    }
                }
            }
        }
    }

    // If still empty, use localhost
    if addresses.is_empty() {
        addresses.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_connection_info() {
        let info = BleConnectionInfo {
            addresses: vec!["192.168.1.100".to_string()],
            port: 17161,
        };

        let encoded = info.encode();
        let decoded = BleConnectionInfo::decode(&encoded).unwrap();

        assert_eq!(decoded.addresses, info.addresses);
        assert_eq!(decoded.port, info.port);
    }
}
