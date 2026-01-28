//! Device discovery via UDP broadcast
//!
//! KDE Connect uses UDP broadcast on port 1716 for device discovery.
//! Devices periodically broadcast their identity packets, and listen
//! for identity packets from other devices.

use crate::protocol::{
    DiscoveredDevice, IdentityPacketBody, NetworkPacket, DEFAULT_TCP_PORT, UDP_BROADCAST_PORT,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, trace};

/// Discovery-related errors
#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Socket error: {0}")]
    Socket(String),
}

/// Events emitted by the discovery service
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new device was discovered
    DeviceDiscovered(DiscoveredDevice),

    /// A known device updated its info
    DeviceUpdated(DiscoveredDevice),

    /// A device hasn't been seen and is considered lost
    DeviceLost(String), // device_id
}

/// Configuration for the discovery service
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to broadcast our identity (default: 5 seconds)
    pub broadcast_interval: Duration,

    /// How long before a device is considered stale (default: 30 seconds)
    pub device_timeout: Duration,

    /// Our TCP port to advertise
    pub tcp_port: u16,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            broadcast_interval: Duration::from_secs(5),
            device_timeout: Duration::from_secs(30),
            tcp_port: DEFAULT_TCP_PORT,
        }
    }
}

/// The discovery service handles finding other KDE Connect devices on the network
pub struct DiscoveryService {
    /// Our device identity
    identity: IdentityPacketBody,

    /// Configuration
    config: DiscoveryConfig,

    /// Known devices
    devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,

    /// Event broadcast channel
    event_tx: broadcast::Sender<DiscoveryEvent>,

    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl DiscoveryService {
    /// Create a new discovery service
    pub fn new(identity: IdentityPacketBody, config: DiscoveryConfig) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            identity,
            config,
            devices: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            shutdown_tx: None,
        }
    }

    /// Subscribe to discovery events
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.event_tx.subscribe()
    }

    /// Get a list of currently known devices
    pub async fn get_devices(&self) -> Vec<DiscoveredDevice> {
        self.devices.read().await.values().cloned().collect()
    }

    /// Start the discovery service
    pub async fn start(&mut self) -> Result<(), DiscoveryError> {
        info!("Starting discovery service on UDP port {}", UDP_BROADCAST_PORT);

        // Create UDP socket for receiving broadcasts
        let recv_socket = create_broadcast_socket(UDP_BROADCAST_PORT)?;
        let recv_socket = UdpSocket::from_std(recv_socket.into())?;

        // Create UDP socket for sending broadcasts
        let send_socket = create_broadcast_socket(0)?; // Bind to any port for sending
        let send_socket = UdpSocket::from_std(send_socket.into())?;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Prepare identity packet
        let identity_with_port = self.identity.clone().with_tcp_port(self.config.tcp_port);
        let identity_packet = identity_with_port.to_packet()?;
        let identity_json = identity_packet.to_json_line()?;

        let devices = self.devices.clone();
        let event_tx = self.event_tx.clone();
        let my_device_id = self.identity.device_id.clone();
        let broadcast_interval = self.config.broadcast_interval;
        let device_timeout = self.config.device_timeout;

        // Spawn the main discovery loop
        tokio::spawn(async move {
            let mut broadcast_timer = tokio::time::interval(broadcast_interval);
            let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));
            let mut recv_buf = [0u8; 4096];

            // Broadcast immediately on start
            if let Err(e) = broadcast_identity(&send_socket, &identity_json).await {
                error!("Failed to broadcast identity: {}", e);
            }

            loop {
                tokio::select! {
                    // Check for shutdown
                    _ = &mut shutdown_rx => {
                        info!("Discovery service shutting down");
                        break;
                    }

                    // Periodic broadcast
                    _ = broadcast_timer.tick() => {
                        trace!("Broadcasting identity");
                        if let Err(e) = broadcast_identity(&send_socket, &identity_json).await {
                            error!("Failed to broadcast identity: {}", e);
                        }
                    }

                    // Periodic cleanup of stale devices
                    _ = cleanup_timer.tick() => {
                        cleanup_stale_devices(&devices, &event_tx, device_timeout).await;
                    }

                    // Receive incoming packets
                    result = recv_socket.recv_from(&mut recv_buf) => {
                        match result {
                            Ok((len, addr)) => {
                                let data = &recv_buf[..len];
                                match handle_incoming_packet(
                                    data,
                                    addr,
                                    &my_device_id,
                                    &devices,
                                    &event_tx,
                                ).await {
                                    Ok(is_new_device) => {
                                        // If this is a new device, send our identity directly to them
                                        // This helps on networks where broadcast doesn't work well (e.g., hotspots)
                                        if is_new_device {
                                            let reply_addr = SocketAddr::new(addr.ip(), UDP_BROADCAST_PORT);
                                            info!("Sending direct identity reply to {}", reply_addr);
                                            if let Err(e) = send_socket.send_to(identity_json.as_bytes(), reply_addr).await {
                                                error!("Failed to send direct reply to {}: {}", reply_addr, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Failed to handle packet from {}: {}", addr, e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to receive UDP packet: {}", e);
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the discovery service
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Send a targeted identity packet to a specific address
    #[allow(dead_code)]
    pub async fn send_identity_to(&self, addr: SocketAddr) -> Result<(), DiscoveryError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let identity_with_port = self.identity.clone().with_tcp_port(self.config.tcp_port);
        let packet = identity_with_port.to_packet()?;
        let json = packet.to_json_line()?;

        socket.send_to(json.as_bytes(), addr).await?;
        debug!("Sent identity to {}", addr);

        Ok(())
    }

    /// Broadcast identity to all devices on the network
    pub async fn broadcast_identity(&self) -> Result<(), DiscoveryError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.set_broadcast(true)?;

        let identity_with_port = self.identity.clone().with_tcp_port(self.config.tcp_port);
        let packet = identity_with_port.to_packet()?;
        let json = packet.to_json_line()?;

        let broadcast_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            UDP_BROADCAST_PORT,
        );

        socket.send_to(json.as_bytes(), broadcast_addr).await?;
        debug!("Broadcast identity");

        Ok(())
    }
}

/// Create a UDP socket suitable for broadcast
fn create_broadcast_socket(port: u16) -> Result<Socket, DiscoveryError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| DiscoveryError::Socket(e.to_string()))?;

    // Allow address reuse so multiple instances can bind
    socket
        .set_reuse_address(true)
        .map_err(|e| DiscoveryError::Socket(e.to_string()))?;

    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| DiscoveryError::Socket(e.to_string()))?;

    // Enable broadcast
    socket
        .set_broadcast(true)
        .map_err(|e| DiscoveryError::Socket(e.to_string()))?;

    // Bind to the port
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&addr.into())
        .map_err(|e| DiscoveryError::Socket(format!("Failed to bind to port {}: {}", port, e)))?;

    // Set non-blocking for tokio
    socket
        .set_nonblocking(true)
        .map_err(|e| DiscoveryError::Socket(e.to_string()))?;

    Ok(socket)
}

/// Broadcast identity to all network interfaces
async fn broadcast_identity(socket: &UdpSocket, identity_json: &str) -> Result<(), DiscoveryError> {
    // Broadcast to 255.255.255.255
    let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), UDP_BROADCAST_PORT);

    socket.send_to(identity_json.as_bytes(), broadcast_addr).await?;
    trace!("Broadcast identity packet ({} bytes)", identity_json.len());

    Ok(())
}

/// Handle an incoming UDP packet
/// Returns true if this was a newly discovered device
async fn handle_incoming_packet(
    data: &[u8],
    addr: SocketAddr,
    my_device_id: &str,
    devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    event_tx: &broadcast::Sender<DiscoveryEvent>,
) -> Result<bool, DiscoveryError> {
    // Parse as UTF-8
    let json = std::str::from_utf8(data)
        .map_err(|e| DiscoveryError::InvalidPacket(format!("Invalid UTF-8: {}", e)))?;

    trace!("Received packet from {}: {}", addr, json.trim());

    // Parse the network packet
    let packet = NetworkPacket::from_json(json)?;

    // We only care about identity packets for discovery
    if packet.packet_type != "kdeconnect.identity" {
        return Ok(false);
    }

    // Parse the identity body
    let identity: IdentityPacketBody = serde_json::from_value(packet.body)?;

    // Ignore our own broadcasts
    if identity.device_id == my_device_id {
        trace!("Ignoring our own broadcast");
        return Ok(false);
    }

    // Get the TCP port from the identity
    let tcp_port = identity.tcp_port.unwrap_or(DEFAULT_TCP_PORT);

    let device = DiscoveredDevice {
        identity: identity.clone(),
        address: addr.ip(),
        tcp_port,
        last_seen: Instant::now(),
    };

    // Check if this is a new device or an update
    let mut devices = devices.write().await;
    let is_new = !devices.contains_key(&identity.device_id);

    devices.insert(identity.device_id.clone(), device.clone());

    // Emit event
    let event = if is_new {
        info!(
            "Discovered new device: {} ({}) at {}:{}",
            identity.device_name, identity.device_type, addr.ip(), tcp_port
        );
        DiscoveryEvent::DeviceDiscovered(device)
    } else {
        debug!("Updated device: {} at {}", identity.device_name, addr.ip());
        DiscoveryEvent::DeviceUpdated(device)
    };

    let _ = event_tx.send(event);

    Ok(is_new)
}

/// Remove devices that haven't been seen recently
async fn cleanup_stale_devices(
    devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    event_tx: &broadcast::Sender<DiscoveryEvent>,
    timeout: Duration,
) {
    let mut devices = devices.write().await;
    let stale_ids: Vec<String> = devices
        .iter()
        .filter(|(_, d)| d.is_stale(timeout))
        .map(|(id, _)| id.clone())
        .collect();

    for id in stale_ids {
        if let Some(device) = devices.remove(&id) {
            info!("Device lost: {}", device.identity.device_name);
            let _ = event_tx.send(DiscoveryEvent::DeviceLost(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DeviceType;

    #[tokio::test]
    async fn test_discovery_service_creation() {
        let identity = IdentityPacketBody::new(
            "test_id".to_string(),
            "Test Device".to_string(),
            DeviceType::Desktop,
        );

        let service = DiscoveryService::new(identity, DiscoveryConfig::default());
        assert!(service.get_devices().await.is_empty());
    }
}
