//! KDE Connect protocol types and constants
//!
//! This module defines the core protocol structures used for KDE Connect communication.
//! The protocol uses JSON packets exchanged over TLS-encrypted TCP connections,
//! with UDP broadcast for device discovery.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version - currently only version 7 is valid
pub const PROTOCOL_VERSION: u32 = 7;

/// UDP port for broadcasting/receiving identity packets
pub const UDP_BROADCAST_PORT: u16 = 1716;

/// Default TCP port for incoming connections
pub const DEFAULT_TCP_PORT: u16 = 1716;

/// Minimum valid TCP port
#[allow(dead_code)]
pub const MIN_TCP_PORT: u16 = 1716;

/// Maximum valid TCP port
#[allow(dead_code)]
pub const MAX_TCP_PORT: u16 = 1764;

/// Device types as defined by the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Desktop,
    Laptop,
    Phone,
    Tablet,
    Tv,
}

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::Desktop
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Desktop => write!(f, "desktop"),
            DeviceType::Laptop => write!(f, "laptop"),
            DeviceType::Phone => write!(f, "phone"),
            DeviceType::Tablet => write!(f, "tablet"),
            DeviceType::Tv => write!(f, "tv"),
        }
    }
}

/// A KDE Connect network packet
///
/// All communication uses this JSON structure with type-specific bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPacket {
    /// Timestamp in milliseconds since UNIX epoch
    pub id: u64,

    /// Packet type (e.g., "kdeconnect.identity", "kdeconnect.ping")
    #[serde(rename = "type")]
    pub packet_type: String,

    /// Type-specific payload
    pub body: serde_json::Value,

    /// Optional payload size for transfer packets
    #[serde(rename = "payloadSize", skip_serializing_if = "Option::is_none")]
    pub payload_size: Option<u64>,

    /// Optional payload transfer info
    #[serde(rename = "payloadTransferInfo", skip_serializing_if = "Option::is_none")]
    pub payload_transfer_info: Option<serde_json::Value>,
}

impl NetworkPacket {
    /// Create a new packet with the current timestamp
    pub fn new(packet_type: impl Into<String>, body: serde_json::Value) -> Self {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            id,
            packet_type: packet_type.into(),
            body,
            payload_size: None,
            payload_transfer_info: None,
        }
    }

    /// Serialize to JSON with trailing newline (as required by protocol)
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Parse from JSON (handles optional trailing newline)
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json.trim())
    }
}

/// Identity packet body - used for device discovery and handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPacketBody {
    /// Unique device identifier (UUIDv4 with underscores instead of hyphens)
    pub device_id: String,

    /// Human-readable device name (1-32 chars, restricted charset)
    pub device_name: String,

    /// Device type
    pub device_type: DeviceType,

    /// Protocol version (must be 7)
    pub protocol_version: u32,

    /// Capabilities this device can receive
    pub incoming_capabilities: Vec<String>,

    /// Capabilities this device can send
    pub outgoing_capabilities: Vec<String>,

    /// TCP port for connections (included in UDP broadcast)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
}

impl IdentityPacketBody {
    /// Create a new identity for this device
    pub fn new(device_id: String, device_name: String, device_type: DeviceType) -> Self {
        Self {
            device_id,
            device_name,
            device_type,
            protocol_version: PROTOCOL_VERSION,
            incoming_capabilities: Vec::new(),
            outgoing_capabilities: Vec::new(),
            tcp_port: None,
        }
    }

    /// Set the TCP port for LAN discovery
    pub fn with_tcp_port(mut self, port: u16) -> Self {
        self.tcp_port = Some(port);
        self
    }

    /// Add capabilities
    pub fn with_capabilities(mut self, incoming: Vec<String>, outgoing: Vec<String>) -> Self {
        self.incoming_capabilities = incoming;
        self.outgoing_capabilities = outgoing;
        self
    }

    /// Convert to a NetworkPacket
    pub fn to_packet(&self) -> Result<NetworkPacket, serde_json::Error> {
        let body = serde_json::to_value(self)?;
        Ok(NetworkPacket::new("kdeconnect.identity", body))
    }
}

/// Represents a discovered device
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    /// Device identity information
    pub identity: IdentityPacketBody,

    /// IP address the device was discovered from
    pub address: std::net::IpAddr,

    /// TCP port for connection
    pub tcp_port: u16,

    /// When this device was last seen
    pub last_seen: std::time::Instant,
}

impl DiscoveredDevice {
    /// Check if this device info is stale (not seen recently)
    pub fn is_stale(&self, timeout: std::time::Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_packet_serialization() {
        let identity = IdentityPacketBody::new(
            "test_device_id".to_string(),
            "Test Device".to_string(),
            DeviceType::Desktop,
        )
        .with_tcp_port(1716);

        let packet = identity.to_packet().unwrap();
        let json = packet.to_json_line().unwrap();

        assert!(json.contains("kdeconnect.identity"));
        assert!(json.contains("test_device_id"));
        assert!(json.ends_with('\n'));

        // Round-trip test
        let parsed = NetworkPacket::from_json(&json).unwrap();
        assert_eq!(parsed.packet_type, "kdeconnect.identity");
    }

    #[test]
    fn test_device_type_serialization() {
        let dt = DeviceType::Laptop;
        let json = serde_json::to_string(&dt).unwrap();
        assert_eq!(json, "\"laptop\"");
    }
}
