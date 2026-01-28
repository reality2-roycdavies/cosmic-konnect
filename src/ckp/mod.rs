//! Cosmic Konnect Protocol (CKP) implementation
//!
//! A lightweight, secure protocol for device-to-device communication.

mod message;
mod crypto;
mod connection;
mod discovery;
mod service;
mod dbus;

pub use message::*;
pub use crypto::*;
pub use connection::*;
pub use discovery::*;
pub use service::*;
pub use dbus::*;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes for message header
pub const MAGIC: [u8; 2] = [0x43, 0x4B]; // "CK"

/// Default ports
pub const UDP_DISCOVERY_PORT: u16 = 17160;
pub const TCP_PORT: u16 = 17161;

/// BLE UUIDs
pub const BLE_SERVICE_UUID: &str = "c05a1c00-a0aa-3c70-9000-000000000001";
pub const BLE_IDENTITY_CHAR_UUID: &str = "c05a1c00-a0aa-3c70-9001-000000000001";
pub const BLE_MESSAGE_CHAR_UUID: &str = "c05a1c00-a0aa-3c70-9002-000000000001";
pub const BLE_CONNECTION_INFO_CHAR_UUID: &str = "c05a1c00-a0aa-3c70-9003-000000000001";

/// Wi-Fi Direct service type
pub const WIFI_DIRECT_SERVICE_TYPE: &str = "_cosmickonnect._tcp";

/// Limits
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MB
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
pub const DISCOVERY_INTERVAL_SECS: u64 = 5;
pub const CONNECTION_TIMEOUT_SECS: u64 = 30;
pub const KEEPALIVE_INTERVAL_SECS: u64 = 60;
