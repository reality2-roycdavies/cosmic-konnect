//! Cosmic Konnect Protocol (CKP) implementation
//!
//! A lightweight, secure protocol for device-to-device communication.

pub mod message;
pub mod crypto;
pub mod connection;

pub use message::*;
pub use crypto::*;
pub use connection::*;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes for message header
pub const MAGIC: [u8; 2] = [0x43, 0x4B]; // "CK"

/// Default ports
pub const UDP_DISCOVERY_PORT: u16 = 17160;
pub const TCP_PORT: u16 = 17161;

/// Limits
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MB
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
pub const DISCOVERY_INTERVAL_SECS: u64 = 5;
pub const CONNECTION_TIMEOUT_SECS: u64 = 30;
pub const KEEPALIVE_INTERVAL_SECS: u64 = 60;
