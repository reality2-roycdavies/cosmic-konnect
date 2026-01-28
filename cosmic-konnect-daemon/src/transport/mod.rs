//! Transport layer for network communication
//!
//! Handles:
//! - mDNS/DNS-SD discovery and advertising
//! - TCP listener for incoming connections
//! - Connection management

pub mod listener;
pub mod mdns;
