//! Error types for the daemon

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    #[error("BLE error: {0}")]
    Ble(#[from] bluer::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Device error: {0}")]
    Device(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for DaemonError {
    fn from(e: serde_json::Error) -> Self {
        DaemonError::Serialization(e.to_string())
    }
}

impl From<rmp_serde::encode::Error> for DaemonError {
    fn from(e: rmp_serde::encode::Error) -> Self {
        DaemonError::Serialization(e.to_string())
    }
}

impl From<rmp_serde::decode::Error> for DaemonError {
    fn from(e: rmp_serde::decode::Error) -> Self {
        DaemonError::Serialization(e.to_string())
    }
}
