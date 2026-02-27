//! Configuration management for the daemon
//!
//! Handles loading and saving daemon configuration, including:
//! - Device identity
//! - Network settings
//! - Paired devices

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info};

use crate::error::DaemonError;

/// Default TCP port for CKP connections (matches Android Protocol.TCP_PORT)
pub const DEFAULT_TCP_PORT: u16 = 17161;

/// Current protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Device type enumeration
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
        Self::Desktop
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

/// Device identity stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub device_type: DeviceType,
}

/// Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Device identity
    pub identity: DeviceIdentity,

    /// TCP port to listen on
    pub tcp_port: u16,

    /// Enable BLE discovery/advertising
    pub ble_enabled: bool,

    /// Enable mDNS discovery/advertising
    pub mdns_enabled: bool,

    /// Enable clipboard sync
    pub clipboard_sync: bool,

    /// Enable notification sync
    pub notification_sync: bool,

    /// Path where config was loaded from
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identity: DeviceIdentity {
                device_id: generate_device_id(),
                device_name: get_device_name(),
                device_type: detect_device_type(),
            },
            tcp_port: DEFAULT_TCP_PORT,
            ble_enabled: true,
            mdns_enabled: true,
            clipboard_sync: true,
            notification_sync: true,
            config_path: None,
        }
    }
}

impl Config {
    /// Load configuration from disk, or create default if not exists
    pub async fn load() -> Result<Self, DaemonError> {
        let config_dir = config_dir()?;
        let config_file = config_dir.join("daemon.json");

        if config_file.exists() {
            debug!("Loading config from {:?}", config_file);
            let content = tokio::fs::read_to_string(&config_file).await?;
            let mut config: Config = serde_json::from_str(&content)?;
            config.config_path = Some(config_file);
            info!("Loaded config for device: {} ({})",
                config.identity.device_name,
                config.identity.device_id
            );
            Ok(config)
        } else {
            info!("Creating new configuration");
            let mut config = Config::default();
            config.config_path = Some(config_file.clone());

            // Ensure directory exists
            tokio::fs::create_dir_all(&config_dir).await?;

            // Save default config
            let content = serde_json::to_string_pretty(&config)?;
            tokio::fs::write(&config_file, content).await?;

            info!("Created new device identity: {} ({}) - {:?}",
                config.identity.device_name,
                config.identity.device_id,
                config.identity.device_type
            );

            Ok(config)
        }
    }

    /// Save configuration to disk
    pub async fn save(&self) -> Result<(), DaemonError> {
        let config_file = self.config_path.clone()
            .unwrap_or_else(|| config_dir().unwrap().join("daemon.json"));

        let content = serde_json::to_string_pretty(self)?;
        tokio::fs::write(&config_file, content).await?;

        debug!("Saved config to {:?}", config_file);
        Ok(())
    }

    /// Get the configuration file path
    pub fn config_path(&self) -> Option<&PathBuf> {
        self.config_path.as_ref()
    }

    /// Get the data directory for storing paired devices, etc.
    pub fn data_dir(&self) -> Result<PathBuf, DaemonError> {
        config_dir()
    }
}

/// Get the config directory for cosmic-konnect
fn config_dir() -> Result<PathBuf, DaemonError> {
    dirs::config_dir()
        .map(|d| d.join("cosmic-konnect"))
        .ok_or_else(|| DaemonError::Config("Could not determine config directory".into()))
}

/// Generate a unique device ID (UUID with underscores instead of hyphens)
fn generate_device_id() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "_")
}

/// Get the device hostname as the device name
fn get_device_name() -> String {
    hostname::get()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|_| "COSMIC Desktop".to_string())
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(32)
        .collect()
}

/// Detect device type based on system characteristics
fn detect_device_type() -> DeviceType {
    // Check for battery (indicates laptop)
    let has_battery = std::path::Path::new("/sys/class/power_supply/BAT0").exists()
        || std::path::Path::new("/sys/class/power_supply/BAT1").exists();

    if has_battery {
        DeviceType::Laptop
    } else {
        DeviceType::Desktop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_device_id() {
        let id = generate_device_id();
        assert!(!id.contains('-'));
        assert!(id.contains('_'));
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn test_device_type_display() {
        assert_eq!(DeviceType::Desktop.to_string(), "desktop");
        assert_eq!(DeviceType::Laptop.to_string(), "laptop");
    }
}
