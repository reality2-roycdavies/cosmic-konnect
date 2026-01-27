//! Device identity management
//!
//! Generates and persists a unique device identity for this installation.
//! The device ID is a UUIDv4 with hyphens replaced by underscores.

use crate::protocol::{DeviceType, IdentityPacketBody};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

/// Identity-related errors
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Failed to determine hostname")]
    Hostname,

    #[error("Failed to determine config directory")]
    ConfigDir,
}

/// Persistent device identity stored on disk
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredIdentity {
    pub device_id: String,
    pub device_name: String,
    pub device_type: DeviceType,
    pub private_key_pem: Option<String>,
    pub certificate_pem: Option<String>,
}

/// Get the config directory for cosmic-konnect
pub fn config_dir() -> Result<PathBuf, IdentityError> {
    dirs::config_dir()
        .map(|d| d.join("cosmic-konnect"))
        .ok_or(IdentityError::ConfigDir)
}

/// Get the path to the identity file
fn identity_file_path() -> Result<PathBuf, IdentityError> {
    Ok(config_dir()?.join("identity.json"))
}

/// Generate a KDE Connect compatible device ID
/// Format: UUIDv4 with hyphens replaced by underscores
fn generate_device_id() -> String {
    Uuid::new_v4().to_string().replace('-', "_")
}

/// Get the device name (hostname, sanitized for KDE Connect)
fn get_device_name() -> Result<String, IdentityError> {
    let name = hostname::get()
        .map_err(|_| IdentityError::Hostname)?
        .to_string_lossy()
        .to_string();

    // Sanitize: KDE Connect restricts to 1-32 chars, no special chars
    let sanitized: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(32)
        .collect();

    if sanitized.is_empty() {
        Ok("COSMIC Desktop".to_string())
    } else {
        Ok(sanitized)
    }
}

/// Detect the device type based on system characteristics
fn detect_device_type() -> DeviceType {
    // Check for laptop indicators
    let is_laptop = std::path::Path::new("/sys/class/power_supply/BAT0").exists()
        || std::path::Path::new("/sys/class/power_supply/BAT1").exists();

    if is_laptop {
        DeviceType::Laptop
    } else {
        DeviceType::Desktop
    }
}

/// Load or create the device identity
pub fn load_or_create_identity() -> Result<StoredIdentity, IdentityError> {
    let identity_path = identity_file_path()?;

    if identity_path.exists() {
        debug!("Loading existing identity from {:?}", identity_path);
        let content = fs::read_to_string(&identity_path)?;
        let identity: StoredIdentity = serde_json::from_str(&content)?;
        info!(
            "Loaded identity: {} ({})",
            identity.device_name, identity.device_id
        );
        return Ok(identity);
    }

    // Create new identity
    info!("Creating new device identity");
    let identity = StoredIdentity {
        device_id: generate_device_id(),
        device_name: get_device_name()?,
        device_type: detect_device_type(),
        private_key_pem: None,
        certificate_pem: None,
    };

    // Save to disk
    let config_dir = config_dir()?;
    fs::create_dir_all(&config_dir)?;

    let content = serde_json::to_string_pretty(&identity)?;
    fs::write(&identity_path, content)?;

    info!(
        "Created new identity: {} ({}) - {:?}",
        identity.device_name, identity.device_id, identity.device_type
    );

    Ok(identity)
}

/// Save the identity (e.g., after adding certificates)
#[allow(dead_code)]
pub fn save_identity(identity: &StoredIdentity) -> Result<(), IdentityError> {
    let identity_path = identity_file_path()?;
    let config_dir = config_dir()?;

    fs::create_dir_all(&config_dir)?;
    let content = serde_json::to_string_pretty(identity)?;
    fs::write(&identity_path, content)?;

    debug!("Saved identity to {:?}", identity_path);
    Ok(())
}

impl StoredIdentity {
    /// Convert to an IdentityPacketBody for network communication
    pub fn to_identity_packet(&self, capabilities: (Vec<String>, Vec<String>)) -> IdentityPacketBody {
        IdentityPacketBody::new(
            self.device_id.clone(),
            self.device_name.clone(),
            self.device_type,
        )
        .with_capabilities(capabilities.0, capabilities.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_device_id() {
        let id = generate_device_id();
        // Should be UUID format with underscores
        assert!(!id.contains('-'));
        assert!(id.contains('_'));
        assert_eq!(id.len(), 36); // UUID length
    }

    #[test]
    fn test_detect_device_type() {
        // This will return Desktop or Laptop depending on the system
        let dt = detect_device_type();
        assert!(matches!(dt, DeviceType::Desktop | DeviceType::Laptop));
    }
}
