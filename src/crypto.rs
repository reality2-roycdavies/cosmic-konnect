//! TLS certificate generation and management
//!
//! KDE Connect uses self-signed certificates for device identity.
//! Each device generates an RSA key pair and certificate on first run.

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info};

use crate::identity::{config_dir, save_identity, StoredIdentity};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Failed to generate key pair: {0}")]
    KeyGeneration(String),

    #[error("Failed to generate certificate: {0}")]
    CertGeneration(String),

    #[error("Failed to parse certificate: {0}")]
    CertParse(String),

    #[error("Failed to parse private key: {0}")]
    KeyParse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Identity error: {0}")]
    Identity(String),
}

/// Load or generate TLS credentials for this device
pub fn load_or_generate_credentials(
    identity: &mut StoredIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CryptoError> {
    // Check if we already have credentials
    if let (Some(cert_pem), Some(key_pem)) =
        (&identity.certificate_pem, &identity.private_key_pem)
    {
        debug!("Loading existing TLS credentials");
        let cert = parse_certificate_pem(cert_pem)?;
        let key = parse_private_key_pem(key_pem)?;
        return Ok((vec![cert], key));
    }

    // Generate new credentials
    info!("Generating new TLS credentials");
    let (cert_pem, key_pem) = generate_certificate(&identity.device_id)?;

    // Save to identity
    identity.certificate_pem = Some(cert_pem.clone());
    identity.private_key_pem = Some(key_pem.clone());
    save_identity(identity).map_err(|e| CryptoError::Identity(e.to_string()))?;

    let cert = parse_certificate_pem(&cert_pem)?;
    let key = parse_private_key_pem(&key_pem)?;

    Ok((vec![cert], key))
}

/// Generate a self-signed certificate for KDE Connect
fn generate_certificate(device_id: &str) -> Result<(String, String), CryptoError> {
    // Generate ECDSA P-256 key pair (KDE Connect supports RSA and ECDSA)
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

    // Set up certificate parameters
    let mut params = CertificateParams::default();

    // KDE Connect uses the device ID as the common name
    params
        .distinguished_name
        .push(DnType::CommonName, device_id.to_string());

    // Valid for 10 years (KDE Connect default)
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(3650);

    // Generate the certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CryptoError::CertGeneration(e.to_string()))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    info!("Generated new TLS certificate for device {}", device_id);

    Ok((cert_pem, key_pem))
}

/// Parse a PEM-encoded certificate
fn parse_certificate_pem(pem: &str) -> Result<CertificateDer<'static>, CryptoError> {
    let pem_parsed = pem::parse(pem).map_err(|e| CryptoError::CertParse(e.to_string()))?;

    Ok(CertificateDer::from(pem_parsed.contents().to_vec()))
}

/// Parse a PEM-encoded private key
fn parse_private_key_pem(pem: &str) -> Result<PrivateKeyDer<'static>, CryptoError> {
    let pem_parsed = pem::parse(pem).map_err(|e| CryptoError::KeyParse(e.to_string()))?;
    let key_bytes = pem_parsed.contents().to_vec();

    // Detect key type from PEM tag
    match pem_parsed.tag() {
        "PRIVATE KEY" => Ok(PrivateKeyDer::Pkcs8(key_bytes.into())),
        "EC PRIVATE KEY" => Ok(PrivateKeyDer::Sec1(key_bytes.into())),
        "RSA PRIVATE KEY" => Ok(PrivateKeyDer::Pkcs1(key_bytes.into())),
        other => Err(CryptoError::KeyParse(format!("Unknown key type: {}", other))),
    }
}

/// Get the path to the trusted devices directory
pub fn trusted_devices_dir() -> Result<PathBuf, CryptoError> {
    let dir = config_dir()
        .map_err(|e| CryptoError::Identity(e.to_string()))?
        .join("trusted_devices");
    Ok(dir)
}

/// Save a trusted device's certificate
pub fn save_trusted_device(device_id: &str, cert_pem: &str) -> Result<(), CryptoError> {
    let dir = trusted_devices_dir()?;
    fs::create_dir_all(&dir)?;

    let cert_path = dir.join(format!("{}.pem", device_id));
    fs::write(&cert_path, cert_pem)?;

    info!("Saved trusted device certificate: {}", device_id);
    Ok(())
}

/// Load a trusted device's certificate
#[allow(dead_code)]
pub fn load_trusted_device(device_id: &str) -> Result<Option<String>, CryptoError> {
    let cert_path = trusted_devices_dir()?.join(format!("{}.pem", device_id));

    if cert_path.exists() {
        let pem = fs::read_to_string(&cert_path)?;
        Ok(Some(pem))
    } else {
        Ok(None)
    }
}

/// Check if a device is trusted
pub fn is_device_trusted(device_id: &str) -> Result<bool, CryptoError> {
    let cert_path = trusted_devices_dir()?.join(format!("{}.pem", device_id));
    Ok(cert_path.exists())
}

/// List all trusted device IDs
#[allow(dead_code)]
pub fn list_trusted_devices() -> Result<Vec<String>, CryptoError> {
    let dir = trusted_devices_dir()?;

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut devices = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "pem") {
            if let Some(stem) = path.file_stem() {
                devices.push(stem.to_string_lossy().to_string());
            }
        }
    }

    Ok(devices)
}

/// Remove a trusted device
#[allow(dead_code)]
pub fn remove_trusted_device(device_id: &str) -> Result<(), CryptoError> {
    let cert_path = trusted_devices_dir()?.join(format!("{}.pem", device_id));

    if cert_path.exists() {
        fs::remove_file(&cert_path)?;
        info!("Removed trusted device: {}", device_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let (cert_pem, key_pem) = generate_certificate("test_device_id").unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }
}
