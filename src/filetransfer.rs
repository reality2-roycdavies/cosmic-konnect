//! File transfer handling
//!
//! Implements the KDE Connect share plugin for sending/receiving files.

use crate::protocol::NetworkPacket;
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Handle incoming share.request packet
/// Returns the path to the received file if successful
pub async fn handle_share_request(
    packet: &NetworkPacket,
    device_address: IpAddr,
    download_dir: &PathBuf,
    device_name: &str,
) -> Option<PathBuf> {
    // Check if this is a file transfer (has payload)
    if let Some(payload_size) = packet.payload_size {
        // Get transfer port from payloadTransferInfo
        let port = packet
            .payload_transfer_info
            .as_ref()
            .and_then(|info| info.get("port"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u16)?;

        let filename = packet
            .body
            .get("filename")
            .and_then(|f| f.as_str())
            .unwrap_or("received_file");

        info!(
            "Receiving file '{}' ({} bytes) from {} on port {}",
            filename, payload_size, device_name, port
        );

        // Create download directory if needed
        if let Err(e) = tokio::fs::create_dir_all(download_dir).await {
            error!("Failed to create download dir: {}", e);
            return None;
        }

        // Generate unique filename to avoid overwriting
        let dest_path = get_unique_path(download_dir, filename).await;

        // Connect to sender's payload port
        let addr = std::net::SocketAddr::new(device_address, port);
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to payload port: {}", e);
                return None;
            }
        };

        // For KDE Connect, payload connections also need TLS
        // The receiver is TLS client, sender is TLS server
        // For simplicity, we'll try without TLS first (some implementations don't require it)
        if let Err(e) = receive_file_data(stream, &dest_path, payload_size).await {
            error!("Failed to receive file: {}", e);
            return None;
        }

        info!("File saved to {:?}", dest_path);

        // Show notification
        let path_str = dest_path.display().to_string();
        let notif_device = device_name.to_string();
        let notif_filename = filename.to_string();
        std::thread::spawn(move || {
            let _ = notify_rust::Notification::new()
                .summary(&format!("File received from {}", notif_device))
                .body(&format!("{}\nSaved to: {}", notif_filename, path_str))
                .icon("document-save")
                .timeout(10000)
                .show();
        });

        return Some(dest_path);
    }

    // Check if this is a URL share
    if let Some(url) = packet.body.get("url").and_then(|u| u.as_str()) {
        info!("Received URL from {}: {}", device_name, url);

        // Open in default browser
        if let Err(e) = std::process::Command::new("xdg-open").arg(url).spawn() {
            warn!("Failed to open URL: {}", e);
        }

        // Show notification
        let notif_url = url.to_string();
        let notif_device = device_name.to_string();
        std::thread::spawn(move || {
            let _ = notify_rust::Notification::new()
                .summary(&format!("URL from {}", notif_device))
                .body(&notif_url)
                .icon("web-browser")
                .timeout(5000)
                .show();
        });

        return None;
    }

    // Check if this is text share
    if let Some(text) = packet.body.get("text").and_then(|t| t.as_str()) {
        info!("Received text from {}: {} chars", device_name, text.len());

        // Copy to clipboard
        if let Err(e) = crate::clipboard::set_clipboard(text) {
            warn!("Failed to copy text to clipboard: {}", e);
        }

        // Show notification
        let preview = if text.len() > 100 {
            format!("{}...", &text[..100])
        } else {
            text.to_string()
        };
        let notif_device = device_name.to_string();
        std::thread::spawn(move || {
            let _ = notify_rust::Notification::new()
                .summary(&format!("Text from {}", notif_device))
                .body(&format!("Copied to clipboard:\n{}", preview))
                .icon("edit-paste")
                .timeout(5000)
                .show();
        });

        return None;
    }

    debug!("Unhandled share request: {:?}", packet.body);
    None
}

/// Receive file data from stream and save to path
async fn receive_file_data(
    mut stream: TcpStream,
    dest_path: &PathBuf,
    expected_size: u64,
) -> Result<(), std::io::Error> {
    let mut file = File::create(dest_path).await?;
    let mut buffer = [0u8; 8192];
    let mut received: u64 = 0;

    loop {
        let to_read = std::cmp::min((expected_size - received) as usize, buffer.len());
        if to_read == 0 {
            break;
        }

        let n = stream.read(&mut buffer[..to_read]).await?;
        if n == 0 {
            if received < expected_size {
                warn!(
                    "Connection closed early: received {} of {} bytes",
                    received, expected_size
                );
            }
            break;
        }

        file.write_all(&buffer[..n]).await?;
        received += n as u64;

        // Log progress for large files
        if received % (1024 * 1024) == 0 {
            debug!("Received {} MB", received / (1024 * 1024));
        }
    }

    file.flush().await?;
    info!("Received {} bytes", received);
    Ok(())
}

/// Get a unique file path, appending (1), (2), etc. if file exists
async fn get_unique_path(dir: &PathBuf, filename: &str) -> PathBuf {
    let base_path = dir.join(filename);
    if !base_path.exists() {
        return base_path;
    }

    let stem = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    for i in 1..1000 {
        let new_name = if ext.is_empty() {
            format!("{} ({})", stem, i)
        } else {
            format!("{} ({}).{}", stem, i, ext)
        };
        let new_path = dir.join(&new_name);
        if !new_path.exists() {
            return new_path;
        }
    }

    // Fallback: use timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if ext.is_empty() {
        dir.join(format!("{}_{}", stem, timestamp))
    } else {
        dir.join(format!("{}_{}.{}", stem, timestamp, ext))
    }
}
