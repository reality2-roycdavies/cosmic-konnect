//! Clipboard synchronization
//!
//! Handles bidirectional clipboard sharing between devices.
//! Uses wl-copy/wl-paste for Wayland compatibility.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::connection::DeviceSenders;
use crate::protocol::NetworkPacket;

/// Clipboard state
pub struct ClipboardState {
    /// Last known clipboard content
    pub content: String,
    /// Timestamp when content was last updated
    pub timestamp: u64,
    /// Whether clipboard sync is enabled
    pub enabled: bool,
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self {
            content: String::new(),
            timestamp: 0,
            enabled: true,
        }
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Get current clipboard content using wl-paste (Wayland)
pub fn get_clipboard() -> Option<String> {
    // Try wl-paste first (Wayland)
    if let Ok(output) = Command::new("wl-paste")
        .arg("--no-newline")
        .output()
    {
        if output.status.success() {
            return String::from_utf8(output.stdout).ok();
        }
    }

    // Fallback to xclip (X11)
    if let Ok(output) = Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output()
    {
        if output.status.success() {
            return String::from_utf8(output.stdout).ok();
        }
    }

    debug!("Failed to read clipboard");
    None
}

/// Set clipboard content using wl-copy (Wayland)
pub fn set_clipboard(content: &str) -> Result<(), String> {
    // Try wl-copy first (Wayland)
    let mut child = Command::new("wl-copy")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run wl-copy: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write to wl-copy: {}", e))?;
    }

    let status = child.wait()
        .map_err(|e| format!("Failed to wait for wl-copy: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        // Fallback to xclip
        let mut child = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to run xclip: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(content.as_bytes())
                .map_err(|e| format!("Failed to write to xclip: {}", e))?;
        }

        child.wait()
            .map_err(|e| format!("Failed to wait for xclip: {}", e))?;

        Ok(())
    }
}

/// Create a clipboard packet
pub fn create_clipboard_packet(content: &str) -> NetworkPacket {
    NetworkPacket::new(
        "kdeconnect.clipboard",
        serde_json::json!({
            "content": content
        }),
    )
}

/// Create a clipboard connect packet (for initial sync)
pub fn create_clipboard_connect_packet(content: &str, timestamp: u64) -> NetworkPacket {
    NetworkPacket::new(
        "kdeconnect.clipboard.connect",
        serde_json::json!({
            "content": content,
            "timestamp": timestamp
        }),
    )
}

/// Handle incoming clipboard packet
pub fn handle_clipboard_packet(packet: &NetworkPacket, state: &mut ClipboardState) {
    if let Some(content) = packet.body.get("content").and_then(|c| c.as_str()) {
        info!("Received clipboard: {} chars", content.len());

        // Update local clipboard
        if let Err(e) = set_clipboard(content) {
            warn!("Failed to set clipboard: {}", e);
            return;
        }

        // Update state to prevent echo
        state.content = content.to_string();
        state.timestamp = current_timestamp_millis();
    }
}

/// Handle incoming clipboard.connect packet (initial sync)
pub fn handle_clipboard_connect_packet(packet: &NetworkPacket, state: &mut ClipboardState) {
    if let Some(content) = packet.body.get("content").and_then(|c| c.as_str()) {
        let remote_timestamp = packet
            .body
            .get("timestamp")
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        // Only update if remote is newer
        if remote_timestamp > state.timestamp {
            info!(
                "Received newer clipboard from connect: {} chars",
                content.len()
            );
            if let Err(e) = set_clipboard(content) {
                warn!("Failed to set clipboard: {}", e);
                return;
            }
            state.content = content.to_string();
            state.timestamp = remote_timestamp;
        }
    }
}

/// Start clipboard monitoring task
/// Returns a receiver that yields packets to send when clipboard changes
pub fn start_clipboard_monitor(
    state: Arc<RwLock<ClipboardState>>,
    device_senders: DeviceSenders,
) -> mpsc::Sender<()> {
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        let mut last_content = String::new();

        // Initialize with current clipboard content
        if let Some(content) = get_clipboard() {
            last_content = content.clone();
            let mut state = state.write().await;
            state.content = content;
            state.timestamp = current_timestamp_millis();
        }

        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    info!("Clipboard monitor stopped");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    // Check if sync is enabled
                    let enabled = {
                        let state = state.read().await;
                        state.enabled
                    };

                    if !enabled {
                        continue;
                    }

                    // Check for clipboard changes
                    if let Some(content) = get_clipboard() {
                        if content != last_content && !content.is_empty() {
                            debug!("Clipboard changed: {} chars", content.len());
                            last_content = content.clone();

                            // Update state
                            {
                                let mut state = state.write().await;
                                state.content = content.clone();
                                state.timestamp = current_timestamp_millis();
                            }

                            // Send to all connected devices
                            let packet = create_clipboard_packet(&content);
                            let senders = device_senders.read().await;
                            for (device_id, sender) in senders.iter() {
                                if let Err(e) = sender.send(packet.clone()).await {
                                    debug!("Failed to send clipboard to {}: {}", device_id, e);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    stop_tx
}
