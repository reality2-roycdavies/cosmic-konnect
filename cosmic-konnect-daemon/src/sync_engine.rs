//! Sync engine for coordinating data sync between devices
//!
//! Handles synchronization of:
//! - Clipboard content
//! - Notifications
//! - Files
//! - Custom data

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

use crate::AppState;
use crate::error::DaemonError;

/// Sync event types
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Clipboard content received
    ClipboardReceived {
        device_id: String,
        content: String,
        timestamp: u64,
    },
    /// Notification received
    NotificationReceived {
        device_id: String,
        app_name: String,
        title: String,
        text: String,
        notification_id: String,
    },
    /// File offer received
    FileOfferReceived {
        device_id: String,
        transfer_id: String,
        filename: String,
        size: u64,
    },
    /// URL shared
    UrlReceived {
        device_id: String,
        url: String,
    },
    /// Text shared
    TextReceived {
        device_id: String,
        text: String,
    },
}

/// Commands to the sync engine
#[derive(Debug)]
pub enum SyncCommand {
    /// Send clipboard to device
    SendClipboard {
        device_id: String,
        content: String,
    },
    /// Broadcast clipboard to all connected devices
    BroadcastClipboard {
        content: String,
    },
    /// Send file to device
    SendFile {
        device_id: String,
        path: std::path::PathBuf,
    },
    /// Share URL with device
    ShareUrl {
        device_id: String,
        url: String,
    },
    /// Share text with device
    ShareText {
        device_id: String,
        text: String,
    },
    /// Dismiss a notification
    DismissNotification {
        device_id: String,
        notification_id: String,
    },
}

/// Sync engine manages data synchronization
pub struct SyncEngine {
    state: Arc<RwLock<AppState>>,
    event_tx: broadcast::Sender<SyncEvent>,
    /// Last clipboard content to avoid echo
    last_clipboard: Arc<RwLock<Option<(String, u64)>>>,
}

impl SyncEngine {
    /// Create a new sync engine
    pub fn new(state: Arc<RwLock<AppState>>) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            state,
            event_tx,
            last_clipboard: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to sync events
    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.event_tx.subscribe()
    }

    /// Handle incoming clipboard
    pub async fn handle_clipboard(&self, device_id: &str, content: String, timestamp: u64) {
        // Check for echo (same content within 5 seconds)
        {
            let last = self.last_clipboard.read().await;
            if let Some((last_content, last_time)) = last.as_ref() {
                if *last_content == content && timestamp.saturating_sub(*last_time) < 5000 {
                    debug!("Ignoring clipboard echo from {}", device_id);
                    return;
                }
            }
        }

        // Store this clipboard
        {
            let mut last = self.last_clipboard.write().await;
            *last = Some((content.clone(), timestamp));
        }

        info!("Clipboard received from {} ({} bytes)", device_id, content.len());

        // Emit event
        let _ = self.event_tx.send(SyncEvent::ClipboardReceived {
            device_id: device_id.to_string(),
            content,
            timestamp,
        });
    }

    /// Handle incoming notification
    pub async fn handle_notification(
        &self,
        device_id: &str,
        app_name: String,
        title: String,
        text: String,
        notification_id: String,
    ) {
        info!("Notification from {} - {}: {}", device_id, app_name, title);

        let _ = self.event_tx.send(SyncEvent::NotificationReceived {
            device_id: device_id.to_string(),
            app_name,
            title,
            text,
            notification_id,
        });
    }

    /// Handle incoming file offer
    pub async fn handle_file_offer(
        &self,
        device_id: &str,
        transfer_id: String,
        filename: String,
        size: u64,
    ) {
        info!("File offer from {}: {} ({} bytes)", device_id, filename, size);

        let _ = self.event_tx.send(SyncEvent::FileOfferReceived {
            device_id: device_id.to_string(),
            transfer_id,
            filename,
            size,
        });
    }

    /// Handle incoming URL share
    pub async fn handle_url(&self, device_id: &str, url: String) {
        info!("URL from {}: {}", device_id, url);

        let _ = self.event_tx.send(SyncEvent::UrlReceived {
            device_id: device_id.to_string(),
            url,
        });
    }

    /// Handle incoming text share
    pub async fn handle_text(&self, device_id: &str, text: String) {
        info!("Text from {} ({} bytes)", device_id, text.len());

        let _ = self.event_tx.send(SyncEvent::TextReceived {
            device_id: device_id.to_string(),
            text,
        });
    }

    /// Send clipboard to a device
    pub async fn send_clipboard(&self, device_id: &str, content: &str) -> Result<(), DaemonError> {
        let timestamp = now_millis();

        // Store to prevent echo
        {
            let mut last = self.last_clipboard.write().await;
            *last = Some((content.to_string(), timestamp));
        }

        // TODO: Send via connection manager
        debug!("Send clipboard to {} ({} bytes)", device_id, content.len());

        Ok(())
    }

    /// Broadcast clipboard to all connected devices
    pub async fn broadcast_clipboard(&self, content: &str) -> Result<u32, DaemonError> {
        let timestamp = now_millis();

        // Store to prevent echo
        {
            let mut last = self.last_clipboard.write().await;
            *last = Some((content.to_string(), timestamp));
        }

        // TODO: Send to all connected devices
        let state = self.state.read().await;
        let connected = state.device_manager.get_connected_devices().await;

        debug!("Broadcast clipboard to {} devices ({} bytes)", connected.len(), content.len());

        Ok(connected.len() as u32)
    }
}

/// Get current timestamp in milliseconds
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
