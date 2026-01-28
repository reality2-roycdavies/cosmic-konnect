//! Phone notification mirroring
//!
//! Displays phone notifications on the desktop.

use crate::protocol::NetworkPacket;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Track active notifications for dismissal
pub struct NotificationManager {
    /// Map of notification ID to active notification handle
    active: HashMap<String, ()>,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
        }
    }

    /// Show a mirrored notification from phone
    pub fn show_notification(
        &mut self,
        id: &str,
        app_name: &str,
        title: &str,
        text: &str,
        device_name: &str,
    ) {
        info!(
            "Notification from {} ({}): {} - {}",
            device_name, app_name, title, text
        );

        let summary = format!("{} ({})", title, app_name);
        let body = text.to_string();

        // Show desktop notification in separate thread to avoid blocking
        std::thread::spawn(move || {
            let _ = notify_rust::Notification::new()
                .summary(&summary)
                .body(&body)
                .icon("phone")
                .timeout(10000) // 10 seconds
                .show();
        });

        // Track as active
        self.active.insert(id.to_string(), ());
    }

    /// Dismiss a notification
    pub fn dismiss(&mut self, id: &str) {
        if self.active.remove(id).is_some() {
            debug!("Notification {} dismissed", id);
        }
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle incoming notification packet
pub fn handle_notification_packet(
    packet: &NetworkPacket,
    manager: &mut NotificationManager,
    device_name: &str,
) {
    let id = packet
        .body
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("");
    let is_cancel = packet
        .body
        .get("isCancel")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);

    if is_cancel {
        manager.dismiss(id);
    } else {
        let app_name = packet
            .body
            .get("appName")
            .and_then(|a| a.as_str())
            .unwrap_or("Unknown");
        let title = packet
            .body
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let text = packet
            .body
            .get("text")
            .and_then(|t| t.as_str())
            .unwrap_or("");

        // Skip empty notifications
        if title.is_empty() && text.is_empty() {
            debug!("Skipping empty notification from {}", app_name);
            return;
        }

        manager.show_notification(id, app_name, title, text, device_name);
    }
}

/// Create a notification request packet (sent on device connect to request notifications)
pub fn create_notification_request_packet() -> NetworkPacket {
    NetworkPacket::new(
        "kdeconnect.notification.request",
        serde_json::json!({
            "request": true
        }),
    )
}
