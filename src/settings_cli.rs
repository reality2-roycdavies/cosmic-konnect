//! CLI settings protocol for cosmic-applet-settings hub integration.

use crate::daemon_client::DaemonClient;

pub fn describe() {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {e}");
            std::process::exit(1);
        }
    };

    rt.block_on(async {
        let mut client = DaemonClient::new();
        let connected = client.connect().await.is_ok();

        let (device_name, device_id, daemon_version, ble_enabled, mdns_enabled, daemon_status) =
            if connected {
                let name = client.device_name().await.unwrap_or_else(|_| "Unknown".into());
                let id = client.device_id().await.unwrap_or_else(|_| "Unknown".into());
                let version = client.version().await.unwrap_or_else(|_| "Unknown".into());
                let ble = client.is_ble_enabled().await.unwrap_or(false);
                let mdns = client.is_mdns_enabled().await.unwrap_or(true);
                (name, id, version, ble, mdns, "Running")
            } else {
                (
                    "Unknown".into(),
                    "Unknown".into(),
                    "Unknown".into(),
                    false,
                    true,
                    "Not running",
                )
            };

        let schema = serde_json::json!({
            "title": "Cosmic Konnect Settings",
            "description": "KDE Connect protocol for COSMIC desktop.",
            "sections": [
                {
                    "title": "Device Info",
                    "items": [
                        {
                            "type": "info",
                            "key": "device_name",
                            "label": "Device Name",
                            "value": device_name
                        },
                        {
                            "type": "info",
                            "key": "device_id",
                            "label": "Device ID",
                            "value": device_id
                        },
                        {
                            "type": "info",
                            "key": "daemon_version",
                            "label": "Daemon Version",
                            "value": daemon_version
                        },
                        {
                            "type": "info",
                            "key": "daemon_status",
                            "label": "Daemon Status",
                            "value": daemon_status
                        }
                    ]
                },
                {
                    "title": "Discovery",
                    "items": [
                        {
                            "type": "toggle",
                            "key": "ble_enabled",
                            "label": "Bluetooth Discovery",
                            "value": ble_enabled
                        },
                        {
                            "type": "toggle",
                            "key": "mdns_enabled",
                            "label": "Network Discovery (mDNS)",
                            "value": mdns_enabled
                        }
                    ]
                }
            ],
            "actions": [
                {"id": "restart_daemon", "label": "Restart Daemon", "style": "standard"},
                {"id": "reload", "label": "Reload", "style": "standard"}
            ]
        });

        println!("{}", serde_json::to_string_pretty(&schema).unwrap());
    });
}

pub fn set(key: &str, value: &str) {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            print_response(false, &format!("Runtime error: {e}"));
            return;
        }
    };

    rt.block_on(async {
        let mut client = DaemonClient::new();
        if let Err(e) = client.connect().await {
            print_response(false, &format!("Daemon not running: {e}"));
            return;
        }

        let result = match key {
            "ble_enabled" => {
                match serde_json::from_str::<bool>(value) {
                    Ok(v) => client.set_ble_enabled(v).await
                        .map(|_| "Updated BLE".to_string())
                        .map_err(|e| format!("{e}")),
                    Err(e) => Err(format!("Invalid boolean: {e}")),
                }
            }
            "mdns_enabled" => {
                match serde_json::from_str::<bool>(value) {
                    Ok(v) => client.set_mdns_enabled(v).await
                        .map(|_| "Updated mDNS".to_string())
                        .map_err(|e| format!("{e}")),
                    Err(e) => Err(format!("Invalid boolean: {e}")),
                }
            }
            _ => Err(format!("Unknown key: {key}")),
        };

        match result {
            Ok(msg) => print_response(true, &msg),
            Err(e) => print_response(false, &e),
        }
    });
}

pub fn action(id: &str) {
    match id {
        "restart_daemon" => {
            use std::process::Command;
            let _ = Command::new("systemctl")
                .args(["--user", "restart", "cosmic-konnect"])
                .output();
            print_response(true, "Daemon restart requested");
        }
        "reload" => {
            print_response(true, "Settings reloaded");
        }
        _ => print_response(false, &format!("Unknown action: {id}")),
    }
}

fn print_response(ok: bool, message: &str) {
    let resp = serde_json::json!({"ok": ok, "message": message});
    println!("{}", resp);
}
