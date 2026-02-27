use cosmic::widget::{button, settings, text, toggler};
use cosmic::Element;

use crate::daemon_client::DaemonClient;

pub struct State {
    pub device_name: String,
    pub device_id: String,
    pub daemon_version: String,
    pub ble_enabled: bool,
    pub mdns_enabled: bool,
    pub daemon_running: bool,
    pub status_message: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    ToggleBle(bool),
    ToggleMdns(bool),
    RestartDaemon,
    Reload,
}

pub fn init() -> State {
    let mut state = State {
        device_name: String::new(),
        device_id: String::new(),
        daemon_version: String::new(),
        ble_enabled: true,
        mdns_enabled: true,
        daemon_running: false,
        status_message: String::new(),
    };

    // Query daemon status
    let rt = tokio::runtime::Runtime::new().ok();
    if let Some(rt) = rt {
        rt.block_on(async {
            let mut client = DaemonClient::new();
            if client.connect().await.is_ok() {
                state.daemon_running = true;
                state.device_name = client.device_name().await.unwrap_or_default();
                state.device_id = client.device_id().await.unwrap_or_default();
                state.daemon_version = client.version().await.unwrap_or_else(|_| "unknown".to_string());
                state.ble_enabled = client.is_ble_enabled().await.unwrap_or(true);
                state.mdns_enabled = client.is_mdns_enabled().await.unwrap_or(true);
            } else {
                state.status_message = "Daemon not running".to_string();
            }
        });
    }

    // Check systemd service status
    if !state.daemon_running {
        if let Ok(output) = std::process::Command::new("systemctl")
            .args(["--user", "is-active", "cosmic-konnect"])
            .output()
        {
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "active" {
                state.daemon_running = true;
            }
        }
    }

    state
}

pub fn update(state: &mut State, message: Message) {
    match message {
        Message::ToggleBle(val) => {
            let rt = tokio::runtime::Runtime::new().ok();
            if let Some(rt) = rt {
                match rt.block_on(async {
                    let mut client = DaemonClient::new();
                    client.connect().await?;
                    client.set_ble_enabled(val).await
                }) {
                    Ok(()) => {
                        state.ble_enabled = val;
                        state.status_message = "BLE discovery updated".to_string();
                    }
                    Err(e) => state.status_message = format!("Error: {e}"),
                }
            }
        }
        Message::ToggleMdns(val) => {
            let rt = tokio::runtime::Runtime::new().ok();
            if let Some(rt) = rt {
                match rt.block_on(async {
                    let mut client = DaemonClient::new();
                    client.connect().await?;
                    client.set_mdns_enabled(val).await
                }) {
                    Ok(()) => {
                        state.mdns_enabled = val;
                        state.status_message = "mDNS discovery updated".to_string();
                    }
                    Err(e) => state.status_message = format!("Error: {e}"),
                }
            }
        }
        Message::RestartDaemon => {
            match std::process::Command::new("systemctl")
                .args(["--user", "restart", "cosmic-konnect"])
                .status()
            {
                Ok(status) if status.success() => {
                    state.status_message = "Daemon restarted".to_string();
                    state.daemon_running = true;
                }
                Ok(_) => state.status_message = "Failed to restart daemon".to_string(),
                Err(e) => state.status_message = format!("Error: {e}"),
            }
        }
        Message::Reload => {
            *state = init();
            state.status_message = "Settings reloaded".to_string();
        }
    }
}

pub fn view(state: &State) -> Element<'_, Message> {
    let page_title = text::title1("Cosmic Konnect Settings");

    // Device info section (read-only)
    let device_section = settings::section()
        .title("Device Info")
        .add(settings::item(
            "Name",
            text::body(if state.device_name.is_empty() {
                "—"
            } else {
                &state.device_name
            }),
        ))
        .add(settings::item(
            "Device ID",
            text::caption(if state.device_id.is_empty() {
                "—"
            } else {
                &state.device_id
            }),
        ))
        .add(settings::item(
            "Daemon Version",
            text::caption(if state.daemon_version.is_empty() {
                "—"
            } else {
                &state.daemon_version
            }),
        ));

    // Discovery section
    let discovery_section = settings::section()
        .title("Discovery")
        .add(settings::item(
            "Bluetooth LE",
            toggler(state.ble_enabled).on_toggle(Message::ToggleBle),
        ))
        .add(settings::item(
            "Local Network (mDNS)",
            toggler(state.mdns_enabled).on_toggle(Message::ToggleMdns),
        ));

    // Service section
    let daemon_status = if state.daemon_running {
        "Running"
    } else {
        "Stopped"
    };

    let service_section = settings::section()
        .title("Service")
        .add(settings::item("Daemon Status", text::body(daemon_status)))
        .add(settings::item_row(vec![
            button::standard("Restart Daemon")
                .on_press(Message::RestartDaemon)
                .into(),
        ]));

    // Actions section
    let actions_section = settings::section()
        .title("Actions")
        .add(settings::item_row(vec![
            button::standard("Reload Settings")
                .on_press(Message::Reload)
                .into(),
        ]));

    let mut content_items: Vec<Element<'_, Message>> = vec![
        page_title.into(),
        device_section.into(),
        discovery_section.into(),
        service_section.into(),
        actions_section.into(),
    ];

    if !state.status_message.is_empty() {
        content_items.push(text::body(&state.status_message).into());
    }

    settings::view_column(content_items).into()
}
