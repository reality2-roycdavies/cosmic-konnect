//! COSMIC Application for cosmic-konnect
//!
//! Provides a GUI window for viewing connected devices and managing settings.
//! Uses the libcosmic toolkit following the Model-View-Update (MVU) pattern.
//! Communicates with the daemon via D-Bus.

use cosmic::app::Core;
use cosmic::iced::Length;
use cosmic::widget::{self, button, container, column, row, settings, text, toggler};
use cosmic::{Action, Application, Element, Task};

use crate::daemon_client::{DaemonClient, DaemonDevice};

/// Application ID
pub const APP_ID: &str = "io.github.reality2_roycdavies.cosmic-konnect";

/// Messages for the application
#[derive(Debug, Clone)]
pub enum Message {
    /// Refresh device list from daemon
    Refresh,
    /// Periodic tick for state sync
    Tick,
    /// Send ping to device
    PingDevice(String),
    /// Ring device to find it
    FindDevice(String),
    /// Request pairing with device
    RequestPairing(String),
    /// Toggle BLE discovery
    ToggleBle(bool),
    /// Toggle mDNS discovery
    ToggleMdns(bool),
    /// Data fetched from daemon
    DataFetched(AppData),
    /// Error occurred
    Error(String),
}

/// Data fetched from daemon
#[derive(Debug, Clone, Default)]
pub struct AppData {
    pub devices: Vec<DaemonDevice>,
    pub our_device_id: String,
    pub our_device_name: String,
    pub daemon_version: String,
    pub ble_enabled: bool,
    pub mdns_enabled: bool,
}

/// Application state
pub struct CosmicKonnectApp {
    core: Core,
    data: AppData,
    status_message: String,
    is_loading: bool,
    daemon_connected: bool,
}

impl Application for CosmicKonnectApp {
    type Executor = cosmic::executor::Default;
    type Flags = ();
    type Message = Message;

    const APP_ID: &'static str = APP_ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn header_start(&self) -> Vec<Element<'_, Self::Message>> {
        vec![]
    }

    fn header_center(&self) -> Vec<Element<'_, Self::Message>> {
        vec![]
    }

    fn header_end(&self) -> Vec<Element<'_, Self::Message>> {
        vec![]
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Action<Self::Message>>) {
        let app = Self {
            core,
            data: AppData::default(),
            status_message: "Connecting to daemon...".to_string(),
            is_loading: true,
            daemon_connected: false,
        };

        // Fetch initial state from daemon
        let init_task = Task::perform(async {}, |_| Action::App(Message::Refresh));

        (app, init_task)
    }

    fn subscription(&self) -> cosmic::iced::Subscription<Self::Message> {
        // Poll daemon every 2 seconds for updates
        cosmic::iced::time::every(std::time::Duration::from_secs(2)).map(|_| Message::Tick)
    }

    fn update(&mut self, message: Self::Message) -> Task<Action<Self::Message>> {
        match message {
            Message::Refresh | Message::Tick => {
                // Fetch data from daemon
                Task::perform(fetch_daemon_data(), |result| {
                    match result {
                        Ok(data) => Action::App(Message::DataFetched(data)),
                        Err(e) => Action::App(Message::Error(e)),
                    }
                })
            }
            Message::PingDevice(device_id) => {
                self.status_message = format!("Pinging {}...", device_id);
                let id = device_id.clone();
                Task::perform(
                    async move {
                        let mut client = DaemonClient::new();
                        if client.connect().await.is_ok() {
                            match client.ping(&id).await {
                                Ok(true) => format!("Ping sent to {}", id),
                                Ok(false) => format!("Device {} not connected", id),
                                Err(e) => format!("Failed to ping: {}", e),
                            }
                        } else {
                            "Daemon not available".to_string()
                        }
                    },
                    |status| Action::App(Message::Error(status)),
                )
            }
            Message::FindDevice(device_id) => {
                self.status_message = format!("Ringing {}...", device_id);
                let id = device_id.clone();
                Task::perform(
                    async move {
                        let mut client = DaemonClient::new();
                        if client.connect().await.is_ok() {
                            match client.find_device(&id).await {
                                Ok(true) => format!("Ringing {}", id),
                                Ok(false) => format!("Device {} not connected", id),
                                Err(e) => format!("Failed to ring: {}", e),
                            }
                        } else {
                            "Daemon not available".to_string()
                        }
                    },
                    |status| Action::App(Message::Error(status)),
                )
            }
            Message::RequestPairing(device_id) => {
                self.status_message = format!("Requesting pairing with {}...", device_id);
                let id = device_id.clone();
                Task::perform(
                    async move {
                        let mut client = DaemonClient::new();
                        if client.connect().await.is_ok() {
                            match client.request_pairing(&id).await {
                                Ok(true) => format!("Pairing requested with {}", id),
                                Ok(false) => format!("Failed to request pairing with {}", id),
                                Err(e) => format!("Pairing error: {}", e),
                            }
                        } else {
                            "Daemon not available".to_string()
                        }
                    },
                    |status| Action::App(Message::Error(status)),
                )
            }
            Message::ToggleBle(enabled) => {
                self.data.ble_enabled = enabled;
                // TODO: Send to daemon
                Task::none()
            }
            Message::ToggleMdns(enabled) => {
                self.data.mdns_enabled = enabled;
                // TODO: Send to daemon
                Task::none()
            }
            Message::DataFetched(data) => {
                self.data = data;
                self.is_loading = false;
                self.daemon_connected = true;
                self.status_message = "Connected to daemon".to_string();
                Task::none()
            }
            Message::Error(error) => {
                self.status_message = error;
                self.is_loading = false;
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Self::Message> {
        // Page title
        let page_title = text::title1("Cosmic Konnect");

        // This device section
        let this_device_section = settings::section()
            .title("This Device")
            .add(settings::item(
                "Name",
                text::body(if self.data.our_device_name.is_empty() {
                    "—"
                } else {
                    &self.data.our_device_name
                }),
            ))
            .add(settings::item(
                "Device ID",
                text::caption(if self.data.our_device_id.is_empty() {
                    "—"
                } else {
                    &self.data.our_device_id
                }),
            ))
            .add(settings::item(
                "Daemon Version",
                text::caption(if self.data.daemon_version.is_empty() {
                    "—"
                } else {
                    &self.data.daemon_version
                }),
            ));

        // Devices section
        let devices_section = if self.data.devices.is_empty() {
            settings::section()
                .title("Discovered Devices")
                .add(settings::item(
                    "No devices found",
                    text::caption("Make sure Cosmic Konnect is running on your phone"),
                ))
        } else {
            let mut section = settings::section().title("Discovered Devices");

            for device in &self.data.devices {
                let device_icon = match device.device_type.to_lowercase().as_str() {
                    "phone" => "phone-symbolic",
                    "tablet" => "tablet-symbolic",
                    "laptop" => "computer-laptop-symbolic",
                    "desktop" => "computer-symbolic",
                    _ => "network-wireless-symbolic",
                };

                let state_text = match device.state.as_str() {
                    "connected" => "● Connected",
                    "discovered" => "○ Discovered",
                    _ => &device.state,
                };
                let state_badge = text::body(state_text);

                let paired_badge = if device.paired {
                    text::caption("Paired")
                } else {
                    text::caption("Not paired")
                };

                let device_id = device.device_id.clone();
                let device_id_ring = device.device_id.clone();
                let device_id_pair = device.device_id.clone();

                let mut action_row = row().spacing(8).align_y(cosmic::iced::Alignment::Center);

                if !device.paired {
                    action_row = action_row.push(
                        button::suggested("Pair").on_press(Message::RequestPairing(device_id_pair)),
                    );
                }

                action_row = action_row
                    .push(button::standard("Ring").on_press(Message::FindDevice(device_id_ring)))
                    .push(button::text("Ping").on_press(Message::PingDevice(device_id)));

                section = section.add(settings::flex_item(
                    &device.name,
                    column()
                        .spacing(4)
                        .push(
                            row()
                                .spacing(12)
                                .align_y(cosmic::iced::Alignment::Center)
                                .push(widget::icon::from_name(device_icon).size(24))
                                .push(state_badge)
                                .push(paired_badge)
                                .push(cosmic::widget::horizontal_space()),
                        )
                        .push(action_row),
                ));
            }

            section
        };

        // Discovery settings section
        let discovery_section = settings::section()
            .title("Discovery")
            .add(settings::item(
                "Bluetooth LE",
                toggler(self.data.ble_enabled).on_toggle(Message::ToggleBle),
            ))
            .add(settings::item(
                "Local Network (mDNS)",
                toggler(self.data.mdns_enabled).on_toggle(Message::ToggleMdns),
            ));

        // Status section
        let status_icon = if self.daemon_connected {
            "emblem-ok-symbolic"
        } else {
            "dialog-warning-symbolic"
        };

        let status_section = settings::section().title("Status").add(settings::flex_item(
            "Daemon",
            row()
                .spacing(8)
                .align_y(cosmic::iced::Alignment::Center)
                .push(widget::icon::from_name(status_icon).size(16))
                .push(text::caption(&self.status_message)),
        ));

        // Actions
        let refresh_btn = button::standard("Refresh").on_press(Message::Refresh);

        let actions_section = settings::section()
            .title("Actions")
            .add(settings::item_row(vec![refresh_btn.into()]));

        // Main content
        let content = settings::view_column(vec![
            page_title.into(),
            text::caption(
                "Connect your phone, tablet, or other devices seamlessly.",
            )
            .into(),
            this_device_section.into(),
            devices_section.into(),
            discovery_section.into(),
            status_section.into(),
            actions_section.into(),
        ]);

        widget::scrollable(
            container(container(content).max_width(800))
                .width(Length::Fill)
                .center_x(Length::Fill)
                .padding(16),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}

/// Fetch data from the daemon
async fn fetch_daemon_data() -> Result<AppData, String> {
    let mut client = DaemonClient::new();
    client.connect().await.map_err(|e| format!("Failed to connect to daemon: {}", e))?;

    // Get all data from daemon
    let devices = client.list_devices().await.unwrap_or_default();
    let our_device_id = client.device_id().await.unwrap_or_default();
    let our_device_name = client.device_name().await.unwrap_or_default();
    let daemon_version = client.version().await.unwrap_or_else(|_| "unknown".to_string());
    let ble_enabled = client.is_ble_enabled().await.unwrap_or(true);
    let mdns_enabled = client.is_mdns_enabled().await.unwrap_or(true);

    Ok(AppData {
        devices,
        our_device_id,
        our_device_name,
        daemon_version,
        ble_enabled,
        mdns_enabled,
    })
}

/// Run the GUI application
pub fn run_app() -> cosmic::iced::Result {
    let settings = cosmic::app::Settings::default()
        .size(cosmic::iced::Size::new(700.0, 600.0))
        .size_limits(
            cosmic::iced::Limits::NONE
                .min_width(500.0)
                .min_height(400.0),
        );

    cosmic::app::run::<CosmicKonnectApp>(settings, ())
}
