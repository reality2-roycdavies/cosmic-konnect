//! COSMIC Application for cosmic-konnect
//!
//! Provides a GUI window for viewing connected devices and managing settings.
//! Uses the libcosmic toolkit following the Model-View-Update (MVU) pattern.
//! Communicates with the tray service via D-Bus.

use cosmic::app::Core;
use cosmic::iced::Length;
use cosmic::widget::{self, button, container, row, settings, text};
use cosmic::{Action, Application, Element, Task};

use crate::dbus_client::KonnectClient;
use crate::service::DeviceInfo;

/// Application ID
pub const APP_ID: &str = "io.github.reality2_roycdavies.cosmic-konnect";

/// Messages for the application
#[derive(Debug, Clone)]
pub enum Message {
    /// Refresh device list from D-Bus
    Refresh,
    /// Periodic tick for state sync
    Tick,
    /// Send ping to device
    PingDevice(String),
    /// Ring device to find it
    FindPhone(String),
    /// Devices fetched from D-Bus
    DevicesFetched(Vec<DeviceInfo>),
    /// Status fetched
    StatusFetched(String),
    /// Error occurred
    Error(String),
}

/// Application state
pub struct CosmicKonnectApp {
    core: Core,
    devices: Vec<DeviceInfo>,
    status_message: String,
    is_loading: bool,
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
            devices: Vec::new(),
            status_message: "Connecting to service...".to_string(),
            is_loading: true,
        };

        // Fetch initial state from D-Bus
        let init_task = Task::perform(async {}, |_| Action::App(Message::Refresh));

        (app, init_task)
    }

    fn subscription(&self) -> cosmic::iced::Subscription<Self::Message> {
        // Poll D-Bus every 2 seconds for updates
        cosmic::iced::time::every(std::time::Duration::from_secs(2)).map(|_| Message::Tick)
    }

    fn update(&mut self, message: Self::Message) -> Task<Action<Self::Message>> {
        match message {
            Message::Refresh | Message::Tick => {
                // Refresh GUI lockfile periodically
                static TICK_COUNT: std::sync::atomic::AtomicU32 =
                    std::sync::atomic::AtomicU32::new(0);
                let count = TICK_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count % 15 == 0 {
                    // Every 30 seconds (15 * 2 second interval)
                    crate::create_gui_lockfile();
                }

                // Fetch devices from D-Bus
                Task::perform(
                    async {
                        match KonnectClient::connect().await {
                            Ok(client) => {
                                let devices = client.get_devices().await.unwrap_or_default();
                                let status = client.get_status().await.unwrap_or_else(|_| "Ready".to_string());
                                (devices, status, None)
                            }
                            Err(e) => (Vec::new(), String::new(), Some(format!("Service not available: {}", e))),
                        }
                    },
                    |(devices, _status, error)| {
                        if let Some(err) = error {
                            Action::App(Message::Error(err))
                        } else {
                            Action::App(Message::DevicesFetched(devices))
                        }
                    },
                )
            }
            Message::PingDevice(device_id) => {
                self.status_message = format!("Pinging {}...", device_id);
                let id = device_id.clone();
                Task::perform(
                    async move {
                        if let Ok(client) = KonnectClient::connect().await {
                            match client.ping_device(&id).await {
                                Ok(()) => format!("Ping sent to {}", id),
                                Err(e) => format!("Failed to ping: {}", e),
                            }
                        } else {
                            "Service not available".to_string()
                        }
                    },
                    |status| Action::App(Message::StatusFetched(status)),
                )
            }
            Message::FindPhone(device_id) => {
                self.status_message = format!("Ringing {}...", device_id);
                let id = device_id.clone();
                Task::perform(
                    async move {
                        if let Ok(client) = KonnectClient::connect().await {
                            match client.find_phone(&id).await {
                                Ok(()) => format!("Ringing {} (tap phone notification to stop)", id),
                                Err(e) => format!("Failed to ring: {}", e),
                            }
                        } else {
                            "Service not available".to_string()
                        }
                    },
                    |status| Action::App(Message::StatusFetched(status)),
                )
            }
            Message::DevicesFetched(devices) => {
                self.devices = devices;
                self.is_loading = false;
                if self.status_message == "Connecting to service..." {
                    self.status_message = "Ready".to_string();
                }
                Task::none()
            }
            Message::StatusFetched(status) => {
                self.status_message = status;
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

        // Devices section
        let devices_section = if self.devices.is_empty() {
            settings::section()
                .title("Connected Devices")
                .add(settings::item(
                    "No devices connected",
                    text::caption("Make sure Cosmic Konnect is running on your phone and the tray is active"),
                ))
        } else {
            let mut section = settings::section().title("Connected Devices");

            for device in &self.devices {
                let battery_text = if device.battery >= 0 {
                    format!("{}%", device.battery)
                } else {
                    "—".to_string()
                };

                let device_icon = match device.device_type.to_lowercase().as_str() {
                    "phone" => "phone-symbolic",
                    "tablet" => "tablet-symbolic",
                    "laptop" => "computer-laptop-symbolic",
                    "desktop" => "computer-symbolic",
                    _ => "device-symbolic",
                };

                let device_id = device.id.clone();
                let device_id_ring = device.id.clone();
                let ping_btn = button::suggested("Ping").on_press(Message::PingDevice(device_id));
                let ring_btn = button::standard("Ring").on_press(Message::FindPhone(device_id_ring));

                let paired_text = if device.is_paired { "Paired" } else { "Not paired" };

                section = section.add(settings::flex_item(
                    &device.name,
                    row()
                        .spacing(12)
                        .align_y(cosmic::iced::Alignment::Center)
                        .push(widget::icon::from_name(device_icon).size(24))
                        .push(text::body(battery_text))
                        .push(text::caption(paired_text))
                        .push(cosmic::widget::horizontal_space())
                        .push(ring_btn)
                        .push(ping_btn),
                ));
            }

            section
        };

        // Status section
        let status_text = if self.is_loading {
            "Loading...".to_string()
        } else {
            self.status_message.clone()
        };

        let status_section = settings::section().title("Status").add(settings::item(
            "Service",
            text::caption(status_text),
        ));

        // Actions
        let refresh_btn = button::standard("Refresh").on_press(Message::Refresh);

        let actions_section =
            settings::section()
                .title("Actions")
                .add(settings::item_row(vec![refresh_btn.into()]));

        // Main content
        let content = settings::view_column(vec![
            page_title.into(),
            text::caption(
                "Connect your phone, tablet, or other devices using the Cosmic Konnect Protocol.",
            )
            .into(),
            devices_section.into(),
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
