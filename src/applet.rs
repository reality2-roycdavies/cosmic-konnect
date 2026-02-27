use cosmic::app::{Core, Task};
use cosmic::iced::window::Id;
use cosmic::iced::{Length, Rectangle};
use cosmic::iced_runtime::core::window;
use cosmic::surface::action::{app_popup, destroy_popup};
use cosmic::widget::{self, text};
use cosmic::Element;

use crate::daemon_client::{DaemonClient, DaemonDevice};

const APP_ID: &str = "io.github.reality2_roycdavies.cosmic-konnect";

enum KonnectCommand {
    PingDevice(String),
    FindDevice(String),
    RequestPairing(String),
}

#[derive(Debug)]
enum KonnectEvent {
    StatusUpdate(Result<KonnectStatus, String>),
    ActionResult(String),
}

#[derive(Debug)]
struct KonnectStatus {
    devices: Vec<DaemonDevice>,
    has_connected: bool,
}

#[derive(Debug, Clone)]
pub enum Message {
    PollStatus,
    PingDevice(String),
    FindDevice(String),
    RequestPairing(String),
    OpenSettings,
    PopupClosed(Id),
    Surface(cosmic::surface::Action),
}

pub struct KonnectApplet {
    core: Core,
    popup: Option<Id>,
    devices: Vec<DaemonDevice>,
    has_connected: bool,
    daemon_available: bool,
    status_message: String,
    status_hold_ticks: u8,
    cmd_tx: std::sync::mpsc::Sender<KonnectCommand>,
    event_rx: std::sync::mpsc::Receiver<KonnectEvent>,
}

impl cosmic::Application for KonnectApplet {
    type Executor = cosmic::SingleThreadExecutor;
    type Flags = ();
    type Message = Message;

    const APP_ID: &'static str = APP_ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Self::Message>) {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::channel();

        // Get initial status
        let (devices, has_connected, daemon_available) = {
            let rt = tokio::runtime::Runtime::new().ok();
            rt.and_then(|rt| {
                rt.block_on(async {
                    let mut client = DaemonClient::new();
                    if client.connect().await.is_ok() {
                        let devices = client.list_devices().await.unwrap_or_default();
                        let has_connected = devices.iter().any(|d| d.state == "connected");
                        Some((devices, has_connected, true))
                    } else {
                        None
                    }
                })
            })
            .unwrap_or((vec![], false, false))
        };

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(run_background(cmd_rx, event_tx));
        });

        let applet = Self {
            core,
            popup: None,
            devices,
            has_connected,
            daemon_available,
            status_message: if daemon_available {
                "Connected to daemon".to_string()
            } else {
                "Daemon not available".to_string()
            },
            status_hold_ticks: 0,
            cmd_tx,
            event_rx,
        };

        (applet, Task::none())
    }

    fn on_close_requested(&self, id: window::Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        match message {
            Message::PollStatus => {
                while let Ok(event) = self.event_rx.try_recv() {
                    match event {
                        KonnectEvent::StatusUpdate(result) => match result {
                            Ok(status) => {
                                self.devices = status.devices;
                                self.has_connected = status.has_connected;
                                self.daemon_available = true;
                                if self.status_hold_ticks > 0 {
                                    self.status_hold_ticks -= 1;
                                } else {
                                    let connected_count =
                                        self.devices.iter().filter(|d| d.state == "connected").count();
                                    self.status_message = if connected_count > 0 {
                                        format!("{} device(s) connected", connected_count)
                                    } else {
                                        "No devices connected".to_string()
                                    };
                                }
                            }
                            Err(_) => {
                                self.daemon_available = false;
                                if self.status_hold_ticks > 0 {
                                    self.status_hold_ticks -= 1;
                                } else {
                                    self.status_message = "Daemon not available".to_string();
                                }
                            }
                        },
                        KonnectEvent::ActionResult(msg) => {
                            self.status_message = msg;
                            self.status_hold_ticks = 3;
                        }
                    }
                }
            }

            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                }
            }

            Message::Surface(action) => {
                return cosmic::task::message(cosmic::Action::Cosmic(
                    cosmic::app::Action::Surface(action),
                ));
            }

            Message::PingDevice(device_id) => {
                let _ = self.cmd_tx.send(KonnectCommand::PingDevice(device_id));
                self.status_message = "Pinging...".to_string();
                self.status_hold_ticks = 3;
            }

            Message::FindDevice(device_id) => {
                let _ = self.cmd_tx.send(KonnectCommand::FindDevice(device_id));
                self.status_message = "Ringing...".to_string();
                self.status_hold_ticks = 3;
            }

            Message::RequestPairing(device_id) => {
                let _ = self.cmd_tx.send(KonnectCommand::RequestPairing(device_id));
                self.status_message = "Pairing requested...".to_string();
                self.status_hold_ticks = 3;
            }

            Message::OpenSettings => {
                std::thread::spawn(|| {
                    // Try unified settings hub first, fall back to standalone
                    let unified = std::process::Command::new("cosmic-applet-settings")
                        .arg(APP_ID)
                        .spawn();
                    if unified.is_err() {
                        let exe = std::env::current_exe()
                            .unwrap_or_else(|_| "cosmic-konnect".into());
                        if let Err(e) = std::process::Command::new(exe)
                            .arg("--settings-standalone")
                            .spawn()
                        {
                            eprintln!("Failed to launch settings: {e}");
                        }
                    }
                });
            }
        }

        Task::none()
    }

    fn subscription(&self) -> cosmic::iced::Subscription<Self::Message> {
        cosmic::iced::time::every(std::time::Duration::from_secs(3))
            .map(|_| Message::PollStatus)
    }

    fn view(&self) -> Element<'_, Message> {
        let icon_name = if self.has_connected {
            "io.github.reality2_roycdavies.cosmic-konnect-connected-symbolic"
        } else {
            "io.github.reality2_roycdavies.cosmic-konnect-disconnected-symbolic"
        };

        let icon: Element<Message> = widget::icon::from_name(icon_name)
            .symbolic(true)
            .into();

        let have_popup = self.popup;
        let btn = self
            .core
            .applet
            .button_from_element(icon, true)
            .on_press_with_rectangle(move |offset, bounds| {
                if let Some(id) = have_popup {
                    Message::Surface(destroy_popup(id))
                } else {
                    Message::Surface(app_popup::<KonnectApplet>(
                        move |state: &mut KonnectApplet| {
                            let new_id = Id::unique();
                            state.popup = Some(new_id);

                            let popup_width = 320u32;
                            let popup_height = 450u32;

                            let mut popup_settings = state.core.applet.get_popup_settings(
                                state.core.main_window_id().unwrap(),
                                new_id,
                                Some((popup_width, popup_height)),
                                None,
                                None,
                            );
                            popup_settings.positioner.anchor_rect = Rectangle {
                                x: (bounds.x - offset.x) as i32,
                                y: (bounds.y - offset.y) as i32,
                                width: bounds.width as i32,
                                height: bounds.height as i32,
                            };
                            popup_settings
                        },
                        Some(Box::new(|state: &KonnectApplet| {
                            Element::from(
                                state.core.applet.popup_container(state.popup_content()),
                            )
                            .map(cosmic::Action::App)
                        })),
                    ))
                }
            });

        let tooltip = if self.has_connected {
            "Cosmic Konnect (Connected)"
        } else {
            "Cosmic Konnect (Disconnected)"
        };

        Element::from(self.core.applet.applet_tooltip::<Message>(
            btn,
            tooltip,
            self.popup.is_some(),
            |a| Message::Surface(a),
            None,
        ))
    }

    fn view_window(&self, _id: Id) -> Element<'_, Message> {
        "".into()
    }

    fn style(&self) -> Option<cosmic::iced_runtime::Appearance> {
        Some(cosmic::applet::style())
    }
}

impl KonnectApplet {
    fn popup_content(&self) -> widget::Column<'_, Message> {
        use cosmic::iced::widget::{column, container, horizontal_space, row, Space};
        use cosmic::iced::{Alignment, Color};

        let divider = || {
            container(Space::new(Length::Fill, Length::Fixed(1.0))).style(
                |theme: &cosmic::Theme| {
                    let cosmic = theme.cosmic();
                    container::Style {
                        background: Some(cosmic::iced::Background::Color(Color::from(
                            cosmic.palette.neutral_5,
                        ))),
                        ..Default::default()
                    }
                },
            )
        };

        // Title row
        let title_row = row![text::body("Cosmic Konnect"), horizontal_space(),]
            .spacing(8)
            .align_y(Alignment::Center);

        // Status info
        let status_text = format!("Status: {}", self.status_message);
        let info_col = column![text::body(status_text)].spacing(2);

        // Devices section
        let total_count = self.devices.len();
        let connected_count = self.devices.iter().filter(|d| d.state == "connected").count();
        let devices_header = text::body(format!(
            "Devices ({connected_count}/{total_count} online)"
        ));

        let mut devices_col = column![devices_header].spacing(2);

        if self.devices.is_empty() {
            devices_col = devices_col.push(text::caption("No devices discovered"));
        } else {
            for device in &self.devices {
                devices_col = devices_col.push(self.device_row(device));
            }
        }

        // Bottom actions row
        let actions_row = row![
            horizontal_space(),
            widget::button::standard("Settings...")
                .on_press(Message::OpenSettings),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        // Assemble
        let mut content = column![title_row, divider(), info_col, divider(),]
            .spacing(8)
            .padding(12);

        content = content.push(devices_col);
        content = content.push(divider()).push(actions_row);

        content
    }

    fn device_row(&self, device: &DaemonDevice) -> Element<'_, Message> {
        use cosmic::iced::widget::{column, horizontal_space, row};
        use cosmic::iced::Alignment;

        let status_indicator = match device.state.as_str() {
            "connected" => "● ",
            _ => "○ ",
        };

        let type_label = match device.device_type.to_lowercase().as_str() {
            "phone" => "Phone",
            "tablet" => "Tablet",
            "laptop" => "Laptop",
            "desktop" => "Desktop",
            _ => "Device",
        };

        let name_label = format!("{status_indicator}{} ({})", device.name, type_label);

        let state_label = if device.paired {
            format!("  {} - Paired", device.state)
        } else {
            format!("  {} - Not paired", device.state)
        };

        let mut device_col = column![text::caption(name_label), text::caption(state_label)].spacing(0);

        // Action buttons
        let device_id = device.device_id.clone();
        let device_id_ring = device.device_id.clone();
        let device_id_pair = device.device_id.clone();

        let mut buttons_row = row![].spacing(4).align_y(Alignment::Center);

        if !device.paired {
            buttons_row = buttons_row.push(
                widget::button::suggested("Pair")
                    .on_press(Message::RequestPairing(device_id_pair)),
            );
        }

        buttons_row = buttons_row
            .push(widget::button::standard("Ring").on_press(Message::FindDevice(device_id_ring)))
            .push(widget::button::text("Ping").on_press(Message::PingDevice(device_id)))
            .push(horizontal_space());

        device_col = device_col.push(buttons_row);

        device_col.into()
    }
}

async fn run_background(
    cmd_rx: std::sync::mpsc::Receiver<KonnectCommand>,
    event_tx: std::sync::mpsc::Sender<KonnectEvent>,
) {
    loop {
        // Check for commands from the UI
        while let Ok(cmd) = cmd_rx.try_recv() {
            let result = async {
                let mut client = DaemonClient::new();
                client.connect().await.map_err(|e| format!("{e}"))?;
                match cmd {
                    KonnectCommand::PingDevice(id) => {
                        match client.ping(&id).await {
                            Ok(true) => Ok(format!("Ping sent to {id}")),
                            Ok(false) => Ok(format!("Device {id} not connected")),
                            Err(e) => Err(format!("Ping failed: {e}")),
                        }
                    }
                    KonnectCommand::FindDevice(id) => {
                        match client.find_device(&id).await {
                            Ok(true) => Ok(format!("Ringing {id}")),
                            Ok(false) => Ok(format!("Device {id} not connected")),
                            Err(e) => Err(format!("Ring failed: {e}")),
                        }
                    }
                    KonnectCommand::RequestPairing(id) => {
                        match client.request_pairing(&id).await {
                            Ok(true) => Ok(format!("Pairing requested with {id}")),
                            Ok(false) => Ok(format!("Pairing failed with {id}")),
                            Err(e) => Err(format!("Pairing error: {e}")),
                        }
                    }
                }
            }
            .await;

            let msg = match result {
                Ok(msg) => msg,
                Err(msg) => msg,
            };
            let _ = event_tx.send(KonnectEvent::ActionResult(msg));
        }

        // Poll current status
        let status = async {
            let mut client = DaemonClient::new();
            client.connect().await.map_err(|e| format!("{e}"))?;
            let devices = client.list_devices().await.map_err(|e| format!("{e}"))?;
            let has_connected = devices.iter().any(|d| d.state == "connected");
            Ok(KonnectStatus {
                devices,
                has_connected,
            })
        }
        .await;

        let _ = event_tx.send(KonnectEvent::StatusUpdate(status));

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}

pub fn run_applet() -> cosmic::iced::Result {
    cosmic::applet::run::<KonnectApplet>(())
}
