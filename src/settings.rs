use cosmic::app::Core;
use cosmic::iced::Length;
use cosmic::widget::{self, container};
use cosmic::{Action, Application, Element, Task};

use crate::settings_page;

const APP_ID: &str = "io.github.reality2_roycdavies.cosmic-konnect.settings";

pub struct SettingsApp {
    core: Core,
    page: settings_page::State,
}

impl Application for SettingsApp {
    type Executor = cosmic::executor::Default;
    type Flags = ();
    type Message = settings_page::Message;

    const APP_ID: &'static str = APP_ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Action<Self::Message>>) {
        let page = settings_page::init();
        let app = Self { core, page };
        (app, Task::none())
    }

    fn header_start(&self) -> Vec<Element<'_, Self::Message>> {
        vec![]
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let content = settings_page::view(&self.page);

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

    fn update(&mut self, message: Self::Message) -> Task<Action<Self::Message>> {
        settings_page::update(&mut self.page, message);
        Task::none()
    }
}

pub fn run_settings() -> cosmic::iced::Result {
    let settings = cosmic::app::Settings::default()
        .size(cosmic::iced::Size::new(700.0, 600.0))
        .size_limits(
            cosmic::iced::Limits::NONE
                .min_width(500.0)
                .min_height(400.0),
        );
    cosmic::app::run::<SettingsApp>(settings, ())
}
