use iced::{
    Border,
    Color,
    Pixels,
    Theme,
    border::Radius,
    widget::{
        Space,
        container,
        rule,
    },
};
use std::str::FromStr;

use anyhow::Context;
use chrono::{
    DateTime,
    Utc,
};
use iced::{
    self,
    Element,
    Length::{
        self,
    },
    Task,
    alignment::{
        Horizontal,
        Vertical,
    },
    widget::{
        column,
        row,
        scrollable,
        space::horizontal,
        text,
        text_editor,
    },
};
use sqlx::{
    Pool,
    Sqlite,
    sqlite::SqlitePoolOptions,
};
use tokio::runtime::Runtime;
use tracing::info;

use crate::screen::{
    self,
    ConnectValues,
    Screen,
    ScreenMessage,
};
pub struct App {
    pub screen: ScreenDisplay,
    pub connect_values: Option<ConnectValues>,
    sqlite_pool: Pool<Sqlite>,
    message: text_editor::Content,
    online: bool,
}
#[derive(Debug, Clone)]
pub enum Message {
    SwitchToMainScreen,
    MessageInsert {
        message_text: String,
        date_of_message: DateTime<Utc>,
        person_from: u8,
    },
    Screen(screen::ScreenMessage),
}
pub enum ScreenDisplay {
    Start(Screen),
    Home,
}
impl App {
    pub fn new() -> Self {
        let output = Self::new_result().expect("Setting up failed");
        info!("Sqlite and Basic Setup was correct");
        output
    }
    fn new_result() -> anyhow::Result<Self> {
        let rt = Runtime::new().context("The tokio Runtime Failed")?;
        let sqlite = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite:otr_demeo.db")?
            .create_if_missing(true);
        let pool = rt.block_on(async {
            let pool = SqlitePoolOptions::new()
                .max_connections(2)
                .connect_with(sqlite)
                .await
                .expect("Sqlite Pool failed");
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .expect("Sqlite Migrations failed");
            pool
        });
        info!("Sqlite Pool worked and connected");
        Ok(Self {
            screen: ScreenDisplay::Start(screen::Screen::new()),
            connect_values: None,
            sqlite_pool: pool,
            message: text_editor::Content::new(),
            online: false,
        })
    }
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match (message, &mut self.screen) {
            (Message::SwitchToMainScreen, ScreenDisplay::Start(screen)) => {
                let build = &mut screen.builderconnectvalues;
                let conversation_pkcs12 = build.build();
                if let Ok(conversation) = conversation_pkcs12 {
                    self.connect_values = Some(conversation);
                    self.screen = ScreenDisplay::Home;
                }
            }
            (
                Message::MessageInsert {
                    message_text,
                    date_of_message,
                    person_from,
                },
                ScreenDisplay::Home,
            ) => todo!(),
            (Message::Screen(screen_message), ScreenDisplay::Start(screen)) => {
                if let ScreenMessage::SwitchToMainScreen = screen_message {
                    screen.button.3 = true;
                    return Task::done(Message::SwitchToMainScreen);
                }
                return screen.update(screen_message).map(Message::Screen);
            }
            _ => return Task::none(),
        }
        Task::none()
    }
    pub fn view(&self) -> iced::Element<'_, Message> {
        return match &self.screen {
            ScreenDisplay::Start(screen) => screen.view().map(Message::Screen),
            ScreenDisplay::Home => Self::home(&self),
        };
    }
    fn home(&self) -> iced::Element<'_, Message> {
        let title = text("Otrv1 Messaging").size(40).center();
        let title = container(title).center_x(Length::Fill);
        let output_column = column![
            Space::new().height(20),
            title,
            Space::new().height(5),
            self.status_bar(),
            rule::horizontal(2),
            self.chat(),
            self.send_message()
        ]
        .spacing(20)
        .max_width(800);
        container(output_column)
            .width(Length::FillPortion(2))
            .height(Length::FillPortion(2))
            .align_y(Vertical::Top)
            .align_x(Horizontal::Center)
            .into()
    }
    fn status_bar(&self) -> Element<'_, Message> {
        let ip_to_text = text(format!(
            "IP: {}",
            if let Some(connect) = &self.connect_values {
                connect.ip.clone().to_string()
            } else {
                "Config Error".to_string()
            }
        ))
        .center();
        let online_indicator: Element<'_, Message> = container("")
            .style(|_: &Theme| {
                let color = if self.online {
                    Color::from_rgb(0.0, 0.8, 0.5)
                } else {
                    Color::from_rgb(0.6, 0.6, 0.6)
                };
                container::Style {
                    background: Some(color.into()),
                    border: Border::default().rounded(Radius::new(Pixels::from(5))),
                    ..Default::default()
                }
            })
            .width(10)
            .height(10)
            .height(Length::Fixed(10.0))
            .into();
        let status_row = row![
            ip_to_text,
            horizontal().width(Length::Fill),
            online_indicator,
            Space::new().width(5),
            text(" Online").center(),
        ]
        .align_y(Vertical::Center);
        container(status_row).width(Length::FillPortion(2)).into()
    }
    fn chat(&self) -> Element<'_, Message> {
        let scroll = scrollable(column![text("Test"), text("Test1")]);
        container(scroll)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
    fn send_message(&self) -> Element<'_, Message> {
        let text = text_editor(&self.message).placeholder("Message ..");
        let row = row![text];
        container(row).into()
    }
}
