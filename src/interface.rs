use std::str::FromStr;

use anyhow::Context;
use chrono::{
    DateTime,
    Utc,
};
use iced::{
    self,
    Task,
    widget::container,
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
        container("Test").into()
    }
}
