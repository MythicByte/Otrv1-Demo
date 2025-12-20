use std::{net::SocketAddr, str::FromStr};

use anyhow::Context;
use chrono::{DateTime, Utc};
use iced::{widget::container, Element};
use openssl::x509::X509;
use sqlx::{Database, Pool, Sqlite, SqlitePool, sqlite::SqlitePoolOptions};
use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct App {
    screen: Screen,
    connect_values: Option<ConnectValues>,
    sqlite_pool: Pool<Sqlite>
}
#[derive(Debug)]
struct ConnectValues {
    cert: X509,
    ip: SocketAddr,
}
#[derive(Debug, Clone)]
pub enum Message {
    MessageInsert(String, DateTime<Utc>, u8),
}
#[derive(Debug, Clone)]
pub enum Screen {
    Start,
    Home,
}
impl App {
    pub fn new() -> Self {
        Self::new_result().expect("Setting up failed")
    }
    fn new_result() -> anyhow::Result<Self> {
        let rt = Runtime::new().context("The tokio Runtime Failed")?;
        let sqlite = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite:otr_demeo.db")?
            .create_if_missing(true);
        let pool = rt.block_on(async {
            let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(sqlite)
            .await.expect("Sqlite Pool failed");
        sqlx::migrate!("./migrations").run(&pool).await.expect("Sqlite Migrations failed");
        pool
        });
        Ok(Self {
            screen: Screen::Home,
            connect_values: None,
            sqlite_pool: pool,
        })
    }
    pub fn update(&mut self, message: Message) {
        match message {
            Message::MessageInsert(text_message, date_time, user_id) => {
                todo!()
            }
        }
    }
    pub fn view(&self) -> iced::Element<'_, Message> {
        return match self.screen {
            Screen::Start => Self::start(&self),
            Screen::Home => Self::home(&self),
        };
    }
    fn start(&self) -> iced::Element<'_, Message> {
        container("Test").into()
    }
    fn home(&self) -> Element<'_, Message> {
        container("Test").into()
    }
}
