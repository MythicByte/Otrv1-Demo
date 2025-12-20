use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use iced::{widget::container, Element};
use openssl::x509::X509;

#[derive(Debug)]
pub struct App {
    screen: Screen,
    connect_values: Option<ConnectValues>,
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
impl Default for App {
    fn default() -> Self {
        Self {
            screen: Screen::Home,
            connect_values: None,
        }
    }
}
