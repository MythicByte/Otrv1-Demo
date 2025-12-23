use iced::{
    Border,
    Color,
    Pixels,
    Subscription,
    Theme,
    border::Radius,
    futures::lock::Mutex,
    widget::{
        Space,
        button,
        container,
        rule,
        scrollable::Viewport,
    },
};
use std::{
    str::FromStr,
    sync::Arc,
};

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
use tracing::{
    error,
    info,
};

use crate::{
    db::{
        self,
        read_all_user,
        write_db,
    },
    net::{
        ServerClientModell,
        diffie_hellman_check,
        setup_connection,
    },
    screen::{
        self,
        ConnectValues,
        Screen,
        ScreenMessage,
    },
};
pub struct App {
    pub screen: ScreenDisplay,
    pub connect_values: Option<ConnectValues>,
    sqlite_pool: Pool<Sqlite>,
    message: text_editor::Content,
    online: bool,
    list_message: Option<Vec<db::Message>>,
    stream: Option<Arc<Mutex<tokio::net::TcpStream>>>,
}
#[derive(Debug, Clone)]
pub enum Message {
    ConnectRightUser(Arc<Mutex<tokio::net::TcpStream>>, Vec<u8>),
    SwitchStartScreen,
    CheckConnection(Arc<Mutex<tokio::net::TcpStream>>, ServerClientModell),
    SwitchToMainScreen,
    MessageInsert {
        message_text: String,
        date_of_message: DateTime<Utc>,
        person_from: u8,
    },
    Screen(screen::ScreenMessage),
    POSTChangeTextField(text_editor::Action),
    PostMessageToPeer,
    CheckDBError(u8),
    ScrollDisplay(Viewport),
    PutListValues(Vec<db::Message>),
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
                .max_connections(4)
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
            list_message: None,
            stream: None,
        })
    }
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match (message, &mut self.screen) {
            (Message::SwitchToMainScreen, ScreenDisplay::Start(screen)) => {
                let build = &mut screen.builderconnectvalues;
                let conversation_pkcs12 = build.build();
                if let Ok(conversation) = conversation_pkcs12 {
                    let ip_clone_for_later = conversation.ip.clone();
                    self.connect_values = Some(conversation);
                    self.screen = ScreenDisplay::Home;
                    return Task::perform(setup_connection(ip_clone_for_later), |x| match x {
                        Ok((correct_tcpstream, user)) => {
                            Message::CheckConnection(Arc::new(Mutex::new(correct_tcpstream)), user)
                        }
                        Err(_) => Message::SwitchStartScreen,
                    });
                } else {
                    return Task::done(Message::SwitchStartScreen);
                }
            }
            (
                Message::MessageInsert {
                    message_text,
                    date_of_message,
                    person_from,
                },
                ScreenDisplay::Home,
            ) => {
                return Task::perform(
                    write_db(
                        self.sqlite_pool.clone(),
                        message_text,
                        date_of_message,
                        person_from,
                    ),
                    |x| {
                        let x = match x {
                            Ok(_) => 0,
                            Err(_) => 1,
                        };
                        Message::CheckDBError(x)
                    },
                );
            }
            (Message::Screen(screen_message), ScreenDisplay::Start(screen)) => {
                if let ScreenMessage::SwitchToMainScreen = screen_message {
                    screen.button.3 = true;
                    return Task::done(Message::SwitchToMainScreen);
                }
                return screen.update(screen_message).map(Message::Screen);
            }
            (Message::POSTChangeTextField(action), ScreenDisplay::Home) => {
                self.message.perform(action);
            }
            (Message::PostMessageToPeer, ScreenDisplay::Home) => {
                if self.message.is_empty() || self.online == false {
                    return Task::none();
                }
                let text = self.message.text();

                // Refreshed the text edit
                self.message = text_editor::Content::new();
                // To the Async Function that sends the code
            }
            (Message::CheckDBError(value), _) => {
                if value == 1 {
                    error!("Db writing Failed");
                }
            }
            (Message::ScrollDisplay(viewport), ScreenDisplay::Home) => {
                return Task::perform({ read_all_user(self.sqlite_pool.clone()) }, |x| {
                    let x = match x {
                        Ok(correct) => correct,
                        Err(_) => Vec::new(),
                    };
                    Message::PutListValues(x)
                });
            }
            (Message::PutListValues(values), ScreenDisplay::Home) => {
                self.list_message = Some(values);
            }
            (Message::SwitchStartScreen, ScreenDisplay::Home) => {
                self.screen = ScreenDisplay::Start(Screen::new());
            }
            (Message::CheckConnection(stream, user), ScreenDisplay::Home) => {
                if let Some(connected_values) = &self.connect_values {
                    info!("Beginning the Diffie Hellman Check");
                    let public_key = match connected_values.x509.public_key() {
                        Ok(correct) => correct,
                        Err(_) => return Task::done(Message::SwitchStartScreen),
                    };
                    return Task::perform(
                        diffie_hellman_check(
                            stream,
                            user,
                            connected_values.cert.pkey.clone(),
                            public_key,
                        ),
                        |x| {
                            let x = match x {
                                Ok(correct) => correct,
                                Err(error) => {
                                    error!("Error with Diffie Hellman {}", error);
                                    return Message::SwitchStartScreen;
                                }
                            };
                            Message::ConnectRightUser(x.0, x.1)
                        },
                    );
                }
            }
            (Message::ConnectRightUser(stream, key), ScreenDisplay::Home) => {
                self.online = true;
                self.stream = Some(stream.clone());
                info!("DH was succesful");
                let (sender, receiver): (
                    tokio::sync::mpsc::Sender<Task<Message>>,
                    tokio::sync::mpsc::Receiver<Task<Message>>,
                ) = tokio::sync::mpsc::channel(100);
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
        let scroll = scrollable(column![text("Test"), text("Test1")])
            .on_scroll(|x| Message::ScrollDisplay(x));
        container(scroll)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
    fn send_message(&self) -> Element<'_, Message> {
        let text_editor = text_editor(&self.message)
            .placeholder("Message ..")
            .on_action(Message::POSTChangeTextField);
        let button_submit_message =
            button(text("Submit").center()).on_press(Message::PostMessageToPeer);
        let row = row![text_editor, Space::new().width(10), button_submit_message];
        container(row).into()
    }
    pub fn subscribtions(&self) -> Subscription<Message> {
        if self.online {
            // return Task::done(Message::SwitchStartScreen);
        }
        Subscription::none()
    }
}
