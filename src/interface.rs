use iced::{
    Border,
    Color,
    Element,
    Pixels,
    Theme,
    border::Radius,
    widget::{
        Space,
        button,
        container,
        rule,
        scrollable::{
            Direction,
            Scrollbar,
            Viewport,
        },
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use std::{
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use chrono::{
    DateTime,
    Local,
    Utc,
};
use iced::{
    self,
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
use tokio::{
    net::tcp::{
        OwnedReadHalf,
        OwnedWriteHalf,
    },
    runtime::Runtime,
    sync::Mutex,
};
use tracing::{
    error,
    info,
};

use crate::{
    connection::{
        check_if_other_user_only,
        post_message,
    },
    db::{
        self,
        read_all_user,
        write_db,
    },
    interface,
    net::{
        MessageSend,
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
    /// Which Dispay is used
    pub screen: ScreenDisplay,
    /// Config Values from Start Screen
    pub connect_values: Option<ConnectValues>,
    /// Sqlx Sqlite connection
    sqlite_pool: Pool<Sqlite>,
    /// The Editor to send or edit messages
    message: text_editor::Content,
    /// Inline indicator
    online: bool,
    /// TCPStream to the right target
    // stream: Option<Arc<Mutex<tokio::net::TcpStream>>>,
    read_stream: Option<Arc<Mutex<OwnedReadHalf>>>,
    write_stream: Option<Arc<Mutex<OwnedWriteHalf>>>,
    /// Whoch Server Model is
    pub clientservermodell: Option<ServerClientModell>,
    pub list_scrollable: Vec<Nachricht>,
}
#[derive(Debug, Clone)]
pub struct Keys {
    open: Vec<u8>,
}
#[derive(Debug, Clone)]
pub enum Message {
    GetSendMessage(MessageSend),
    /// Disconnect to the other user
    DisconnectOtherUser,
    ConnectRightUser(Arc<Mutex<tokio::net::TcpStream>>, Vec<u8>),
    SwitchStartScreen,
    CheckConnection(Arc<Mutex<tokio::net::TcpStream>>, ServerClientModell),
    SwitchToMainScreen,
    MessageInsert(Nachricht),
    Screen(screen::ScreenMessage),
    POSTChangeTextField(text_editor::Action),
    PostMessageToPeer,
    CheckDBError(u8),
    ScrollDisplay(Viewport),
    PutListValues(Vec<db::Message>),
    DoNothing,
}
/// The different Screens
pub enum ScreenDisplay {
    Start(Screen),
    Home,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nachricht {
    pub message_text: String,
    pub date_of_message: DateTime<Utc>,
    pub person_from: u8,
}
impl Nachricht {
    pub fn new(message_text: String, date_of_message: DateTime<Utc>, person_from: u8) -> Self {
        Self {
            message_text,
            date_of_message,
            person_from,
        }
    }
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
            // stream: None,
            clientservermodell: None,
            list_scrollable: Vec::new(),
            read_stream: None,
            write_stream: None,
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
            (Message::MessageInsert(nachricht), ScreenDisplay::Home) => {
                return Task::perform(
                    write_db(
                        self.sqlite_pool.clone(),
                        nachricht.message_text,
                        nachricht.date_of_message,
                        nachricht.person_from,
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
                // Only for testing disable
                if self.message.is_empty() || self.online == false {
                    return Task::none();
                }
                let text = self.message.text();
                // Refreshed the text edit
                self.message = text_editor::Content::new();
                // To the Async Function that sends the code
                let local_time = Utc::now();
                let send_message = MessageSend::Encrypted {
                    content: text.as_bytes().to_vec(),
                    mac: Vec::new(),
                    old_mac_key: Vec::new(),
                    new_open_key: Vec::new(),
                };
                let nachricht = Nachricht::new(text, local_time, 0);
                self.list_scrollable.push(nachricht.clone());
                info!("nachricht wurde verschickt");
                let send = match postcard::to_allocvec(&send_message) {
                    Ok(x) => x,
                    Err(_) => return Task::done(Message::SwitchStartScreen),
                };
                if let Some(stream) = &self.write_stream {
                    return Task::perform(post_message(stream.clone(), send), |x| {
                        Message::DoNothing
                    });
                }
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
            (Message::SwitchStartScreen, ScreenDisplay::Home) => {
                self.screen = ScreenDisplay::Start(Screen::new());
            }
            (Message::CheckConnection(stream, user), ScreenDisplay::Home) => {
                self.clientservermodell = Some(user.clone());
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
                let stream = match Arc::try_unwrap(stream) {
                    Ok(x) => x,
                    Err(_) => return Task::done(Message::SwitchStartScreen),
                };
                let (reader, writer) = stream.into_inner().into_split();
                self.read_stream = Some(Arc::new(Mutex::new(reader)));
                self.write_stream = Some(Arc::new(Mutex::new(writer)));
                info!("DH was succesful");
                let read_stream = match &self.read_stream {
                    Some(x) => x,
                    None => return Task::done(Message::SwitchStartScreen),
                };
                return Task::sip(
                    check_if_other_user_only(read_stream.clone()),
                    |message| message,
                    |x| {
                        dbg!(x);
                        Message::DoNothing
                    },
                );
            }
            (Message::DisconnectOtherUser, ScreenDisplay::Home) => {
                self.online = false;
                self.read_stream = None;
                self.write_stream = None;
                info!("Connection Disconnected");
                if let Some(user) = &self.clientservermodell
                    && let Some(reader_stream) = self.read_stream.take()
                    && let Some(writer_stream) = self.write_stream.take()
                {
                    let reader_stream = match Arc::try_unwrap(reader_stream) {
                        Ok(x) => x,
                        Err(_) => return Task::done(Message::SwitchStartScreen),
                    };
                    let writer_stream = match Arc::try_unwrap(writer_stream) {
                        Ok(x) => x,
                        Err(_) => return Task::done(Message::SwitchStartScreen),
                    };
                    let read_stream = reader_stream.into_inner();
                    let writer_stream = writer_stream.into_inner();
                    let tcp_stream = match read_stream.reunite(writer_stream) {
                        Ok(x) => x,
                        Err(_) => return Task::done(Message::SwitchStartScreen),
                    };
                    let tcp_stream = Arc::new(Mutex::new(tcp_stream));
                    return Task::done(Message::CheckConnection(tcp_stream, user.clone()));
                }
            }
            (Message::GetSendMessage(message), ScreenDisplay::Home) => match message {
                MessageSend::Encrypted {
                    content,
                    mac,
                    old_mac_key,
                    new_open_key,
                } => {
                    info!("Messing incomming");
                    let nachricht =
                        Nachricht::new(String::from_utf8(content).unwrap(), Utc::now(), 1);
                    // Fix Later
                    self.list_scrollable.push(nachricht);
                    info!("Nachricht was recieved");
                }
                MessageSend::Exit => return Task::none(),
            },
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
        let scroll = scrollable(column(
            self.list_scrollable
                .iter()
                .map(|x| self.message_scrollable(x)),
        ))
        .direction(Direction::Vertical(
            Scrollbar::new().anchor(scrollable::Anchor::Start),
        ))
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
    fn message_scrollable(&self, info: &interface::Nachricht) -> Element<'_, Message> {
        let clock_number = info
            .date_of_message
            .with_timezone(&Local)
            .format("%H:%M %d/%m/%Y ")
            .to_string();
        let x: Element<'_, Message> = column![
            text(info.message_text.clone()).size(20).center(),
            text(clock_number).size(10)
        ]
        .into();
        let x: Element<'_, Message> = container(x)
            .style(|theme: &Theme| {
                let palette = theme.extended_palette();
                container::Style {
                    text_color: palette.success.strong.color.into(),
                    background: Some(palette.background.base.color.into()),
                    ..container::Style::default()
                }
            })
            .into();
        return match info.person_from {
            0 => row![x, Space::new().width(Length::Fill)].into(),
            _ => row![Space::new().width(Length::Fill), x].into(),
        };
    }
}
