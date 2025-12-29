//! # Gui
//! This is the main gui application code.
//! The start Screen is descript in [Screen](crate::screen::Screen), there is the entire config for loading the building values.
//!
//! # Iced gui Recap
//! The [Message](crate::interface::Message) are the **Signals** for the application. They react with it and can be seen with the debugger.
//! The **view** methode gives back the iced gui Elements thart are displayed.
//! The **update** Is there for mutating the data and making task possibel.
//! [App](crate::interface::App) and [Screen](crate::screen::Screen) have there one update and view methode which are pullen, when one is on focus.
use iced::{
    Border,
    Color,
    Element,
    Pixels,
    Subscription,
    Theme,
    border::Radius,
    widget::{
        Container,
        Space,
        button,
        container,
        rule,
        scrollable::{
            Direction,
            Scrollbar,
        },
    },
};
use openssl::{
    dh::Dh,
    hash::{
        MessageDigest,
        hash,
    },
    pkey::Private,
};
use serde::{
    Deserialize,
    Serialize,
};
use std::{
    sync::Arc,
    time::Duration,
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
    prelude::FromRow,
    sqlite::{
        SqliteConnectOptions,
        SqlitePoolOptions,
    },
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
        Iv,
        check_if_other_user_only,
        decrypt_data_for_transend,
        encrpyt_data_for_transend,
        post_message,
    },
    db::{
        read_nachricht_with_id_max,
        write_db,
    },
    interface,
    net::{
        DiffieHellmanSend,
        MessageSend,
        ServerClientModell,
        diffie_hellman_check_singed,
        generate_db_to_send,
        give_pub_key_back,
        reading_keying,
        setup_connection,
    },
    screen::{
        self,
        ConnectValues,
        Screen,
        ScreenMessage,
    },
};
/// The main struct for the gui and application
pub struct App {
    /// Which Dispay is used
    pub screen: ScreenDisplay,
    /// Config Values from Start Screen
    pub connect_values: Option<ConnectValues>,
    /// Sqlx Sqlite connection
    sqlite_pool: Pool<Sqlite>,
    /// For fetching the latest message
    message_last_id: u64,
    /// The Editor to send or edit messages
    message: text_editor::Content,
    /// If the other user is online
    online: bool,
    /// The tokio right stream for a tcpstream
    read_stream: Option<Arc<Mutex<OwnedReadHalf>>>,
    /// The tokio write stream for a tcpstream
    write_stream: Option<Arc<Mutex<OwnedWriteHalf>>>,
    /// Who is Server and who is Client
    pub clientservermodell: Option<ServerClientModell>,
    /// The content that is diplayed
    pub list_scrollable: Vec<Nachricht>,
    /// The key for AES CTR 256 for encryption
    symmetric_key: Option<[u8; 32]>,
    /// The old mac key to include in the next message
    pub old_mac: Option<[u8; 64]>,
    /// Hte iv for AES encryption
    pub iv: Iv,
    /// The DH key for Rekying
    pub diffie_hellman_key: Option<Dh<Private>>,
    /// The HMAC key derived from the symmetric key
    pub hmac_key: Option<[u8; 64]>,
}
/// The Signals for Iced Runtime
///
/// Specifiy all action taken from the iced gui libary
#[derive(Debug, Clone)]
pub enum Message {
    /// DH Respone from the other client
    IncomingDhBack(DiffieHellmanSend),
    /// Scrollable List add to display
    AddScrollableList(Vec<Nachricht>),
    /// Check if new input for the scroll wheel is there
    ScrollCheckNewInput,
    /// Send Rekying message
    PostRekying(DiffieHellmanSend),
    /// Initialize Rekying
    Rekying,
    /// Recives a [MessageSend] and responde to it
    GetSendMessage(MessageSend),
    /// Disconnect to the other user
    DisconnectOtherUser,
    /// Checks if the right user connected with DH
    ConnectRightUser(Arc<Mutex<tokio::net::TcpStream>>, [u8; 32]),
    /// Switch to start Screen
    SwitchStartScreen,
    /// Switch to Main Screen
    SwitchToMainScreen,
    /// Check Connection to connect to
    CheckConnection(Arc<Mutex<tokio::net::TcpStream>>, ServerClientModell),
    /// Insert a new Message in the Sqlite and the content displayed
    MessageInsert(Nachricht),
    /// Placeholder for the Screen Struct and function
    Screen(screen::ScreenMessage),
    /// Text Field Editor change
    POSTChangeTextField(text_editor::Action),
    /// Send the Message in the text field to the other user
    PostMessageToPeer,
    /// Ignore do nothing
    DoNothing,
}
/// The different Screens
pub enum ScreenDisplay {
    /// The start screen and store for the struct
    Start(Screen),
    /// Home Screen
    Home,
}
/// How Content is Displayed and stored in the db
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Nachricht {
    /// The Message
    #[sqlx(rename = "text")]
    pub message_text: String,
    /// Time of the Message
    #[sqlx(rename = "date")]
    pub date_of_message: DateTime<Utc>,
    /// Who has send the message
    ///
    /// 0 for myself
    ///
    /// 1 for the other person
    #[sqlx(rename = "partner")]
    pub person_from: u8,
}
impl Nachricht {
    /// Construct Nachricht
    pub fn new(message_text: String, date_of_message: DateTime<Utc>, person_from: u8) -> Self {
        Self {
            message_text,
            date_of_message,
            person_from,
        }
    }
}
impl App {
    /// Construct App
    pub fn new() -> Self {
        let output = Self::new_result().expect("Setting up failed");
        info!("Sqlite and Basic Setup was correct");
        output
    }
    /// Creates the initial gui, which can return a error
    fn new_result() -> anyhow::Result<Self> {
        let rt = Runtime::new().context("The tokio Runtime Failed")?;
        let pool = rt.block_on(async {
            let start_optins = SqliteConnectOptions::new()
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .in_memory(true);
            let pool = SqlitePoolOptions::new()
                .max_connections(4)
                .min_connections(1)
                .connect_with(start_optins)
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
            symmetric_key: None,
            old_mac: None,
            message_last_id: 0,
            iv: Iv::default(),
            diffie_hellman_key: None,
            hmac_key: None,
        })
    }
    /// The Loop that updates Variabels and do the have leafting
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match (message, &mut self.screen) {
            (Message::SwitchToMainScreen, ScreenDisplay::Start(screen)) => {
                let build = &mut screen.builderconnectvalues;
                let conversation_pkcs12 = build.build();
                if let Ok(conversation) = conversation_pkcs12 {
                    let ip_clone_for_later = conversation.ip;
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
                // For db overhole disabled
                //
                return Task::perform(write_db(self.sqlite_pool.clone(), nachricht), |x| {
                    match x {
                        Ok(_) => {
                            // info!("Db was written Input to");
                            Message::ScrollCheckNewInput
                        }
                        Err(e) => {
                            error!("Erro with the Db writing :{}", e);
                            Message::DoNothing
                        }
                    }
                });
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
                if self.message.is_empty() || !self.online {
                    return Task::none();
                }
                if let Some(key) = self.symmetric_key
                    && let Some(hmac_key_raw) = self.hmac_key
                {
                    let old_mac_key = self.old_mac.unwrap_or([0; 64]);
                    let text = self.message.text();
                    // Refreshed the text edit
                    self.message = text_editor::Content::new();
                    // To the Async Function that sends the code
                    let local_time = Utc::now();
                    let send_message = match encrpyt_data_for_transend(
                        self,
                        text.clone().into(),
                        key,
                        old_mac_key,
                        hmac_key_raw,
                    ) {
                        Ok(x) => {
                            if self.iv.check_rekying_should_be_done() {
                                return Task::done(Message::Rekying);
                            }
                            x
                        }
                        Err(e) => {
                            error!("Encryption Failed {}", e);
                            return Task::none();
                        }
                    };
                    let nachricht = Nachricht::new(text, local_time, 0);
                    // We are witing to the db know ignore
                    // self.list_scrollable.push(nachricht.clone());
                    info!("nachricht wurde verschickt");
                    let send = match postcard::to_allocvec(&send_message) {
                        Ok(x) => x,
                        Err(_) => return Task::done(Message::SwitchStartScreen),
                    };
                    if let Some(stream) = &self.write_stream {
                        return Task::perform(post_message(stream.clone(), send), |_| {
                            Message::MessageInsert(nachricht)
                        })
                        .chain(Task::done(Message::Rekying));
                        // .chain(Task::done(Message::Rekying(ServerClientModell::Client)));
                    }
                }
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
                        diffie_hellman_check_singed(
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
                self.symmetric_key = Some(key);
                self.hmac_key = Some(
                    hash(MessageDigest::sha3_512(), &key)
                        .map(|x| x.to_vec())
                        .unwrap_or(vec![0; 64])
                        .try_into()
                        .unwrap_or([0; 64]),
                );
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
                    |_| {
                        // dbg!(x);
                        Message::DisconnectOtherUser
                    },
                );
            }
            (Message::DisconnectOtherUser, ScreenDisplay::Home) => {
                self.online = false;
                self.read_stream = None;
                self.write_stream = None;
                self.iv = Iv::default();
                info!("Connection Disconnected");
                if let Some(conversation) = &self.connect_values {
                    return Task::perform(setup_connection(conversation.ip), |x| match x {
                        Ok((correct_tcpstream, user)) => {
                            Message::CheckConnection(Arc::new(Mutex::new(correct_tcpstream)), user)
                        }
                        Err(_) => Message::SwitchStartScreen,
                    });
                } else {
                    return Task::done(Message::SwitchStartScreen);
                }
            }
            (Message::GetSendMessage(message), ScreenDisplay::Home) => match message {
                MessageSend::Encrypted { content, mac, .. } => {
                    if let Some(key) = self.symmetric_key
                        && let Some(hmac_key_raw) = self.hmac_key
                    {
                        info!("Message got in");
                        let mac = match mac.try_into() {
                            Ok(x) => x,
                            Err(_) => return Task::none(),
                        };
                        let clear_text = match decrypt_data_for_transend(
                            self,
                            content,
                            key,
                            mac,
                            hmac_key_raw,
                        ) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("Decryption Error Ignore {}", e);
                                return Task::none();
                            }
                        };
                        let text = match String::from_utf8(clear_text) {
                            Ok(x) => x,
                            Err(_) => {
                                error!("Deserialie String to Utf8 failed gets ignored");
                                return Task::none();
                            }
                        };
                        info!("Messing incomming");
                        let nachricht = Nachricht::new(text, Utc::now(), 1);
                        // Fix Later
                        // self.list_scrollable.push(nachricht.clone());
                        info!("Nachricht was recieved");
                        return Task::done(Message::MessageInsert(nachricht));
                    }
                }
                // Checks what's heppening when A Dh is comming in
                _ => return Task::none(),
            },
            (Message::Rekying, ScreenDisplay::Home) => {
                if let Some(writer) = self.write_stream.clone() {
                    info!("Rekying started");
                    let dh = match generate_db_to_send() {
                        Ok(x) => x,
                        Err(_) => return Task::none(),
                    };
                    self.diffie_hellman_key = Some(dh.0);
                    let send_bytes = match postcard::to_allocvec(&MessageSend::Dh(dh.1)) {
                        Ok(x) => x,
                        Err(_) => return Task::none(),
                    };
                    return Task::perform(post_message(writer.clone(), send_bytes), |x| match x {
                        Ok(_) => Message::DoNothing,
                        Err(_) => {
                            error!("error with sending");
                            Message::SwitchToMainScreen
                        }
                    });
                } else {
                    error!("Error with the Rekying has happend");
                    return Task::done(Message::DisconnectOtherUser);
                }
            }
            (Message::PostRekying(diffie), ScreenDisplay::Home) => {
                if self.diffie_hellman_key.is_none() {
                    match generate_db_to_send() {
                        Ok(x) => {
                            info!("Keys are rotated");
                            self.diffie_hellman_key = Some(x.0);
                        }
                        Err(_) => {
                            error!("With the Rekying");
                            return Task::none();
                        }
                    };
                }
                if let Some(writer) = self.write_stream.clone()
                    && let Some(diffie_hellman_key) = &mut self.diffie_hellman_key
                {
                    info!("rekying incoming");
                    let key = match reading_keying(diffie_hellman_key, &diffie) {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Error with1: {}", e);
                            return Task::none();
                        }
                    };

                    info!("Keys are rotated");
                    self.symmetric_key = Some(key);
                    self.hmac_key = Some(
                        hash(MessageDigest::sha3_512(), &key)
                            .map(|x| x.to_vec())
                            .unwrap_or(vec![0; 64])
                            .try_into()
                            .unwrap_or([0; 64]),
                    );
                    // Only for testing on
                    // dbg!(&self.symmetric_key);
                    let send_back = match give_pub_key_back(diffie_hellman_key) {
                        Ok(x) => x,
                        Err(_) => {
                            error!("With send back Erro");
                            return Task::none();
                        }
                    };
                    let to_serialize_output = MessageSend::DhBack(send_back);
                    let message = match postcard::to_allocvec(&to_serialize_output) {
                        Ok(x) => x,
                        Err(_) => {
                            error!("Serialize Error");
                            return Task::none();
                        }
                    };
                    return Task::perform(post_message(writer, message), |x| {
                        if let Err(e) = x {
                            error!("Error with Rekying: {}", e);
                        }
                        info!("Rekying is send back");
                        Message::DoNothing
                    });
                }
            }
            (Message::ScrollCheckNewInput, ScreenDisplay::Home) => {
                return Task::perform(
                    read_nachricht_with_id_max(
                        self.sqlite_pool.clone(),
                        self.message_last_id as i64,
                    ),
                    |x| match x {
                        Ok(x) => Message::AddScrollableList(x),
                        Err(e) => {
                            error!("Adding content do Scroll failed: {}", e);
                            Message::DoNothing
                        }
                    },
                );
            }
            (Message::AddScrollableList(add), ScreenDisplay::Home) => {
                self.list_scrollable.extend(add);
                self.message_last_id = self.list_scrollable.len() as u64;
            }
            (Message::IncomingDhBack(dh), ScreenDisplay::Home) => {
                if let Some(dh_key) = &mut self.diffie_hellman_key {
                    let new_key = match reading_keying(dh_key, &dh) {
                        Ok(x) => x,
                        Err(_) => {
                            error!("Error with Dh");
                            return Task::none();
                        }
                    };
                    self.symmetric_key = Some(new_key);
                    self.hmac_key = Some(
                        hash(MessageDigest::sha3_512(), &new_key)
                            .map(|x| x.to_vec())
                            .unwrap_or(vec![0; 64])
                            .try_into()
                            .unwrap_or([0; 64]),
                    );
                    info!("Rekying worked");
                }
            }
            _ => return Task::none(),
        }
        Task::none()
    }
    /// Gives the gui elements back
    ///
    /// Give for each Screen the correct element back
    pub fn view(&self) -> iced::Element<'_, Message> {
        return match &self.screen {
            ScreenDisplay::Start(screen) => screen.view().map(Message::Screen),
            ScreenDisplay::Home => Self::home(self),
        };
    }
    /// For the home Screen the gui elements
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
    /// The status bar displayed on the top
    ///
    /// activate button for testing
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
        // Comment later out, only for testing
        // Only make on for testing
        //
        // let reky_button: Element<'_, Message> =
        // button("One Reky").on_press(Message::Rekying).into();
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
            // The Button for testing the rekying feature
            //
            // Space::new().width(5),
            // reky_button,
            horizontal().width(Length::Fill),
            online_indicator,
            Space::new().width(5),
            text(" Online").center(),
        ]
        .align_y(Vertical::Center);
        container(status_row).width(Length::FillPortion(2)).into()
    }
    /// The Chat Content that is scrollable
    fn chat(&self) -> Element<'_, Message> {
        let scroll = scrollable(column(
            self.list_scrollable
                .iter()
                .map(|x| self.message_scrollable(x)),
        ))
        .direction(Direction::Vertical(
            Scrollbar::new().anchor(scrollable::Anchor::Start),
        ))
        .auto_scroll(true)
        .on_scroll(|_viewport| Message::ScrollCheckNewInput);
        container(scroll)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
    /// Gives the [Message] to send the content in the text editor field
    fn send_message(&self) -> Element<'_, Message> {
        let text_editor = text_editor(&self.message)
            .placeholder("Message ..")
            .on_action(Message::POSTChangeTextField);
        let button_submit_message =
            button(text("Submit").center()).on_press(Message::PostMessageToPeer);
        let row = row![text_editor, Space::new().width(10), button_submit_message];
        container(row).into()
    }
    /// A helper function for creating a message Element, which interprets [Nachricht] to a display thing
    fn message_scrollable<'a>(&self, info: &'a interface::Nachricht) -> Element<'a, Message> {
        let clock_number = info
            .date_of_message
            .with_timezone(&Local)
            .format("%H:%M %d/%m/%Y ")
            .to_string();
        let x: Element<'_, Message> = column![
            text(info.message_text.clone()).size(20).center(),
            text(clock_number).size(10).center()
        ]
        .into();
        let x: Container<'_, Message> = container(x)
            .style(|theme: &Theme| {
                let palette = theme.extended_palette();
                match info.person_from {
                    0 => container::Style {
                        text_color: palette.success.strong.color.into(),
                        background: Some(palette.background.base.color.into()),
                        ..container::Style::default()
                    },
                    _ => container::Style {
                        text_color: palette.primary.strong.color.into(),
                        background: Some(palette.background.base.color.into()),
                        ..container::Style::default()
                    },
                }
            })
            .into();
        return match info.person_from {
            0 => row![
                x.align_left(Length::Shrink),
                Space::new().width(Length::Fill)
            ]
            .into(),
            _ => row![
                Space::new().width(Length::Fill),
                x.align_right(Length::Shrink)
            ]
            .into(),
        };
    }
    /// That every ten minutes a DH Rekying  is happening
    pub fn subscribtion(&self) -> Subscription<Message> {
        if let ScreenDisplay::Home = self.screen {
            return iced::time::every(Duration::from_mins(1)).map(|_| Message::Rekying);
        }
        Subscription::none()
    }
}
