use std::{
    fs::{
        self,
        File,
    },
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

use anyhow::Context;
use chrono::{
    DateTime,
    Utc,
};
use iced::{
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
        button,
        column,
        container,
        row,
        text,
        text_input,
    },
};
use openssl::{
    pkcs12::Pkcs12,
    x509::X509,
};
use rfd::AsyncFileDialog;
use sqlx::{
    Pool,
    Sqlite,
    sqlite::SqlitePoolOptions,
};
use tokio::runtime::Runtime;
use tracing::info;

pub struct App {
    screen: Screen,
    connect_values: Option<ConnectValues>,
    sqlite_pool: Pool<Sqlite>,
}
pub struct ConnectValues {
    cert: Pkcs12,
    ip: SocketAddr,
    x509: X509,
}
impl ConnectValues {
    pub fn new(cert: Pkcs12, ip: SocketAddr, x509: X509) -> Self {
        Self { cert, ip, x509 }
    }
}
pub struct BuilderConnectValues {
    cert: Option<Pkcs12>,
    ip: Option<String>,
    x509: Option<X509>,
}
impl BuilderConnectValues {
    pub fn new() -> Self {
        Self {
            cert: None,
            ip: None,
            x509: None,
        }
    }
    pub fn set_cert(&mut self, input_cert_der: &[u8]) -> anyhow::Result<()> {
        self.cert = Some(Pkcs12::from_der(input_cert_der).context("Parsing from Pkcs12 Failed")?);
        Ok(())
    }
    pub fn set_ip(&mut self, input_ip: String) {
        self.ip = Some(input_ip);
    }
    pub fn build(&mut self) -> anyhow::Result<ConnectValues> {
        return match (self.cert.take(), self.ip.clone(), self.x509.take()) {
            (Some(cert), Some(ip), Some(x509)) => {
                let ip = SocketAddr::from_str(&ip).context("Parsing to Ip failed")?;
                Ok(ConnectValues::new(cert, ip, x509))
            }
            _ => {
                info!("The Check of the Sumbit Failed");
                Err(anyhow::anyhow!("Cert and Ip Failed. Builder Failed"))
            }
        };
    }
    pub fn get_the_numer_of_values_set(&self) -> u8 {
        let mut output: u8 = 0;
        if let Some(_) = self.cert {
            output += 1;
        }
        if let Some(_) = self.ip {
            output += 1;
        }
        output
    }
    pub fn set_x509(&mut self, input: &[u8]) -> anyhow::Result<()> {
        let x509_parsed = X509::from_der(input).context("Parser Failed for the X509 Cert")?;
        self.x509 = Some(x509_parsed);
        Ok(())
    }
    pub fn get_ip(&self) -> String {
        let value = self.ip.clone();
        if let Some(value) = value {
            return value.to_string();
        }
        "".to_string()
    }
}
#[derive(Debug, Clone)]
pub struct FilePathWithEnum {
    pub path: Option<PathBuf>,
    pub filedialogacion: FileDialogAction,
}
impl FilePathWithEnum {
    pub fn new(path: Option<PathBuf>, filedialogacion: FileDialogAction) -> Self {
        Self {
            path,
            filedialogacion,
        }
    }
}
#[derive(Debug, Clone)]
pub enum Message {
    PostFilePath(FilePathWithEnum),
    OpenFileDiaglog {
        title: String,
        filter: Option<String>,
        fileactiondialog: FileDialogAction,
    },
    MessageInsert {
        message_text: String,
        date_of_message: DateTime<Utc>,
        person_from: u8,
    },
    SwitchToMainScreen,
    PostIp(String),
}
pub enum Screen {
    Start(BuilderConnectValues),
    Home,
}
#[derive(Debug, Clone)]
pub enum FileDialogAction {
    PkCS12,
    X509,
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
            screen: Screen::Start(BuilderConnectValues::new()),
            connect_values: None,
            sqlite_pool: pool,
        })
    }
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SwitchToMainScreen => {
                if let Screen::Start(build) = &mut self.screen {
                    let conversation_pkcs12 = build.build();
                    if let Ok(conversation) = conversation_pkcs12 {
                        self.connect_values = Some(conversation);
                        self.screen = Screen::Home;
                    }
                }
            }
            Message::OpenFileDiaglog {
                title,
                filter,
                fileactiondialog,
            } => {
                return Task::perform(
                    async {
                        let file_dialog = AsyncFileDialog::new();
                        let file_dialog = match filter {
                            Some(filter_checked) => file_dialog
                                .add_filter(filter_checked.clone(), filter_checked.as_bytes()),
                            None => file_dialog,
                        };
                        let file_dialog = file_dialog.pick_file();
                        let handle = file_dialog.await;
                        let output = if let Some(handle_checked) = handle {
                            Some(handle_checked.path().to_path_buf())
                        } else {
                            None
                        };
                        info!("File choosen is {:?}", output);
                        FilePathWithEnum::new(output, fileactiondialog)
                    },
                    Message::PostFilePath,
                );
            }
            Message::MessageInsert {
                message_text,
                date_of_message,
                person_from,
            } => todo!(),
            Message::PostIp(ip) => match &mut self.screen {
                Screen::Start(builder_connect_values) => builder_connect_values.set_ip(ip),
                Screen::Home => (),
            },
            // parsing Failes
            Message::PostFilePath(file_path_with_enum) => match file_path_with_enum.filedialogacion
            {
                FileDialogAction::PkCS12 => {
                    use std::io::BufReader;
                    let path = file_path_with_enum.path;
                    if let Some(path_checked) = path
                        && let Screen::Start(builder) = &mut self.screen
                    {
                        let file_output = File::open(&path_checked);
                        if let Ok(file_open) = file_output
                            && let Ok(file_data) = fs::metadata(path_checked.as_path())
                        {
                            let mut buffer_file = Vec::with_capacity(
                                file_data.len().try_into().unwrap_or_else(|_| usize::MAX),
                            );
                            // Can be adde Later
                            let buff_reader =
                                BufReader::new(file_open).read_to_end(&mut buffer_file);
                            // Check Result can be ignored or checked
                            // Something for Later
                            // Not needed because in the build function it is checked
                            let check = builder.set_cert(&buffer_file);
                            info!(
                                "PCKS File was checked Result: {:?} if Nothing than alls if fine",
                                check
                            );
                        }
                    }
                }
                FileDialogAction::X509 => {
                    use std::io::BufReader;

                    let path = file_path_with_enum.path;
                    if let Some(path_checked) = path
                        && let Screen::Start(builder) = &mut self.screen
                    {
                        let file_output = File::open(&path_checked);
                        if let Ok(file_open) = file_output
                            && let Ok(file_data) = fs::metadata(path_checked.as_path())
                        {
                            let mut buffer_file = Vec::with_capacity(
                                file_data.len().try_into().unwrap_or_else(|_| usize::MAX),
                            );
                            // Can be adde Later
                            let buff_reader =
                                BufReader::new(file_open).read_to_end(&mut buffer_file);
                            // Check Result can be ignored or checked
                            // Something for Later
                            // Not needed because in the build function it is checked
                            let check = builder.set_cert(&buffer_file);
                            info!(
                                "X509 File was checked Result: {:?} if Nothing than alls if fine",
                                check
                            );
                        }
                    }
                }
            },
        }
        #[allow(unreachable_code)]
        Task::none()
    }
    pub fn view(&self) -> iced::Element<'_, Message> {
        return match &self.screen {
            Screen::Start(connectvalues) => Self::start(&self, &connectvalues),
            Screen::Home => Self::home(&self),
        };
    }
    fn home(&self) -> iced::Element<'_, Message> {
        container("Test").into()
    }
    fn start(&self, pcks12_struct: &BuilderConnectValues) -> Element<'_, Message> {
        let button_file_other_user: Element<'_, Message> = button(text("Cert X509"))
            .on_press(Message::OpenFileDiaglog {
                title: "Check Other User Cert X509".to_string(),
                filter: None,
                fileactiondialog: FileDialogAction::X509,
            })
            .into();
        let row_cert_other_x509 = row![
            text("Choose Path to Cert from other User"),
            container(button_file_other_user)
        ]
        .spacing(60);

        let button_client_pkcs12: Element<'_, Message> = button(text("Cert PKCS12"))
            .on_press(Message::OpenFileDiaglog {
                title: "Choose Our own PKCS12 Cert".to_string(),
                filter: None,
                fileactiondialog: FileDialogAction::PkCS12,
            })
            .into();
        let row_own_cert_pkcs12 = row![
            text("Choose Your own Cert and private key"),
            button_client_pkcs12
        ]
        .spacing(50);

        let input_ip: Element<'_, Message> =
            text_input("Ip Adress of the peer ...", &pcks12_struct.get_ip())
                .on_input(Message::PostIp)
                .width(Length::Fixed(130.0))
                .into();
        let row3 = row![text!("IP of the other User"), input_ip].spacing(190);
        let button_submit: Element<'_, Message> = button(text("Submit"))
            .on_press(Message::SwitchToMainScreen)
            .into();
        let column = column![
            text("Welcome to OTRv1 Client").size(40),
            row_cert_other_x509,
            row_own_cert_pkcs12,
            row3,
            container(button_submit)
                .align_y(Vertical::Center)
                .align_x(Horizontal::Center)
        ]
        .spacing(10);
        container(column)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}
