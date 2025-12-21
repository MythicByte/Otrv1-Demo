use std::{
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

use std::{
    fs::{
        self,
        File,
    },
    io::Read,
};

use anyhow::Context;
use iced::{
    self,
    Element,
    Length,
    Task,
    Theme,
    alignment::{
        Horizontal,
        Vertical,
    },
    theme::palette,
    widget::{
        button,
        column,
        container,
        row,
        space::horizontal,
        text,
        text_input,
    },
};
use openssl::{
    pkcs12::Pkcs12,
    x509::X509,
};
use rfd::AsyncFileDialog;
use tracing::info;

pub struct Screen {
    pub builderconnectvalues: BuilderConnectValues,
    pub button: (bool, bool, bool, bool),
}
#[derive(Debug, Clone)]
pub enum ScreenMessage {
    SwitchToMainScreen,
    PostFilePath(FilePathWithEnum),
    OpenFileDiaglog {
        title: String,
        filter: Option<String>,
        fileactiondialog: FileDialogAction,
    },
    PostIp(String),
    PostPassword(String),
}
#[derive(Debug, Clone)]
pub enum FileDialogAction {
    PkCS12,
    X509,
}
impl Screen {
    pub fn new() -> Self {
        Self {
            builderconnectvalues: BuilderConnectValues::new(),
            button: (false, false, false, false),
        }
    }
    pub fn update(&mut self, screenmessage: ScreenMessage) -> Task<ScreenMessage> {
        match screenmessage {
            ScreenMessage::OpenFileDiaglog {
                title,
                filter,
                fileactiondialog,
            } => {
                return Task::perform(
                    async {
                        let file_dialog = AsyncFileDialog::new().set_title(title);
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
                    ScreenMessage::PostFilePath,
                );
            }
            ScreenMessage::PostIp(ip) => {
                self.button.2 = true;
                self.builderconnectvalues.set_ip(ip);
            }
            ScreenMessage::PostFilePath(file_path_with_enum) => {
                match file_path_with_enum.filedialogacion {
                    FileDialogAction::PkCS12 => {
                        self.button.1 = true;
                        use std::io::BufReader;
                        let path = file_path_with_enum.path;
                        if let Some(path_checked) = path {
                            let builder = &mut self.builderconnectvalues;
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
                                let check = builder.set_cert_pkcs12(&buffer_file);
                                info!(
                                    "PCKS File was checked Result: {:?} if Nothing than alls if fine",
                                    check
                                );
                            }
                        }
                    }
                    FileDialogAction::X509 => {
                        self.button.0 = true;
                        use std::io::BufReader;

                        let path = file_path_with_enum.path;
                        if let Some(path_checked) = path {
                            let builder = &mut self.builderconnectvalues;
                            let file_output = File::open(&path_checked);
                            if let Ok(file_open) = file_output
                                && let Ok(file_data) = fs::metadata(path_checked.as_path())
                            {
                                let mut buffer_capacity = Vec::with_capacity(
                                    file_data.len().try_into().unwrap_or_else(|_| usize::MAX),
                                );
                                // Can be adde Later
                                let buff_reader =
                                    BufReader::new(file_open).read_to_end(&mut buffer_capacity);
                                // Check Result can be ignored or checked
                                // Something for Later
                                // Not needed because in the build function it is checked
                                let check = builder.set_x509(&buffer_capacity);
                            }
                        }
                    }
                }
            }
            ScreenMessage::SwitchToMainScreen => {
                return Task::none();
            }
            ScreenMessage::PostPassword(password) => {
                self.builderconnectvalues.set_password(password);
            }
        }
        Task::none()
    }
    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let button_file_other_user: Element<'_, ScreenMessage> = button(text("Cert X509").center())
            .on_press(ScreenMessage::OpenFileDiaglog {
                title: "Check Other User Cert X509".to_string(),
                filter: None,
                fileactiondialog: FileDialogAction::X509,
            })
            .style(|theme: &Theme, status| {
                let palette = theme.extended_palette();
                if !self.button.0 {
                    return button::primary(theme, status);
                }
                match status {
                    button::Status::Active => {
                        if self.builderconnectvalues.x509.is_some() {
                            button::Style {
                                background: Some(palette.success.base.color.into()),
                                text_color: palette.success.base.text,
                                ..button::Style::default()
                            }
                        } else {
                            button::Style {
                                background: Some(palette.danger.base.color.into()),
                                text_color: palette.danger.base.text,
                                ..button::Style::default()
                            }
                        }
                    }
                    _ => button::primary(theme, status),
                }
            })
            .width(Length::Fixed(113.0))
            .into();
        let row_cert_other_x509 = row![
            text("Choose Path to Cert from other User"),
            horizontal().width(Length::Fill),
            container(button_file_other_user)
        ]
        .width(Length::Fill);

        let button_client_pkcs12: Element<'_, ScreenMessage> = button(text("Cert PKCS12"))
            .on_press(ScreenMessage::OpenFileDiaglog {
                title: "Choose Our own PKCS12 Cert".to_string(),
                filter: None,
                fileactiondialog: FileDialogAction::PkCS12,
            })
            .style(|theme: &Theme, status| {
                let palette = theme.extended_palette();
                if !self.button.1 {
                    return button::primary(theme, status);
                }
                match status {
                    button::Status::Active => {
                        if self.builderconnectvalues.get_pkcs_correct() {
                            button::Style {
                                background: Some(palette.success.base.color.into()),
                                text_color: palette.success.base.text,
                                ..Default::default()
                            }
                        } else {
                            button::Style {
                                background: Some(palette.danger.base.color.into()),
                                text_color: palette.danger.base.text,
                                ..Default::default()
                            }
                        }
                    }
                    _ => button::primary(theme, status),
                }
            })
            .into();
        let input_password_pkcs12: Element<'_, ScreenMessage> = text_input(
            "PKCS12 Password",
            &self.builderconnectvalues.get_password_stern(),
        )
        .on_input(ScreenMessage::PostPassword)
        .width(Length::Fixed(140.0))
        .secure(true)
        .into();

        let row_own_cert_pkcs12 = row![
            text("Choose own private key & Cert"),
            horizontal().width(Length::Fill),
            button_client_pkcs12,
            if self.builderconnectvalues.get_pkcs_correct() {
                input_password_pkcs12
            } else {
                row![].into()
            }
        ];
        let input_ip: Element<'_, ScreenMessage> = text_input(
            "Ip Adress of the peer ...",
            &self.builderconnectvalues.get_ip(),
        )
        .on_input(ScreenMessage::PostIp)
        .width(Length::Fixed(180.0))
        .style(|theme: &Theme, status| {
            let palette = theme.extended_palette();
            if !self.button.2 {
                return text_input::default(theme, status);
            }
            if SocketAddr::from_str(&self.builderconnectvalues.get_ip()).is_ok() {
                text_input::Style {
                    background: palette.success.base.color.into(),
                    value: palette.success.base.text,
                    ..text_input::default(theme, status)
                }
            } else {
                text_input::Style {
                    background: palette.danger.weak.color.into(),
                    ..text_input::default(theme, status)
                }
            }
        })
        .into();
        let row3 = row![
            text!("IP of the other User"),
            horizontal().width(Length::Fill),
            input_ip
        ];
        let button_submit: Element<'_, ScreenMessage> = button(text("Submit"))
            .on_press(ScreenMessage::SwitchToMainScreen)
            .style(|theme: &Theme, status| {
                let palette = theme.extended_palette();
                if self.button.3 {
                    button::Style {
                        background: Some(palette.danger.base.color.into()),
                        text_color: palette.danger.base.text,
                        ..Default::default()
                    }
                } else {
                    button::primary(theme, status)
                }
            })
            .into();
        let column = column![
            text("Welcome to OTRv1 Client").size(42),
            row_cert_other_x509,
            row_own_cert_pkcs12,
            row3,
            container(button_submit)
                .align_y(Vertical::Center)
                .align_x(Horizontal::Center)
        ]
        .max_width(500)
        .spacing(10);
        container(column)
            .height(Length::Fill)
            .width(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}

pub struct ConnectValues {
    cert: Pkcs12,
    ip: SocketAddr,
    x509: X509,
    pkcs_password: String,
}
impl ConnectValues {
    pub fn new(cert: Pkcs12, ip: SocketAddr, x509: X509, pkcs_password: String) -> Self {
        Self {
            cert,
            ip,
            x509,
            pkcs_password,
        }
    }
}
pub struct BuilderConnectValues {
    cert: Option<Pkcs12>,
    pkcs_passwod: String,
    ip: Option<String>,
    x509: Option<X509>,
}
impl BuilderConnectValues {
    pub fn new() -> Self {
        Self {
            cert: None,
            ip: None,
            x509: None,
            pkcs_passwod: "".to_string(),
        }
    }
    pub fn set_cert_pkcs12(&mut self, input_cert_der: &[u8]) -> anyhow::Result<()> {
        self.cert = Some(Pkcs12::from_der(input_cert_der).context("Parsing from Pkcs12 Failed")?);
        Ok(())
    }
    pub fn set_ip(&mut self, input_ip: String) {
        self.ip = Some(input_ip);
    }
    pub fn set_password(&mut self, input_password: String) {
        self.pkcs_passwod = input_password;
    }
    pub fn get_password_stern(&self) -> String {
        "*".repeat(self.pkcs_passwod.len())
    }
    pub fn get_pkcs_correct(&self) -> bool {
        self.cert.is_some()
    }
    pub fn build(&mut self) -> anyhow::Result<ConnectValues> {
        return match (
            self.cert.take(),
            self.ip.clone(),
            self.x509.take(),
            self.pkcs_passwod.clone(),
        ) {
            (Some(cert), Some(ip), Some(x509), pkcs_password) => {
                let ip = SocketAddr::from_str(&ip).context("Parsing to Ip failed")?;
                info!("Conversation Succeded and worked. Going to Main Screen");
                Ok(ConnectValues::new(cert, ip, x509, pkcs_password))
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
        let x509_parsed = X509::from_pem(input)
            .or_else(|_| X509::from_der(input))
            .context("Parser Failed for the X509 Cert")?;
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
