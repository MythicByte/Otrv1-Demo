use crate::interface::{
    App,
    Message,
};
use iced::{
    Subscription,
    Task,
};
use serde::{
    Deserialize,
    Serialize,
};
use tokio::{
    io::Interest,
    net::TcpListener,
};
#[derive(Debug, Serialize, Deserialize)]
pub enum MessageSend {
    Encrypted {
        content: String,
        mac: String,
        old_mac_key: String,
        new_open_key: String,
    },
    ClientHello {
        open_key: Vec<u8>,
    },
    ServerHello {
        ack: bool,
        open_key: Vec<u8>,
    },
    ShareSecretKey {
        key: Vec<u8>,
    },
    Exit,
    ReykyingDiffieHellman {
        open_key: Vec<u8>,
        group: Vec<u8>,
        prime: Vec<u8>,
    },
    ReykyingDiffieHellmanAnswer {
        open_key: Vec<u8>,
    },
}
pub async fn connect_to_other_peer(app: &App) -> Subscription<Message> {
    if let Some(connect_some) = &app.connect_values {
        let ip_tcp_bind = match TcpListener::bind(connect_some.ip).await {
            Ok(correct_value) => correct_value,
            Err(_) => return Subscription::none(),
        };
        let ip = match ip_tcp_bind.accept().await {
            Ok(ip) => ip,
            Err(_) => return Subscription::none(),
        };
        loop {
            let read_message = match ip.0.ready(Interest::READABLE).await {
                Ok(correct) => correct,
                Err(_) => return Subscription::none(),
            };
            Subscription::run(Task::run(stream, f))
        }
    }
    Subscription::none()
}
