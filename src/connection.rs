use std::sync::Arc;

use iced::{
    Task,
    advanced::graphics::Mesh,
    futures::{
        Stream,
        lock::Mutex,
    },
};

use crate::interface;

// pub async fn check_if_other_user_only(stream: Arc<Mutex<tokio::net::TcpStream>>) -> impl Stream {
// Task::done(interface::Message::SwitchStartScreen)
// }
