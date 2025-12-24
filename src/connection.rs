use std::sync::Arc;

use iced::{
    self,
    Task,
    task::{
        Straw,
        sipper,
    },
};
use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::TcpStream,
    sync::Mutex,
};
use tracing::info;

use crate::{
    interface::{
        App,
        Message,
    },
    net::MessageSend,
};

pub fn check_if_other_user_only(
    stream: Arc<Mutex<tokio::net::TcpStream>>,
) -> impl Straw<(), Message, anyhow::Error> {
    sipper(move |mut output| async move {
        let stream = stream.clone();
        let stream = Arc::clone(&stream);
        let mut entlock_stream = stream.lock().await;
        loop {
            let size = entlock_stream.read_u64().await?;
            info!("Print size: {size}");
            let mut buffer_content = vec![0; size as usize];
            let _ = entlock_stream.read_exact(&mut buffer_content).await?;
            let deserialize_content: MessageSend = postcard::from_bytes(&buffer_content)?;
            info!("Paket Recieved Length: {}", size);
            output
                .send(Message::GetSendMessage(deserialize_content))
                .await;
        }
    })
}
pub async fn post_message(stream: Arc<Mutex<TcpStream>>, content: Vec<u8>) -> anyhow::Result<()> {
    let length = content.len();
    let length: u64 = length.try_into()?;
    let mut stream = stream.lock().await;
    stream.write_u64(length).await?;
    stream.write_all(&content).await?;
    info!("Message send tcpstream");
    Ok(())
}
