use std::sync::Arc;

use iced::{
    self,
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
    net::tcp::{
        OwnedReadHalf,
        OwnedWriteHalf,
    },
    sync::Mutex,
};
use tracing::{
    error,
    info,
};

use crate::{
    interface::Message,
    net::MessageSend,
};
pub fn check_if_other_user_only(
    stream: Arc<Mutex<OwnedReadHalf>>,
) -> impl Straw<(), Message, anyhow::Error> {
    sipper(move |mut output| async move {
        output.send(Message::DoNothing).await;
        let stream = stream.clone();
        let stream = Arc::clone(&stream);
        let mut entlock_stream = stream.lock().await;
        loop {
            let size = entlock_stream.read_u64().await?;
            // info!("Print size: {size}");
            let mut buffer_content = vec![0; size as usize];
            let _ = entlock_stream.read_exact(&mut buffer_content).await?;
            let deserialize_content: MessageSend = match postcard::from_bytes(&buffer_content) {
                Ok(x) => x,
                Err(_) => {
                    error!("Package Revied Deserialization Error");
                    continue;
                }
            };
            // info!("Paket Recieved Length: {}", size);
            output
                .send(Message::GetSendMessage(deserialize_content))
                .await;
        }
    })
}
pub async fn post_message(
    stream: Arc<Mutex<OwnedWriteHalf>>,
    content: Vec<u8>,
) -> anyhow::Result<()> {
    let length = content.len();
    let length: u64 = length.try_into()?;
    let mut stream = stream.lock().await;
    stream.write_u64(length).await?;
    stream.write_all(&content).await?;
    info!("Message send tcpstream");
    Ok(())
}
