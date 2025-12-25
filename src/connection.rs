use std::sync::Arc;

use anyhow::{
    Context,
    anyhow,
};
use iced::{
    self,
    task::{
        Straw,
        sipper,
    },
};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::{
        Signer,
        Verifier,
    },
    symm::{
        Cipher,
        decrypt,
        encrypt,
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
/// Recieves Messages from the other client
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
            info!("Paket Recieved Length: {}", size);
            match deserialize_content {
                content_correct @ MessageSend::Encrypted { .. } => {
                    output.send(Message::GetSendMessage(content_correct)).await;
                }
                MessageSend::Dh(diffie_hellman_send) => {
                    output.send(Message::PostRekying(diffie_hellman_send)).await;
                }
            }
        }
    })
}
/// Send message to the other user
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
pub fn encrpyt_data_for_transend(
    message: Vec<u8>,
    key: [u8; 32],
    old_mac: [u8; 64],
) -> anyhow::Result<MessageSend> {
    let aes_256_ctr = Cipher::aes_256_ctr();
    let ciphertext = encrypt(aes_256_ctr, &key, None, &message).context("Encrpytion Failed")?;
    let hmac_key = PKey::hmac(&key).context("Hmac Error")?;
    let mut sign =
        Signer::new(MessageDigest::sha3_512(), &hmac_key).context("Signer creation failed")?;
    sign.update(&ciphertext).context("Error with mac")?;
    let final_hmac = sign.sign_to_vec().context("mac error")?;
    let send_message = MessageSend::Encrypted {
        content: ciphertext,
        mac: final_hmac,
        old_mac_key: old_mac.try_into().context("Try into failed")?,
        new_open_key: Vec::new(),
    };
    Ok(send_message)
}
pub fn decrypt_data_for_transend(
    message: Vec<u8>,
    key: [u8; 32],
    mac: [u8; 64],
) -> anyhow::Result<Vec<u8>> {
    let aes_256_ctr = Cipher::aes_256_ctr();
    let hmac_key = PKey::hmac(&key).context("Hmac Error")?;
    let mut verifiy =
        Signer::new(MessageDigest::sha3_512(), &hmac_key).context("Verifyer failed creation")?;
    verifiy.update(&message).context("Verifyer failed update")?;
    let result = verifiy.sign_to_vec().context("Signer Result Error")?;
    if result != mac {
        error!("Mac Tag failed");
        return Err(anyhow!("Mac Authentication Failed"));
    }
    let cleartext = decrypt(aes_256_ctr, &key, None, &message).context("Encrpytion Failed")?;
    Ok(cleartext)
}
