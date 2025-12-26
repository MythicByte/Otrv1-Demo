use std::{
    ops::AddAssign,
    sync::Arc,
};

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
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{
        PKey,
        Private,
    },
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
    interface::{
        App,
        Message,
    },
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
    app: &mut App,
    message: Vec<u8>,
    key: [u8; 32],
    old_mac: [u8; 64],
) -> anyhow::Result<MessageSend> {
    let aes_256_ctr = Cipher::aes_256_ctr();
    let ciphertext =
        encrypt(aes_256_ctr, &key, Some(&app.iv.0), &message).context("Encrpytion Failed")?;
    let (hmac_key, hmac_signer_final_key) = hmac(key, message)?;
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
    let old_mac_add: [u8; 64] = match hmac_signer_final_key.try_into() {
        Ok(x) => x,
        Err(_) => return Err(anyhow!("Error with mac conversion")),
    };
    app.old_mac = Some(old_mac_add);
    dbg!(&send_message);
    app.iv.add_one();
    Ok(send_message)
}
pub fn decrypt_data_for_transend(
    iv: Iv,
    message: Vec<u8>,
    key: [u8; 32],
    mac: [u8; 64],
) -> anyhow::Result<Vec<u8>> {
    let aes_256_ctr = Cipher::aes_256_ctr();
    let (hmac_key, hmac_key_final) = hmac(key, message.clone()).context("Hmac Error")?;
    let creat_hmac = Signer::new(MessageDigest::sha512(), &hmac_key)
        .context("hmac creation error")?
        .sign_to_vec()
        .context("Vec error")?;
    let hmac_key = PKey::hmac(&creat_hmac).context("Hmac Error")?;
    let mut verifiy =
        Signer::new(MessageDigest::sha3_512(), &hmac_key).context("Verifyer failed creation")?;
    verifiy.update(&message).context("Verifyer failed update")?;
    let result = verifiy.sign_to_vec().context("Signer Result Error")?;
    if result != mac {
        error!("Mac Tag failed");
        return Err(anyhow!("Mac Authentication Failed"));
    }
    let cleartext =
        decrypt(aes_256_ctr, &key, Some(&iv.0), &message).context("Encrpytion Failed")?;
    Ok(cleartext)
}
fn hmac(key: [u8; 32], message: Vec<u8>) -> Result<(PKey<Private>, Vec<u8>), ErrorStack> {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;
    let xor1 = key.map(|x| x & IPAD);
    let xor1 = PKey::hmac(&xor1)?;
    let mut sign = Signer::new(MessageDigest::sha3_512(), &xor1)?;
    sign.update(&message)?;
    let hmac_final_key = sign.sign_to_vec()?;
    let xor2 = key.map(|x| x ^ OPAD);
    let xor2 = PKey::hmac(&xor2)?;
    let mut hmac_signer = Signer::new(MessageDigest::sha3_512(), &xor2)?;
    hmac_signer.update(&hmac_final_key)?;
    let hmac_key = hmac_signer.sign_to_vec()?;
    let hmac_final = PKey::hmac(&hmac_key)?;
    Ok((hmac_final, hmac_final_key))
}
#[derive(Debug, Clone, Default)]
pub struct Iv([u8; 16]);
impl Iv {
    pub fn add_one(&mut self) {
        for (index, value) in self.0.iter_mut().enumerate() {
            let result = value.checked_add(1);
            match result {
                Some(x) => {
                    *value = x;
                    break;
                }
                None => match index {
                    15 => {
                        self.0 = [0; 16];
                        break;
                    }
                    _ => continue,
                },
            };
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_add_iv() {
        let mut iv = Iv::default();
        for _ in 0..=4080 {
            iv.add_one();
        }
        assert_eq!(iv.0, [0; 16]);
        // dbg!(iv.0);
    }
}
