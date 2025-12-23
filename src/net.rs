use std::{
    net::SocketAddr,
    sync::Arc,
};

use iced::futures::lock::Mutex;
use openssl::{
    dh::Dh,
    hash::MessageDigest,
    pkey::{
        PKey,
        Private,
        Public,
    },
    sign::{
        Signer,
        Verifier,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use thiserror::Error;
use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::{
        TcpListener,
        TcpStream,
    },
};
use tracing::info;
#[derive(Debug, Serialize, Deserialize)]
pub enum MessageSend {
    Encrypted {
        content: String,
        mac: String,
        old_mac_key: String,
        new_open_key: String,
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
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DiffieHellmanSend {
    pub open_key: Vec<u8>,
    pub signed: Vec<u8>,
}
#[derive(Debug, Clone)]
pub enum ServerClientModell {
    Server,
    Client,
}
#[derive(Debug, Error)]
pub enum ErrorDiffieHellman {
    #[error("Diffie Hellman Generation failed")]
    DHGeneration,
    #[error("Diffie Hellman Key Generation with parameters failed")]
    DHKeyGeneration,
    #[error("The Signing Key was not there")]
    SigningKeyNotThere,
    #[error("The Creation for the DH Signer failed")]
    SignerCreationFailed,
    #[error("Failing of DH failed")]
    FinalSignFailed,
    #[error("Serializiton failed")]
    SerializationFailed,
    #[error("Sending of a message failed")]
    SendingPayloadFailed,
    #[error("Conversation Failed")]
    U64ToUsizeFailed,
    #[error("Format from Client was wrong")]
    AnswerFormatWrong,
    #[error("Error with Verifier")]
    VerfifierError,
    #[error("The signatur is wrong")]
    ErrorDHSignedWrong,
    #[error("Reading or Writing from/to Stream error")]
    ReadOrWritingProblem(#[from] std::io::Error),
}
pub async fn diffie_hellman_check(
    tcpstream: Arc<Mutex<tokio::net::TcpStream>>,
    client_or_server: ServerClientModell,
    key_for_signing: Option<PKey<Private>>,
    pub_key_for_checking: PKey<Public>,
) -> Result<Arc<Mutex<tokio::net::TcpStream>>, ErrorDiffieHellman> {
    let key_for_signing = match key_for_signing {
        Some(x) => x,
        None => return Err(ErrorDiffieHellman::SigningKeyNotThere),
    };
    let diffie_hellman = Dh::get_2048_256().map_err(|_| ErrorDiffieHellman::DHGeneration)?;
    let diffie_hellman_key = diffie_hellman
        .generate_key()
        .map_err(|_| ErrorDiffieHellman::DHKeyGeneration)?;
    let mut private_key_to_cert = Signer::new(MessageDigest::sha512(), &key_for_signing)
        .map_err(|_| ErrorDiffieHellman::SignerCreationFailed)?;
    let mut client_diffie_hellman: DiffieHellmanSend = DiffieHellmanSend::default();
    client_diffie_hellman.open_key = diffie_hellman_key.public_key().to_vec();
    private_key_to_cert
        .update(&client_diffie_hellman.open_key)
        .map_err(|_| ErrorDiffieHellman::SignerCreationFailed)?;
    client_diffie_hellman.signed = private_key_to_cert
        .sign_to_vec()
        .map_err(|_| ErrorDiffieHellman::FinalSignFailed)?;
    let send: Vec<u8> = postcard::to_allocvec(&client_diffie_hellman)
        .map_err(|_| ErrorDiffieHellman::SerializationFailed)?;
    let mut tcp_have = tcpstream.lock().await;
    match client_or_server {
        ServerClientModell::Server => {
            tcp_have
                .write_u64(send.len() as u64)
                .await
                .map_err(|_| ErrorDiffieHellman::SendingPayloadFailed)?;
            tcp_have
                .write_all(&send)
                .await
                .map_err(|_| ErrorDiffieHellman::SendingPayloadFailed)?;

            let mut length: [u8; 8] = [0; 8];
            tcp_have.read_exact(&mut length).await?;
            let mut result: Vec<u8> = vec![
                0;
                u64::from_be_bytes(length)
                    .try_into()
                    .map_err(|_| ErrorDiffieHellman::U64ToUsizeFailed)?
            ];
            tcp_have.read_exact(&mut result).await?;
            let result_final: DiffieHellmanSend =
                postcard::from_bytes(&result).map_err(|_| ErrorDiffieHellman::AnswerFormatWrong)?;
            let mut verifyer = Verifier::new(MessageDigest::sha512(), &pub_key_for_checking)
                .map_err(|_| ErrorDiffieHellman::VerfifierError)?;
            verifyer
                .update(&result_final.open_key)
                .map_err(|_| ErrorDiffieHellman::VerfifierError)?;
            let check_if_other_user_correct = verifyer
                .verify(&result_final.signed)
                .map_err(|_| ErrorDiffieHellman::VerfifierError)?;
            if check_if_other_user_correct {
                // Add to the key to the db
                drop(tcp_have);
                return Ok(tcpstream);
            } else {
                return Err(ErrorDiffieHellman::ErrorDHSignedWrong);
            }
        }
        ServerClientModell::Client => {
            let mut length: [u8; 8] = [0; 8];
            tcp_have.read_exact(&mut length).await?;
            let mut result: Vec<u8> = vec![
                0;
                u64::from_be_bytes(length)
                    .try_into()
                    .map_err(|_| ErrorDiffieHellman::U64ToUsizeFailed)?
            ];
            tcp_have.read_exact(&mut result).await?;
            let result_final: DiffieHellmanSend =
                postcard::from_bytes(&result).map_err(|_| ErrorDiffieHellman::AnswerFormatWrong)?;
            tcp_have
                .write_u64(send.len() as u64)
                .await
                .map_err(|_| ErrorDiffieHellman::SendingPayloadFailed)?;
            tcp_have
                .write_all(&send)
                .await
                .map_err(|_| ErrorDiffieHellman::SendingPayloadFailed)?;
            let mut verifyer = Verifier::new(MessageDigest::sha512(), &pub_key_for_checking)
                .map_err(|_| ErrorDiffieHellman::VerfifierError)?;
            verifyer
                .update(&result_final.open_key)
                .map_err(|_| ErrorDiffieHellman::VerfifierError)?;
            let check_if_other_user_correct = verifyer
                .verify(&result_final.signed)
                .map_err(|_| ErrorDiffieHellman::VerfifierError)?;
            if check_if_other_user_correct {
                // Add to the key to the db
                drop(tcp_have);
                return Ok(tcpstream);
            } else {
                return Err(ErrorDiffieHellman::ErrorDHSignedWrong);
            }
        }
    }
}
pub async fn setup_connection(ip: SocketAddr) -> anyhow::Result<(TcpStream, ServerClientModell)> {
    tokio::select! {

    Ok(listen_finished) = TcpListener::bind(&ip) =>{
        info!("Tcp Listener correct");
        let (stream,_) = listen_finished.accept().await?;
        return Ok((stream,ServerClientModell::Server));
    }
    Ok(reached_out_finished) = TcpStream::connect(&ip)=> {
        info!("Tcp Stream correct");
        return Ok((reached_out_finished, ServerClientModell::Client));
    }
    }
}
