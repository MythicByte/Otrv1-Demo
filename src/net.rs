use std::{
    net::SocketAddr,
    sync::Arc,
};

use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{
        Hasher,
        MessageDigest,
    },
    pkey::{
        PKey,
        Params,
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
    sync::Mutex,
};
use tracing::info;

/// The Messages that are send over the wire
///
/// Which is Serialized/Deserialized with the postcard libary
///
/// Bincode was not used, because the project is abended
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum MessageSend {
    /// A Message Encrypted
    Encrypted {
        /// The Message itself encryptet
        content: Vec<u8>,
        /// A Hmac SHA 3 512
        mac: Vec<u8>,
        /// Old Hmac
        old_mac_key: Vec<u8>,
        /// New Diffie hellman public key
        new_open_dh_key_not_singed: Vec<u8>,
    },
    /// DH Offering for the other Client
    Dh(DiffieHellmanSend),
    /// The Respone to DH
    DhBack(DiffieHellmanSend),
}
/// How a Dh ist transfered over wire
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffieHellmanSend {
    /// DH open key
    pub open_key: Vec<u8>,
    /// For the signed Hmac
    pub signed: Vec<u8>,
}
/// If we have here a Server or Client
///
/// Depends for Reconnecting and other work
#[derive(Debug, Clone)]
pub enum ServerClientModell {
    /// Is server
    Server,
    /// Is client
    Client,
}
/// Defines Erros for the Diffie Hellman connection
///
/// # Todo
/// Combine some Error variants and remove the not needed anymore
#[derive(Debug, Error)]
pub enum ErrorDiffieHellman {
    /// Generation Error
    #[error("Diffie Hellman Generation failed")]
    DHGeneration,
    /// Key Generation Error
    #[error("Diffie Hellman Key Generation with parameters failed")]
    DHKeyGeneration,
    /// Check if sign key was there
    #[error("The Signing Key was not there")]
    SigningKeyNotThere,
    /// Sign failed
    #[error("The Creation for the DH Signer failed")]
    SignerCreationFailed,
    /// Final sign failed
    #[error("Failing of DH failed")]
    FinalSignFailed,
    /// Serialization failed
    #[error("Serializiton failed")]
    SerializationFailed,
    /// Sending payload failed
    #[error("Sending of a message failed")]
    SendingPayloadFailed,
    /// Conversion Error
    #[error("Conversation Failed")]
    U64ToUsizeFailed,
    /// Wrong format
    #[error("Format from Client was wrong")]
    AnswerFormatWrong,
    #[error("Error with Verifier")]
    /// Verify has given an error
    VerfifierError,
    #[error("The signatur is wrong")]
    /// EH signed Wrong
    ErrorDHSignedWrong,
    /// Tokio Problem
    #[error("Reading or Writing from/to Stream error")]
    ReadOrWritingProblem(#[from] std::io::Error),
    /// Openssl has given an Error
    #[error("Openssl hat thrown a error")]
    OpenSSL(#[from] openssl::error::ErrorStack),
    /// Konversation Error
    #[error("Error with the vec to array")]
    AesKeyToArray,
}
/// Creates the first Diffie Hellman for the Authentication with the other user
pub async fn diffie_hellman_check_singed(
    tcpstream: Arc<Mutex<tokio::net::TcpStream>>,
    client_or_server: ServerClientModell,
    key_for_signing: Option<PKey<Private>>,
    pub_key_for_checking: PKey<Public>,
) -> Result<(Arc<Mutex<tokio::net::TcpStream>>, [u8; 32]), ErrorDiffieHellman> {
    let key_for_signing = match key_for_signing {
        Some(x) => x,
        None => return Err(ErrorDiffieHellman::SigningKeyNotThere),
    };
    let diffie_hellman = generate_rf_3526_4096().map_err(|_| ErrorDiffieHellman::DHGeneration)?;
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
                let number = BigNum::from_slice(&result_final.open_key)?;
                let final_dffie_hellman = diffie_hellman_key.compute_key(&number)?;
                let mut final_symmetrik_key = Hasher::new(MessageDigest::sha3_256())?;
                final_symmetrik_key.update(&final_dffie_hellman)?;
                let aes_key_256: [u8; 32] = final_symmetrik_key
                    .finish()?
                    .to_vec()
                    .try_into()
                    .map_err(|_| ErrorDiffieHellman::AesKeyToArray)?;
                // Add to the key to the db
                drop(tcp_have);
                return Ok((tcpstream, aes_key_256));
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
                let number = BigNum::from_slice(&result_final.open_key)?;
                let final_dffie_hellman = diffie_hellman_key.compute_key(&number)?;
                let mut final_symmetrik_key = Hasher::new(MessageDigest::sha3_256())?;
                final_symmetrik_key.update(&final_dffie_hellman)?;
                let aes_key_256: [u8; 32] = final_symmetrik_key
                    .finish()?
                    .to_vec()
                    .try_into()
                    .map_err(|_| ErrorDiffieHellman::AesKeyToArray)?;
                // Add to the key to the db
                // Becuase of the Mutex
                drop(tcp_have);
                return Ok((tcpstream, aes_key_256));
            } else {
                return Err(ErrorDiffieHellman::ErrorDHSignedWrong);
            }
        }
    }
}

/// Works with Async code to wait what is free and connect to it
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
/// Write the Dh in the Thing for Rekying without signing
pub fn generate_db_to_send() -> Result<(Dh<Private>, DiffieHellmanSend), ErrorDiffieHellman> {
    let diffie_hellman = generate_rf_3526_4096().map_err(|_| ErrorDiffieHellman::DHGeneration)?;
    let diffie_hellman_key = diffie_hellman
        .generate_key()
        .map_err(|_| ErrorDiffieHellman::DHKeyGeneration)?;
    let mut client_diffie_hellman: DiffieHellmanSend = DiffieHellmanSend::default();
    client_diffie_hellman.open_key = diffie_hellman_key.public_key().to_vec();
    Ok((diffie_hellman_key, client_diffie_hellman))
}
/// Reades Dh key
///
/// gives back the new shared secret
pub fn reading_keying(
    // DH key pair
    key: &mut Dh<Private>,
    // The other public key
    message: &DiffieHellmanSend,
) -> Result<[u8; 32], ErrorDiffieHellman> {
    let number = BigNum::from_slice(&message.open_key)?;
    let shared_secret = key.compute_key(&number)?;
    let mut final_symmetrik_key = Hasher::new(MessageDigest::sha3_256())?;
    final_symmetrik_key.update(&shared_secret)?;
    let aes_key_256: [u8; 32] = final_symmetrik_key
        .finish()?
        .to_vec()
        .try_into()
        .map_err(|_| ErrorDiffieHellman::AesKeyToArray)?;
    Ok(aes_key_256)
}
/// Gives the pub key from DH back
pub fn give_pub_key_back(key: &mut Dh<Private>) -> anyhow::Result<DiffieHellmanSend> {
    let pub_key = key.public_key().to_vec();
    let mut output = DiffieHellmanSend::default();
    output.open_key = pub_key;
    Ok(output)
}
/// Generates the DH Keys
///
/// 4096-bit MODP Group from the rfc 3526
fn generate_rf_3526_4096() -> Result<Dh<Params>, ErrorDiffieHellman> {
    let p = BigNum::get_rfc3526_prime_4096()?;
    let g = BigNum::from_u32(2)?;
    let dh = Dh::from_pqg(p, None, g)?;
    Ok(dh)
}
