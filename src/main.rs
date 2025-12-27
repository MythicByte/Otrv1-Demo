#![deny(clippy::all)]
#![deny(missing_docs)]
//! This  is a **Demo** project implements a gui with the OTRv1 Protcol.
//! The only differenc is that, moderner parameters are used.
//! AES Key Length was upgraded, a longer hmac was choosen,
//! The DH Parameter were set higher and then more then 3000 Bits.
//!
//!
//! Most of the code is **async** with tokio and iced. Tcp is only used because of the relibility for a Demo and prototyping.
//! The Sqlite db stors the data in memory, it was before persistend. Choose only to save the the currect session.
//! # Technical Details
//! AES 256 CTR
//!
//! HMAC SHA 3 512
//!
//! DH 4096-bit MODP Group from the rfc 3526
//! # Warning
//! This app has no DDOS protection, use with caution. Recommended is localhost or inside a local network.
//! Works with Tcp for secure that both sides get the messae, for a demo better for testing.
//! # Future Work
//! Messages are stored in the Sqlite db, they can be changed or deletet.
//! Make a gui Button to rename something or delete something.
//!
//! Make the Sqlite db not work anymore in the memory and one a seperate file permanent.

/// Decryption and Networking code
pub mod connection;
/// Defines the db interface Sqlite here
pub mod db;
/// Main Gui Code
pub mod interface;
/// Retrieves the Packets, Diffie Hellman, Read Loop
pub mod net;
/// Home Screen
pub mod screen;
use iced::Theme;
use interface::App;
use tracing::{
    Level,
    info,
};
use tracing_subscriber::FmtSubscriber;
/// iced configuration
fn main() -> iced::Result {
    // log output
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    // set gloab default
    tracing::subscriber::set_global_default(subscriber)
        .expect("Tracing Subscriber failed to setup");

    info!("Application ist starting");
    // Openssl start
    openssl::init();
    iced::application(App::new, App::update, App::view)
        .theme(Theme::Dark)
        .title("OTRv1 Demo Project")
        .subscription(App::subscribtion)
        .centered()
        .run()
}
