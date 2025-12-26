#![deny(clippy::all)]
#![deny(missing_docs)]
//! Test

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
