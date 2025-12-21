#![deny(clippy::all)]
pub mod diffie_hellman;
pub mod interface;
pub mod message;
pub mod screen;
use iced::Theme;
use interface::App;
use tracing::{
    Level,
    info,
};
use tracing_subscriber::FmtSubscriber;
fn main() -> iced::Result {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Tracing Subscriber failed to setup");

    info!("Application ist starting");
    openssl::init();
    iced::application(App::new, App::update, App::view)
        .theme(Theme::Dark)
        .title("OTRv1 Demo Project")
        .centered()
        .run()
}
