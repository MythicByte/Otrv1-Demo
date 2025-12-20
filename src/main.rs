#![deny(clippy::all)]
pub mod diffie_hellman;
pub mod interface;
pub mod message;
use iced::Theme;
use interface::App;
fn main() -> iced::Result {
    openssl::init();
    iced::application(App::default, App::update, App::view)
        .theme(Theme::Dark)
        .title("OTRv1 Demo Project")
        .run()
}
