use iced::widget::{container, Container};

#[derive(Debug)]
pub struct App {}
#[derive(Debug, Clone)]
pub enum Message {}
impl App {
    pub fn update(&mut self, message: Message) {
        match message {}
    }
    pub fn view(&self) -> iced::Element<'_, Message> {
        container("This is a test").padding(10).into()
    }
}
impl Default for App {
    fn default() -> Self {
        Self {}
    }
}
