use ratatui::style::{Color, Modifier, Style};

pub struct Theme {
    pub border: Style,
    pub border_active: Style,
    pub title: Style,
    pub text: Style,
    pub highlight: Style,
    pub pass: Style,
    pub drop: Style,
    pub warn: Style,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            border: Style::default().fg(Color::DarkGray),
            border_active: Style::default().fg(Color::Cyan),
            title: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            text: Style::default().fg(Color::White),
            highlight: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            pass: Style::default().fg(Color::Green),
            drop: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            warn: Style::default().fg(Color::LightYellow),
        }
    }
}
