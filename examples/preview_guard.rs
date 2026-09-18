use std::io::stdout;
use std::thread;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use xdp_ai_guard::engine::stats::GuardMetrics;
use xdp_ai_guard::ui::theme::Theme;
use xdp_ai_guard::ui::views::guard_view;

fn main() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut metrics = GuardMetrics::new(50);
    let theme = Theme::default();
    let mut total_pass = 1000u64;
    let mut total_drop = 20u64;

    // Simulation loop
    let tick_rate = Duration::from_millis(100);
    loop {
        // Synthesize fluctuating network traffic
        let synthetic_burst = (rand_simple() % 150) + 20;
        total_pass += synthetic_burst;
        if synthetic_burst % 7 == 0 {
            total_drop += 2;
        }

        metrics.update(total_pass, total_drop);

        terminal.draw(|f| {
            guard_view::render(f, f.area(), &metrics, "lo (MOCK)", &theme);
        })?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

// Lightweight deterministic pseudo-random generator without extra deps
fn rand_simple() -> u64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;
    nanos % 1000
}
