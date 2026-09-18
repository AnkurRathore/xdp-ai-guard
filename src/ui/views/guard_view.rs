use crate::engine::stats::GuardMetrics;
use crate::ui::theme::Theme;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, Gauge, Paragraph, Row, Sparkline, Table},
};

pub fn render(f: &mut Frame, area: Rect, metrics: &GuardMetrics, iface: &str, theme: &Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header stats summary
            Constraint::Length(10), // Real-time Sparklines & Throughput
            Constraint::Min(8),     // Metrics Breakdown & System State
        ])
        .split(area);

    // 1. Header Summary Banner
    let summary = Line::from(vec![
        Span::raw(" Interface: "),
        Span::styled(format!("{:<8} ", iface), theme.highlight),
        Span::raw(" |  Total Passed: "),
        Span::styled(format!("{:<10} ", metrics.total_pass), theme.pass),
        Span::raw(" |  Total Dropped: "),
        Span::styled(format!("{:<8} ", metrics.total_drop), theme.drop),
        Span::raw(" |  Current Rate: "),
        Span::styled(format!("{} pkts/s", metrics.pass_pps), theme.highlight),
    ]);

    let summary_widget = Paragraph::new(summary).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border)
            .title(" Guard Status "),
    );
    f.render_widget(summary_widget, chunks[0]);

    // 2. Traffic Flow Sparkline
    let mid_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(chunks[1]);

    let sparkline_data: Vec<u64> = metrics.pps_history.iter().copied().collect();
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(" Ingress Traffic Intensity (pkts/sec) ")
                .borders(Borders::ALL)
                .border_style(theme.border_active),
        )
        .data(&sparkline_data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(sparkline, mid_chunks[0]);

    // Ratio Gauge
    let total = (metrics.total_pass + metrics.total_drop).max(1);
    let pass_ratio = ((metrics.total_pass as f64 / total as f64) * 100.0) as u16;
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" Allow / Pass Ratio ")
                .borders(Borders::ALL)
                .border_style(theme.border),
        )
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .percent(pass_ratio.min(100));
    f.render_widget(gauge, mid_chunks[1]);

    // 3. Lower Detail Table
    let rows = vec![
        Row::new(vec!["Engine Mode", "XDP / Native Driver Offload"]),
        Row::new(vec!["CO-RE Relocation", "Active (vmlinux.h BTF matched)"]),
        Row::new(vec!["Memory Model", "Lock-free Per-CPU Array Map"]),
        Row::new(vec![
            "Inference Server Shield",
            "Enabled (Port 8000/8080/v1)",
        ]),
    ];

    let details_table = Table::new(
        rows,
        [Constraint::Percentage(40), Constraint::Percentage(60)],
    )
    .block(
        Block::default()
            .title(" Telemetry & Subsystem Details ")
            .borders(Borders::ALL)
            .border_style(theme.border),
    );

    f.render_widget(details_table, chunks[2]);
}
