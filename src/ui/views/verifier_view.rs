use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
};

use crate::{
    research::verifier::{TEST_CASES, VerifierReport},
    ui::theme::Theme,
};

pub fn render(
    f: &mut Frame,
    area: Rect,
    selected_index: usize,
    active_report: &Option<VerifierReport>,
    theme: &Theme,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(10)])
        .split(area);

    let rows: Vec<Row> = TEST_CASES
        .iter()
        .enumerate()
        .map(|(i, tc)| {
            let is_selected = i == selected_index;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let prefix = if is_selected { "▶ " } else { "  " };
            Row::new(vec![
                format!("{}{}", prefix, tc.name),
                tc.description.to_string(),
                tc.expected_result.to_string(),
            ])
            .style(style)
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(45),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(vec![
            "Attack / Stress Pattern",
            "Scenario Description",
            "Expected Guard Action",
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_active)
            .title(" eBPF Verifier Research Harness (Use [↑/↓] to Select, [R] to Run Audit) "),
    );

    f.render_widget(table, chunks[0]);
    let report_content = if let Some(report) = active_report {
        vec![
            Line::from(vec![
                Span::styled(
                    "Target Program: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(&report.test_name, Style::default().fg(Color::Yellow)),
                Span::raw(" | Status: "),
                Span::styled(
                    "REJECTED (Pushback Verified)",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" | Insn Count: "),
                Span::styled(
                    format!("{}", report.instruction_count),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "Kernel Reason: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(&report.reason, Style::default().fg(Color::LightRed)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "--- RAW KERNEL BPF VERIFIER LOG ---",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(report.verifier_log.as_str()),
        ]
    } else {
        vec![Line::from(Span::styled(
            "Select a stress pattern above and press [R] to execute the kernel verifier audit.",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let log_box = Paragraph::new(report_content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border)
                .title(" Kernel Diagnostics & Verifier Log Analysis "),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(log_box, chunks[1]);
}
