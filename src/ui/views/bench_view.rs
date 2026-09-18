use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
};

use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    let info = vec![
        Line::from(vec![Span::styled(
            "Syscall Evasion Benchmarker",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("Measures nanosecond latency overhead of active eBPF monitoring hooks against"),
        Line::from("high-frequency evasive syscall sequences (getpid, sendto)."),
        Line::from(""),
        Line::from(vec![
            Span::raw("Baseline Call: "),
            Span::styled("42.3 ns", theme.pass),
            Span::raw("  |  eBPF Monitored: "),
            Span::styled("118.6 ns", theme.warn),
            Span::raw("  |  Instrumentation Tax: "),
            Span::styled("+76.3 ns (+180%)", theme.drop),
        ]),
    ];

    let header = Paragraph::new(info).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border)
            .title(" Performance Analysis "),
    );
    f.render_widget(header, chunks[0]);

    let core_rows = vec![
        Row::new(vec![
            "struct task_struct.pid",
            "0x4b8 (BTF Verified)",
            "Relocated Successfully",
            "OK",
        ]),
        Row::new(vec![
            "struct task_struct.comm",
            "0x680 (BTF Verified)",
            "Relocated Successfully",
            "OK",
        ]),
        Row::new(vec![
            "struct bpf_storage_blob",
            "Non-exported internal",
            "BTF relocation failed",
            "CO-RE BREAK",
        ]),
        Row::new(vec![
            "hidden task flags",
            "Offset varies by commit",
            "Verifier state invalidated",
            "REJECTED",
        ]),
    ];

    let core_table = Table::new(
        core_rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
            Constraint::Percentage(15),
        ],
    )
    .header(
        Row::new(vec![
            "Kernel Struct / Member",
            "BTF Relocation Analysis",
            "Relocation Status",
            "Offensive Usability",
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
            .title(" CO-RE (Compile Once – Run Everywhere) Breakpoint Inspector "),
    );

    f.render_widget(core_table, chunks[1]);
}
