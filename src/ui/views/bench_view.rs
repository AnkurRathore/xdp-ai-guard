use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
};

use crate::research::syscall_bench::BenchResult;
use crate::ui::theme::Theme;

/// Renders View 3: Syscall Overhead Benchmarking & CO-RE Breakpoint Inspector.
///
/// Layout:
/// - Top Chunk (Height 9): Live hardware performance metrics, instrumentation tax, and evasion cost.
/// - Bottom Chunk (Min 8): CO-RE / BTF kernel struct member relocation matrix.
pub fn render(f: &mut Frame, area: Rect, bench: &BenchResult, theme: &Theme) {
    // Split view area vertically into top (metrics card) and bottom (CO-RE table)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(8)])
        .split(area);

    // Visual badge indicating whether benchmark ran against live kernel eBPF or simulated mock
    let mode_span = if bench.is_live_ebpf {
        Span::styled(
            "[LIVE KERNEL PROBE]",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "[MOCK / SIMULATED PROBE]",
            Style::default().fg(Color::Yellow),
        )
    };

    // Construct header block content: summary, baseline vs. monitored metrics, and calculated tax
    let info = vec![
        Line::from(vec![
            Span::styled(
                "Dynamic Syscall Overhead Benchmarker ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            mode_span,
            Span::raw(format!("  (Iterations: {})", bench.iterations)),
        ]),
        Line::from(
            "Empirically measures single-syscall nanosecond tax before and after eBPF probe attachment.",
        ),
        Line::from("Press [B] to trigger a live hardware re-measurement."),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Baseline (No Probe):  "),
            Span::styled(format!("{:.1} ns", bench.baseline_ns), theme.pass),
            Span::raw("   |   With eBPF Hook:  "),
            Span::styled(format!("{:.1} ns", bench.monitored_ns), theme.warn),
            Span::raw("   |   Instrumentation Tax:  "),
            Span::styled(
                format!("+{:.1} ns (+{:.1}%)", bench.tax_ns, bench.overhead_percent),
                theme.drop,
            ),
        ]),
        Line::from(vec![Span::styled(
            format!(
                "  Estimated cost of 1M evasion syscalls: {:.2} ms CPU time",
                (bench.tax_ns * 1_000_000.0) / 1_000_000.0
            ),
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let header = Paragraph::new(info).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_active)
            .title(" Live Hardware Performance Analysis "),
    );
    f.render_widget(header, chunks[0]);

    // Matrix demonstrating CO-RE (Compile Once - Run Everywhere) relocation outcomes
    // for various kernel structs (standard exported vs. unstable/internal).
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
            Constraint::Percentage(30), // Struct / Member
            Constraint::Percentage(25), // BTF Offset / Verification
            Constraint::Percentage(30), // Relocation Status
            Constraint::Percentage(15), // Offensive Usability Verdict
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
            .border_style(theme.border)
            .title(" CO-RE (Compile Once – Run Everywhere) Breakpoint Inspector "),
    );

    f.render_widget(core_table, chunks[1]);
}
