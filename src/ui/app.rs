use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Tabs},
};

use crate::engine::stats::GuardMetrics;
use crate::research::syscall_bench::{BenchResult, run_benchmark};
use crate::research::verifier::{TEST_CASES, VerifierReport, run_verifier_audit};
use crate::ui::theme::Theme;
use crate::ui::views::{bench_view, guard_view, verifier_view};

/// Available primary dashboard views in the TUI.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Tab {
    /// Live XDP packet inspection, pass/drop rates, and sparkline history.
    Guard,
    /// Interactive BPF verifier security audit and pushback trace inspection.
    VerifierResearch,
    /// Live syscall latency benchmarking and CO-RE relocation matrix.
    SyscallBenchmark,
}

/// Central state manager holding telemetry, research metrics, and UI selection states.
pub struct App {
    /// Currently active tab view rendered on screen.
    pub current_tab: Tab,
    /// Global UI color scheme and styling rules.
    pub theme: Theme,
    /// Target network interface name (e.g., "eth0", "lo").
    pub iface: String,
    /// Real-time packet telemetry and historical rate-limit buffers.
    pub metrics: GuardMetrics,
    /// Selected test case index in the Verifier Lab catalog.
    pub selected_verifier_test: usize,
    /// Active kernel verifier audit report (if a test has been executed).
    pub active_report: Option<VerifierReport>,
    /// Latest syscall latency and CO-RE benchmark result.
    pub bench_result: BenchResult,
}

impl App {
    /// Initializes application state, setting up metrics ring buffers and running an initial benchmark warmup.
    pub fn new(iface: String) -> Self {
        // Run an initial baseline measurement on startup
        let initial_bench = run_benchmark::<fn() -> Box<dyn std::any::Any>>(50_000, None);

        Self {
            current_tab: Tab::Guard,
            theme: Theme::default(),
            iface,
            // 50-sample history window for live sparklines
            metrics: GuardMetrics::new(50),
            selected_verifier_test: 0,
            active_report: None,
            bench_result: initial_bench,
        }
    }

    /// Cycles forward to the next dashboard tab.
    pub fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Guard => Tab::VerifierResearch,
            Tab::VerifierResearch => Tab::SyscallBenchmark,
            Tab::SyscallBenchmark => Tab::Guard,
        };
    }

    /// Cycles backward to the previous dashboard tab.
    pub fn prev_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Guard => Tab::SyscallBenchmark,
            Tab::VerifierResearch => Tab::Guard,
            Tab::SyscallBenchmark => Tab::VerifierResearch,
        };
    }

    /// Advances selection to the next verifier test case with bounds checking.
    pub fn next_verifier_test(&mut self) {
        if self.selected_verifier_test + 1 < TEST_CASES.len() {
            self.selected_verifier_test += 1;
        }
    }

    /// Moves selection to the previous verifier test case with lower-bound checking.
    pub fn prev_verifier_test(&mut self) {
        if self.selected_verifier_test > 0 {
            self.selected_verifier_test -= 1;
        }
    }

    /// Executes the currently highlighted verifier test and records the resulting audit report.
    pub fn execute_selected_audit(&mut self) {
        self.active_report = Some(run_verifier_audit(self.selected_verifier_test));
    }

    /// Re-runs the hardware syscall benchmark and updates stored latency results.
    pub fn run_hardware_benchmark(&mut self) {
        self.bench_result = run_benchmark::<fn() -> Box<dyn std::any::Any>>(50_000, None);
    }

    /// Orchestrates frame rendering across the 3-tier layout: Navigation Tabs, Active View, and Keybinding Footer.
    pub fn render(&self, f: &mut Frame) {
        let area = f.area();
        // 3-tier vertical layout: Header Tabs (3 lines), Main View (flexible), Footer (1 line)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Top Navigation Bar
                Constraint::Min(10),   // Active Tab Body
                Constraint::Length(1), // Footer Keybindings
            ])
            .split(area);

        // Header Navigation Tabs
        let titles = vec![
            Line::from("[1] Live Guard Dashboard"),
            Line::from("[2] Verifier Pushback Lab"),
            Line::from("[3] Syscall & CO-RE Benchmark"),
        ];

        let selected_index = match self.current_tab {
            Tab::Guard => 0,
            Tab::VerifierResearch => 1,
            Tab::SyscallBenchmark => 2,
        };

        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(self.theme.border)
                    .title(" xdp-ai-guard :: Research & Protection Engine "),
            )
            .select(selected_index)
            .style(Style::default().fg(Color::DarkGray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );

        f.render_widget(tabs, chunks[0]);

        // Active View Dispatch: Render only the active tab into the middle chunk
        match self.current_tab {
            Tab::Guard => {
                guard_view::render(f, chunks[1], &self.metrics, &self.iface, &self.theme);
            }
            Tab::VerifierResearch => {
                verifier_view::render(
                    f,
                    chunks[1],
                    self.selected_verifier_test,
                    &self.active_report,
                    &self.theme,
                );
            }
            Tab::SyscallBenchmark => {
                bench_view::render(f, chunks[1], &self.bench_result, &self.theme);
            }
        }

        // Footer Keybindings Bar
        let footer = Line::from(vec![
            Span::styled(" [Tab/1-3] ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch Views | "),
            Span::styled(" [↑/↓] ", Style::default().fg(Color::Yellow)),
            Span::raw("Select Test | "),
            Span::styled(" [R] ", Style::default().fg(Color::Yellow)),
            Span::raw("Run Verifier Audit | "),
            Span::styled(" [B] ", Style::default().fg(Color::Yellow)),
            Span::raw("Re-run Benchmark | "),
            Span::styled(" [Q] ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit"),
        ]);
        f.render_widget(footer, chunks[2]);
    }
}
