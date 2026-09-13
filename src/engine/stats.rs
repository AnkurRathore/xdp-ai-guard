use std::collections::VecDeque;
use std::time::Instant;

/// A struct that holds the metrics for the guard.
pub struct GuardMetrics {
    pub total_pass: u64,
    pub total_drop: u64,
    pub pass_pps: u64,
    pub drop_pps: u64,
    pub pps_history: VecDeque<u64>,
    pub drop_pps_history: VecDeque<u64>,
    pub last_sample: Instant,
    last_pass: u64,
    last_drop: u64,
}

impl GuardMetrics {
    pub fn new(capacity: usize) -> Self {
        Self {
            total_pass: 0,
            total_drop: 0,
            pass_pps: 0,
            drop_pps: 0,
            pps_history: VecDeque::from(vec![0; capacity]),
            drop_pps_history: VecDeque::from(vec![0; capacity]),
            last_sample: Instant::now(),
            last_pass: 0,
            last_drop: 0,
        }
    }

    pub fn update(&mut self, total_pass: u64, total_drop: u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample).as_secs_f64();

        if elapsed >= 0.25 {
            let pass_delta = total_pass.saturating_sub(self.last_pass);
            let drop_delta = total_drop.saturating_sub(self.last_drop);

            self.pass_pps = (pass_delta as f64 / elapsed) as u64;
            self.drop_pps = (drop_delta as f64 / elapsed) as u64;

            self.pps_history.pop_front();
            self.pps_history.push_back(self.pass_pps);
            self.drop_pps_history.pop_front();
            self.drop_pps_history.push_back(self.drop_pps);

            self.total_pass = total_pass;
            self.total_drop = total_drop;
            self.last_pass = total_pass;
            self.last_drop = total_drop;
            self.last_sample = now;
        }
    }
}
