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
    initialized: bool,
    max_capacity: usize,
}

impl GuardMetrics {
    pub fn new(capacity: usize) -> Self {
        Self {
            total_pass: 0,
            total_drop: 0,
            pass_pps: 0,
            drop_pps: 0,
            // Pre-fill only if capacity > 0; otherwise start truly empty
            pps_history: if capacity > 0 {
                VecDeque::from(vec![0; capacity])
            } else {
                VecDeque::new()
            },
            drop_pps_history: if capacity > 0 {
                VecDeque::from(vec![0; capacity])
            } else {
                VecDeque::new()
            },
            last_sample: Instant::now(),
            last_pass: 0,
            last_drop: 0,
            initialized: false,
            max_capacity: capacity,
        }
    }

    pub fn update(&mut self, total_pass: u64, total_drop: u64) {
        let now = Instant::now();

        //Establish baseline on first poll without calculating any fake delta
        if !self.initialized {
            self.total_pass = total_pass;
            self.total_drop = total_drop;
            self.last_pass = total_pass;
            self.last_drop = total_drop;
            self.last_sample = now;
            self.initialized = true;

            return;
        }

        // unconditionally update live totals on every tick
        self.total_pass = total_pass;
        self.total_drop = total_drop;

        let elapsed = now.duration_since(self.last_sample).as_secs_f64();
        // Minimum interval between updates is 0.25 seconds
        if elapsed >= 0.25 {
            let pass_delta = total_pass.saturating_sub(self.last_pass);
            let drop_delta = total_drop.saturating_sub(self.last_drop);

            self.pass_pps = (pass_delta as f64 / elapsed) as u64;
            self.drop_pps = (drop_delta as f64 / elapsed) as u64;

            // Push and evict safely respecting max_capacity
            if self.max_capacity > 0 {
                self.pps_history.push_back(self.pass_pps);
                if self.pps_history.len() > self.max_capacity {
                    self.pps_history.pop_front();
                }

                self.drop_pps_history.push_back(self.drop_pps);
                if self.drop_pps_history.len() > self.max_capacity {
                    self.drop_pps_history.pop_front();
                }
            }

            // update last sample state after calculating deltas
            self.last_pass = total_pass;
            self.last_drop = total_drop;
            self.last_sample = now;
        }
    }
}
