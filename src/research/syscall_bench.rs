use std::hint::black_box;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct BenchResult {
    pub iterations: u32,
    pub baseline_ns: f64,
    pub monitored_ns: f64,
    pub tax_ns: f64,
    pub overhead_percent: f64,
    pub is_live_ebpf: bool,
    pub measured_at: String,
}

impl Default for BenchResult {
    fn default() -> Self {
        Self {
            iterations: 50_000,
            baseline_ns: 0.0,
            monitored_ns: 0.0,
            tax_ns: 0.0,
            overhead_percent: 0.0,
            is_live_ebpf: false,
            measured_at: pub_date(),
        }
    }
}

fn pub_date() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    format!("{}s after boot", now % 86400)
}

/// Run raw getpid() syscalls in a tight loop and calculate average nanoseconds per call
fn measure_syscall_batch(iterations: u32) -> f64 {
    // 1. Cache Warmup
    for _ in 0..5_000 {
        unsafe {
            black_box(libc::syscall(libc::SYS_getpgid));
        }
    }
    //2. Timed measurment
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            black_box(libc::syscall(libc::SYS_getpid));
        }
    }
    let elapsed = start.elapsed();

    elapsed.as_nanos() as f64 / iterations as f64
}

/// Runs the benchmark. If `probe_attacher` is provided, runs a true kernel A/B test.
pub fn run_benchmark<F>(iterations: u32, mut probe_attacher: Option<F>) -> BenchResult
where
    F: FnMut() -> Box<dyn std::any::Any>, // returns guard/link to hold attachment
{
    // Step 1: Measure baseline (no probe attached)
    let baseline_ns = measure_syscall_batch(iterations);

    // Step 2: Measure monitored
    let (monitored_ns, is_live) = if let Some(ref mut attach) = probe_attacher {
        let _link = attach(); // Probe is attached to the kernel here
        let monitored = measure_syscall_batch(iterations);
        (monitored, true) // Link is dropped upon leaving scope
    } else {
        // Mock fallback: Real CPU baseline + synthetic 2.8x probe multiplier
        (baseline_ns * 2.78, false)
    };
    let tax_ns = (monitored_ns - baseline_ns).max(0.0);
    let overhead_percent = if baseline_ns > 0.0 {
        (tax_ns / baseline_ns) * 100.0
    } else {
        0.0
    };

    BenchResult {
        iterations,
        baseline_ns,
        monitored_ns,
        tax_ns,
        overhead_percent,
        is_live_ebpf: is_live,
        measured_at: pub_date(),
    }
}
