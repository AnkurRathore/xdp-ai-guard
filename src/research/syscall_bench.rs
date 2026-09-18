use std::hint::black_box;
use std::time::Instant;

/// Benchmark metrics detailing syscall execution times before and after eBPF instrumentation.
#[derive(Clone, Debug)]
pub struct BenchResult {
    /// Number of syscall invocations performed per batch measurement.
    pub iterations: u32,
    /// Unmonitored baseline cost per syscall in nanoseconds.
    pub baseline_ns: f64,
    /// Monitored cost per syscall with eBPF probe attached in nanoseconds.
    pub monitored_ns: f64,
    /// Net overhead (monitored - baseline) introduced solely by the eBPF hook.
    pub tax_ns: f64,
    /// Percentage increase in execution time over baseline.
    pub overhead_percent: f64,
    /// True if measured against an active kernel eBPF probe, false if simulated.
    pub is_live_ebpf: bool,
    /// Human-readable timestamp of when the benchmark was executed.
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

/// Generates a lightweight relative timestamp string for report tracking.
fn pub_date() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    format!("{}s after boot", now % 86400)
}

/// Runs raw `getpid()` syscalls in a tight loop and calculates the average nanoseconds per call.
///
/// Uses `black_box` to prevent LLVM dead-code elimination and includes a 5,000-iteration
/// warmup loop to prime CPU instruction caches and branch predictors.
fn measure_syscall_batch(iterations: u32) -> f64 {
    // 1. Cache Warmup: Prime CPU L1 instruction cache and branch predictors
    for _ in 0..5_000 {
        unsafe {
            black_box(libc::syscall(libc::SYS_getpgid));
        }
    }

    // 2. Timed Measurement: Execute raw system calls in a tight loop
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            black_box(libc::syscall(libc::SYS_getpid));
        }
    }
    let elapsed = start.elapsed();

    elapsed.as_nanos() as f64 / iterations as f64
}

/// Executes an A/B performance isolation benchmark.
///
/// - **Baseline**: Measures raw syscall latency with no probe attached.
/// - **Monitored**: Invokes `probe_attacher` (if provided) to attach a live eBPF kprobe/tracepoint,
///   measures syscall latency, and relies on RAII to automatically detach the probe when `_link` drops.
/// - **Fallback**: If `probe_attacher` is `None`, applies a synthetic 2.78x multiplier for non-root/mock testing.
pub fn run_benchmark<F>(iterations: u32, mut probe_attacher: Option<F>) -> BenchResult
where
    // F is a closure that attaches the eBPF hook and returns a boxed RAII link/guard
    F: FnMut() -> Box<dyn std::any::Any>,
{
    // Step 1: Measure baseline (no probe attached)
    let baseline_ns = measure_syscall_batch(iterations);

    // Step 2: Measure monitored state (with eBPF hook active)
    let (monitored_ns, is_live) = if let Some(ref mut attach) = probe_attacher {
        // Probe is attached to the kernel; _link holds the active attachment
        let _link = attach();
        let monitored = measure_syscall_batch(iterations);
        // _link drops here at the end of the block, automatically detaching the probe via RAII
        (monitored, true)
    } else {
        // Mock fallback: Real CPU baseline + synthetic 2.78x probe multiplier
        (baseline_ns * 2.78, false)
    };

    // Step 3: Compute instrumentation tax and relative percentage overhead
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
