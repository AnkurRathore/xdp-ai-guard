use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::maps::HashMap;
use aya::maps::PerCpuArray;
use aya::util::nr_cpus;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s3")]
    iface: String,

    /// IP address to block immediately at startup (Optional)
    #[clap(long)]
    block: Option<Ipv4Addr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include the eBPF object file as raw bytes at compile-time and load it at
    // runtime.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-api-guard"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    {
        // 1. Get reference to the map
        let mut blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;

        // 2. Add IP from CLI args (if provided)
        if let Some(ip) = opt.block {
            let ip_u32: u32 = u32::from(ip); // Converts 1.2.3.4 -> u32

            println!("Adding {} to Blocklist...", ip);
            blocklist.insert(ip_u32, 1, 0)?;
        }
        // 3. Adding a hardcoded test IP (Google DNS) just to be sure
        // 8.8.8.8 is 0x08080808 (Palindrome, so endianness doesn't matter)
        blocklist.insert(0x08080808, 1, 0)?;
    }

    let program: &mut Xdp = ebpf.program_mut("xdp_api_guard").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    //Get the stats map reference
    let stats_map: PerCpuArray<_,u64> = PerCpuArray::try_from(ebpf.map("STATS").unwrap())?;
        
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    // 2. Run the loop AND the Ctrl-C listener together
    // Whichever finishes first will stop the other.
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("Exiting...");
        }
        _ = async {
            let num_cpus = nr_cpus().unwrap();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                
                // Read Index 0 (DROPPED)
                // We use 0 as the index into the map (Key 0)
                // We use 0 as the flags
                match stats_map.get(&0, 0) {
                    Ok(drops) => {
                        let total_drops: u64 = drops.iter().sum();
                        
                        // Read Index 1 (PASSED)
                        let passes = stats_map.get(&1, 0).unwrap();
                        let total_passes: u64 = passes.iter().sum();

                        // --- THE UI RENDERING ---
                
                // \x1B[2J = Clear Screen
                // \x1B[1;1H = Move Cursor to Top-Left
                print!("\x1B[2J\x1B[1;1H");

                println!("╔═══════════════════════════════════════════╗");
                println!("║             XDP AI GUARD DASHBOARD        ║");
                println!("╠══════════════════════════╤════════════════╣");
                println!("║  METRIC                  │  COUNT         ║");
                println!("╟──────────────────────────┼────────────────╢");
                println!("║     Dropped Packets      │  {:<13} ║", total_drops);
                println!("║     Passed Packets       │  {:<13} ║", total_passes);
                println!("╚══════════════════════════╧════════════════╝");
                println!("\n (Press Ctrl+C to exit firewall)");
                        use std::io::Write;
                        std::io::stdout().flush().unwrap();
                    }
                    Err(_) => {
                        // Map might not be ready yet
                    }
                }
            }
        } => {}
    }

    Ok(())
}
