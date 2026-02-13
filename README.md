# 🛡️ xdp-ai-guard

**A high-performance Denial-of-Service (DoS) filter for AI Inference servers, written in Rust using eBPF/XDP.**

![Status](https://img.shields.io/badge/status-active_development-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-nightly-red)

## ⚡ The Problem: GPU Cycles are Expensive
Running Large Language Models (like Llama-3-70B) is computationally expensive.
Standard firewalls (Nginx, Iptables) drop malicious packets **after** the OS has already allocated memory (`sk_buff`) and performed context switches.

If an inference server receives a flood of spam/DDoS traffic, the CPU wastes cycles processing network interrupts instead of feeding data to the GPU.

## 🚀 The Solution: XDP (eXpress Data Path)
**xdp-ai-guard** runs an eBPF program directly in the Network Interface Card (NIC) driver. It inspects and drops malicious packets **before** the Linux Kernel even sees them.

*   **Zero Allocation:** Drops packets without allocating an `sk_buff`.
*   **Line Rate:** capable of filtering millions of packets per second.
*   **Dynamic Blocking:** Updates the blocklist via eBPF Maps from userspace without reloading the program.

## 🏗️ Architecture

This project uses the **Aya** framework to write eBPF logic in safe Rust.

1.  **Kernel Space (`xdp-api-guard-ebpf`):**
    *   Runs inside the kernel VM.
    *   Parses Ethernet and IPv4 headers.
    *   Checks Source IP against a `HashMap` (Blocklist).
    *   Returns `XDP_DROP` or `XDP_PASS`.

2.  **User Space (`xdp-api-guard`):**
    *   Loads the BPF program into the kernel.
    *   Populates the Blocklist Map.
    *   Reads logs from the kernel via the `aya_log` ring buffer.

## 🛠️ Prerequisites

You need a Linux environment with a modern kernel (5.10+ recommended).

1.  **Rust Nightly:** Required for compiling BPF bytecode.
    ```bash
    rustup toolchain install nightly --component rust-src
    ```
2.  **BPF Linker:**
    ```bash
    cargo install bpf-linker
    ```
3.  **Dependencies:** `llvm`, `clang`, `libssl-dev`.

## 🏃 Usage

### 1. Build
```bash
cargo build
```

### 2. Run (Requires Root)
You must specify the network interface to attach to (e.g., `eth0`, `enp0s3`).

```bash
RUST_LOG=info sudo -E cargo run --bin xdp-api-guard -- --iface enp0s3
```

### 3. Verify
In another terminal, try to ping the machine. You should see logs indicating packet inspection.

## 🚧 Roadmap

*   [x] Basic XDP Pass/Drop scaffolding
*   [ ] Packet Header Parsing (Eth/IPv4)
*   [ ] eBPF Map integration for dynamic IP blocking
*   [ ] Rate Limiting logic (Token Bucket)

## 📚 References
*   [Aya Book](https://aya-rs.dev/book/)
*   [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
*   [Cloudflare L4Drop](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)

## 📄 License
MIT / Apache 2.0