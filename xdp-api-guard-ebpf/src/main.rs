#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map,xdp},
    maps::HashMap, 
    programs::XdpContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use core::mem;
use network_types::{
    eth::{EthHdr,EtherType},
    ip::Ipv4Hdr,
};

#[map]
static RATE_LIMIT_MAP: HashMap::<u32, PacketLog> = HashMap::<u32, PacketLog>::with_max_entries(1024,0);
// Threshold:10 packets per sconds
const LIMIT: u64 = 10;
const WINDOW_NS: u64 = 1_000_000_000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct  PacketLog
{
    pub count: u64,
    pub last_seen: u64,//Nanoseconds since boot
}


#[xdp]
pub fn xdp_api_guard(ctx: XdpContext) -> u32 {
    match try_xdp_api_guard(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// Helper function to check bounds
#[inline(always)] //Force inline
fn ptr_at<T>(ctx: &XdpContext, offset:usize) -> Result<*const T, ()>{
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    //Check: Does the packet have enough bytes
    if start + offset + len > end {
        return Err(());
    }
    // return the Raw pointer
    Ok((start + offset) as *const T)

}
fn try_xdp_api_guard(ctx: XdpContext) -> Result<u32, ()> {
    
    //Parse the ehternet header
    let eth_proto = unsafe {
        let ptr = ptr_at::<EthHdr>(&ctx, 0)?;
        //Read the protocol id
        (*ptr).ether_type
     };

     //Filter IPV4 packets only
     if eth_proto != EtherType::Ipv4{
        return Ok(xdp_action::XDP_PASS);
     }

     // Parse IPV4 header
     let ipv4_src = unsafe{
        let ptr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
        u32::from_be((*ptr).src_addr)
     };

     // Blocking Logic
     // Check if source ip exists in the BLOCKING MAP
    //  if unsafe { BLOCKLIST.get(&ipv4_src)}.is_some(){
    //     info!(&ctx, "BLOCKED packet from:{:x}", ipv4_src);
    //     return Ok(xdp_action::XDP_DROP)
    //  }

    // Get the current time
    let now = unsafe {(bpf_ktime_get_ns()) };
    // check the map
    match unsafe {RATE_LIMIT_MAP.get_ptr_mut(&ipv4_src)}{
        Some(entry) => {
            let log = unsafe { &mut *entry};

            // check if the 1 second window has passed
            if now - log.last_seen > WINDOW_NS{
                // RESET the Window
                log.count = 1;
                log.last_seen = now;
            }else {
                // Same Window
                log.count +=1;
            }

            // Apply the limit
            if log.count > LIMIT {
                info!(&ctx, "LIMIT_EXCEEDED: {:x} (Count: {})", ipv4_src, log.count);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        None => {
            // First time seeing this IP: Add to MAP
            let new_entry = PacketLog{
                count :1,
                last_seen: now,

            };
            unsafe {RATE_LIMIT_MAP.insert(&ipv4_src, &new_entry, 0) }.map_err(|_| ())?;
        }
    }
     
     Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
