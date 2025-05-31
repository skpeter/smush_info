use skyline::libc::{socket, sendto, sockaddr_in, in_addr, AF_INET, SOCK_DGRAM, IPPROTO_UDP};
use skyline::libc::bind;
use skyline::libc::{errno_loc, strerror};
use skyline::nn::nifm;
use std::net::UdpSocket;
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::CStr;

use crate::IPPROTO_IP;

static MDNS_SOCKET: AtomicI32 = AtomicI32::new(-1);
const MDNS_MULTICAST_ADDR: [u8; 4] = [224, 0, 0, 251];
const MDNS_PORT: u16 = 5353;


fn get_mdns_socket() -> Option<i32> {
    let sock_fd = MDNS_SOCKET.load(Ordering::Relaxed);
    if sock_fd >= 0 {
        return Some(sock_fd);
    }

    unsafe {
        let sock = socket(AF_INET as i32, SOCK_DGRAM as i32, IPPROTO_UDP as i32);
        if sock < 0 {
            println!("[mDNS] Failed to create socket");
            return None;
        }

        MDNS_SOCKET.store(sock, Ordering::Relaxed);
        Some(sock)
    }
}


/// Creates a basic mDNS response packet for `_smash._tcp.local`
fn create_mdns_response(service_port: u16) -> Vec<u8> {
    let hostname = b"switch.local.";
    let service_type = b"_smartcv._tcp.local.";
    let service_instance = b"switch._smartcv._tcp.local.";

    // let ip_bytes: [u8; 4] = get_nifm_ip().unwrap_or([192, 168, 1, 123]);
    let ip_bytes: [u8; 4] = [192, 168, 1, 123];

    let mut response = Vec::new();

    // Header
    response.extend_from_slice(&[
        0x00, 0x00, // Transaction ID
        0x84, 0x00, // Flags: response, authoritative
        0x00, 0x00, // Questions
        0x00, 0x04, // Answer RRs
        0x00, 0x00, // Authority
        0x00, 0x00, // Additional
    ]);

    // ---- PTR ----
    response.extend_from_slice(&service_name_to_dns_format(service_type));
    response.extend_from_slice(&[
        0x00, 0x0c, // Type: PTR
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 120, // TTL
    ]);
    let ptr_data = service_name_to_dns_format(service_instance);
    response.extend_from_slice(&(ptr_data.len() as u16).to_be_bytes());
    response.extend_from_slice(&ptr_data);

    // ---- SRV ----
    response.extend_from_slice(&service_name_to_dns_format(service_instance));
    response.extend_from_slice(&[
        0x00, 0x21, // Type: SRV
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 120, // TTL
    ]);
    let target = service_name_to_dns_format(hostname);
    let srv_data_len = 6 + target.len(); // priority(2) + weight(2) + port(2) + target
    response.extend_from_slice(&(srv_data_len as u16).to_be_bytes());
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // priority + weight
    response.extend_from_slice(&service_port.to_be_bytes());
    response.extend_from_slice(&target);

    // ---- TXT ----
    response.extend_from_slice(&service_name_to_dns_format(service_instance));
    response.extend_from_slice(&[
        0x00, 0x10, // Type: TXT
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 120, // TTL
    ]);
    let txt_str = b"device=switch";
    response.extend_from_slice(&((txt_str.len() + 1) as u16).to_be_bytes()); // Length
    response.push(txt_str.len() as u8); // TXT length prefix
    response.extend_from_slice(txt_str);

    // ---- A ----
    response.extend_from_slice(&service_name_to_dns_format(hostname));
    response.extend_from_slice(&[
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 120, // TTL
        0x00, 0x04, // Data length
    ]);
    response.extend_from_slice(&ip_bytes);

    response
}

/// Converts a service name like "_smash._tcp.local" into DNS label format
fn service_name_to_dns_format(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let parts = name.split(|&c| c == b'.');
    for part in parts {
        out.push(part.len() as u8);
        out.extend_from_slice(part);
    }
    out.push(0); // Null terminator
    out
}

/// Broadcasts the mDNS response to the local network
pub fn broadcast_mdns_response(port: u16) {
    unsafe {
        let sock = match get_mdns_socket() {
            Some(s) => s,
            None => return,
        };

        // Optional: Set multicast TTL to 255 (max scope)
        let ttl: u32 = 255;
        let ttl_result = skyline::libc::setsockopt(
            sock,
            IPPROTO_IP,
            skyline::libc::IP_MULTICAST_TTL,
            &ttl as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );
        if ttl_result < 0 {
            println!("[mDNS] setsockopt TTL failed");
        }

        // Construct destination: mDNS multicast
        let addr = sockaddr_in {
            sin_len: std::mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as u8,
            sin_port: MDNS_PORT.to_be(), // mDNS port 5353
            sin_addr: in_addr {
                // Use native byte order (not network!) for Horizon
                s_addr: u32::from_ne_bytes(MDNS_MULTICAST_ADDR),
            },
            sin_zero: [0; 8],
        };

        // Build packet
        let packet = create_mdns_response(port);

        // Send to multicast
        println!("[mDNS] About to send mDNS response...");
        let sent = sendto(
            sock,
            packet.as_ptr() as *const _,
            packet.len(),
            0,
            &addr as *const _ as *const _,
            std::mem::size_of::<sockaddr_in>() as u32,
        );
        println!("[mDNS] sendto result: {}", sent);

        if sent < 0 {
            let errno_ptr = skyline::libc::errno_loc();
            let errno_val = *(errno_ptr as *const i32);
            let err_str_ptr = skyline::libc::strerror(errno_val);
            let err_msg = std::ffi::CStr::from_ptr(err_str_ptr as *const i8)
                .to_str()
                .unwrap_or("unknown");

            println!(
                "[mDNS] Failed to send mDNS packet: sendto returned {}, errno = {}, {}",
                sent, errno_val, err_msg
            );
        } else {
            println!("[mDNS] Sent mDNS announcement for _smash._tcp.local");
        }
    }
}