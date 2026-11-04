//! TCP/WebSocket match feed on port 4242.

use skyline::libc::*;
use smush_info_shared::{handshake_response, text_frame};
use std::mem::size_of_val;
use std::time::Duration;

use crate::GAME_INFO;

fn send_bytes(socket: i32, mut bytes: &[u8]) -> Result<(), i64> {
    while !bytes.is_empty() {
        unsafe {
            let ret = send(socket, bytes.as_ptr() as *const _, bytes.len(), 0);
            if ret > 0 {
                bytes = &bytes[ret as usize..];
            } else if ret == 0 {
                return Err(32);
            } else {
                return Err(*errno_loc());
            }
        }
    }
    Ok(())
}

fn close_socket_if_open(socket: &mut i32) {
    if *socket >= 0 {
        unsafe {
            close(*socket);
        }
        *socket = -1;
    }
}

// SO_SNDTIMEO / SO_RCVTIMEO (BSD-style) so send() fails after a few seconds on dead
// connections, and a quiet client can be told apart from a browser upgrade.
const SO_SNDTIMEO: i32 = 0x1005;
const SO_RCVTIMEO: i32 = 0x1006;

#[repr(C)]
struct timeval {
    tv_sec: i64,
    tv_usec: i64,
}

/// The console takes a 16-byte `timeval`. Emulators read a 4-byte millisecond
/// count and ignore the rest, which turns a 1 ms timeout into a blocking recv.
/// Send both forms; the one the host rejects leaves the other in place.
fn set_sock_timeout(socket: i32, option: i32, millis: i64) -> bool {
    unsafe {
        let tv = timeval {
            tv_sec: millis / 1000,
            tv_usec: (millis % 1000) * 1000,
        };
        let bsd = setsockopt(
            socket,
            SOL_SOCKET,
            option,
            &tv as *const _ as *const c_void,
            size_of_val(&tv) as u32,
        ) == 0;
        let ms = millis as u32;
        let emulated = setsockopt(
            socket,
            SOL_SOCKET,
            option,
            &ms as *const _ as *const c_void,
            size_of_val(&ms) as u32,
        ) == 0;
        bsd || emulated
    }
}

fn set_send_timeout(socket: i32, secs: i64) {
    if !set_sock_timeout(socket, SO_SNDTIMEO, secs * 1000) {
        let e = unsafe { *errno_loc() };
        println!("[smush_info] setsockopt SO_SNDTIMEO failed (errno {}), continuing without send timeout", e);
    }
}

fn recv_some(socket: i32, buf: &mut [u8]) -> Result<Option<usize>, i64> {
    unsafe {
        let n = recv(socket, buf.as_mut_ptr() as *mut _, buf.len(), 0);
        if n > 0 {
            Ok(Some(n as usize))
        } else if n == 0 {
            Err(54)
        } else {
            let err = *errno_loc();
            // 11 EAGAIN, 60 the console's ETIMEDOUT, 110 the emulator's.
            if err == 11 || err == 60 || err == 110 {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

struct MatchClient {
    socket: i32,
    websocket: bool,
    probing: bool,
    started: std::time::Instant,
    request: Vec<u8>,
}

/// Browser clients send an upgrade immediately. Raw TCP clients send nothing.
fn poll_probe(client: &mut MatchClient) -> Result<(), i64> {
    let mut tmp = [0u8; 512];
    match recv_some(client.socket, &mut tmp)? {
        Some(n) => {
            client.request.extend_from_slice(&tmp[..n]);
            if client.request.windows(4).any(|w| w == b"\r\n\r\n") || client.request.len() >= 2048 {
                finish_probe(client)?;
            }
            Ok(())
        }
        None => {
            if client.request.is_empty() && client.started.elapsed() >= Duration::from_millis(200) {
                client.probing = false;
                client.websocket = false;
                println!("[smush_info] tcp client connected");
            } else if !client.request.is_empty() && client.started.elapsed() >= Duration::from_millis(200) {
                return Err(60);
            }
            Ok(())
        }
    }
}

fn finish_probe(client: &mut MatchClient) -> Result<(), i64> {
    let text = String::from_utf8_lossy(&client.request);
    let Some(response) = handshake_response(&text) else {
        println!("[smush_info] closing client that did not request a websocket");
        return Err(32);
    };
    send_bytes(client.socket, response.as_bytes())?;
    client.request.clear();
    client.probing = false;
    client.websocket = true;
    println!("[smush_info] websocket client connected");
    Ok(())
}

fn drain_websocket(socket: i32) -> Result<(), i64> {
    let mut tmp = [0u8; 256];
    loop {
        if recv_some(socket, &mut tmp)?.is_none() {
            return Ok(());
        }
    }
}

fn accept_clients(listener_socket: i32, incoming: std::sync::mpsc::Sender<i32>) {
    loop {
        match accept_client_socket(listener_socket) {
            Ok(socket) => {
                if incoming.send(socket).is_err() {
                    unsafe {
                        close(socket);
                    }
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn accept_client_socket(listener_socket: i32) -> Result<i32, i64> {
    unsafe {
        let mut client_addr: sockaddr_in = std::mem::zeroed();
        let mut addr_len: u32 = size_of_val(&client_addr) as u32;
        let client_socket = accept(
            listener_socket,
            &mut client_addr as *mut sockaddr_in as *mut sockaddr,
            &mut addr_len,
        );
        if client_socket < 0 {
            Err(*errno_loc())
        } else {
            Ok(client_socket)
        }
    }
}

fn start_server() -> Result<(), i64> {
    unsafe {
        let server_addr: sockaddr_in = sockaddr_in {
            sin_family: AF_INET as _,
            sin_port: 4242u16.to_be(),
            sin_len: 4,
            sin_addr: in_addr {
                s_addr: INADDR_ANY as _,
            },
            sin_zero: [0; 8],
        };

        let mut listener_socket = socket(AF_INET, SOCK_STREAM, 0);
        let mut client_socket: i32 = -1;

        macro_rules! dbg_err {
            ($expr:expr) => {
                let rval = $expr;
                if rval < 0 {
                    let errno = *errno_loc();
                    dbg!(errno);
                    close_socket_if_open(&mut client_socket);
                    close_socket_if_open(&mut listener_socket);
                    return Err(errno);
                }
            };
        }

        if listener_socket < 0 {
            let errno = *errno_loc();
            dbg!(errno);
            return Err(errno);
        }

        let flags: u32 = 1;

        dbg_err!(setsockopt(
            listener_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            &flags as *const _ as *const c_void,
            size_of_val(&flags) as u32,
        ));

        dbg_err!(setsockopt(
            listener_socket,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &flags as *const _ as *const c_void,
            size_of_val(&flags) as u32,
        ));

        dbg_err!(bind(
            listener_socket,
            &server_addr as *const sockaddr_in as *const sockaddr,
            size_of_val(&server_addr) as u32,
        ));

        dbg_err!(listen(listener_socket, 8));
        println!("[smush_info] match socket listening on 4242");
        let (incoming_tx, incoming_rx) = std::sync::mpsc::channel();
        let accept_listener = listener_socket;
        std::thread::spawn(move || accept_clients(accept_listener, incoming_tx));

        let mut clients: Vec<MatchClient> = Vec::new();
        loop {
            loop {
                match incoming_rx.try_recv() {
                    Ok(socket) => {
                        set_send_timeout(socket, 3);
                        if !set_sock_timeout(socket, SO_RCVTIMEO, 1) {
                            println!("[smush_info] no receive timeout, handshake may block");
                        }
                        println!("[smush_info] match client accepted");
                        let keepalive: u32 = 1;
                        setsockopt(
                            socket,
                            SOL_SOCKET,
                            SO_KEEPALIVE,
                            &keepalive as *const _ as *const c_void,
                            size_of_val(&keepalive) as u32,
                        );
                        clients.push(MatchClient {
                            socket,
                            websocket: false,
                            probing: true,
                            started: std::time::Instant::now(),
                            request: Vec::new(),
                        });
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        for client in &mut clients {
                            close_socket_if_open(&mut client.socket);
                        }
                        close_socket_if_open(&mut listener_socket);
                        return Err(54);
                    }
                }
            }

            let mut index = 0;
            while index < clients.len() {
                if !clients[index].probing {
                    index += 1;
                    continue;
                }
                if let Err(errno) = poll_probe(&mut clients[index]) {
                    println!("[smush_info] client dropped during handshake (errno {})", errno);
                    close_socket_if_open(&mut clients[index].socket);
                    clients.swap_remove(index);
                } else {
                    index += 1;
                }
            }

            if clients.iter().any(|client| !client.probing) {
                crate::tick_match_state(false);
                let payload = match serde_json::to_vec(&GAME_INFO) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("[smush_info] match snapshot serialize failed: {}", e);
                        std::thread::sleep(Duration::from_millis(16));
                        continue;
                    }
                };
                let websocket_frame = text_frame(&payload);
                let mut tcp_frame = payload;
                tcp_frame.push(b'\n');
                index = 0;
                while index < clients.len() {
                    if clients[index].probing {
                        index += 1;
                        continue;
                    }
                    let sent = if clients[index].websocket {
                        drain_websocket(clients[index].socket)
                            .and_then(|_| send_bytes(clients[index].socket, &websocket_frame))
                    } else {
                        send_bytes(clients[index].socket, &tcp_frame)
                    };
                    match sent {
                        Ok(()) => index += 1,
                        Err(errno) => {
                            println!("[smush_info] client dropped (errno {})", errno);
                            close_socket_if_open(&mut clients[index].socket);
                            clients.swap_remove(index);
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(16));
        }
    }
}

pub fn server_supervisor() {
    // Give network stack time to come up (UDP thread uses 5s delay for the same reason).
    std::thread::sleep(Duration::from_secs(2));
    let backoff_steps = [1u64, 2, 5];
    let mut restart_count: usize = 0;
    loop {
        println!("[smush_info] starting tcp server");
        match start_server() {
            Ok(_) => {
                restart_count = 0;
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(errno) => {
                restart_count = restart_count.saturating_add(1);
                let backoff = backoff_steps
                    .get(restart_count.saturating_sub(1))
                    .copied()
                    .unwrap_or(5);
                println!(
                    "[smush_info] tcp server exited (errno {}), restarting in {}s",
                    errno, backoff
                );
                std::thread::sleep(Duration::from_secs(backoff));
            }
        }
    }
}
