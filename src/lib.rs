#![feature(proc_macro_hygiene)]
#![feature(simd_ffi)]

use skyline::hooks::{getRegionAddress, Region, InlineCtx};
use skyline::from_c_str;
use skyline::libc::*;
use std::time::Duration;
use std::mem::size_of_val;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use smash::app;
use smash::app::lua_bind::*;
use smash::lib::lua_const::*;
use smash::lib::L2CValue;
use smash::Vector2f;
use smash::Vector3f;

use smush_info_shared::{
    clear_results_session, handshake_response, menu_is_gameplay, menu_is_vault,
    new_match_resets_save, should_arm_clock_zero, should_submit, should_write_stats_snapshot,
    text_frame, Character, Info,
};
use lazy_static::lazy_static;


use smashline::{
    original_status, Agent, L2CFighterCommon as SmashlineFighterCommon, Main, Pre,
};

mod conversions;
use conversions::{kind_to_char, stage_id_to_stage};
mod match_feed;
mod overrides;
mod results_log;
mod replay_dump;
mod udp;

static mut OFFSET1 : usize = 0x1b52a0;
static mut OFFSET2 : usize = 0x22de458;
static mut OFFSET3 : usize = 0xd7140;

// 13.0.5. The hook is the BL 0x10 bytes after this pattern, where X0 is the
// fighter pointer. The BL immediate itself is not part of the pattern.
static mut FIGHTER_SELECTED_OFFSET: usize = 0x66e140;

static FIGHTER_SELECTED_SEARCH_CODE: &[u8] = &[
    0xa8, 0x66, 0x40, 0xb9, // ldr w8, [x21, #0x64]
    0x08, 0x01, 0x00, 0x32, // orr w8, w8, #1
    0xe0, 0x03, 0x17, 0xaa, // mov x0, x23
    0xa8, 0x66, 0x00, 0xb9, // str w8, [x21, #0x64]
];

extern "C" {
    #[link_name = "\u{1}_ZN3app7utility8get_kindEPKNS_26BattleObjectModuleAccessorE"]
    pub fn get_kind(module_accessor: &mut app::BattleObjectModuleAccessor) -> i32;

    #[link_name = "\u{1}_ZN3app14sv_information8stage_idEv"]
    pub fn stage_id() -> i32;

    #[link_name = "\u{1}_ZN3app14sv_information27get_remaining_time_as_frameEv"]
    pub fn get_remaining_time_as_frame() -> u32;

    #[link_name = "\u{1}_ZN3app17sv_camera_manager15world_to_screenERKN3phx8Vector3fEb"]
    pub fn world_to_screen(vec: *const Vector3f, unk: bool) -> Float32x2;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Float32x2 {
    pub x: f32,
    pub y: f32,
}

fn as_pixels(vec: Vector3f) -> Vector2f {
    unsafe {
        let screen = world_to_screen(&vec, true);
        Vector2f { x: screen.x, y: screen.y }
    }
}

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

fn drop_client(client: &mut MatchClient) {
    close_socket_if_open(&mut client.socket);
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

// Smashline status scripts — skyline `replace = L2CFighterCommon_*` on common NRO
// crashes on 13.0.5 when Smashline is loaded.
/// 0 = not waiting. `u64::MAX` = a results poll is in progress.
static RESULT_POLL_NOT_BEFORE: AtomicU64 = AtomicU64::new(0);
const RESULT_POLL_DELAY_MS: u64 = 3_000;
const RESULT_POLL_RETRY_MS: u64 = 500;

fn mono_ms() -> u64 {
    lazy_static! {
        static ref MONO_START: std::time::Instant = std::time::Instant::now();
    }
    MONO_START.elapsed().as_millis() as u64
}

fn schedule_result_poll() {
    if RESULT_POLL_NOT_BEFORE.load(Ordering::SeqCst) == u64::MAX {
        return;
    }
    RESULT_POLL_NOT_BEFORE.store(mono_ms().saturating_add(RESULT_POLL_DELAY_MS), Ordering::SeqCst);
}

fn cancel_result_poll() {
    if RESULT_POLL_NOT_BEFORE.load(Ordering::SeqCst) == u64::MAX {
        return;
    }
    RESULT_POLL_NOT_BEFORE.store(0, Ordering::SeqCst);
}

/// Vault playback on Eden. Consoles resolve `emulator_mode` off and never read the menu here.
pub(crate) unsafe fn emulator_vault_inert() -> bool {
    if !overrides::emulator_mode() {
        return false;
    }
    let menu: u32 = *(offset_to_addr(MENU_OFFSET) as *const u32);
    menu_is_vault(menu)
}

/// Live socket flags. The TCP thread must not call `FighterManager` (that races
/// replay teardown). Stage select used to clear `is_results_screen`; replays never
/// take that path, so the results latch stayed on for the next game.
/// Vault playback still publishes this. SMART starts a game from these flags.
unsafe fn refresh_reported_match() {
    let mgr: *mut app::FighterManager = if FIGHTER_MANAGER_ADDR == 0 {
        std::ptr::null_mut()
    } else {
        *(FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager)
    };
    let current_menu: u32 = *(offset_to_addr(MENU_OFFSET) as *const u32);
    // Controls and Mii Maker pose fighters (a sandbag and Mario) without being a match.
    let menu_is_gameplay = menu_is_gameplay(current_menu);
    let has_entries = !mgr.is_null() && FighterManager::entry_count(mgr) > 0 && menu_is_gameplay;
    let result_mode = has_entries && FighterManager::is_result_mode(mgr);
    let in_match = has_entries && !result_mode;
    GAME_INFO.current_menu.store(current_menu, Ordering::SeqCst);
    GAME_INFO.is_match.store(in_match, Ordering::SeqCst);
    GAME_INFO.is_results_screen.store(result_mode, Ordering::SeqCst);
    let remaining = if in_match || result_mode {
        get_remaining_time_as_frame()
    } else {
        -1.0 as u32
    };
    GAME_INFO.remaining_frames.store(remaining, Ordering::SeqCst);
}

/// Installed so the results read runs on the game thread. Returns before any
/// fighter-module read while a death is pending. The KO camera frame only stores
/// that deadline. While no death is pending, sample this fighter. The socket
/// flags refresh once per frame inside `tick_match_once_per_frame`.
unsafe extern "C" fn poll_results_after_ko(fighter: &mut SmashlineFighterCommon) {
    // Replay save and the results file arm from this tick. Once per frame, including
    // the KO-camera wait. This does not read fighter modules or the camera.
    tick_match_once_per_frame();
    let due = RESULT_POLL_NOT_BEFORE.load(Ordering::SeqCst);
    if due == 0 {
        sample_live_fighter(fighter);
        return;
    }
    if due == u64::MAX {
        return;
    }
    let now = mono_ms();
    if now < due {
        return;
    }
    if RESULT_POLL_NOT_BEFORE
        .compare_exchange(due, u64::MAX, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let done = unsafe { read_results_if_ready() };
    if done {
        RESULT_POLL_NOT_BEFORE.store(0, Ordering::SeqCst);
    } else {
        RESULT_POLL_NOT_BEFORE.store(now.saturating_add(RESULT_POLL_RETRY_MS), Ordering::SeqCst);
    }
}

/// One live frame for one fighter. No-op on the results screen, at clock 0,
/// and once a death has scheduled the KO-camera wait. Does not read
/// `FighterInformation`. Screen position is updated only on a live frame.
unsafe fn sample_live_fighter(fighter: &mut SmashlineFighterCommon) {
    if hooks_quiesced() {
        return;
    }
    let clock_zero = GAME_INFO.remaining_frames.load(Ordering::SeqCst) == 0;
    if !GAME_INFO.is_match.load(Ordering::SeqCst)
        || GAME_INFO.is_results_screen.load(Ordering::SeqCst)
    {
        match_feed::set_sampling(false);
        // Time-up can flip to the results screen on the same frame the clock
        // hits 0. Arm before sudden death, without reading fighter info.
        if clock_zero {
            arm_clock_zero();
        }
        return;
    }
    // Time-up. Stop before touching fighter modules. Sudden death is not recorded.
    if clock_zero {
        match_feed::set_sampling(false);
        arm_clock_zero();
        return;
    }
    latch_versus_on_entry();
    let module_accessor = fighter.module_accessor;
    let entry_id =
        WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    if entry_id < 0 {
        return;
    }
    if StatusModule::status_kind(module_accessor) == *FIGHTER_STATUS_KIND_DEAD {
        return;
    }
    store_screen_position(module_accessor, entry_id as usize);
    match_feed::capture(module_accessor, entry_id as usize);
}

fn install_results_poll_hook() {
    Agent::new("fighter")
        .on_line(Main, poll_results_after_ko)
        .install();
}

unsafe fn store_screen_position(
    module_accessor: *mut app::BattleObjectModuleAccessor,
    entry: usize,
) {
    if entry >= GAME_INFO.players.len() {
        return;
    }
    let pos = Vector3f {
        x: PostureModule::pos_x(module_accessor),
        y: PostureModule::pos_y(module_accessor),
        z: PostureModule::pos_z(module_accessor),
    };
    let screen = as_pixels(pos);
    GAME_INFO.players[entry].x.store(screen.x, Ordering::SeqCst);
    GAME_INFO.players[entry].y.store(screen.y, Ordering::SeqCst);
}

unsafe extern "C" fn handle_pre_entry(fighter: &mut SmashlineFighterCommon) -> L2CValue {
    cancel_result_poll();
    let was_quiesced = HOOKS_QUIESCED.swap(false, Ordering::SeqCst);
    if was_quiesced {
        for player in &GAME_INFO.players {
            player.is_in_game.store(false, Ordering::SeqCst);
        }
        release_fighter_hooks_for_new_match();
    }
    let module_accessor = app::sv_system::battle_object_module_accessor(fighter.lua_state_agent);
    set_player_information(module_accessor);
    GAME_INFO
        .stage
        .store(stage_id_to_stage(stage_id()) as u32, Ordering::SeqCst);
    latch_versus_on_entry();
    original_status(Pre, fighter, *FIGHTER_STATUS_KIND_ENTRY)(fighter)
}

unsafe extern "C" fn handle_pre_rebirth(fighter: &mut SmashlineFighterCommon) -> L2CValue {
    if !hooks_quiesced() {
        // Respawn means that stock loss was not the end of the match.
        cancel_result_poll();
        let module_accessor = app::sv_system::battle_object_module_accessor(fighter.lua_state_agent);
        set_player_information(module_accessor);
    }
    original_status(Pre, fighter, *FIGHTER_STATUS_KIND_REBIRTH)(fighter)
}

unsafe extern "C" fn handle_pre_dead(fighter: &mut SmashlineFighterCommon) -> L2CValue {
    if !hooks_quiesced() {
        // The KO replay camera faults if stocks are read from this status.
        // Final stocks are read once the results screen is up.
        schedule_result_poll();
    }
    original_status(Pre, fighter, *FIGHTER_STATUS_KIND_DEAD)(fighter)
}

fn install_fighter_status_hooks() {
    Agent::new("fighter")
        .status(Pre, *FIGHTER_STATUS_KIND_ENTRY, handle_pre_entry)
        .status(Pre, *FIGHTER_STATUS_KIND_REBIRTH, handle_pre_rebirth)
        .status(Pre, *FIGHTER_STATUS_KIND_DEAD, handle_pre_dead)
        .install();
}


pub(crate) static GAME_INFO: Info = Info::new();

/// Set when a stock match is decided or the clock hits 0. Cleared on the next entry.
/// While set, rebirth and death do not touch fighter modules.
static HOOKS_QUIESCED: AtomicBool = AtomicBool::new(false);

fn hooks_quiesced() -> bool {
    HOOKS_QUIESCED.load(Ordering::SeqCst)
}

fn quiesce_fighter_hooks() {
    HOOKS_QUIESCED.store(true, Ordering::SeqCst);
    match_feed::set_sampling(false);
}

/// Called from the delayed Main poll, only after `is_result_mode` is true.
/// Returns true when the wait is over (results recorded, or sudden death discarded).
unsafe fn read_results_if_ready() -> bool {
    if FIGHTER_MANAGER_ADDR == 0 {
        return false;
    }
    let mgr = *(FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager);
    if mgr.is_null() || FighterManager::entry_count(mgr) <= 0 {
        return false;
    }
    if !FighterManager::is_result_mode(mgr) {
        return false;
    }
    let remaining = get_remaining_time_as_frame();
    GAME_INFO.remaining_frames.store(remaining, Ordering::SeqCst);
    if remaining == 0 {
        // Sudden death still reports 0. Do not read stocks. If the clock-zero
        // frame did not arm the latched snapshot, arm it now.
        quiesce_fighter_hooks();
        arm_clock_zero();
        return true;
    }
    let count = (FighterManager::entry_count(mgr) as usize).min(GAME_INFO.players.len());
    for entry in 0..count {
        let fighter_information = FighterManager::get_fighter_information(
            mgr,
            app::FighterEntryID(entry as i32),
        ) as *mut app::FighterInformation;
        if fighter_information.is_null() {
            continue;
        }
        let stocks = FighterInformation::stock_count(fighter_information) as u32;
        let sd_count = FighterInformation::suicide_count(fighter_information, 0) as u32;
        let player = &GAME_INFO.players[entry];
        player.stocks.store(stocks, Ordering::SeqCst);
        player.self_destructs.store(sd_count, Ordering::SeqCst);
        player.is_in_game.store(true, Ordering::SeqCst);
    }
    GAME_INFO.is_results_screen.store(true, Ordering::SeqCst);
    // Final stocks were not readable on the killing blow. Fold them in now,
    // before the dump thread encodes the frozen summary.
    match_feed::sync_stocks(&GAME_INFO);
    arm_stock_result();
    true
}

/// Versus eligibility is latched once both fighters have entered. The per-frame
/// sampler is not installed; this only marks the match so the death hook can write.
fn latch_versus_on_entry() {
    let training = unsafe { app::smashball::is_training_mode() };
    if training {
        return;
    }
    let ice = (0..8).any(|slot| {
        let player = &GAME_INFO.players[slot];
        player.is_in_game.load(Ordering::SeqCst)
            && is_ice_climbers(player.character.load(Ordering::SeqCst))
    });
    if ice || match_feed::active_pair(&GAME_INFO).is_none() {
        return;
    }
    let mut state = match MATCH_TICK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    reopen_match_state_if_idle(&mut state);
    if state.pending_reopen || state.stats_was_eligible {
        return;
    }
    match_feed::reset(&GAME_INFO);
    state.stats_dumped = false;
    state.stats_latched = true;
    state.stats_was_eligible = true;
    match_feed::set_sampling(true);
    GAME_INFO.is_match.store(true, Ordering::SeqCst);
}

/// Clock hit 0 on a latched versus. One snapshot, then hooks stay quiet so
/// the next entry can reset. Does not read fighter modules.
fn arm_clock_zero() {
    let arm = {
        let state = match MATCH_TICK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        should_arm_clock_zero(state.stats_latched, state.stats_dumped, state.pending_dump)
    };
    if arm {
        arm_stock_result();
    }
}

/// Results screen is up, or the clock just hit 0. Arm the results file and
/// stop further module reads.
fn arm_stock_result() {
    quiesce_fighter_hooks();
    {
        let mut state = match MATCH_TICK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let latched = state.stats_latched && !state.stats_dumped;
        let cooldown_ok = state.ticks_since_dump >= SNAPSHOT_COOLDOWN_TICKS;
        if (latched || cooldown_ok) && !state.pending_dump {
            state.pending_dump = true;
            state.pending_openings = latched;
        }
        state.prev_game_over = true;
    }
    request_large_stack_flush();
}

fn release_fighter_hooks_for_new_match() {
    let mut state = match MATCH_TICK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let dump_in_flight = state.pending_dump || LARGE_STACK_FLUSH_SPAWNED.load(Ordering::SeqCst);
    if dump_in_flight {
        state.pending_reopen = true;
        return;
    }
    state.stats_was_eligible = false;
    state.saw_match = false;
    state.prev_game_over = false;
    state.prev_is_match = false;
    state.dumped_this_match = false;
}

fn reopen_match_state_if_idle(state: &mut MatchTickState) {
    if !state.pending_reopen {
        return;
    }
    let dump_in_flight = state.pending_dump || LARGE_STACK_FLUSH_SPAWNED.load(Ordering::SeqCst);
    if dump_in_flight {
        return;
    }
    state.pending_reopen = false;
    state.stats_was_eligible = false;
    state.saw_match = false;
    state.prev_game_over = false;
    state.prev_is_match = false;
    state.dumped_this_match = false;
}

pub(crate) fn game_info() -> &'static Info {
    &GAME_INFO
}

const MATCH_TICK_MS: u64 = 16;
const SNAPSHOT_COOLDOWN_TICKS: u64 = 120_000 / MATCH_TICK_MS;
const DUMP_RETRY_TICKS: u64 = 45;

#[derive(Clone, Copy)]
struct PlayerSnap {
    stocks: u32,
    damage: f32,
    character: u32,
}

fn collect_players(filter_invalid: bool, out: &mut [PlayerSnap; 8]) -> usize {
    let mut n = 0;
    for p in &GAME_INFO.players {
        if n >= out.len() {
            break;
        }
        let snap = PlayerSnap {
            stocks: p.stocks.load(Ordering::SeqCst),
            damage: p.damage.load(Ordering::SeqCst),
            character: p.character.load(Ordering::SeqCst),
        };
        if filter_invalid {
            let in_game = p.is_in_game.load(Ordering::SeqCst);
            let cpu = p.is_cpu.load(Ordering::SeqCst);
            if !(in_game || cpu) {
                continue;
            }
        }
        out[n] = snap;
        n += 1;
    }
    n
}

/// Last stock already taken. The clock is handled separately: time-up ends the match.
fn stock_match_decided() -> bool {
    let mut buf = [PlayerSnap {
        stocks: 0,
        damage: 0.0,
        character: 0,
    }; 8];
    let n = collect_players(true, &mut buf);
    n >= 2 && has_singles_or_doubles_winner(&buf[..n], u32::MAX)
}

fn is_ice_climbers(character: u32) -> bool {
    character == Character::Nana as u32 || character == Character::Popo as u32
}

/// Port of reframed2startgg `hasSinglesOrDoublesWinner` (winner presence only).
fn has_singles_or_doubles_winner(players: &[PlayerSnap], remaining_frames: u32) -> bool {
    let player_count = players.len();
    let mut winners = [0usize; 8];
    let mut winner_count = 0usize;
    let mut loser_count = 0usize;
    for (i, p) in players.iter().enumerate() {
        if p.stocks > 0 {
            winners[winner_count] = i;
            winner_count += 1;
        } else {
            loser_count += 1;
        }
    }

    if player_count <= 2 && winner_count == 1 && loser_count == 1 {
        return true;
    }
    let winner_pair = if winner_count == 2 {
        Some((winners[0], winners[1]))
    } else {
        None
    };
    if player_count <= 4
        && (1..=2).contains(&winner_count)
        && loser_count >= 2
        && winner_pair != Some((0, 2))
        && winner_pair != Some((1, 3))
    {
        return true;
    }
    // `u32::MAX` skips this branch. Sudden death also reports 0 frames left.
    if remaining_frames == 0 && !players.is_empty() {
        let first = &players[0];
        if players
            .iter()
            .all(|p| p.stocks == first.stocks && p.damage == first.damage)
        {
            return false;
        }
        return true;
    }
    false
}

#[inline(never)]
fn is_game_over(is_results: bool, is_match: bool) -> bool {
    let remaining = GAME_INFO.remaining_frames.load(Ordering::SeqCst);
    let filter_invalid = is_match && !is_results;
    let mut buf = [PlayerSnap {
        stocks: 0,
        damage: 0.0,
        character: 0,
    }; 8];
    let n = collect_players(filter_invalid, &mut buf);
    let players = &buf[..n];
    if players.len() > 1 && is_match && players.iter().any(|p| is_ice_climbers(p.character)) {
        return false;
    }
    // Clock at 0 ends the match even when stocks and percent are tied.
    // Sudden death is not part of the recorded result.
    if is_match && remaining == 0 && !players.is_empty() {
        return true;
    }
    is_results || has_singles_or_doubles_winner(players, remaining)
}

#[inline(never)]
fn game_version() -> String {
    let mut ver = nnsdk::oe::DisplayVersion { name: [0; 16] };
    unsafe {
        nnsdk::oe::GetDisplayVersion(&mut ver);
    }
    let n = ver.name.iter().position(|&b| b == 0).unwrap_or(ver.name.len());
    String::from_utf8_lossy(&ver.name[..n]).into_owned()
}

#[inline(never)]
fn encode_game_info_snapshot(include_openings: bool) -> Option<Vec<u8>> {
    match serde_json::to_value(&GAME_INFO) {
        Ok(mut value) => {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "game_version".to_string(),
                    serde_json::Value::String(game_version()),
                );
                if include_openings {
                    object.insert("openings".to_string(), match_feed::openings_json());
                }
            }
            match serde_json::to_vec(&value) {
                Ok(mut data) => {
                    data.push(b'\n');
                    Some(data)
                }
                Err(e) => {
                    println!("[smush_info] results snapshot serialize failed: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            println!("[smush_info] results snapshot serialize failed: {}", e);
            None
        }
    }
}

#[inline(never)]
fn dump_game_info_snapshot(include_openings: bool) -> bool {
    let log = overrides::results_log();
    let replay = overrides::replay_save();
    if !log && !replay {
        return true;
    }
    // Match-end MainThread Data Aborts correlated with CreateFile during results
    // transition. This runs on the 1MB dump thread, then waits for the game's FS work.
    std::thread::sleep(Duration::from_secs(2));
    if !log {
        return match results_log::timestamp_stem() {
            Some(stem) => {
                replay_dump::on_json_written(stem);
                true
            }
            None => false,
        };
    }
    let Some(data) = encode_game_info_snapshot(include_openings) else {
        return false;
    };
    match results_log::write_snapshot(&data) {
        Some(stem) => {
            if replay {
                replay_dump::on_json_written(stem);
            }
            true
        }
        None => false,
    }
}


struct MatchTickState {
    prev_game_over: bool,
    prev_is_match: bool,
    saw_match: bool,
    dumped_this_match: bool,
    ticks_since_dump: u64,
    stats_was_eligible: bool,
    stats_latched: bool,
    stats_dumped: bool,
    pending_dump: bool,
    pending_openings: bool,
    /// Previous match ended while a dump was still encoding. The next tick resets.
    pending_reopen: bool,
}

impl MatchTickState {
    const fn new() -> Self {
        Self {
            prev_game_over: false,
            prev_is_match: false,
            saw_match: false,
            dumped_this_match: false,
            ticks_since_dump: SNAPSHOT_COOLDOWN_TICKS,
            stats_was_eligible: false,
            stats_latched: false,
            stats_dumped: false,
            pending_dump: false,
            pending_openings: false,
            pending_reopen: false,
        }
    }
}

lazy_static! {
    static ref MATCH_TICK: Mutex<MatchTickState> = Mutex::new(MatchTickState::new());
}

static LARGE_STACK_FLUSH_SPAWNED: AtomicBool = AtomicBool::new(false);

/// Openings serde + SD write + prune must not run on L2C or 64KB plugin threads. Spawn 1MB.
fn request_large_stack_flush() {
    let pending = {
        let state = match MATCH_TICK.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.pending_dump
    };
    if !pending {
        return;
    }
    if LARGE_STACK_FLUSH_SPAWNED.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawn = std::thread::Builder::new()
        .name("smush_stats_dump".into())
        .stack_size(1024 * 1024)
        .spawn(|| {
            flush_match_snapshot();
            LARGE_STACK_FLUSH_SPAWNED.store(false, Ordering::SeqCst);
        });
    if let Err(e) = spawn {
        println!("[smush_info] stats dump thread spawn failed: {}", e);
        LARGE_STACK_FLUSH_SPAWNED.store(false, Ordering::SeqCst);
    }
}

#[inline(never)]
fn flush_match_snapshot() {
    let (pending, include_openings) = {
        let state = match MATCH_TICK.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !state.pending_dump {
            return;
        }
        (true, state.pending_openings)
    };
    if !pending {
        return;
    }
    // Do not hold MATCH_TICK across serde / SD write.
    let dump: fn(bool) -> bool = dump_game_info_snapshot;
    let ok = std::hint::black_box(dump)(include_openings);
    let mut state = match MATCH_TICK.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };
    if ok {
        state.ticks_since_dump = 0;
        state.pending_dump = false;
        state.dumped_this_match = true;
        if include_openings {
            state.stats_dumped = true;
        }
    }
}

static LAST_MATCH_TICK_MS: AtomicU64 = AtomicU64::new(u64::MAX);

fn tick_match_once_per_frame() {
    let now = mono_ms();
    let prev = LAST_MATCH_TICK_MS.load(Ordering::SeqCst);
    if prev == now {
        return;
    }
    if LAST_MATCH_TICK_MS
        .compare_exchange(prev, now, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    tick_match_state(true);
    // Same values for every fighter in the frame. A pending KO-camera read
    // still skips this, so the results timer is not published during that wait.
    if RESULT_POLL_NOT_BEFORE.load(Ordering::SeqCst) == 0 {
        unsafe { refresh_reported_match() };
    }
}

#[inline(never)]
fn tick_match_state(on_game_thread: bool) {
    if !on_game_thread {
        // The socket and UDP threads used to call FighterManager here. That races
        // the game thread tearing the match down at the end of a replay, and the
        // frame update then null-dereferences. Only flush a dump the game thread
        // already armed.
        let pending = {
            let state = match MATCH_TICK.lock() {
                Ok(s) => s,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.pending_dump
        };
        if pending {
            request_large_stack_flush();
        }
        return;
    }
    let pump = {
        let mut state = match MATCH_TICK.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        unsafe {
            update_match_state(&mut state, true);
        }
        // Pumping continues for the whole dump wait. The task waits on the
        // worker between calls, so once a frame is enough.
        replay_dump::take_direct_save();
        should_submit(replay_submit_offset(), replay_dump::direct_wait_active())
    };
    if pump {
        unsafe { pump_replay_save() };
    } else {
        unsafe { end_replay_pump() };
    }
    request_large_stack_flush();
}

#[inline(never)]
unsafe fn update_match_state(state: &mut MatchTickState, on_game_thread: bool) {
    // Playback looks like a finished match. Publishing the feed is what SMART
    // scores. Arming replay save here would press A through the Vault UI.
    if emulator_vault_inert() {
        replay_dump::set_results(false);
        return;
    }
    reopen_match_state_if_idle(state);
    // FighterManager singleton may not exist yet (early in app boot, before title screen)
    // and FIGHTER_MANAGER_ADDR can be 0 if LookupSymbol failed. Treat both as "no match"
    // to avoid dereferencing a null this-pointer in entry_count/is_result_mode.
    let mgr: *mut app::FighterManager = if FIGHTER_MANAGER_ADDR == 0 {
        std::ptr::null_mut()
    } else {
        *(FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager)
    };
    let current_menu: u32 = *(offset_to_addr(MENU_OFFSET) as *const u32);
    // Controls and Mii Maker pose fighters (a sandbag and Mario) without being a match.
    let menu_is_gameplay = menu_is_gameplay(current_menu);
    let is_results = !mgr.is_null()
        && FighterManager::entry_count(mgr) > 0
        && menu_is_gameplay
        && FighterManager::is_result_mode(mgr);
    let is_match = !mgr.is_null()
        && FighterManager::entry_count(mgr) > 0
        && !FighterManager::is_result_mode(mgr)
        && menu_is_gameplay;

    // The save Yes dialog clears is_result_mode while fighters stay entered,
    // so is_match rises in the middle of results. saw_match stays set until
    // both flags are false, which is when we have actually left. Resetting
    // on that dip drops the in-flight save and the pending replay pair,
    // and the next results tick starts a fresh 7.5s mute.
    if new_match_resets_save(is_match, state.prev_is_match, state.saw_match) {
        replay_dump::on_match_rising();
        state.dumped_this_match = false;
        state.ticks_since_dump = DUMP_RETRY_TICKS;
    }
    if is_match {
        GAME_INFO.remaining_frames.store(get_remaining_time_as_frame(), Ordering::SeqCst);
        GAME_INFO.is_match.store(true, Ordering::SeqCst);
        state.saw_match = true;
    }

    let game_over = state.saw_match && is_game_over(is_results, is_match);
    // Clock at 0 or last stock ends stat sampling. Sudden death is discarded.
    // Screen position is not part of this and keeps updating on Main.
    let time_up = is_match && GAME_INFO.remaining_frames.load(Ordering::SeqCst) == 0;
    let match_finished = is_results || time_up || stock_match_decided();
    // gstack-shortcut(dec-6ea7e982-17b2-4d92-824f-8fa6f2edd87d): 6/10, upgrade when Spirits, Classic, and World of Light menu ids are known
    let entry_count = if mgr.is_null() {
        0
    } else {
        FighterManager::entry_count(mgr)
    };
    let training = app::smashball::is_training_mode();
    let ice_climbers = (0..8).any(|slot| {
        let player = &GAME_INFO.players[slot];
        player.is_in_game.load(Ordering::SeqCst) && is_ice_climbers(player.character.load(Ordering::SeqCst))
    });
    let eligible = is_match && entry_count == 2 && !training && !ice_climbers;
    if on_game_thread {
        if match_finished {
            match_feed::set_sampling(false);
        } else if eligible {
            if !state.stats_was_eligible {
                match_feed::reset(&GAME_INFO);
                state.stats_dumped = false;
                state.stats_latched = true;
                state.stats_was_eligible = true;
            }
            match_feed::set_sampling(true);
        } else {
            match_feed::set_sampling(false);
            // The match→results gap is neither flag. A latched game still owes a file.
            let dump_in_flight =
                state.pending_dump || LARGE_STACK_FLUSH_SPAWNED.load(Ordering::SeqCst);
            let keep_latched = state.stats_latched && !state.stats_dumped;
            if !dump_in_flight && !keep_latched {
                state.stats_was_eligible = false;
                state.stats_latched = false;
                state.stats_dumped = false;
                state.pending_dump = false;
                state.pending_openings = false;
                match_feed::reset(&GAME_INFO);
            }
        }
    }

    let game_over_edge = game_over && !state.prev_game_over;
    let latched_write = state.stats_latched && !state.stats_dumped;
    let write_edge = game_over_edge || (latched_write && game_over);
    let stats_write = should_write_stats_snapshot(
        latched_write,
        write_edge,
        state.ticks_since_dump,
        SNAPSHOT_COOLDOWN_TICKS,
    );
    // Replay save uses the results screen even when the stats winner check is quiet.
    // Arm only. The 1MB thread writes the file and pairs the replay.
    let replay_write = !state.dumped_this_match
        && (is_results || game_over_edge)
        && state.ticks_since_dump >= DUMP_RETRY_TICKS;
    if stats_write || replay_write {
        if is_results {
            GAME_INFO.is_results_screen.store(true, Ordering::SeqCst);
        }
        if !state.pending_dump {
            state.pending_dump = true;
            state.pending_openings = state.stats_latched;
            match_feed::set_sampling(false);
        }
    }

    if !is_match {
        GAME_INFO.remaining_frames.store(-1.0 as u32, Ordering::SeqCst);
        GAME_INFO.is_match.store(false, Ordering::SeqCst);
        for player in &GAME_INFO.players {
            player.is_in_game.store(false, Ordering::SeqCst);
            player.team.store(-1, Ordering::SeqCst);
        }
    }

    GAME_INFO.current_menu.store(current_menu, Ordering::SeqCst);
    replay_dump::set_results(is_results);
    if !mgr.is_null() && FighterManager::entry_count(mgr) > 0 && menu_is_gameplay {
        GAME_INFO.is_results_screen.store(FighterManager::is_result_mode(mgr), Ordering::SeqCst);
    }

    if clear_results_session(is_match, is_results) {
        state.saw_match = false;
    }

    state.prev_game_over = game_over;
    state.prev_is_match = is_match;
    state.ticks_since_dump = state.ticks_since_dump.saturating_add(1);
    if match_finished {
        HOOKS_QUIESCED.store(true, Ordering::SeqCst);
    }
}

#[allow(unreachable_code)]
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
                            drop_client(client);
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
                    drop_client(&mut clients[index]);
                    clients.swap_remove(index);
                } else {
                    index += 1;
                }
            }

            if clients.iter().any(|client| !client.probing) {
                tick_match_state(false);
                let payload = serde_json::to_vec(&GAME_INFO).unwrap();
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
                            drop_client(&mut clients[index]);
                            clients.swap_remove(index);
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(16));
        }
        /*let magic = recv_bytes(tcp_socket, 4).unwrap();
        if &magic == b"HRLD" {
            let num_bytes = recv_u32(tcp_socket).unwrap();
        } else if &magic == b"ECHO" {
            println!("\n\n----\nECHO\n\n");
        } else {
            println!("Invalid magic")
        }*/
        
        dbg_err!(close(listener_socket));
    }

    Ok(())
}

pub fn offset_to_addr(offset: usize) -> *const () {
    unsafe {
        (getRegionAddress(Region::Text) as *const u8).offset(offset as isize) as _
    }
}

#[inline(always)]
fn get_fp() -> *const u64 {
    let r;
    unsafe { std::arch::asm!("mov {0}, x29",out(reg) r) }
    r
}

#[skyline::hook(offset = OFFSET1)] //1
fn some_strlen_thing(x: usize) -> usize {
    unsafe {
        let y = (x + 0x18) as *const *const c_char;
        if !y.is_null() {
            let text = getRegionAddress(Region::Text) as u64;
            let lr_offset = *get_fp().offset(1) - text;
            if lr_offset == OFFSET2 as u64 { //2
                let arena_id = from_c_str(*y);
                if arena_id.len() == 5 {
                    GAME_INFO.arena_id.store_str(Some(&arena_id), Ordering::SeqCst);
                }
            }
        }
    }
    original!()(x)
}

static OFFSET1_SEARCH_CODE: &[u8] = &[ //add 38
    0x81, 0x0e, 0x40, 0xf9, //.text:00000071001B5268                 LDR             X1, [X20,#0x18] ; src
    0xe0, 0x03, 0x16, 0xaa  //.text:00000071001B526C                 MOV             X0, X22 ; dest
                            //.text:00000071001B5270                 MOV             X2, X21 ; n
                            //.text:00000071001B5274                 BL              memcpy_0
                            //.text:00000071001B5278                 LDR             X8, [X19,#0x18]
                            //.text:00000071001B527C                 STRB            WZR, [X8,X21]
                            //.text:00000071001B5280                 LDP             X29, X30, [SP,#0x30+var_s0]
                            //.text:00000071001B5284                 LDP             X20, X19, [SP,#0x30+var_10]
                            //.text:00000071001B5288                 LDP             X22, X21, [SP,#0x30+var_20]
                            //.text:00000071001B528C                 LDP             X24, X23, [SP+0x30+var_30],#0x40
                            //.text:00000071001B5290                 RET
                            //below is req function
                            //.text:00000071001B52A0                 LDR             X0, [X0,#0x18] ; s
                            //.text:00000071001B52A4                 B               strlen_0
];

static OFFSET2_SEARCH_CODE: &[u8] = &[ //add -C, just below is the address needed
                            //.text:000000710225DC2C                 MOV             X0, X20 ; this
                            //.text:000000710225DC30                 BL              _ZNSt3__115recursive_mutex6unlockEv_0 ; std::__1::recursive_mutex::unlock(void)
                            //.text:000000710225DC34                 LDR             X0, [X21]
    0x60, 0x02, 0x00, 0xb4, //.text:000000710225DC38                 CBZ             X0, loc_710225DC84
    0x14, 0x58, 0x40, 0xa9  //.text:000000710225DC3C                 LDP             X20, X22, [X0]
                            //.text:000000710225DC40                 LDR             X8, [X0,#0x10]!
                            //.text:000000710225DC44                 LDR             X8, [X8]
                            //.text:000000710225DC48                 BLR             X8
                            //.text:000000710225DC4C                 LDR             X8, [X27,#0x30]
                            //.text:000000710225DC50                 LDR             X8, [X8,#8]
                            //.text:000000710225DC54                 STR             X8, [X27,#0x20]
                            //.text:000000710225DC58                 CBNZ            X8, loc_710225DC64
                            //.text:000000710225DC5C                 LDR             X8, [X27,#0x28]
                            //.text:000000710225DC60                 STR             X8, [X27,#0x20]
];

#[skyline::hook(offset = OFFSET3)] //3, remained same somehow
fn close_arena(param_1: usize) {
    GAME_INFO.arena_id.store_str(None, Ordering::SeqCst);
    original!()(param_1);
}

static OFFSET3_SEARCH_CODE: &[u8] = &[ //exact
    0xff, 0x83, 0x01, 0xd1, //.text:00000071000D7140                 SUB             SP, SP, #0x60
    0xf6, 0x57, 0x03, 0xa9, //.text:00000071000D7144                 STP             X22, X21, [SP,#0x50+var_20]
    0xf4, 0x4f, 0x04, 0xa9, //.text:00000071000D7148                 STP             X20, X19, [SP,#0x50+var_10]
    0xfd, 0x7b, 0x05, 0xa9, //.text:00000071000D714C                 STP             X29, X30, [SP,#0x50+var_s0]
    0xfd, 0x43, 0x01, 0x91, //.text:00000071000D7150                 ADD             X29, SP, #0x50
    0x15, 0x44, 0x40, 0xf9  //.text:00000071000D7154                 LDR             X21, [X0,#0x88]
                            //.text:00000071000D7158                 MOV             X19, X0
                            //.text:00000071000D715C                 CBZ             X21, loc_71000D71B4
                            //.text:00000071000D7160                 LDR             X8, [X21,#0x10]
                            //.text:00000071000D7164                 CBZ             X8, loc_71000D71B4
                            //.text:00000071000D7168                 LDP             X8, X20, [X21]
                            //.text:00000071000D716C                 LDR             X9, [X8,#8]
                            //.text:00000071000D7170                 LDR             X10, [X20]
                            //.text:00000071000D7174                 STR             X9, [X10,#8]
                            //.text:00000071000D7178                 LDR             X8, [X8,#8]
                            //.text:00000071000D717C                 CMP             X20, X21
                            //.text:00000071000D7180                 STR             X10, [X8]
                            //.text:00000071000D7184                 STR             XZR, [X21,#0x10]
                            //.text:00000071000D7188                 B.EQ            loc_71000D71B4
];

pub(crate) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub static mut FIGHTER_MANAGER_ADDR: usize = 0;

pub unsafe fn note_fighter_from_modules(module_accessor: &mut app::BattleObjectModuleAccessor) {
    let entry_id = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    if entry_id < 0 {
        return;
    }
    let player_num = entry_id as usize;
    if player_num >= GAME_INFO.players.len() {
        return;
    }
    let character = kind_to_char(get_kind(module_accessor)) as u32;
    let damage = DamageModule::damage(module_accessor, 0);
    let skin = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_COLOR) as u32;
    let team = TeamModule::team_no(module_accessor) as i32;
    let player = &GAME_INFO.players[player_num];
    player.is_in_game.store(true, Ordering::SeqCst);
    player.character.store(character, Ordering::SeqCst);
    player.damage.store(damage, Ordering::SeqCst);
    player.skin.store(skin, Ordering::SeqCst);
    player.team.store(team, Ordering::SeqCst);
}

pub unsafe fn set_player_information(module_accessor: &mut app::BattleObjectModuleAccessor) {
    let entry_id = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    if entry_id < 0 {
        return;
    }
    let player_num = entry_id as usize;
    if player_num >= GAME_INFO.players.len() || FIGHTER_MANAGER_ADDR == 0 {
        return;
    }
    let mgr = *(FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager);
    if mgr.is_null() {
        return;
    }
    let fighter_information = FighterManager::get_fighter_information(
        mgr, 
        app::FighterEntryID(entry_id)
    ) as *mut app::FighterInformation;
    if fighter_information.is_null() {
        return;
    }

    let character = kind_to_char(get_kind(module_accessor)) as u32;
    let damage = DamageModule::damage(module_accessor, 0);
    let stock_count = FighterInformation::stock_count(fighter_information) as u32;
    let sd_count = FighterInformation::suicide_count(fighter_information, 0) as u32;
    let is_cpu = FighterInformation::is_operation_cpu(fighter_information);
    let skin = (WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_COLOR)) as u32; //returns costume slot 0-indexed
    let team = TeamModule::team_no(module_accessor) as i32;

    if FighterManager::entry_count(mgr) > 0 {
        GAME_INFO.players[player_num].hero_menu_selected.store(false, Ordering::SeqCst);
        GAME_INFO.players[player_num].hero_menu_open.store(false, Ordering::SeqCst);            
    }
    GAME_INFO.players[player_num].is_in_game.store(true, Ordering::SeqCst);
    GAME_INFO.players[player_num].character.store(character, Ordering::SeqCst);
    GAME_INFO.players[player_num].damage.store(damage, Ordering::SeqCst);
    GAME_INFO.players[player_num].stocks.store(stock_count, Ordering::SeqCst);
    GAME_INFO.players[player_num].self_destructs.store(sd_count, Ordering::SeqCst);
    GAME_INFO.players[player_num].is_cpu.store(is_cpu, Ordering::SeqCst);
    GAME_INFO.players[player_num].skin.store(skin, Ordering::SeqCst);
    GAME_INFO.players[player_num].team.store(team, Ordering::SeqCst);
    println!("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ player tag {}", get_tag_of_player(player_num));
    GAME_INFO.players[player_num].name.store_str(Some(&get_tag_of_player(player_num)), Ordering::SeqCst);
}

// UPDATE_TAG unchanged across 13.0.4/13.0.5. Data offsets slide +0x1000 on 13.0.5;
// stage select is a code offset (+0x450). Submit, the task constructor, and the
// pump share a text offset. The allocator, task slot, and replay-source global
// do not. Defaults are 13.0.5; apply_version_offsets() rewinds them for 13.0.4.
static UPDATE_TAG_FOR_PLAYER_OFFSET: usize = 0x19fd0b0;
static mut PLAYER_SAVE_OFFSET: usize = 0x5314510;
static mut PLAYER_SAVE_ADDRESS: *const u64 = 0x0 as *const u64;
static mut PLAYER_TAG_OFFSET: usize = 0x52C5758;
static mut MENU_OFFSET: usize = 0x53050f0;
static mut STAGE_SELECTED_OFFSET: usize = 0x23355d4;
// `void submit(Task*)`. Same text offset on 13.0.4 and 13.0.5. The pump is what
// runs; a zero offset means the entry was not found and must not be called.
static mut REPLAY_SUBMIT_OFFSET: usize = 0x143d5d0;
// BSS box. `task = *(u64*)(*(u64*)(image + slot))`.
static mut REPLAY_TASK_SLOT_OFFSET: usize = 0x52c35b8;
// Results menu: alloc(align, size) then `ctor(box)` which stores the task in the box.
// The menu only runs this from its save step, which the direct path never enters.
static mut REPLAY_TASK_ALLOC_OFFSET: usize = 0x392e290;
static mut REPLAY_TASK_CTOR_OFFSET: usize = 0x143e850;
// `*(u64*)(image + slot)` is the replay manager. The menu calls
// `(*(manager+0x588))[0x18/8](manager+0x588)` and stores the result at task+0x198.
// The write callback bails when that field is still 0.
static mut REPLAY_SOURCE_OFFSET: usize = 0x52c50f0;
// Results pump. The menu calls this once a frame. State 1 enqueues, then
// later frames wait until the worker sets task+0x11c before advancing.
// Calling submit on the same tick replaces that callback, so the worker
// never opens a file.
static mut REPLAY_TASK_PUMP_OFFSET: usize = 0x143ea40;
/// Match ticks are once a millisecond. The results menu pumps once a frame,
/// and spinning the state machine faster than that hitches the results screen.
const REPLAY_PUMP_INTERVAL_MS: u64 = 16;
static mut PUMP_LIVE: bool = false;
static mut PUMP_BUSY: bool = false;
static mut PUMP_TASK: u64 = 0;
static mut PUMP_NOT_BEFORE: u64 = 0;

pub(crate) fn replay_submit_offset() -> usize {
    unsafe { REPLAY_SUBMIT_OFFSET }
}

fn display_version() -> String {
    skyline::nn::oe::get_display_version()
}

fn parse_display_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// True for 13.0.5 and newer. Unknown/unparseable versions keep the 13.0.5 offsets.
fn uses_13_0_5_offsets(version: &str) -> bool {
    match parse_display_version(version) {
        Some(v) => v >= (13, 0, 5),
        None => true,
    }
}

unsafe fn apply_version_offsets() {
    let version = display_version();
    if uses_13_0_5_offsets(&version) {
        PLAYER_SAVE_OFFSET = 0x5314510;
        PLAYER_TAG_OFFSET = 0x52C5758;
        MENU_OFFSET = 0x53050f0;
        STAGE_SELECTED_OFFSET = 0x23355d4;
        REPLAY_SUBMIT_OFFSET = 0x143d5d0;
        REPLAY_TASK_SLOT_OFFSET = 0x52c35b8;
        REPLAY_TASK_ALLOC_OFFSET = 0x392e290;
        REPLAY_TASK_CTOR_OFFSET = 0x143e850;
        REPLAY_SOURCE_OFFSET = 0x52c50f0;
        REPLAY_TASK_PUMP_OFFSET = 0x143ea40;
        println!("[smush_info] game {} — using 13.0.5 offsets", version);
    } else {
        PLAYER_SAVE_OFFSET = 0x5313510;
        PLAYER_TAG_OFFSET = 0x52C4758;
        MENU_OFFSET = 0x53040f0;
        STAGE_SELECTED_OFFSET = 0x2335184;
        REPLAY_SUBMIT_OFFSET = 0x143d5d0;
        REPLAY_TASK_SLOT_OFFSET = 0x52c25b8;
        REPLAY_TASK_ALLOC_OFFSET = 0x392dce0;
        REPLAY_TASK_CTOR_OFFSET = 0x143e850;
        REPLAY_SOURCE_OFFSET = 0x52c40f0;
        REPLAY_TASK_PUMP_OFFSET = 0x143ea40;
        println!("[smush_info] game {} — using 13.0.4 offsets", version);
    }
}

/// Allocate the 8-byte box and run the results-menu constructor.
/// Returns 0 when the allocator or the constructor offset is missing.
#[inline(never)]
unsafe fn make_replay_task_box() -> u64 {
    let alloc_off = REPLAY_TASK_ALLOC_OFFSET;
    let ctor_off = REPLAY_TASK_CTOR_OFFSET;
    if alloc_off == 0 || ctor_off == 0 {
        return 0;
    }
    let alloc: unsafe extern "C" fn(u64, u64) -> u64 =
        std::mem::transmute(offset_to_addr(alloc_off) as *const ());
    let ctor: unsafe extern "C" fn(u64) =
        std::mem::transmute(offset_to_addr(ctor_off) as *const ());
    // Same arguments the results menu passes: align 16, size 8.
    let box_ptr = std::hint::black_box(alloc)(0x10, 8);
    if box_ptr == 0 {
        return 0;
    }
    std::hint::black_box(ctor)(box_ptr);
    box_ptr
}

/// Same call the results menu makes after the constructor. Returns the pointer
/// stored at `task+0x198`, or 0 when the manager is not there.
#[inline(never)]
unsafe fn attach_replay_source(task: u64) -> u64 {
    let slot_off = REPLAY_SOURCE_OFFSET;
    if slot_off == 0 || task == 0 {
        return 0;
    }
    let root = *(offset_to_addr(slot_off) as *const u64);
    if root == 0 {
        return 0;
    }
    let vt = *((root + 0x588) as *const u64);
    if vt == 0 {
        return 0;
    }
    let method = *((vt + 0x18) as *const u64);
    if method == 0 {
        return 0;
    }
    let fetch: unsafe extern "C" fn(u64) -> u64 =
        std::mem::transmute(method as *const ());
    let replay = std::hint::black_box(fetch)(root + 0x588);
    *((task + 0x198) as *mut u64) = replay;
    replay
}

/// Drop the in-flight pump so the next dump wait builds a new task.
unsafe fn end_replay_pump() {
    PUMP_LIVE = false;
    PUMP_TASK = 0;
    PUMP_NOT_BEFORE = 0;
}

/// Build the task the way the results menu does, once per dump wait.
/// A fresh box each wait: a finished task left in the slot would not save again.
unsafe fn start_replay_task() -> bool {
    let slot_off = REPLAY_TASK_SLOT_OFFSET;
    let pump_off = REPLAY_TASK_PUMP_OFFSET;
    if slot_off == 0 || pump_off == 0 {
        return false;
    }
    let box_ptr = make_replay_task_box();
    if box_ptr == 0 {
        return false;
    }
    let slot = offset_to_addr(slot_off) as *mut u64;
    *slot = box_ptr;
    let task = *(box_ptr as *const u64);
    if task == 0 {
        return false;
    }
    attach_replay_source(task);
    *((task as *mut u8).add(0xa8) as *mut i32) = 1;
    *((task as *mut u8).add(0x108) as *mut u32) = 0;
    PUMP_TASK = task;
    true
}

/// One pump about every frame. The menu does this until `task+0x108` is 1 or 2.
/// Submit is a later state; calling it here overwrites the callback state 1 queued.
#[inline(never)]
unsafe fn pump_replay_save() {
    if PUMP_BUSY {
        return;
    }
    let now = mono_ms();
    if PUMP_LIVE && now < PUMP_NOT_BEFORE {
        return;
    }
    PUMP_BUSY = true;
    if !PUMP_LIVE {
        if !start_replay_task() {
            PUMP_BUSY = false;
            return;
        }
        PUMP_LIVE = true;
    }
    let task = PUMP_TASK;
    let status_now = *((task as *const u8).add(0x108) as *const u32);
    if status_now == 1 || status_now == 2 {
        PUMP_NOT_BEFORE = u64::MAX;
        PUMP_BUSY = false;
        return;
    }
    let pump_off = REPLAY_TASK_PUMP_OFFSET;
    let pump: unsafe extern "C" fn(u64) -> u32 =
        std::mem::transmute(offset_to_addr(pump_off) as *const ());
    std::hint::black_box(pump)(task);
    PUMP_NOT_BEFORE = now.saturating_add(REPLAY_PUMP_INTERVAL_MS);
    PUMP_BUSY = false;
}

pub fn get_tag_of_player(player_index: usize) -> String {
    let player_tag_offset = unsafe { PLAYER_TAG_OFFSET } + (player_index * 0x260);
    let player_tag_addr: *const u16 = offset_to_addr(player_tag_offset) as *const u16;
    
    unsafe {
        let mut len = 0;
        while *player_tag_addr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(player_tag_addr, len);
        String::from_utf16_lossy(slice)
    }
}

pub fn get_tag_from_save(tag_index: u8) -> String {
    unsafe {
        let addr = (***((*((*PLAYER_SAVE_ADDRESS) as *const u64) + 0x58) as *const *const *const u64) + ((tag_index as u64) * 0xF7D8) + 0xC) as *const u16;
        let mut len = 0;
        while *addr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(addr, len);
        String::from_utf16_lossy(slice)
    }
}

#[skyline::hook(offset = UPDATE_TAG_FOR_PLAYER_OFFSET)]
pub fn update_tag_for_player(param_1: u64, tag_index: *const u8){
    unsafe {
        let player_index = *((param_1 as *mut u8).offset(0x1d4) as *mut i32) as usize;
        GAME_INFO.players[player_index].name.store_str(Some(&get_tag_from_save(*tag_index)), Ordering::SeqCst);
        
        println!("AAAAAAAAAAAAAAAAAAAA PLAYER NAME OF INDEX {} IS {}", player_index, get_tag_from_save(*tag_index));
        call_original!(param_1, tag_index);
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct UnkPtr1 {
    ptrs: [&'static u64; 7],
}

#[derive(Debug)]
#[allow(dead_code)]
struct UnkPtr2 {
    bunch_bytes: [u8; 0x20],
    bunch_bytes2: [u8; 0x20]
}

#[derive(Debug)]
#[repr(C)]
pub struct FighterInfo {
    unk_ptr1: &'static UnkPtr1,
    unk_ptr2: &'static UnkPtr2,
    unk1: [u8; 0x20],
    unk2: [u8; 0x20],
    unk3: [u8; 0x8],
    fighter_id: u8,
    unk4: [u8;0xB],
    fighter_slot: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct FighterInfoBasic {
    field0_0x0: *mut (),
    field1_0x8: *mut (),
    field2_0x10: [u8; 0x30],
    ice_climber_going_first: u32,
    field67_0x54: u32,
    fighter_id: u32,
    redirected_fighter_id: u32,
    field70_0x60: u32,
    fighter_slot: u32,
    field72_0x68: u16,
    field73_0x6a: u16,
    field74_0x6c: u32,
    field75_0x70: u32,
    field76_0x74: u32,
    field77_0x78: u32,
    field78_0x7c: bool,
    field79_0x7d: u8,
    field80_0x7e: u8,
    field81_0x7f: u8,
    field82_0x80: i32,
    field83_0x84: [u8; 0x64],
}

#[skyline::hook(offset = FIGHTER_SELECTED_OFFSET, inline)]
fn css_fighter_selected(ctx: &InlineCtx) {
    let infos = unsafe { &*(ctx.registers[0].x() as *const FighterInfo) };
    let infosbasic = unsafe { &*(ctx.registers[0].x() as *const FighterInfoBasic) };
    let fighter_id = infos.fighter_id as i32;
    let skin = infos.fighter_slot as u32;
    let character = kind_to_char(fighter_id) as u32;
    let port = (infosbasic.field77_0x78 & 0xFFFF) as usize;
    println!("character {}\nskin {}\nport {}\n ", character, skin, port);
    GAME_INFO.players[port].character.store(character, Ordering::SeqCst);
    GAME_INFO.players[port].skin.store(skin, Ordering::SeqCst);
}

fn search_offsets() {
    unsafe {
        let text_ptr = getRegionAddress(Region::Text) as *const u8;
        let text_size = (getRegionAddress(Region::Rodata) as usize) - (text_ptr as usize);
        let text = std::slice::from_raw_parts(text_ptr, text_size);

        if let Some(offset) = find_subsequence(text, FIGHTER_SELECTED_SEARCH_CODE) {
            FIGHTER_SELECTED_OFFSET = offset + 0x10;
        } else {
            println!("Error: no offset found for 'css_fighter_selected'. Keeping the built-in 13.0.5 offset.");
        }
    }
}

fn server_supervisor() {
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

#[skyline::hook(offset = STAGE_SELECTED_OFFSET, inline)]
unsafe fn selected_stage(_ctx: &InlineCtx) {
    println!("stage has been selected");
    GAME_INFO.is_results_screen.store(false, Ordering::SeqCst);
}

extern "C" {
    #[link_name = "_ZN3app24FighterSpecializer_Brave23special_lw_open_commandERNS_7FighterE"]
    fn special_lw_open_command();
    #[link_name = "_ZN3app24FighterSpecializer_Brave23special_lw_close_windowERNS_7FighterEbbb"]
    fn special_lw_close_window(fighter: *mut app::Fighter, arg2: bool, no_decide: bool, arg4: bool);
    #[link_name = "_ZN3app24FighterSpecializer_Brave25special_lw_decide_commandERNS_7FighterENS_28FighterBraveSpecialLwCommandEi"]
    fn special_lw_decide_command(fighter: *mut app::Fighter, command: app::FighterBraveSpecialLwCommand, idx: i32);
    #[link_name = "_ZN3app24FighterSpecializer_Brave23special_lw_select_indexERNS_7FighterEi"]
    fn special_lw_select_index(fighter: *mut app::Fighter, index: i32);
}

#[skyline::hook(replace = special_lw_open_command)]
pub unsafe fn special_lw_open_command_hook(fighter: &mut app::Fighter) {
    let module_accessor: *mut app::BattleObjectModuleAccessor = app::sv_battle_object::module_accessor(*(((&mut (fighter.battle_object) as *mut app::BattleObject) as u64 + 8) as *mut u32)); //this is a mess
    let entry_id = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    let player_num = entry_id as usize;

    GAME_INFO.players[player_num].hero_menu_open.store(true, Ordering::SeqCst);
    GAME_INFO.players[player_num].hero_menu_selection.store(0, Ordering::SeqCst);

    call_original!(fighter);
}

#[skyline::hook(replace = special_lw_select_index)]
pub unsafe fn special_lw_select_index_hook(fighter: &mut app::Fighter, index: i32) {
    let module_accessor: *mut app::BattleObjectModuleAccessor = app::sv_battle_object::module_accessor(*(((&mut (fighter.battle_object) as *mut app::BattleObject) as u64 + 8) as *mut u32)); //this is a mess
    let entry_id = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    let player_num = entry_id as usize;

    GAME_INFO.players[player_num].hero_menu_selection.store(index as u32, Ordering::SeqCst);
    call_original!(fighter, index);
}

#[skyline::hook(replace = special_lw_decide_command)]
pub unsafe fn special_lw_decide_command_hook(fighter: &mut app::Fighter, command: app::FighterBraveSpecialLwCommand, idx: i32) {
    let module_accessor: *mut app::BattleObjectModuleAccessor = app::sv_battle_object::module_accessor(*(((&mut (fighter.battle_object) as *mut app::BattleObject) as u64 + 8) as *mut u32)); //this is a mess
    let entry_id = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    let player_num = entry_id as usize;

    GAME_INFO.players[player_num].hero_menu_selection.store(idx as u32, Ordering::SeqCst);
    GAME_INFO.players[player_num].hero_menu_selected.store(true, Ordering::SeqCst);

    call_original!(fighter, command, idx);
}

#[skyline::hook(replace = special_lw_close_window)]
pub unsafe fn special_lw_close_window_hook(fighter: &mut app::Fighter, arg2: bool, no_decide: bool, arg4: bool) {
    let module_accessor: *mut app::BattleObjectModuleAccessor = app::sv_battle_object::module_accessor(*(((&mut (fighter.battle_object) as *mut app::BattleObject) as u64 + 8) as *mut u32)); //this is a mess
    let entry_id = WorkModule::get_int(module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID) as i32;
    let player_num = entry_id as usize;

    
    GAME_INFO.players[player_num].hero_menu_selected.store(false, Ordering::SeqCst);
    GAME_INFO.players[player_num].hero_menu_open.store(false, Ordering::SeqCst);

    call_original!(fighter, arg2, no_decide, arg4);
}

#[inline(never)]
fn udp_broadcast_loop() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        udp::broadcast_device_info();
        // Flush a dump the game thread already armed. Do not read FighterManager here.
        let tick: fn(bool) = tick_match_state;
        std::hint::black_box(tick)(false);
    }
}

#[skyline::main(name = "smush_info")]
pub fn main() {
    overrides::load();
    // The sheet is parsed on the first real lookup. Do that here, on the load
    // thread, so the first hit of a session does not stall the game thread.
    smush_info_shared::preload_move_names();
    unsafe {
        skyline::nn::ro::LookupSymbol(
            &raw mut FIGHTER_MANAGER_ADDR,
            "_ZN3lib9SingletonIN3app14FighterManagerEE9instance_E\u{0}".as_bytes().as_ptr(),
        );
        apply_version_offsets();
    }

    search_offsets();
    unsafe {
        PLAYER_SAVE_ADDRESS = offset_to_addr(PLAYER_SAVE_OFFSET) as *const u64;
        let text_ptr = getRegionAddress(Region::Text) as *const u8;
        let text_size = (getRegionAddress(Region::Rodata) as usize) - (text_ptr as usize);
        let text = std::slice::from_raw_parts(text_ptr, text_size);
        if let Some(offset) = find_subsequence(text, OFFSET1_SEARCH_CODE) {
            OFFSET1 = offset + 0x38;
        }
        if let Some(offset) = find_subsequence(text, OFFSET2_SEARCH_CODE) {
            OFFSET2 = offset - 0xc;
        }
        if let Some(offset) = find_subsequence(text, OFFSET3_SEARCH_CODE) {
            OFFSET3 = offset;
        }
    }

    skyline::install_hooks!(
        some_strlen_thing,
        close_arena,
        update_tag_for_player,
        css_fighter_selected,
        selected_stage,
        special_lw_open_command_hook,
        special_lw_close_window_hook,
        special_lw_decide_command_hook,
        special_lw_select_index_hook
    );
    replay_dump::install();
    // Main samples a live 1v1 and polls for the results screen a few seconds
    // after a death. It does not read fighter modules on the KO camera frame.
    // The same hook arms the replay save. Screen position is updated only on
    // live frames, not on the death status.
    install_results_poll_hook();
    install_fighter_status_hooks();

    std::thread::spawn(server_supervisor);

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(5));
        println!("[smush_info] starting broadcast");
        let start: fn() = udp_broadcast_loop;
        std::hint::black_box(start)();
    });
}
