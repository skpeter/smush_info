use crate::results_log;
use skyline::hooks::A64HookFunction;
use skyline::libc::{c_char, c_void};
use skyline::nn::hid::{NpadGcState, NpadHandheldState};
use smash::app::{self, lua_bind::FighterManager};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const CAP_BYTES: usize = 8 * 1024 * 1024;
const PROBE_MAX: usize = 50;
const REPLAY_UTF16: &[u8] = &[b'R', 0, b'e', 0, b'p', 0, b'l', 0, b'a', 0, b'y', 0];
const WRITE_BIT: i32 = nnsdk::fs::OpenMode_OpenMode_Write as i32;

struct Capture {
    path: String,
    buf: Vec<u8>,
    truncated: bool,
}

enum Pair {
    Idle,
    Pending {
        stem: String,
        wrote_bin: bool,
        best_magic: u8,
        best_len: usize,
    },
    Orphan {
        files: Vec<Capture>,
    },
}

struct DumpState {
    captures: HashMap<u64, Capture>,
    pair: Pair,
    path_confirmed: bool,
    probe_unique: HashSet<String>,
    results: bool,
    hid_began: Option<Instant>,
    last_hid_poll: Option<Instant>,
    hid_released: bool,
    hid_logged_wait: bool,
    hid_logged_start: bool,
    hid_session: bool,
    hid_unfocused: bool,
}

impl DumpState {
    fn new() -> Self {
        Self {
            captures: HashMap::new(),
            pair: Pair::Idle,
            path_confirmed: false,
            probe_unique: HashSet::new(),
            results: false,
            hid_began: None,
            last_hid_poll: None,
            hid_released: false,
            hid_logged_wait: false,
            hid_logged_start: false,
            hid_session: false,
            hid_unfocused: false,
        }
    }

    fn probe_window(&self) -> bool {
        self.results
            || matches!(self.pair, Pair::Pending { .. } | Pair::Orphan { .. })
    }

    fn hid_got_write(&self) -> bool {
        match &self.pair {
            Pair::Pending { wrote_bin: true, .. } => true,
            Pair::Orphan { files } => files.iter().any(|f| magic_score(&f.buf) > 0),
            _ => false,
        }
    }

    fn wants_hid_mask(&self, live_results: bool) -> bool {
        live_results && !self.hid_released
    }

    fn reset_hid(&mut self) {
        self.hid_began = None;
        self.last_hid_poll = None;
        self.hid_released = false;
        self.hid_logged_wait = false;
        self.hid_logged_start = false;
        self.hid_session = false;
        self.hid_unfocused = false;
    }

    fn begin_hid_session(&mut self) {
        if self.hid_session {
            return;
        }
        self.reset_hid();
        self.hid_session = true;
        let now = Instant::now();
        self.hid_began = Some(now);
        self.last_hid_poll = Some(now);
    }

    fn absorb_suspend_gap(&mut self, now: Instant) {
        let Some(last) = self.last_hid_poll else {
            return;
        };
        let gap = now.saturating_duration_since(last);
        if gap.as_millis() < HID_SUSPEND_GAP_MS {
            return;
        }
        if let Some(began) = self.hid_began {
            self.hid_began = Some(began + gap);
            println!(
                "[smush_info] replay auto-save: paused {}ms (HOME/suspend)",
                gap.as_millis()
            );
        }
    }
}

lazy_static::lazy_static! {
    static ref STATE: Mutex<DumpState> = Mutex::new(DumpState::new());
}

fn lock_state() -> std::sync::MutexGuard<'static, DumpState> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn path_from_ptr(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { skyline::from_c_str(p as *const c_char) }
}

fn has_utf16_replay(buf: &[u8]) -> bool {
    if buf.len() >= 0x0C + REPLAY_UTF16.len() && &buf[0x0C..0x0C + REPLAY_UTF16.len()] == REPLAY_UTF16
    {
        return true;
    }
    buf.windows(REPLAY_UTF16.len()).any(|w| w == REPLAY_UTF16)
}

fn has_fram(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"FRAM")
}

fn magic_score(buf: &[u8]) -> u8 {
    has_utf16_replay(buf) as u8 + has_fram(buf) as u8
}

fn is_better(magic: u8, len: usize, best_magic: u8, best_len: usize) -> bool {
    magic > best_magic || (magic == best_magic && len > best_len)
}

fn eligible_path(path: &str, confirmed: bool) -> bool {
    if path.contains("smush_info") {
        return false;
    }
    if confirmed {
        return path.contains("save_data/replay");
    }
    path.contains("replay")
}

fn maybe_probe(st: &mut DumpState, path: &str, mode: i32) {
    if st.path_confirmed || !st.probe_window() {
        return;
    }
    if (mode & WRITE_BIT) == 0 {
        return;
    }
    if !(path.starts_with("save:") || path.contains("save:/") || path.contains("save:")) {
        return;
    }
    if st.probe_unique.len() < PROBE_MAX && st.probe_unique.insert(path.to_string()) {
        println!("[smush_info] fs open mode={} path={}", mode, path);
    }
    if path.contains("save_data/replay") {
        st.path_confirmed = true;
        println!("[smush_info] replay path confirmed: {}", path);
    }
}

fn apply_write(cap: &mut Capture, position: i64, data: &[u8]) {
    if position < 0 {
        return;
    }
    let start = position as usize;
    if start >= CAP_BYTES {
        cap.truncated = true;
        return;
    }
    let max_copy = CAP_BYTES.saturating_sub(start);
    let copy_len = data.len().min(max_copy);
    if copy_len < data.len() {
        cap.truncated = true;
    }
    let end = start + copy_len;
    if cap.buf.len() < end {
        cap.buf.resize(end, 0);
    }
    cap.buf[start..end].copy_from_slice(&data[..copy_len]);
}

fn apply_set_size(cap: &mut Capture, new_size: i64) {
    if new_size < 0 {
        return;
    }
    let n = new_size as usize;
    if n > CAP_BYTES {
        cap.truncated = true;
        cap.buf.resize(CAP_BYTES, 0);
    } else {
        cap.buf.resize(n, 0);
    }
}

fn game_version() -> String {
    let mut ver = nnsdk::oe::DisplayVersion { name: [0; 16] };
    unsafe {
        nnsdk::oe::GetDisplayVersion(&mut ver);
    }
    let n = ver.name.iter().position(|&b| b == 0).unwrap_or(ver.name.len());
    String::from_utf8_lossy(&ver.name[..n]).into_owned()
}

fn log_probe(buf: &[u8], stem: &str, truncated: bool) {
    println!(
        "[smush_info] replay dump {} bytes={} truncated={} replay_utf16={} fram={} version={}",
        stem,
        buf.len(),
        truncated,
        has_utf16_replay(buf),
        has_fram(buf),
        game_version()
    );
}

fn emit_bin(stem: &str, cap: &Capture) -> bool {
    log_probe(&cap.buf, stem, cap.truncated);
    results_log::write_replay(stem, &cap.buf)
}

fn pick_best(files: &[Capture]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, f) in files.iter().enumerate() {
        match best {
            None => best = Some(i),
            Some(b) => {
                let bm = magic_score(&files[b].buf);
                let im = magic_score(&f.buf);
                if is_better(im, f.buf.len(), bm, files[b].buf.len()) {
                    best = Some(i);
                }
            }
        }
    }
    best
}

#[inline(never)]
pub fn on_json_written(stem: String) {
    let mut to_write: Option<(String, Capture)> = None;
    {
        let mut st = lock_state();
        match &mut st.pair {
            Pair::Idle => {
                st.pair = Pair::Pending {
                    stem,
                    wrote_bin: false,
                    best_magic: 0,
                    best_len: 0,
                };
            }
            Pair::Pending { .. } => {}
            Pair::Orphan { files } => {
                let mut files = std::mem::take(files);
                if let Some(i) = pick_best(&files) {
                    for (j, f) in files.iter().enumerate() {
                        if j != i {
                            println!(
                                "[smush_info] replay extra path={} bytes={}",
                                f.path,
                                f.buf.len()
                            );
                        }
                    }
                    let cap = files.swap_remove(i);
                    let magic = magic_score(&cap.buf);
                    let len = cap.buf.len();
                    to_write = Some((stem.clone(), cap));
                    st.pair = Pair::Pending {
                        stem,
                        wrote_bin: false,
                        best_magic: magic,
                        best_len: len,
                    };
                } else {
                    st.pair = Pair::Pending {
                        stem,
                        wrote_bin: false,
                        best_magic: 0,
                        best_len: 0,
                    };
                }
            }
        }
    }
    if let Some((stem, cap)) = to_write {
        let ok = emit_bin(&stem, &cap);
        if ok {
            let mut st = lock_state();
            if let Pair::Pending {
                stem: s, wrote_bin, ..
            } = &mut st.pair
            {
                if s == &stem {
                    *wrote_bin = true;
                }
            }
        }
    }
}

#[inline(never)]
pub fn on_match_rising() {
    let mut st = lock_state();
    match &st.pair {
        Pair::Pending { stem, wrote_bin, .. } if !wrote_bin => {
            println!("[smush_info] replay dump missed for {}", stem);
        }
        Pair::Orphan { .. } => {
            println!("[smush_info] replay dump missed (orphan, no json)");
        }
        _ => {}
    }
    st.pair = Pair::Idle;
    st.results = false;
    st.reset_hid();
}

#[inline(never)]
pub fn set_results(is_results: bool) {
    let mut st = lock_state();
    if crate::overrides::hid_enabled() && is_results && !st.results {
        st.begin_hid_session();
    }
    st.results = is_results;
    if st.hid_session {
        if let Some(t) = st.hid_began {
            hid_store_elapsed(Instant::now().saturating_duration_since(t).as_millis());
        }
    } else {
        hid_store_elapsed(0);
    }
}

fn finish_close(cap: Capture) {
    let mut emit: Option<(String, Capture)> = None;
    {
        let mut st = lock_state();
        match &mut st.pair {
            Pair::Idle => {
                st.pair = Pair::Orphan { files: vec![cap] };
            }
            Pair::Orphan { files } => {
                files.push(cap);
            }
            Pair::Pending {
                stem,
                wrote_bin,
                best_magic,
                best_len,
            } => {
                let magic = magic_score(&cap.buf);
                let len = cap.buf.len();
                let better = is_better(magic, len, *best_magic, *best_len);
                if *wrote_bin && !better {
                    println!(
                        "[smush_info] replay extra path={} bytes={}",
                        cap.path,
                        cap.buf.len()
                    );
                } else {
                    *best_magic = magic;
                    *best_len = len;
                    emit = Some((stem.clone(), cap));
                }
            }
        }
    }
    if let Some((stem, cap)) = emit {
        let truncated = cap.truncated;
        let ok = emit_bin(&stem, &cap);
        if ok {
            let mut st = lock_state();
            if let Pair::Pending {
                stem: s,
                wrote_bin,
                ..
            } = &mut st.pair
            {
                if s == &stem {
                    *wrote_bin = true;
                    if truncated {
                        println!(
                            "[smush_info] replay dump truncated {} cap=8MiB",
                            s
                        );
                    }
                }
            }
        }
    }
}

const KEY_A: u64 = 1;
const KEY_Y: u64 = 1 << 3;
const KEY_RIGHT: u64 = 1 << 14;
const NPAD_P1: u32 = 0;
const NPAD_HANDHELD: u32 = 0x20;
const HID_ANIM_MS: u128 = 8000;
const HID_SUSPEND_GAP_MS: u128 = 1000;
const OE_FOCUS_OUT: i32 = 2;
const OE_FOCUS_BG: i32 = 3;
const HID_PULSE_MS: u128 = 100;
const HID_GAP_MS: u128 = 250;
const HID_VAULT_MS: u128 = 2000;
const HID_EXIT_MS: u128 = 8000;
const HID_SAVE_MS: u128 = (HID_PULSE_MS + HID_GAP_MS) * 6;

fn npad_id(id: *const u32) -> u32 {
    if id.is_null() {
        0
    } else {
        unsafe { *id }
    }
}

fn is_save_pad(id: u32) -> bool {
    id == NPAD_P1 || id == NPAD_HANDHELD
}

fn hid_exit_a(ms: u128) -> u64 {
    let cycle = HID_PULSE_MS + HID_GAP_MS;
    if (ms % cycle) < HID_PULSE_MS {
        KEY_A
    } else {
        0
    }
}

fn hid_save_buttons(ms: u128) -> u64 {
    let steps: [(u64, u128); 6] = [
        (KEY_A, HID_GAP_MS),
        (KEY_A, HID_GAP_MS),
        (KEY_Y, HID_GAP_MS),
        (KEY_RIGHT, HID_GAP_MS),
        (KEY_A, HID_GAP_MS),
        (KEY_A, HID_GAP_MS),
    ];
    let mut t = 0u128;
    for (btn, gap) in steps {
        if (t..t + HID_PULSE_MS).contains(&ms) {
            return btn;
        }
        t += HID_PULSE_MS + gap;
    }
    0
}

fn hid_save_ms() -> u128 {
    if crate::overrides::replay_save() {
        HID_SAVE_MS
    } else {
        0
    }
}

fn hid_vault_ms() -> u128 {
    if crate::overrides::replay_save() {
        HID_VAULT_MS
    } else {
        0
    }
}

fn hid_buttons_for_pad(action_ms: u128, pad: u32, wrote: bool) -> Option<u64> {
    let save_ms = hid_save_ms();
    let vault_ms = hid_vault_ms();
    let skip = crate::overrides::results_skip();
    if action_ms < save_ms {
        if is_save_pad(pad) {
            Some(hid_save_buttons(action_ms))
        } else {
            Some(0)
        }
    } else {
        let after_save = action_ms - save_ms;
        if crate::overrides::replay_save() && !wrote && after_save < vault_ms {
            Some(0)
        } else if skip {
            let exit_ms = if crate::overrides::replay_save() && !wrote {
                after_save - vault_ms
            } else {
                after_save
            };
            if exit_ms >= HID_EXIT_MS {
                None
            } else {
                Some(hid_exit_a(exit_ms))
            }
        } else {
            None
        }
    }
}

fn hid_info() -> &'static smush_info_shared::Info {
    &crate::GAME_INFO
}

fn hid_store_elapsed(ms: u128) {
    hid_info()
        .hid_elapsed_ms
        .store(ms.min(u128::from(u32::MAX)) as u32, Ordering::Relaxed);
}

unsafe fn mask_npad(state: *mut NpadHandheldState, buttons: u64) {
    if state.is_null() {
        return;
    }
    (*state).Buttons = buttons;
    (*state).LStickX = 0;
    (*state).LStickY = 0;
    (*state).RStickX = 0;
    (*state).RStickY = 0;
}

fn hid_count(count: i32) -> usize {
    count.clamp(0, 16) as usize
}

fn note_npad_hit() {
    hid_info().hid_npad_hits.fetch_add(1, Ordering::Relaxed);
}

fn apply_mask_npads(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    let Some(buttons) = hid_mask_buttons(npad_id(id)) else {
        hid_info().hid_masking.store(false, Ordering::Relaxed);
        return;
    };
    hid_info().hid_masking.store(true, Ordering::Relaxed);
    let n = hid_count(count);
    unsafe {
        for i in 0..n {
            mask_npad(state.add(i), buttons);
        }
    }
}

fn apply_mask_gc(state: *mut NpadGcState, count: i32, id: *const u32) {
    let Some(buttons) = hid_mask_buttons(npad_id(id)) else {
        hid_info().hid_masking.store(false, Ordering::Relaxed);
        return;
    };
    hid_info().hid_masking.store(true, Ordering::Relaxed);
    let n = hid_count(count);
    unsafe {
        for i in 0..n {
            let p = state.add(i);
            mask_npad(p as *mut NpadHandheldState, buttons);
            (*p).LTrigger = 0;
            (*p).RTrigger = 0;
        }
    }
}

static ORIG_STATE: [AtomicPtr<()>; 6] = [
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
];
static ORIG_STATES: [AtomicPtr<()>; 6] = [
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
];

unsafe fn call_orig_state(idx: usize, state: *mut NpadHandheldState, id: *const u32) {
    let p = ORIG_STATE[idx].load(Ordering::Relaxed);
    if p.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(*mut NpadHandheldState, *const u32) = std::mem::transmute(p);
    f(state, id);
}

unsafe fn call_orig_states(idx: usize, state: *mut NpadHandheldState, count: i32, id: *const u32) {
    let p = ORIG_STATES[idx].load(Ordering::Relaxed);
    if p.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(*mut NpadHandheldState, i32, *const u32) = std::mem::transmute(p);
    f(state, count, id);
}

unsafe extern "C" fn hook_state_hh(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(0, state, id);
    apply_mask_npads(state, 1, id);
}
unsafe extern "C" fn hook_state_fk(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(1, state, id);
    apply_mask_npads(state, 1, id);
}
unsafe extern "C" fn hook_state_gc(state: *mut NpadGcState, id: *const u32) {
    note_npad_hit();
    let p = ORIG_STATE[2].load(Ordering::Relaxed);
    if !p.is_null() {
        let f: unsafe extern "C" fn(*mut NpadGcState, *const u32) = std::mem::transmute(p);
        f(state, id);
    }
    apply_mask_gc(state, 1, id);
}
unsafe extern "C" fn hook_state_jd(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(3, state, id);
    apply_mask_npads(state, 1, id);
}
unsafe extern "C" fn hook_state_jl(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(4, state, id);
    apply_mask_npads(state, 1, id);
}
unsafe extern "C" fn hook_state_jr(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(5, state, id);
    apply_mask_npads(state, 1, id);
}

unsafe extern "C" fn hook_states_hh(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(0, state, count, id);
    apply_mask_npads(state, count, id);
}
unsafe extern "C" fn hook_states_fk(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(1, state, count, id);
    apply_mask_npads(state, count, id);
}
unsafe extern "C" fn hook_states_gc(state: *mut NpadGcState, count: i32, id: *const u32) {
    note_npad_hit();
    let p = ORIG_STATES[2].load(Ordering::Relaxed);
    if !p.is_null() {
        let f: unsafe extern "C" fn(*mut NpadGcState, i32, *const u32) = std::mem::transmute(p);
        f(state, count, id);
    }
    apply_mask_gc(state, count, id);
}
unsafe extern "C" fn hook_states_jd(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(3, state, count, id);
    apply_mask_npads(state, count, id);
}
unsafe extern "C" fn hook_states_jl(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(4, state, count, id);
    apply_mask_npads(state, count, id);
}
unsafe extern "C" fn hook_states_jr(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(5, state, count, id);
    apply_mask_npads(state, count, id);
}

fn hook_abs(sym: &[u8], replace: *const c_void, orig: &AtomicPtr<()>) -> bool {
    unsafe {
        let mut addr: usize = 0;
        skyline::nn::ro::LookupSymbol(&mut addr, sym.as_ptr());
        if addr == 0 {
            return false;
        }
        let mut temp: *mut c_void = std::ptr::null_mut();
        A64HookFunction(addr as *const c_void, replace, &mut temp);
        orig.store(temp as *mut (), Ordering::SeqCst);
        true
    }
}

fn install_npad_abs_hooks() {
    let mut n = 0u32;
    let state: [(&[u8], *const (), usize); 6] = [
        (b"_ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj\0", hook_state_hh as *const (), 0),
        (b"_ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj\0", hook_state_fk as *const (), 1),
        (b"_ZN2nn3hid12GetNpadStateEPNS0_11NpadGcStateERKj\0", hook_state_gc as *const (), 2),
        (b"_ZN2nn3hid12GetNpadStateEPNS0_16NpadJoyDualStateERKj\0", hook_state_jd as *const (), 3),
        (b"_ZN2nn3hid12GetNpadStateEPNS0_16NpadJoyLeftStateERKj\0", hook_state_jl as *const (), 4),
        (b"_ZN2nn3hid12GetNpadStateEPNS0_17NpadJoyRightStateERKj\0", hook_state_jr as *const (), 5),
    ];
    let states: [(&[u8], *const (), usize); 6] = [
        (b"_ZN2nn3hid13GetNpadStatesEPNS0_17NpadHandheldStateEiRKj\0", hook_states_hh as *const (), 0),
        (b"_ZN2nn3hid13GetNpadStatesEPNS0_16NpadFullKeyStateEiRKj\0", hook_states_fk as *const (), 1),
        (b"_ZN2nn3hid13GetNpadStatesEPNS0_11NpadGcStateEiRKj\0", hook_states_gc as *const (), 2),
        (b"_ZN2nn3hid13GetNpadStatesEPNS0_16NpadJoyDualStateEiRKj\0", hook_states_jd as *const (), 3),
        (b"_ZN2nn3hid13GetNpadStatesEPNS0_16NpadJoyLeftStateEiRKj\0", hook_states_jl as *const (), 4),
        (b"_ZN2nn3hid13GetNpadStatesEPNS0_17NpadJoyRightStateEiRKj\0", hook_states_jr as *const (), 5),
    ];
    for (sym, hk, idx) in state {
        if hook_abs(sym, hk as *const c_void, &ORIG_STATE[idx]) {
            n += 1;
        }
    }
    for (sym, hk, idx) in states {
        if hook_abs(sym, hk as *const c_void, &ORIG_STATES[idx]) {
            n += 1;
        }
    }
    hid_info().hid_hooks.store(n, Ordering::SeqCst);
    println!("[smush_info] replay auto-save HID abs hooks {}/12", n);
}

unsafe fn live_is_results() -> bool {
    if crate::FIGHTER_MANAGER_ADDR == 0 {
        return false;
    }
    let mgr = *(crate::FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager);
    if mgr.is_null() {
        return false;
    }
    FighterManager::entry_count(mgr) > 0 && FighterManager::is_result_mode(mgr)
}

fn game_unfocused() -> bool {
    let s = unsafe { nnsdk::oe::GetCurrentFocusState() };
    s == OE_FOCUS_OUT || s == OE_FOCUS_BG
}

fn hid_mask_buttons(pad: u32) -> Option<u64> {
    if !crate::overrides::hid_enabled() {
        return None;
    }
    let live = unsafe { live_is_results() };
    let mut st = lock_state();
    if live {
        st.begin_hid_session();
    } else {
        st.hid_session = false;
        st.last_hid_poll = None;
        st.hid_unfocused = false;
        hid_store_elapsed(0);
        return None;
    }
    let now = Instant::now();
    if game_unfocused() {
        if !st.hid_unfocused {
            st.hid_unfocused = true;
            println!("[smush_info] replay auto-save: unfocused, pause wait");
        }
        return Some(0);
    }
    if st.hid_unfocused {
        st.hid_unfocused = false;
    }
    st.absorb_suspend_gap(now);
    st.last_hid_poll = Some(now);
    let elapsed = st
        .hid_began
        .map(|t| Instant::now().saturating_duration_since(t).as_millis())
        .unwrap_or(0);
    hid_store_elapsed(elapsed);
    if !st.wants_hid_mask(true) {
        return None;
    }
    if elapsed < HID_ANIM_MS {
        if !st.hid_logged_wait {
            st.hid_logged_wait = true;
            println!("[smush_info] replay auto-save: mute pads, wait 8s for results UI");
        }
        return Some(0);
    }
    if !st.hid_logged_start {
        st.hid_logged_start = true;
        let save = crate::overrides::replay_save();
        let skip = crate::overrides::results_skip();
        if save && skip {
            println!("[smush_info] replay auto-save: P1 A A Y Right A A, vault wait, then exit A");
        } else if save {
            println!("[smush_info] replay auto-save: P1 A A Y Right A A, vault wait");
        } else {
            println!("[smush_info] results skip: A all pads");
        }
    }
    let action_ms = elapsed - HID_ANIM_MS;
    match hid_buttons_for_pad(action_ms, pad, st.hid_got_write()) {
        Some(buttons) => Some(buttons),
        None => {
            st.hid_released = true;
            println!("[smush_info] replay auto-save hid done; pads live");
            None
        }
    }
}

pub fn install() {
    if crate::overrides::replay_save() {
        skyline::install_hooks!(
            open_file_hook,
            write_file_hook,
            set_file_size_hook,
            close_file_hook
        );
    } else {
        println!("[smush_info] replay save disabled, skip FS dump hooks");
    }
    if crate::overrides::hid_enabled() {
        install_npad_abs_hooks();
    } else {
        println!("[smush_info] HID results seq disabled");
    }
}

#[skyline::hook(replace = nnsdk::fs::OpenFile)]
#[inline(never)]
pub fn open_file_hook(
    handle: *mut nnsdk::fs::FileHandle,
    path: *const u8,
    mode: i32,
) -> u32 {
    let rc = call_original!(handle, path, mode);
    let path_s = path_from_ptr(path);
    let h = if handle.is_null() {
        0
    } else {
        unsafe { (*handle).handle }
    };
    {
        let mut st = lock_state();
        maybe_probe(&mut st, &path_s, mode);
        if rc == 0
            && h != 0
            && (mode & WRITE_BIT) != 0
            && eligible_path(&path_s, st.path_confirmed)
        {
            st.captures.insert(
                h,
                Capture {
                    path: path_s,
                    buf: Vec::new(),
                    truncated: false,
                },
            );
        }
    }
    rc
}

#[skyline::hook(replace = nnsdk::fs::WriteFile)]
#[inline(never)]
pub fn write_file_hook(
    handle: nnsdk::fs::FileHandle,
    file_offset: i64,
    buff: *const u8,
    size: u64,
    option: *const nnsdk::fs::WriteOption,
) -> u32 {
    let rc = call_original!(handle, file_offset, buff, size, option);
    if !buff.is_null() && size > 0 {
        let data = unsafe { std::slice::from_raw_parts(buff, size as usize) };
        let mut st = lock_state();
        if let Some(cap) = st.captures.get_mut(&handle.handle) {
            apply_write(cap, file_offset, data);
        }
    }
    rc
}

#[skyline::hook(replace = nnsdk::fs::SetFileSize)]
#[inline(never)]
pub fn set_file_size_hook(handle: nnsdk::fs::FileHandle, filesize: i64) -> u32 {
    let rc = call_original!(handle, filesize);
    let mut st = lock_state();
    if let Some(cap) = st.captures.get_mut(&handle.handle) {
        apply_set_size(cap, filesize);
    }
    rc
}

#[skyline::hook(replace = nnsdk::fs::CloseFile)]
#[inline(never)]
pub fn close_file_hook(handle: nnsdk::fs::FileHandle) {
    call_original!(handle);
    let cap = {
        let mut st = lock_state();
        st.captures.remove(&handle.handle)
    };
    if let Some(cap) = cap {
        finish_close(cap);
    }
}
