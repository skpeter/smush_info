use crate::results_log;
use smush_info_shared::hid_route::{
    observe_save_silence, restart_save_clock_on_retarget, takes_save_press, PadKind,
    SAVE_PAD_SILENT_POLLS, STYLE_FULL, STYLE_FULLKEY, STYLE_GC, STYLE_HANDHELD, STYLE_JOYDUAL,
    STYLE_JOYLEFT, STYLE_JOYRIGHT, STYLE_SINGLE,
};
use skyline::hooks::A64HookFunction;
use skyline::libc::{c_char, c_void};
use skyline::nn::hid::{NpadGcState, NpadHandheldState};
use smash::app::{self, lua_bind::FighterManager};
use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const CAP_BYTES: usize = 8 * 1024 * 1024;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum HidPhase {
    Anim,
    WaitPad,
    Save,
    DumpWait,
    Back,
    Skip,
    Done,
}

struct DumpState {
    captures: HashMap<u64, Capture>,
    pair: Pair,
    path_confirmed: bool,
    results: bool,
    hid_began: Option<Instant>,
    last_hid_poll: Option<Instant>,
    hid_released: bool,
    hid_session: bool,
    hid_unfocused: bool,
    save_npad: Option<u32>,
    /// Primary-style polls of other pads since the game last polled `save_npad`.
    /// A slot the game never polls is a ghost: its style bits stay set and the
    /// pick keeps choosing it. Joy polls of a Pro do not count.
    save_pad_polls: u32,
    hid_phase: HidPhase,
    phase_began: Option<Instant>,
    save_attempts: u8,
    logged_live_drop: bool,
    logged_wait_write: bool,
    logged_wait_pad: bool,
}

impl DumpState {
    fn new() -> Self {
        Self {
            captures: HashMap::new(),
            pair: Pair::Idle,
            path_confirmed: false,
            results: false,
            hid_began: None,
            last_hid_poll: None,
            hid_released: false,
            hid_session: false,
            hid_unfocused: false,
            save_npad: None,
            save_pad_polls: 0,
            hid_phase: HidPhase::Anim,
            phase_began: None,
            save_attempts: 0,
            logged_live_drop: false,
            logged_wait_write: false,
            logged_wait_pad: false,
        }
    }

    fn dump_ok(&self) -> bool {
        matches!(
            self.pair,
            Pair::Pending {
                wrote_bin: true,
                ..
            }
        )
    }

    fn probe_window(&self) -> bool {
        self.results
            || matches!(self.pair, Pair::Pending { .. } | Pair::Orphan { .. })
    }

    fn wants_hid_mask(&self) -> bool {
        self.hid_session && !self.hid_released
    }

    fn reset_hid(&mut self) {
        self.hid_began = None;
        self.last_hid_poll = None;
        self.hid_released = false;
        self.hid_session = false;
        self.hid_unfocused = false;
        self.save_npad = None;
        self.save_pad_polls = 0;
        self.hid_phase = HidPhase::Anim;
        self.phase_began = None;
        self.save_attempts = 0;
        self.logged_live_drop = false;
        self.logged_wait_write = false;
        self.logged_wait_pad = false;
    }

    fn begin_hid_session(&mut self) {
        // One session per match. `hid_released` only clears on
        // `on_match_rising`. Without this, one poll with is_result_mode
        // false (save dialog, player poking the menu after pads went live)
        // drops `hid_session`, the next live poll starts a fresh session,
        // and results gets muted for another 7.5s + save attempts. The 60s
        // cap is per session, so that loop never ends.
        if self.hid_session || self.hid_released {
            return;
        }
        self.reset_hid();
        self.hid_session = true;
        self.save_npad = pick_save_npad();
        let now = Instant::now();
        self.hid_began = Some(now);
        self.last_hid_poll = Some(now);
        self.phase_began = Some(now);
        self.hid_phase = HidPhase::Anim;
        self.save_attempts = 0;
    }

    fn set_phase(&mut self, phase: HidPhase, now: Instant) {
        if phase != HidPhase::DumpWait {
            self.logged_wait_write = false;
        }
        self.hid_phase = phase;
        self.phase_began = Some(now);
    }

    fn pause_phase_clock(&mut self, gap: std::time::Duration) {
        let Some(phase_t) = self.phase_began else {
            return;
        };
        self.phase_began = Some(phase_t.checked_add(gap).unwrap_or(phase_t));
    }

    fn absorb_suspend_gap(&mut self, now: Instant) {
        let Some(last) = self.last_hid_poll else {
            return;
        };
        let gap = now.saturating_duration_since(last);
        if gap.as_millis() < HID_SUSPEND_GAP_MS {
            return;
        }
        // Hitch or save UI can pause pad polls. Hold the button clock;
        // replaying A A Y on a half-open dialog cancels it.
        self.pause_phase_clock(gap);
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
    if path.contains("save_data/replay") {
        st.path_confirmed = true;
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

fn emit_bin(stem: &str, cap: &Capture) -> bool {
    if cap.truncated {
        return false;
    }
    if magic_score(&cap.buf) < 2 {
        return false;
    }
    let ok = results_log::write_replay(stem, &cap.path, &cap.buf);
    if ok {
        delete_vault_after_export(&cap.path);
    }
    ok
}

fn vault_path_ok(path: &str) -> bool {
    !path.is_empty()
        && !path.contains("smush_info")
        && path.contains("save_data/replay")
}

static DELETE_FILE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

fn delete_file_fn() -> Option<unsafe extern "C" fn(*const u8) -> u32> {
    let mut p = DELETE_FILE.load(Ordering::Relaxed);
    if p.is_null() {
        let mut addr: usize = 0;
        unsafe {
            skyline::nn::ro::LookupSymbol(&mut addr, b"_ZN2nn2fs10DeleteFileEPKc\0".as_ptr());
        }
        if addr == 0 {
            return None;
        }
        p = addr as *mut ();
        DELETE_FILE.store(p, Ordering::Relaxed);
    }
    Some(unsafe { std::mem::transmute(p) })
}

fn delete_vault_after_export(path: &str) {
    if !crate::overrides::replay_save() {
        return;
    }
    if !vault_path_ok(path) {
        return;
    }
    let Some(delete_file) = delete_file_fn() else {
        return;
    };
    let mut bytes = path.as_bytes().to_vec();
    if bytes.last().copied() != Some(0) {
        bytes.push(0);
    }
    let rc = unsafe { delete_file(bytes.as_ptr()) };
    let _ = rc;
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
                if !(*wrote_bin && !better) {
                    *best_magic = magic;
                    *best_len = len;
                    emit = Some((stem.clone(), cap));
                }
            }
        }
    }
    if let Some((stem, cap)) = emit {
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
                }
            }
        }
    }
}

const KEY_A: u64 = 1;
const KEY_B: u64 = 1 << 1;
const KEY_X: u64 = 1 << 2;
const KEY_Y: u64 = 1 << 3;
const KEY_LEFT: u64 = 1 << 12;
const KEY_UP: u64 = 1 << 13;
const KEY_RIGHT: u64 = 1 << 14;
const KEY_DOWN: u64 = 1 << 15;
const KEY_LEFT_SL: u64 = 1 << 24;
const KEY_LEFT_SR: u64 = 1 << 25;
const KEY_RIGHT_SL: u64 = 1 << 26;
const KEY_RIGHT_SR: u64 = 1 << 27;
const NPAD_HANDHELD: u32 = 0x20;
const NPAD_ATTR_CONNECTED: u32 = 1;
const STICK_MAX: i32 = 28000;
const HID_ANIM_MS: u128 = 7500;
const HID_SUSPEND_GAP_MS: u128 = 1000;
const OE_FOCUS_OUT: i32 = 2;
const OE_FOCUS_BG: i32 = 3;
const HID_PULSE_MS: u128 = 100;
const HID_GAP_MS: u128 = 340;
const HID_EXIT_MS: u128 = 3000;
const HID_SAVE_MS: u128 = (HID_PULSE_MS + HID_GAP_MS) * 5;
const HID_DUMP_WAIT_MS: u128 = 6000;
const HID_BACK_MS: u128 = HID_PULSE_MS + HID_GAP_MS * 2;
const HID_MAX_SAVE_ATTEMPTS: u8 = 3;
const HID_SESSION_MAX_MS: u128 = 60_000;
/// Other-pad primary-style polls with no poll of the save slot before we drop it.
/// JoyLeft/JoyRight polls of a Pro do not count: one other Pro at 60Hz is ~1s.
const HID_SAVE_PAD_SILENT_POLLS: u32 = SAVE_PAD_SILENT_POLLS;

fn hid_phase_name(phase: HidPhase) -> &'static str {
    match phase {
        HidPhase::Anim => "anim",
        HidPhase::WaitPad => "wait_pad",
        HidPhase::Save => "save",
        HidPhase::DumpWait => "dump_wait",
        HidPhase::Back => "back",
        HidPhase::Skip => "skip",
        HidPhase::Done => "done",
    }
}

fn npad_id(id: *const u32) -> u32 {
    if id.is_null() {
        0
    } else {
        unsafe { *id }
    }
}

/// Per-npad styles seen connected, from the states the game actually polls.
/// Index 8 is the handheld npad. Each style keeps its own bit: a GC pad is
/// polled as both Gc and FullKey, and every pad gets polled as JoyLeft /
/// JoyRight too, so one style must never clear another.
static PAD_STYLES: [AtomicU32; 9] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

fn pad_slot(id: u32) -> Option<usize> {
    if id == NPAD_HANDHELD {
        Some(8)
    } else if id < 8 {
        Some(id as usize)
    } else {
        None
    }
}

fn slot_npad(slot: usize) -> u32 {
    if slot == 8 {
        NPAD_HANDHELD
    } else {
        slot as u32
    }
}

fn note_polled_pad(id: u32, kind: PadKind, flags: u32) {
    let Some(slot) = pad_slot(id) else {
        return;
    };
    let bit = kind.style_bit();
    if (flags & NPAD_ATTR_CONNECTED) != 0 {
        PAD_STYLES[slot].fetch_or(bit, Ordering::Relaxed);
    } else {
        PAD_STYLES[slot].fetch_and(!bit, Ordering::Relaxed);
    }
}

fn pad_styles(id: u32) -> u32 {
    pad_slot(id).map_or(0, |slot| PAD_STYLES[slot].load(Ordering::Relaxed))
}

fn npad_can_save(id: u32) -> bool {
    pad_styles(id) & (STYLE_FULL | STYLE_SINGLE) != 0
}

/// Pro / dual / handheld / GC can drive the whole menu. A lone Joy-Con only
/// gets picked when nothing better is connected.
fn pick_save_npad() -> Option<u32> {
    let mut single = None;
    for slot in 0..PAD_STYLES.len() {
        let styles = PAD_STYLES[slot].load(Ordering::Relaxed);
        if styles & STYLE_FULL != 0 {
            return Some(slot_npad(slot));
        }
        if single.is_none() && styles & STYLE_SINGLE != 0 {
            single = Some(slot_npad(slot));
        }
    }
    single
}

fn style_names(styles: u32) -> String {
    const NAMES: [(u32, &str); 6] = [
        (STYLE_FULLKEY, "pro"),
        (STYLE_HANDHELD, "handheld"),
        (STYLE_JOYDUAL, "dual"),
        (STYLE_JOYLEFT, "joyl"),
        (STYLE_JOYRIGHT, "joyr"),
        (STYLE_GC, "gc"),
    ];
    let mut out = String::new();
    for (bit, name) in NAMES {
        if styles & bit != 0 {
            if !out.is_empty() {
                out.push('|');
            }
            out.push_str(name);
        }
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

fn log_pad_inventory() {
    for slot in 0..PAD_STYLES.len() {
        let styles = PAD_STYLES[slot].load(Ordering::Relaxed);
        if styles != 0 {
            println!(
                "[smush_info] hid: pad {:#x} styles {}",
                slot_npad(slot),
                style_names(styles)
            );
        }
    }
}

/// Returns true when the save pad changed, so the caller can restart the
/// tap sequence on the new pad instead of feeding it the tail end.
fn refresh_save_npad(st: &mut DumpState) -> bool {
    if let Some(id) = st.save_npad {
        if st.save_pad_polls >= HID_SAVE_PAD_SILENT_POLLS {
            // PAD_STYLES only clears a style when the game polls that id
            // with that style and gets "not connected". A pad that left
            // (unplugged, re-paired under another id) stops being polled
            // at all, so its bits go stale and pick_save_npad keeps
            // choosing a ghost. Forget it so the pick moves on.
            println!(
                "[smush_info] hid: save pad {:#x} not polled for {} polls, drop",
                id, st.save_pad_polls
            );
            if let Some(slot) = pad_slot(id) {
                PAD_STYLES[slot].store(0, Ordering::Relaxed);
            }
            st.save_npad = None;
        } else if npad_can_save(id) {
            return false;
        }
    }
    let next = pick_save_npad();
    st.save_pad_polls = 0;
    if next == st.save_npad {
        return false;
    }
    match next {
        Some(id) => println!(
            "[smush_info] hid: save pad {:?} -> {:#x} ({})",
            st.save_npad,
            id,
            style_names(pad_styles(id))
        ),
        None => println!("[smush_info] hid: save pad {:?} -> none", st.save_npad),
    }
    st.save_npad = next;
    true
}

fn is_save_pad(id: u32, save_npad: Option<u32>) -> bool {
    match save_npad {
        Some(s) => id == s,
        None => false,
    }
}

fn any_full_pad() -> bool {
    PAD_STYLES
        .iter()
        .any(|s| s.load(Ordering::Relaxed) & STYLE_FULL != 0)
}

fn full_pad_count() -> usize {
    PAD_STYLES
        .iter()
        .filter(|s| s.load(Ordering::Relaxed) & STYLE_FULL != 0)
        .count()
}

fn pad_gets_macro(pad: u32, kind: PadKind, save_npad: Option<u32>) -> bool {
    takes_save_press(
        pad_styles(pad),
        kind,
        any_full_pad(),
        is_save_pad(pad, save_npad),
    )
}

fn note_replay_saved(skip: bool) {
    if skip {
        println!("[smush_info] hid: replay saved to sd, skipping results");
    } else {
        println!("[smush_info] hid: replay saved to sd, results left up");
    }
}

fn hid_exit_buttons(kind: PadKind, ms: u128) -> u64 {
    let cycle = HID_PULSE_MS + HID_GAP_MS;
    if (ms % cycle) >= HID_PULSE_MS {
        return 0;
    }
    match kind {
        PadKind::JoyLeft => KEY_A | KEY_LEFT | KEY_RIGHT | KEY_UP | KEY_DOWN | KEY_LEFT_SL | KEY_LEFT_SR,
        PadKind::JoyRight => KEY_A | KEY_B | KEY_X | KEY_Y | KEY_RIGHT_SL | KEY_RIGHT_SR,
        _ => KEY_A,
    }
}

#[derive(Clone, Copy)]
struct HidOut {
    buttons: u64,
    stick_x: i32,
}

impl HidOut {
    const MUTE: Self = Self {
        buttons: 0,
        stick_x: 0,
    };

    fn buttons(buttons: u64) -> Self {
        Self {
            buttons,
            stick_x: 0,
        }
    }
}

enum HidAction {
    /// Overwrite this poll's state with our own buttons/stick.
    Mask(HidOut),
    /// Leave the poll alone: the player keeps full control.
    Pass,
    /// Leave the poll alone and end the session.
    Release,
}

/// A lone Joy-Con held sideways has no d-pad, so menu Right comes from the
/// stick. The left Joy-Con's four buttons sit where the right one's face
/// buttons are: Right=A, Down=B, Up=X, Left=Y.
fn hid_map_logical(kind: PadKind, logical: u64) -> HidOut {
    if !matches!(kind, PadKind::JoyLeft | PadKind::JoyRight) {
        return HidOut::buttons(logical);
    }
    if logical & KEY_RIGHT != 0 {
        return HidOut {
            buttons: 0,
            stick_x: STICK_MAX,
        };
    }
    if kind == PadKind::JoyRight {
        return HidOut::buttons(logical);
    }
    let mut buttons = 0u64;
    if logical & KEY_A != 0 {
        buttons |= KEY_RIGHT;
    }
    if logical & KEY_B != 0 {
        buttons |= KEY_DOWN;
    }
    if logical & KEY_X != 0 {
        buttons |= KEY_UP;
    }
    if logical & KEY_Y != 0 {
        buttons |= KEY_LEFT;
    }
    HidOut::buttons(buttons)
}

fn hid_save_buttons(ms: u128) -> u64 {
    let steps: [(u64, u128); 5] = [
        (KEY_A, HID_GAP_MS),
        (KEY_A, HID_GAP_MS),
        (KEY_Y, HID_GAP_MS),
        (KEY_RIGHT, HID_GAP_MS),
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

fn hid_back_buttons(ms: u128) -> u64 {
    if ms < HID_PULSE_MS {
        KEY_B
    } else {
        0
    }
}

fn hid_buttons_for_pad(
    phase: HidPhase,
    phase_ms: u128,
    pad: u32,
    kind: PadKind,
    save_npad: Option<u32>,
) -> HidAction {
    match phase {
        HidPhase::Anim | HidPhase::DumpWait => HidAction::Mask(HidOut::MUTE),
        // Nothing we can drive, so muting would only trap the players here.
        HidPhase::WaitPad => HidAction::Pass,
        HidPhase::Save => {
            if pad_gets_macro(pad, kind, save_npad) {
                HidAction::Mask(hid_map_logical(kind, hid_save_buttons(phase_ms)))
            } else {
                HidAction::Mask(HidOut::MUTE)
            }
        }
        HidPhase::Back => {
            if pad_gets_macro(pad, kind, save_npad) {
                HidAction::Mask(hid_map_logical(kind, hid_back_buttons(phase_ms)))
            } else {
                HidAction::Mask(HidOut::MUTE)
            }
        }
        HidPhase::Skip => {
            if crate::overrides::results_skip() {
                HidAction::Mask(HidOut::buttons(hid_exit_buttons(kind, phase_ms)))
            } else {
                HidAction::Release
            }
        }
        HidPhase::Done => HidAction::Release,
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

unsafe fn mask_npad(state: *mut NpadHandheldState, out: HidOut) {
    if state.is_null() {
        return;
    }
    (*state).Buttons = out.buttons;
    (*state).LStickX = out.stick_x;
    (*state).LStickY = 0;
    (*state).RStickX = out.stick_x;
    (*state).RStickY = 0;
}

fn hid_count(count: i32) -> usize {
    count.clamp(0, 16) as usize
}

fn note_npad_hit() {
    hid_info().hid_npad_hits.fetch_add(1, Ordering::Relaxed);
}

fn apply_mask_npads(state: *mut NpadHandheldState, count: i32, id: *const u32, kind: PadKind) {
    let pad = npad_id(id);
    if !state.is_null() {
        note_polled_pad(pad, kind, unsafe { (*state).Flags });
    }
    let HidAction::Mask(out) = hid_mask_buttons(pad, kind) else {
        hid_info().hid_masking.store(false, Ordering::Relaxed);
        return;
    };
    hid_info().hid_masking.store(true, Ordering::Relaxed);
    let n = hid_count(count);
    unsafe {
        for i in 0..n {
            mask_npad(state.add(i), out);
        }
    }
}

fn apply_mask_gc(state: *mut NpadGcState, count: i32, id: *const u32) {
    let pad = npad_id(id);
    if !state.is_null() {
        note_polled_pad(pad, PadKind::Gc, unsafe { (*state).Flags });
    }
    let HidAction::Mask(out) = hid_mask_buttons(pad, PadKind::Gc) else {
        hid_info().hid_masking.store(false, Ordering::Relaxed);
        return;
    };
    hid_info().hid_masking.store(true, Ordering::Relaxed);
    let n = hid_count(count);
    unsafe {
        for i in 0..n {
            let p = state.add(i);
            mask_npad(p as *mut NpadHandheldState, out);
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
    apply_mask_npads(state, 1, id, PadKind::Handheld);
}
unsafe extern "C" fn hook_state_fk(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(1, state, id);
    apply_mask_npads(state, 1, id, PadKind::FullKey);
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
    apply_mask_npads(state, 1, id, PadKind::JoyDual);
}
unsafe extern "C" fn hook_state_jl(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(4, state, id);
    apply_mask_npads(state, 1, id, PadKind::JoyLeft);
}
unsafe extern "C" fn hook_state_jr(state: *mut NpadHandheldState, id: *const u32) {
    note_npad_hit();
    call_orig_state(5, state, id);
    apply_mask_npads(state, 1, id, PadKind::JoyRight);
}

unsafe extern "C" fn hook_states_hh(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(0, state, count, id);
    apply_mask_npads(state, count, id, PadKind::Handheld);
}
unsafe extern "C" fn hook_states_fk(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(1, state, count, id);
    apply_mask_npads(state, count, id, PadKind::FullKey);
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
    apply_mask_npads(state, count, id, PadKind::JoyDual);
}
unsafe extern "C" fn hook_states_jl(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(4, state, count, id);
    apply_mask_npads(state, count, id, PadKind::JoyLeft);
}
unsafe extern "C" fn hook_states_jr(state: *mut NpadHandheldState, count: i32, id: *const u32) {
    note_npad_hit();
    call_orig_states(5, state, count, id);
    apply_mask_npads(state, count, id, PadKind::JoyRight);
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
    println!("[smush_info] hid: {}/12 npad hooks installed", n);
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

fn hid_mask_buttons(pad: u32, kind: PadKind) -> HidAction {
    if !crate::overrides::hid_enabled() {
        return HidAction::Pass;
    }
    let live = unsafe { live_is_results() };
    let mut st = lock_state();
    if live {
        st.logged_live_drop = false;
        st.begin_hid_session();
    } else if st.wants_hid_mask() {
        // Save Yes dialog often clears is_result_mode. Aborting here
        // drops the seq mid-press and leaves results with no skip.
        if !st.logged_live_drop {
            st.logged_live_drop = true;
            println!(
                "[smush_info] hid: is_result_mode false during {}, keep seq",
                hid_phase_name(st.hid_phase)
            );
        }
    } else {
        st.hid_session = false;
        st.last_hid_poll = None;
        st.hid_unfocused = false;
        hid_store_elapsed(0);
        return HidAction::Pass;
    }
    let now = Instant::now();
    if game_unfocused() {
        if let (Some(last), Some(phase_t)) = (st.last_hid_poll, st.phase_began) {
            let gap = now.saturating_duration_since(last);
            st.phase_began = Some(phase_t.checked_add(gap).unwrap_or(phase_t));
        }
        st.last_hid_poll = Some(now);
        st.hid_unfocused = true;
        return HidAction::Mask(HidOut::MUTE);
    }
    if st.hid_unfocused {
        st.hid_unfocused = false;
        if matches!(
            st.hid_phase,
            HidPhase::Save | HidPhase::DumpWait | HidPhase::Back
        ) {
            println!(
                "[smush_info] hid: HOME resume during {}, B then retry save",
                hid_phase_name(st.hid_phase)
            );
            st.set_phase(HidPhase::Back, now);
        }
    }
    st.absorb_suspend_gap(now);
    st.last_hid_poll = Some(now);
    if let Some(id) = st.save_npad {
        st.save_pad_polls = observe_save_silence(
            st.save_pad_polls,
            id == pad,
            pad_styles(pad),
            kind,
        );
    }
    let elapsed = st
        .hid_began
        .map(|t| now.saturating_duration_since(t).as_millis())
        .unwrap_or(0);
    hid_store_elapsed(elapsed);
    if !st.wants_hid_mask() {
        return HidAction::Pass;
    }
    if elapsed >= HID_SESSION_MAX_MS && st.hid_phase != HidPhase::Done {
        println!(
            "[smush_info] hid: {}ms in {}, giving pads back",
            elapsed,
            hid_phase_name(st.hid_phase)
        );
        st.set_phase(HidPhase::Done, now);
        st.hid_released = true;
        return HidAction::Release;
    }
    let mut phase_ms = st
        .phase_began
        .map(|t| now.saturating_duration_since(t).as_millis())
        .unwrap_or(0);
    let skip = crate::overrides::results_skip();
    let dump_ok = st.dump_ok();
    if matches!(st.hid_phase, HidPhase::Save | HidPhase::Back | HidPhase::WaitPad) {
        let switched = refresh_save_npad(&mut st);
        if switched
            && st.hid_phase == HidPhase::Save
            && st.save_npad.is_some()
            && restart_save_clock_on_retarget(any_full_pad())
        {
            // Lone Joy-Con remap target changed. It was not receiving the
            // earlier taps, so start A A Y over. Full slots share one clock.
            st.set_phase(HidPhase::Save, now);
            phase_ms = 0;
        }
    }
    if st.hid_phase == HidPhase::WaitPad
        || (matches!(st.hid_phase, HidPhase::Save | HidPhase::Back) && st.save_npad.is_none())
    {
        if st.save_npad.is_some() {
            st.logged_wait_pad = false;
            println!(
                "[smush_info] hid: controller showed up, save seq, full pads {}",
                full_pad_count()
            );
            st.set_phase(HidPhase::Save, now);
            phase_ms = 0;
        } else if st.hid_phase != HidPhase::WaitPad {
            if !st.logged_wait_pad {
                st.logged_wait_pad = true;
                println!("[smush_info] hid: no controller, wait for one (pads live)");
            }
            st.set_phase(HidPhase::WaitPad, now);
            phase_ms = 0;
        }
    }

    if st.hid_phase == HidPhase::Anim && phase_ms >= HID_ANIM_MS {
        if crate::overrides::replay_save() {
            log_pad_inventory();
            st.save_npad = pick_save_npad();
            st.save_pad_polls = 0;
            if let Some(id) = st.save_npad {
                println!(
                    "[smush_info] hid: save pad {:#x} ({}), full pads {}",
                    id,
                    style_names(pad_styles(id)),
                    full_pad_count()
                );
                st.set_phase(HidPhase::Save, now);
            } else {
                if !st.logged_wait_pad {
                    st.logged_wait_pad = true;
                    println!("[smush_info] hid: no controller, wait for one (pads live)");
                }
                st.set_phase(HidPhase::WaitPad, now);
            }
        } else if skip {
            st.set_phase(HidPhase::Skip, now);
        } else {
            st.set_phase(HidPhase::Done, now);
        }
        phase_ms = 0;
    }
    if st.hid_phase == HidPhase::Save && dump_ok {
        note_replay_saved(skip);
        st.set_phase(if skip { HidPhase::Skip } else { HidPhase::Done }, now);
        phase_ms = 0;
    } else if st.hid_phase == HidPhase::Save && phase_ms >= HID_SAVE_MS {
        st.set_phase(HidPhase::DumpWait, now);
        phase_ms = 0;
    }
    if st.hid_phase == HidPhase::DumpWait && dump_ok {
        note_replay_saved(skip);
        st.set_phase(if skip { HidPhase::Skip } else { HidPhase::Done }, now);
        phase_ms = 0;
    } else if st.hid_phase == HidPhase::DumpWait && phase_ms >= HID_DUMP_WAIT_MS {
        if !st.captures.is_empty() {
            if !st.logged_wait_write {
                st.logged_wait_write = true;
                println!(
                    "[smush_info] hid: dump wait, vault write still open ({})",
                    st.captures.len()
                );
            }
        } else if st.save_attempts + 1 >= HID_MAX_SAVE_ATTEMPTS {
            println!(
                "[smush_info] hid: no dump after {} attempts, pads live",
                st.save_attempts + 1
            );
            st.set_phase(HidPhase::Done, now);
            phase_ms = 0;
        } else {
            st.save_attempts = st.save_attempts.saturating_add(1);
            println!(
                "[smush_info] hid: no dump, B then retry {}/{}",
                st.save_attempts + 1,
                HID_MAX_SAVE_ATTEMPTS
            );
            st.set_phase(HidPhase::Back, now);
            phase_ms = 0;
        }
    }
    if st.hid_phase == HidPhase::Back && phase_ms >= HID_BACK_MS {
        st.set_phase(HidPhase::Save, now);
        phase_ms = 0;
    }
    if st.hid_phase == HidPhase::Skip && phase_ms >= HID_EXIT_MS {
        st.set_phase(HidPhase::Done, now);
        phase_ms = 0;
    }

    let save_npad = st.save_npad;
    let phase = st.hid_phase;
    let action = hid_buttons_for_pad(phase, phase_ms, pad, kind, save_npad);
    if matches!(action, HidAction::Release) {
        st.hid_released = true;
    }
    action
}

pub fn install() {
    if crate::overrides::replay_save() {
        skyline::install_hooks!(
            open_file_hook,
            write_file_hook,
            set_file_size_hook,
            close_file_hook
        );
    }
    if crate::overrides::hid_enabled() {
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(3));
            install_npad_abs_hooks();
        });
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
