use crate::results_log;
use skyline::libc::c_char;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

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
}

impl DumpState {
    fn new() -> Self {
        Self {
            captures: HashMap::new(),
            pair: Pair::Idle,
            path_confirmed: false,
            probe_unique: HashSet::new(),
            results: false,
        }
    }

    fn probe_window(&self) -> bool {
        self.results
            || matches!(self.pair, Pair::Pending { .. } | Pair::Orphan { .. })
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
}

#[inline(never)]
pub fn set_results(is_results: bool) {
    lock_state().results = is_results;
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

pub fn install() {
    skyline::install_hooks!(open_file_hook, write_file_hook, set_file_size_hook, close_file_hook);
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
