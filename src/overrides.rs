use std::sync::atomic::{AtomicBool, Ordering};

const PATH: &str = "sd:/ultimate/smush_info/overrides.toml";
const FLAG_RESULTS_LOG: &str = "disable_results_log";
const FLAG_REPLAY_SAVE: &str = "disable_replay_save";
const FLAG_RESULTS_SKIP: &str = "disable_results_skip";
const FLAG_DEBUG_MODE: &str = "debug_mode";

static DISABLE_RESULTS_LOG: AtomicBool = AtomicBool::new(false);
static DISABLE_REPLAY_SAVE: AtomicBool = AtomicBool::new(false);
static DISABLE_RESULTS_SKIP: AtomicBool = AtomicBool::new(false);
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

pub fn results_log() -> bool {
    !DISABLE_RESULTS_LOG.load(Ordering::Relaxed)
}

pub fn replay_save() -> bool {
    !DISABLE_REPLAY_SAVE.load(Ordering::Relaxed)
}

pub fn results_skip() -> bool {
    !DISABLE_RESULTS_SKIP.load(Ordering::Relaxed)
}

pub fn hid_enabled() -> bool {
    replay_save() || results_skip()
}

/// Trace lines on the game thread. Off unless `debug_mode` is uncommented.
pub fn debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::Relaxed)
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

pub fn load() {
    let text = match std::fs::read_to_string(PATH) {
        Ok(t) => t,
        Err(_) => {
            println!("[smush_info] no overrides.toml, features on, debug off");
            return;
        }
    };

    let mut disable_log = false;
    let mut disable_replay = false;
    let mut disable_skip = false;
    let mut debug = false;
    for line in text.lines() {
        let line = strip_comment(line);
        if line.contains(FLAG_RESULTS_LOG) {
            disable_log = true;
        }
        if line.contains(FLAG_REPLAY_SAVE) {
            disable_replay = true;
        }
        if line.contains(FLAG_RESULTS_SKIP) {
            disable_skip = true;
        }
        if line.contains(FLAG_DEBUG_MODE) {
            debug = true;
        }
    }

    DISABLE_RESULTS_LOG.store(disable_log, Ordering::Relaxed);
    DISABLE_REPLAY_SAVE.store(disable_replay, Ordering::Relaxed);
    DISABLE_RESULTS_SKIP.store(disable_skip, Ordering::Relaxed);
    DEBUG_MODE.store(debug, Ordering::Relaxed);
    println!(
        "[smush_info] overrides: results_log={} replay_save={} results_skip={} debug_mode={}",
        !disable_log,
        !disable_replay,
        !disable_skip,
        debug
    );
}
