use std::sync::atomic::{AtomicBool, Ordering};

use smush_info_shared::{parse_emulator_mode, resolve_emulator_mode, EmulatorMode};

const PATH: &str = "sd:/ultimate/smush_info/overrides.toml";
const ATMOSPHERE_MARKER: &str = "sd:/atmosphere/package3";
const FLAG_RESULTS_LOG: &str = "disable_results_log";
const FLAG_REPLAY_SAVE: &str = "disable_replay_save";
const FLAG_RESULTS_SKIP: &str = "disable_results_skip";

static DISABLE_RESULTS_LOG: AtomicBool = AtomicBool::new(false);
static DISABLE_REPLAY_SAVE: AtomicBool = AtomicBool::new(false);
static DISABLE_RESULTS_SKIP: AtomicBool = AtomicBool::new(false);
static EMULATOR_MODE: AtomicBool = AtomicBool::new(false);

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

/// Resolved `emulator_mode`. `auto` is on when `sd:/atmosphere/package3` is missing.
pub fn emulator_mode() -> bool {
    EMULATOR_MODE.load(Ordering::Relaxed)
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
            println!("[smush_info] no overrides.toml, all features on");
            String::new()
        }
    };

    let mut disable_log = false;
    let mut disable_replay = false;
    let mut disable_skip = false;
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
    }

    DISABLE_RESULTS_LOG.store(disable_log, Ordering::Relaxed);
    DISABLE_REPLAY_SAVE.store(disable_replay, Ordering::Relaxed);
    DISABLE_RESULTS_SKIP.store(disable_skip, Ordering::Relaxed);
    if !text.is_empty() {
        println!(
            "[smush_info] overrides: results_log={} replay_save={} results_skip={}",
            !disable_log,
            !disable_replay,
            !disable_skip
        );
    }

    let mode = parse_emulator_mode(&text);
    let marker = std::fs::metadata(ATMOSPHERE_MARKER).is_ok();
    let on = resolve_emulator_mode(mode, marker);
    EMULATOR_MODE.store(on, Ordering::Relaxed);
    let why = match mode {
        EmulatorMode::Auto if marker => "sd:/atmosphere/package3 present",
        EmulatorMode::Auto => "no sd:/atmosphere/package3",
        _ => "overrides.toml",
    };
    println!(
        "[smush_info] emulator_mode={} -> {} ({})",
        mode.as_str(),
        if on { "on" } else { "off" },
        why
    );
}
