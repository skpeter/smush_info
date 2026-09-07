use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const DIR: &str = "sd:/smush_info";
const MAX_MATCHES: usize = 100;

lazy_static::lazy_static! {
    static ref DIR_LOCK: Mutex<()> = Mutex::new(());
}

fn dir_guard() -> std::sync::MutexGuard<'static, ()> {
    DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[inline(never)]
pub(crate) fn timestamp_stem() -> Option<String> {
    unsafe {
        if !nnsdk::time::IsInitialized() {
            return None;
        }
        let mut posix = nnsdk::time::PosixTime { time: 0 };
        let rc = nnsdk::time::StandardUserSystemClock::GetCurrentTime(&mut posix);
        if rc != 0 {
            println!("[smush_info] GetCurrentTime failed (result {})", rc);
            return None;
        }
        let mut calendar = nnsdk::time::CalendarTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        };
        let mut extra = nnsdk::time::CalendarAdditionalInfo {
            dayOfTheWeek: 0,
            dayofYear: 0,
            timeZone: nnsdk::time::TimeZone::default(),
        };
        nnsdk::time::ToCalendarTime(&mut calendar, &mut extra, &posix);
        Some(format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            calendar.year,
            calendar.month,
            calendar.day,
            calendar.hour,
            calendar.minute,
            calendar.second
        ))
    }
}

fn ensure_dir() -> bool {
    let dir = Path::new(DIR);
    if dir.is_dir() {
        return true;
    }
    if let Err(e) = fs::create_dir_all(dir) {
        println!("[smush_info] failed to create {}: {}", DIR, e);
        return false;
    }
    true
}

fn stem_of(name: &str) -> Option<&str> {
    let stem = name.split('.').next()?;
    if stem.len() == 14 && stem.bytes().all(|b| b.is_ascii_digit()) {
        Some(stem)
    } else {
        None
    }
}

pub(crate) fn native_filename(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let base = normalized.rsplit('/').next()?.trim();
    if base.is_empty() || base == "." || base == ".." {
        return None;
    }
    if base.bytes().any(|b| matches!(b, 0 | b'/' | b'\\')) {
        return None;
    }
    Some(base.to_string())
}

fn patch_replay_file(stem: &str, replay_file: &str) {
    let path = Path::new(DIR).join(format!("{}.log", stem));
    let Ok(raw) = fs::read(&path) else {
        return;
    };
    let mut value: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => return,
    };
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    obj.insert(
        "replay_file".to_string(),
        serde_json::Value::String(replay_file.to_string()),
    );
    match serde_json::to_vec(&value) {
        Ok(mut data) => {
            if !data.ends_with(&[b'\n']) {
                data.push(b'\n');
            }
            if let Err(e) = fs::write(&path, data) {
                println!("[smush_info] failed to patch replay_file {:?}: {}", path, e);
            }
        }
        Err(_) => {}
    }
}

fn remove_match(stem: &str) {
    for ext in [".log", ".bin"] {
        let path = PathBuf::from(DIR).join(format!("{}{}", stem, ext));
        if path.exists() {
            if let Err(e) = fs::remove_file(&path) {
                println!("[smush_info] failed to prune {:?}: {}", path, e);
            }
        }
    }
    let dir = PathBuf::from(DIR).join(stem);
    if dir.is_dir() {
        if let Err(e) = fs::remove_dir_all(&dir) {
            println!("[smush_info] failed to prune {:?}: {}", dir, e);
        }
    }
}

#[inline(never)]
fn prune_oldest(keep_stem: &str) {
    let entries = match fs::read_dir(DIR) {
        Ok(it) => it,
        Err(e) => {
            println!("[smush_info] failed to list {}: {}", DIR, e);
            return;
        }
    };

    let mut stems: Vec<String> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.metadata().is_err() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(s) = stem_of(&name) {
            if !stems.iter().any(|x| x == s) {
                stems.push(s.to_string());
            }
        }
    }

    stems.sort();
    while stems.len() > MAX_MATCHES {
        let oldest = match stems.iter().find(|s| s.as_str() != keep_stem) {
            Some(s) => s.clone(),
            None => break,
        };
        remove_match(&oldest);
        stems.retain(|s| s != &oldest);
    }
}

#[inline(never)]
pub fn write_snapshot(json: &[u8]) -> Option<String> {
    let _g = dir_guard();
    if !ensure_dir() {
        return None;
    }
    let stem = timestamp_stem()?;
    let path = Path::new(DIR).join(format!("{}.log", stem));
    if let Err(e) = fs::write(&path, json) {
        println!("[smush_info] failed to write results log {:?}: {}", path, e);
        return None;
    }
    prune_oldest(&stem);
    Some(stem)
}

#[inline(never)]
pub fn write_replay(stem: &str, vault_path: &str, data: &[u8]) -> bool {
    if !crate::overrides::replay_save() {
        return false;
    }
    let _g = dir_guard();
    if !ensure_dir() {
        return false;
    }
    let name = native_filename(vault_path).unwrap_or_else(|| "replay.bin".to_string());
    let dir = Path::new(DIR).join(stem);
    if let Err(e) = fs::create_dir_all(&dir) {
        println!("[smush_info] failed to create {:?}: {}", dir, e);
        return false;
    }
    let path = dir.join(&name);
    if let Err(e) = fs::write(&path, data) {
        println!("[smush_info] failed to write replay {:?}: {}", path, e);
        return false;
    }
    patch_replay_file(stem, &name);
    prune_oldest(stem);
    true
}
