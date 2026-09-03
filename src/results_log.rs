use std::fs;
use std::path::{Path, PathBuf};

const DIR: &str = "sd:/smush_info";
const MAX_FILES: usize = 100;

#[inline(never)]
fn timestamp_filename() -> Option<String> {
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
            "{:04}{:02}{:02}{:02}{:02}{:02}.log",
            calendar.year,
            calendar.month,
            calendar.day,
            calendar.hour,
            calendar.minute,
            calendar.second
        ))
    }
}

#[inline(never)]
pub fn write_snapshot(json: &[u8]) -> bool {
    let dir = Path::new(DIR);
    if !dir.is_dir() {
        return false;
    }
    let Some(name) = timestamp_filename() else {
        return false;
    };
    let path = dir.join(&name);
    if let Err(e) = fs::write(&path, json) {
        println!("[smush_info] failed to write results log {:?}: {}", path, e);
        return false;
    }
    prune_oldest(path.file_name());
    true
}

#[inline(never)]
fn prune_oldest(just_written_name: Option<&std::ffi::OsStr>) {
    let entries = match fs::read_dir(DIR) {
        Ok(it) => it,
        Err(e) => {
            println!("[smush_info] failed to list {}: {}", DIR, e);
            return;
        }
    };

    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let is_file = match entry.metadata() {
            Ok(m) => m.is_file(),
            Err(_) => continue,
        };
        if !is_file {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        files.push((path, name));
    }

    if files.len() <= MAX_FILES {
        return;
    }

    let oldest = files
        .iter()
        .filter(|(p, _)| just_written_name.map(|n| p.file_name() != Some(n)).unwrap_or(true))
        .min_by(|a, b| a.1.cmp(&b.1));

    if let Some((path, _)) = oldest {
        if let Err(e) = fs::remove_file(path) {
            println!("[smush_info] failed to prune {:?}: {}", path, e);
        }
    }
}
