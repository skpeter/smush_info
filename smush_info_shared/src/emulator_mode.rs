//! `emulator_mode` from `overrides.toml`, and whether it is in effect.
//!
//! `auto` treats a missing `sd:/atmosphere/package3` as an emulator: every
//! Atmosphère SD has it, and Eden's text base is randomized, so the fixed
//! text-address check other mods use does not work there.

pub const KEY: &str = "emulator_mode";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EmulatorMode {
    Auto,
    On,
    Off,
}

impl EmulatorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EmulatorMode::Auto => "auto",
            EmulatorMode::On => "on",
            EmulatorMode::Off => "off",
        }
    }
}

/// The last valid `emulator_mode = ...` line wins. Missing, commented out, or
/// unrecognized values fall back to `Auto`.
pub fn parse_emulator_mode(text: &str) -> EmulatorMode {
    let mut mode = EmulatorMode::Auto;
    for line in text.lines() {
        let line = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let (key, value) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if key.trim() != KEY {
            continue;
        }
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
        match value.to_ascii_lowercase().as_str() {
            "auto" => mode = EmulatorMode::Auto,
            "on" | "true" => mode = EmulatorMode::On,
            "off" | "false" => mode = EmulatorMode::Off,
            _ => {}
        }
    }
    mode
}

pub fn resolve_emulator_mode(mode: EmulatorMode, atmosphere_marker_present: bool) -> bool {
    match mode {
        EmulatorMode::On => true,
        EmulatorMode::Off => false,
        EmulatorMode::Auto => !atmosphere_marker_present,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_key_is_auto() {
        assert_eq!(parse_emulator_mode(""), EmulatorMode::Auto);
        assert_eq!(parse_emulator_mode("disable_results_log\n"), EmulatorMode::Auto);
    }

    #[test]
    fn plain_values_parse() {
        assert_eq!(parse_emulator_mode("emulator_mode = on"), EmulatorMode::On);
        assert_eq!(parse_emulator_mode("emulator_mode = off"), EmulatorMode::Off);
        assert_eq!(parse_emulator_mode("emulator_mode = auto"), EmulatorMode::Auto);
    }

    #[test]
    fn off_is_not_mistaken_for_on() {
        assert_eq!(parse_emulator_mode("emulator_mode = off\n"), EmulatorMode::Off);
        assert_eq!(parse_emulator_mode("emulator_mode=\"off\""), EmulatorMode::Off);
    }

    #[test]
    fn quotes_spacing_and_case_are_ignored() {
        assert_eq!(parse_emulator_mode("emulator_mode=\"on\""), EmulatorMode::On);
        assert_eq!(parse_emulator_mode("  emulator_mode   =   'OFF'  "), EmulatorMode::Off);
        assert_eq!(parse_emulator_mode("emulator_mode = On\r\n"), EmulatorMode::On);
        assert_eq!(parse_emulator_mode("emulator_mode = true"), EmulatorMode::On);
    }

    #[test]
    fn trailing_comment_is_stripped() {
        assert_eq!(parse_emulator_mode("emulator_mode = on # Eden"), EmulatorMode::On);
    }

    #[test]
    fn commented_line_is_auto() {
        assert_eq!(parse_emulator_mode("# emulator_mode = on"), EmulatorMode::Auto);
        assert_eq!(parse_emulator_mode("#emulator_mode = off"), EmulatorMode::Auto);
    }

    #[test]
    fn garbage_value_is_auto() {
        assert_eq!(parse_emulator_mode("emulator_mode = maybe"), EmulatorMode::Auto);
        assert_eq!(parse_emulator_mode("emulator_mode ="), EmulatorMode::Auto);
        assert_eq!(parse_emulator_mode("emulator_mode"), EmulatorMode::Auto);
    }

    #[test]
    fn similar_keys_do_not_match() {
        assert_eq!(parse_emulator_mode("disable_emulator_mode = on"), EmulatorMode::Auto);
        assert_eq!(parse_emulator_mode("emulator_mode_x = on"), EmulatorMode::Auto);
    }

    #[test]
    fn last_valid_line_wins() {
        let text = "emulator_mode = on\nemulator_mode = bogus\nemulator_mode = off\n";
        assert_eq!(parse_emulator_mode(text), EmulatorMode::Off);
        let text = "emulator_mode = off\nemulator_mode = bogus\n";
        assert_eq!(parse_emulator_mode(text), EmulatorMode::Off);
    }

    #[test]
    fn auto_follows_marker() {
        assert!(!resolve_emulator_mode(EmulatorMode::Auto, true));
        assert!(resolve_emulator_mode(EmulatorMode::Auto, false));
    }

    #[test]
    fn explicit_mode_ignores_marker() {
        for marker in [true, false] {
            assert!(resolve_emulator_mode(EmulatorMode::On, marker));
            assert!(!resolve_emulator_mode(EmulatorMode::Off, marker));
        }
    }
}
