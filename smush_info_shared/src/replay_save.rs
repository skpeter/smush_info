//! When the results screen arms one direct replay save, and when that wait ends.
//!
//! The 7.5s mute clock stays in the plugin. These functions only decide.

/// A pad poll this long, or longer, is a HOME press or a suspend. Shorter
/// hitches leave the deadline where it is.
pub const PAUSE_GAP_MS: u128 = 1000;

/// Results leave on a 3 second A pulse. An 8 second pulse walks into the next menu.
pub const SKIP_PULSE_MS: u128 = 3000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SaveWait {
    KeepWaiting,
    Skip,
    Done,
    GiveUp,
}

/// Arm once, from menu-gated results, whether or not a save pad is connected.
/// A missing pad is not an input: docked with nothing paired still arms.
pub fn should_arm_save(results: bool, replay_save: bool, already_armed: bool) -> bool {
    results && replay_save && !already_armed
}

/// What the post-submit wait does on this poll.
///
/// A landed SD file wins. An open vault write keeps the wait alive past the
/// deadline. When the deadline passes with nothing open and no file, give up:
/// pads come back, and the skip pulse does not run.
pub fn save_wait_result(
    file_landed: bool,
    skip_on: bool,
    write_open: bool,
    wait_elapsed: bool,
) -> SaveWait {
    if file_landed {
        return if skip_on {
            SaveWait::Skip
        } else {
            SaveWait::Done
        };
    }
    if write_open || !wait_elapsed {
        return SaveWait::KeepWaiting;
    }
    SaveWait::GiveUp
}

/// Push `deadline_ms` forward by `gap_ms` when the gap is a pause.
pub fn pause_deadline(deadline_ms: u128, gap_ms: u128) -> u128 {
    if gap_ms >= PAUSE_GAP_MS {
        deadline_ms.saturating_add(gap_ms)
    } else {
        deadline_ms
    }
}

pub fn skip_phase_done(phase_ms: u128) -> bool {
    phase_ms >= SKIP_PULSE_MS
}

/// A zero offset is a missing entry. That does not call.
pub fn should_submit(offset: usize, pending: bool) -> bool {
    offset != 0 && pending
}

/// The Yes dialog clears `is_result_mode` for one poll while fighters stay
/// entered. The session ends only when both flags are false.
pub fn clear_results_session(is_match: bool, is_results: bool) -> bool {
    !is_match && !is_results
}

/// A rising match resets the in-flight save only when this results session
/// has actually ended (`saw_match` clear).
pub fn new_match_resets_save(is_match: bool, prev_is_match: bool, saw_match: bool) -> bool {
    is_match && !prev_is_match && !saw_match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arms_when_results_save_enabled_and_not_yet_armed() {
        assert!(should_arm_save(true, true, false));
    }

    #[test]
    fn does_not_arm_when_results_is_false() {
        assert!(!should_arm_save(false, true, false));
    }

    #[test]
    fn does_not_arm_when_save_is_disabled() {
        assert!(!should_arm_save(true, false, false));
    }

    #[test]
    fn does_not_arm_twice() {
        assert!(!should_arm_save(true, true, true));
    }

    #[test]
    fn arms_when_there_is_no_save_pad() {
        assert!(should_arm_save(true, true, false));
    }

    #[test]
    fn file_landed_and_skip_on_goes_to_skip() {
        assert_eq!(
            save_wait_result(true, true, false, false),
            SaveWait::Skip
        );
    }

    #[test]
    fn file_landed_and_skip_off_is_done() {
        assert_eq!(
            save_wait_result(true, false, true, true),
            SaveWait::Done
        );
    }

    #[test]
    fn write_handle_open_keeps_waiting() {
        assert_eq!(
            save_wait_result(false, true, true, true),
            SaveWait::KeepWaiting
        );
    }

    #[test]
    fn wait_elapsed_with_nothing_gives_up_without_skipping() {
        assert_eq!(
            save_wait_result(false, true, false, false),
            SaveWait::KeepWaiting
        );
        assert_eq!(
            save_wait_result(false, true, false, true),
            SaveWait::GiveUp
        );
    }

    #[test]
    fn poll_gap_of_one_second_pushes_the_deadline() {
        assert_eq!(pause_deadline(10_000, 999), 10_000);
        assert_eq!(pause_deadline(10_000, PAUSE_GAP_MS), 11_000);
        assert_eq!(pause_deadline(10_000, 2_500), 12_500);
    }

    #[test]
    fn skip_phase_ends_at_three_seconds_not_eight() {
        assert_eq!(SKIP_PULSE_MS, 3_000);
        assert_ne!(SKIP_PULSE_MS, 8_000);
        assert!(!skip_phase_done(2_999));
        assert!(skip_phase_done(3_000));
    }

    #[test]
    fn one_poll_results_drop_does_not_clear_the_session_or_rearm() {
        let is_match = true;
        let is_results = false;
        let saw_match = true;
        let prev_is_match = false;
        assert!(!clear_results_session(is_match, is_results));
        assert!(!new_match_resets_save(
            is_match,
            prev_is_match,
            saw_match
        ));
        assert!(!should_arm_save(is_results, true, true));
        assert!(clear_results_session(false, false));
        assert!(new_match_resets_save(true, false, false));
    }

    #[test]
    fn offset_zero_does_not_submit_and_a_cleared_flag_does_not_call_again() {
        assert!(!should_submit(0, true));
        assert!(should_submit(0x143d5d0, true));
        assert!(!should_submit(0x143d5d0, false));
    }
}
