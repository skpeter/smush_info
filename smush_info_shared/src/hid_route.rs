//! Which controller polls receive the results-screen save presses.
//!
//! Smash reads one slot (or the last slot it sampled) for menu buttons.
//! Driving only the lowest slot and zeroing the others drops the sequence
//! whenever the results screen is listening to the second Pro Controller.

pub const STYLE_FULLKEY: u32 = 1 << 0;
pub const STYLE_HANDHELD: u32 = 1 << 1;
pub const STYLE_JOYDUAL: u32 = 1 << 2;
pub const STYLE_JOYLEFT: u32 = 1 << 3;
pub const STYLE_JOYRIGHT: u32 = 1 << 4;
pub const STYLE_GC: u32 = 1 << 5;
pub const STYLE_FULL: u32 = STYLE_FULLKEY | STYLE_HANDHELD | STYLE_JOYDUAL | STYLE_GC;
pub const STYLE_SINGLE: u32 = STYLE_JOYLEFT | STYLE_JOYRIGHT;

/// Other-pad polls with no poll of the save slot before we forget it.
/// Counted in primary-style polls, so one other Pro Controller at 60Hz is ~1s.
pub const SAVE_PAD_SILENT_POLLS: u32 = 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PadKind {
    FullKey,
    Handheld,
    JoyDual,
    Gc,
    JoyLeft,
    JoyRight,
}

impl PadKind {
    pub fn style_bit(self) -> u32 {
        match self {
            PadKind::FullKey => STYLE_FULLKEY,
            PadKind::Handheld => STYLE_HANDHELD,
            PadKind::JoyDual => STYLE_JOYDUAL,
            PadKind::Gc => STYLE_GC,
            PadKind::JoyLeft => STYLE_JOYLEFT,
            PadKind::JoyRight => STYLE_JOYRIGHT,
        }
    }
}

fn primary_kind(styles: u32) -> Option<PadKind> {
    const ORDER: [(u32, PadKind); 6] = [
        (STYLE_FULLKEY, PadKind::FullKey),
        (STYLE_HANDHELD, PadKind::Handheld),
        (STYLE_JOYDUAL, PadKind::JoyDual),
        (STYLE_GC, PadKind::Gc),
        (STYLE_JOYLEFT, PadKind::JoyLeft),
        (STYLE_JOYRIGHT, PadKind::JoyRight),
    ];
    for &(bit, kind) in &ORDER {
        if styles & bit != 0 {
            return Some(kind);
        }
    }
    None
}

/// Save / back taps. Every full-style slot gets them: the results screen
/// listens to one slot, and it is not always the lowest id. Zeroing the
/// others drops the sequence until that slot is unplugged and the pick moves.
/// A lone Joy-Con stays on the single selected slot so a sideways remap is
/// not merged with a real face button.
pub fn takes_save_press(styles: u32, kind: PadKind, any_full: bool, selected: bool) -> bool {
    if styles & STYLE_FULL != 0 {
        return match kind {
            PadKind::FullKey => styles & STYLE_FULLKEY != 0,
            PadKind::Handheld => styles & STYLE_HANDHELD != 0,
            PadKind::JoyDual => styles & STYLE_JOYDUAL != 0,
            PadKind::Gc => styles & STYLE_GC != 0,
            PadKind::JoyLeft | PadKind::JoyRight => false,
        };
    }
    if any_full || !selected {
        return false;
    }
    match kind {
        PadKind::JoyLeft => styles & STYLE_JOYLEFT != 0,
        PadKind::JoyRight => styles & STYLE_JOYRIGHT != 0,
        _ => false,
    }
}

/// One count per other slot per pass: its primary style only. JoyLeft polls
/// of a Pro, and polls of empty slots, must not look like the save slot left.
pub fn counts_toward_save_pad_silence(styles: u32, kind: PadKind) -> bool {
    primary_kind(styles) == Some(kind)
}

pub fn observe_save_silence(polls: u32, is_save_slot: bool, styles: u32, kind: PadKind) -> u32 {
    if is_save_slot {
        return 0;
    }
    if counts_toward_save_pad_silence(styles, kind) {
        polls.saturating_add(1)
    } else {
        polls
    }
}

/// Full slots already share one tap clock. Rewinding it when the primary id
/// changes holds A forever and the Y / d-pad steps never land.
pub fn restart_save_clock_on_retarget(any_full: bool) -> bool {
    !any_full
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_pros_both_receive_the_save_press_on_fullkey() {
        let pro = STYLE_FULLKEY | STYLE_JOYLEFT | STYLE_JOYRIGHT;
        assert!(takes_save_press(pro, PadKind::FullKey, true, true));
        assert!(
            takes_save_press(pro, PadKind::FullKey, true, false),
            "second pro was muted, so whichever slot the results screen reads never sees A"
        );
    }

    #[test]
    fn pro_joy_polls_do_not_get_a_remapped_press() {
        let pro = STYLE_FULLKEY | STYLE_JOYLEFT | STYLE_JOYRIGHT;
        assert!(!takes_save_press(pro, PadKind::JoyLeft, true, true));
        assert!(!takes_save_press(pro, PadKind::JoyRight, true, true));
    }

    #[test]
    fn gc_pad_gets_both_fullkey_and_gc_presses() {
        let gc = STYLE_GC | STYLE_FULLKEY;
        assert!(takes_save_press(gc, PadKind::Gc, true, true));
        assert!(takes_save_press(gc, PadKind::FullKey, true, false));
        assert!(!takes_save_press(gc, PadKind::JoyLeft, true, true));
    }

    #[test]
    fn lone_joycon_only_the_selected_slot_is_driven() {
        assert!(takes_save_press(
            STYLE_JOYLEFT,
            PadKind::JoyLeft,
            false,
            true
        ));
        assert!(!takes_save_press(
            STYLE_JOYLEFT,
            PadKind::JoyLeft,
            false,
            false
        ));
        assert!(!takes_save_press(
            STYLE_JOYRIGHT,
            PadKind::JoyLeft,
            false,
            true
        ));
    }

    #[test]
    fn full_pad_present_mutes_a_lone_joycon() {
        assert!(!takes_save_press(
            STYLE_JOYLEFT,
            PadKind::JoyLeft,
            true,
            true
        ));
    }

    #[test]
    fn joy_polls_of_the_other_pro_do_not_look_like_the_save_slot_left() {
        let pro = STYLE_FULLKEY | STYLE_JOYLEFT | STYLE_JOYRIGHT;
        let mut polls = 0u32;
        for _ in 0..500 {
            if counts_toward_save_pad_silence(pro, PadKind::JoyLeft) {
                polls += 1;
            }
            if counts_toward_save_pad_silence(pro, PadKind::JoyRight) {
                polls += 1;
            }
            if counts_toward_save_pad_silence(0, PadKind::FullKey) {
                polls += 1;
            }
        }
        assert!(
            polls < SAVE_PAD_SILENT_POLLS,
            "style noise tripped the ghost drop ({} polls)",
            polls
        );
        for _ in 0..SAVE_PAD_SILENT_POLLS - 1 {
            if counts_toward_save_pad_silence(pro, PadKind::FullKey) {
                polls += 1;
            }
        }
        assert!(polls < SAVE_PAD_SILENT_POLLS);
        if counts_toward_save_pad_silence(pro, PadKind::FullKey) {
            polls += 1;
        }
        assert_eq!(polls, SAVE_PAD_SILENT_POLLS);
    }

    #[test]
    fn retarget_among_full_pads_does_not_rewind_the_tap_clock() {
        assert!(!restart_save_clock_on_retarget(true));
        assert!(restart_save_clock_on_retarget(false));
    }

    #[test]
    fn two_pros_polled_together_never_trip_the_ghost_drop() {
        let pro = STYLE_FULLKEY | STYLE_JOYLEFT | STYLE_JOYRIGHT;
        let mut polls = 0u32;
        for _ in 0..30 {
            for kind in [PadKind::JoyLeft, PadKind::JoyRight, PadKind::FullKey] {
                polls = observe_save_silence(polls, false, pro, kind);
                polls = observe_save_silence(polls, false, 0, kind);
            }
        }
        assert!(
            polls < SAVE_PAD_SILENT_POLLS,
            "live second pro looked like the save slot left ({})",
            polls
        );
        polls = observe_save_silence(polls, true, pro, PadKind::FullKey);
        assert_eq!(polls, 0);
    }
}
