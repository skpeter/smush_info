//! Classify the game's current menu word.
//!
//! The top byte is the top-level menu. The controls screen poses a sandbag and
//! Mario, and Mii Maker does the same, so both report fighters without being a
//! match. Vault replay playback reports `0x5010100`.

pub const CONTROLS_SCREEN_MENU: u32 = 0x6020000;
pub const MII_MAKER_MENU: u32 = 0x4050000;
pub const VAULT_MENU: u32 = 0x5000000;
/// Versus, including a live match and the winner card. Vault playback writes
/// this same id when the replay reaches that card (crash 01793207547).
pub const VERSUS_RESULTS_MENU: u32 = 0x2010000;
const TOP_LEVEL_MENU_MASK: u32 = 0xff000000;

pub fn menu_is_gameplay(menu: u32) -> bool {
    menu != CONTROLS_SCREEN_MENU && menu != MII_MAKER_MENU
}

pub fn menu_is_vault(menu: u32) -> bool {
    (menu & TOP_LEVEL_MENU_MASK) == VAULT_MENU
}

/// A match you just played can save. Vault playback raises the same results
/// flag, and the save pump then faults on an archive that is not loaded.
pub fn replay_save_on_menu(menu: u32) -> bool {
    !menu_is_vault(menu)
}

/// A Vault playback session survives the winner card. The game rewrites the
/// menu from `0x5010100` to `0x2010000` there, which is also the id of a live
/// versus. Any other menu ends the session, so the next real match can save.
pub fn still_in_playback(was_playback: bool, menu: u32) -> bool {
    if menu_is_vault(menu) {
        return true;
    }
    was_playback && menu == VERSUS_RESULTS_MENU
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_playback_and_vault_root_are_vault() {
        assert!(menu_is_vault(0x5010100));
        assert!(menu_is_vault(0x5000000));
    }

    #[test]
    fn other_top_level_menus_are_not_vault() {
        for menu in [0, 0x1000000, 0x2010000, 0x4050000, 0x6020000, 0x50000, 0x15000000] {
            assert!(!menu_is_vault(menu), "{:#x}", menu);
        }
    }

    #[test]
    fn vault_playback_does_not_save() {
        // Crash 01793156795: results during playback, menu 0x5010100.
        assert!(!replay_save_on_menu(0x5010100));
        assert!(!replay_save_on_menu(VAULT_MENU));
        // The versus results that saved on console the same day.
        assert!(replay_save_on_menu(0x2010000));
    }

    #[test]
    fn playback_winner_card_stays_playback() {
        // The replay itself is Vault. The winner card then uses the versus id.
        assert!(still_in_playback(false, 0x5010100));
        assert!(still_in_playback(true, VERSUS_RESULTS_MENU));
        // A live versus is the same id, and it saves when playback was not open.
        assert!(!still_in_playback(false, VERSUS_RESULTS_MENU));
        // Leaving to any other menu ends the session.
        assert!(!still_in_playback(true, 0x1000000));
        assert!(!still_in_playback(true, 0));
    }

    #[test]
    fn versus_and_vault_are_gameplay() {
        for menu in [0, 0x1000000, 0x2010000, 0x5010100] {
            assert!(menu_is_gameplay(menu), "{:#x}", menu);
        }
    }

    #[test]
    fn controls_and_mii_maker_are_not_gameplay() {
        assert!(!menu_is_gameplay(CONTROLS_SCREEN_MENU));
        assert!(!menu_is_gameplay(MII_MAKER_MENU));
    }
}
