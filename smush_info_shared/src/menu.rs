//! Classify the game's current menu word.
//!
//! The top byte is the top-level menu. The controls screen poses a sandbag and
//! Mario, and Mii Maker does the same, so both report fighters without being a
//! match. Vault replay playback reports `0x5010100`.

pub const CONTROLS_SCREEN_MENU: u32 = 0x6020000;
pub const MII_MAKER_MENU: u32 = 0x4050000;
pub const VAULT_MENU: u32 = 0x5000000;
const TOP_LEVEL_MENU_MASK: u32 = 0xff000000;

pub fn menu_is_gameplay(menu: u32) -> bool {
    menu != CONTROLS_SCREEN_MENU && menu != MII_MAKER_MENU
}

pub fn menu_is_vault(menu: u32) -> bool {
    (menu & TOP_LEVEL_MENU_MASK) == VAULT_MENU
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
