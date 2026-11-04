//#![feature(const_mut_refs)]
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use serde::{Serialize, Deserialize};

mod atomic_f32;
pub use atomic_f32::AtomicF32;

mod atomic_arena_id;
pub use atomic_arena_id::AtomicArenaId;

mod atomic_name;
pub use atomic_name::AtomicName;

mod atomic_text;
pub use atomic_text::AtomicText;

mod match_stats;
pub use match_stats::{
    active_entry_pair, map_status, should_arm_clock_zero, should_write_stats_snapshot, slot_for_entry,
    tick_owner_entry,
    FighterSummary, FrameSample, MatchStats, OpeningRecord, Phase,
};

mod move_names;
pub use move_names::{display_name, preload as preload_move_names};

mod ws;
pub use ws::{handshake_response, text_frame};

mod menu;
pub use menu::{
    menu_is_gameplay, menu_is_vault, replay_save_on_menu, still_in_playback, CONTROLS_SCREEN_MENU,
    MII_MAKER_MENU, VAULT_MENU, VERSUS_RESULTS_MENU,
};

mod emulator_mode;
pub use emulator_mode::{parse_emulator_mode, resolve_emulator_mode, EmulatorMode};

mod replay_save;
pub use replay_save::{
    abandon_save_for_menu, clear_results_session, new_match_resets_save, pause_deadline,
    save_wait_result, should_arm_save, should_pump_replay, should_submit, SaveWait, PAUSE_GAP_MS,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Info {
    pub arena_id: AtomicArenaId,
    pub remaining_frames: AtomicU32,
    pub current_menu: AtomicU32,
    pub is_match: AtomicBool,
    pub is_results_screen: AtomicBool,
    pub hid_hooks: AtomicU32,
    pub hid_npad_hits: AtomicU32,
    pub hid_elapsed_ms: AtomicU32,
    pub stage: AtomicU32,
    pub players: [Player; 8]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Player {
    pub is_in_game: AtomicBool,
    pub name: AtomicName,
    pub character: AtomicU32,
    pub stocks: AtomicU32,
    pub self_destructs: AtomicU32,
    pub damage: AtomicF32,
    pub is_cpu: AtomicBool,
    pub skin: AtomicU32,
    pub x: AtomicF32,
    pub y: AtomicF32,
    pub hero_menu_open: AtomicBool,
    pub hero_menu_selected: AtomicBool,
    pub hero_menu_selection: AtomicU32,
    /// Team index from `TeamModule::team_no`: 0–3 in team battle, -1 otherwise.
    pub team: AtomicI32,
    #[serde(default)]
    pub neutral_wins: AtomicU32,
    #[serde(default)]
    pub neutral_losses: AtomicU32,
    #[serde(default)]
    pub non_killing_wins: AtomicU32,
    #[serde(default)]
    pub stage_control: AtomicU32,
    #[serde(default)]
    pub avg_damage_per_opening: AtomicF32,
    #[serde(default)]
    pub top_opener: AtomicU64,
    #[serde(default)]
    pub top_opener_name: AtomicText,
    #[serde(default)]
    pub avg_death: AtomicF32,
    #[serde(default)]
    pub earliest_death: AtomicF32,
    #[serde(default)]
    pub latest_death: AtomicF32,
    #[serde(default)]
    pub damage_dealt: AtomicF32,
    #[serde(default)]
    pub damage_taken: AtomicF32,
    #[serde(default)]
    pub match_self_destructs: AtomicU32,
    #[serde(default)]
    pub stocks_taken: AtomicU32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum Character {
    None = 0,
    Bayonetta,
    Brave,
    Buddy,
    Captain,
    Chrom,
    Cloud,
    Daisy,
    Dedede,
    Demon,
    Diddy,
    Dolly,
    Donkey,
    Duckhunt,
    Edge,
    Eflame,
    Elight,
    Falco,
    Fox,
    Fushigisou,
    Gamewatch,
    Ganon,
    Gaogaen,
    Gekkouga,
    Ike,
    Inkling,
    Jack,
    Kamui,
    Ken,
    Kirby,
    Koopa,
    Koopag,
    Koopajr,
    Krool,
    Link,
    Littlemac,
    Lizardon,
    Lucario,
    Lucas,
    Lucina,
    Luigi,
    Mario,
    Mariod,
    Marth,
    Master,
    Metaknight,
    Mewtwo,
    Miienemyf,
    Miienemyg,
    Miienemys,
    Miifighter,
    Miigunner,
    Miiswordsman,
    Murabito,
    Nana,
    Ness,
    Packun,
    Pacman,
    Palutena,
    Peach,
    Pfushigisou,
    Pichu,
    Pickel,
    Pikachu,
    Pikmin,
    Pit,
    Pitb,
    Plizardon,
    Popo,
    Purin,
    Pzenigame,
    Reflet,
    Richter,
    Ridley,
    Robot,
    Rockman,
    Rosetta,
    Roy,
    Ryu,
    Samus,
    Samusd,
    Sheik,
    Shizue,
    Shulk,
    Simon,
    Snake,
    Sonic,
    Szerosuit,
    Tantan,
    Toonlink,
    Trail,
    Wario,
    Wiifit,
    Wolf,
    Yoshi,
    Younglink,
    Zelda,
    Zenigame,
    Max,
}

impl Character {
    pub fn from_u32(c: u32) -> Character {
        if (0..Character::Max as u32).contains(&c) {
            unsafe { core::mem::transmute(c) }
        } else {
            Character::None
        }
    }
}

// see `Character` for how this should be used
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum Stage {
    None = 0,
    _75m,
    Animal_City,
    Animal_Island,
    Animal_Village,
    BalloonFight,
    Battle_75m,
    Battle_Animal_City,
    Battle_Animal_Island,
    Battle_Animal_Village,
    Battle_BalloonFight,
    Battle_Bayo_Clock,
    Battle_Brave_Altar,
    Battle_Buddy_Spiral,
    Battle_Demon_Dojo,
    Battle_DK_Jungle,
    Battle_DK_Lodge,
    Battle_DK_WaterFall,
    Battle_Dolly_Stadium,
    Battle_Dracula_Castle,
    Battle_DuckHunt,
    Battle_End,
    Battle_FE_Arena,
    Battle_FE_Colloseum,
    Battle_FE_Shrine,
    Battle_FE_Siege,
    Battle_FF_Cave,
    Battle_FF_Midgar,
    Battle_FlatZoneX,
    Battle_Fox_Corneria,
    Battle_Fox_LylatCruise,
    Battle_Fox_Venom,
    Battle_Fzero_Bigblue,
    Battle_Fzero_Mutecity3DS,
    Battle_Fzero_Porttown,
    Battle_Icarus_Angeland,
    Battle_Icarus_SkyWorld,
    Battle_Icarus_Uprising,
    Battle_Ice_Top,
    Battle_Jack_Mementoes,
    Battle_Kart_CircuitFor,
    Battle_Kart_CircuitX,
    Battle_Kirby_Cave,
    Battle_Kirby_Fountain,
    Battle_Kirby_Gameboy,
    Battle_Kirby_Greens,
    Battle_Kirby_Halberd,
    Battle_Kirby_Pupupu64,
    Battle_LuigiMansion,
    Battle_Mario_3DLand,
    Battle_Mario_Castle64,
    Battle_Mario_CastleDx,
    Battle_Mario_Dolpic,
    Battle_Mario_Galaxy,
    Battle_Mario_Maker,
    Battle_Mario_NewBros2,
    Battle_Mario_Odyssey,
    Battle_Mario_Paper,
    Battle_Mario_Past64,
    Battle_Mario_PastUsa,
    Battle_Mario_PastX,
    Battle_Mario_Rainbow,
    Battle_Mario_Uworld,
    Battle_MarioBros,
    Battle_Metroid_Kraid,
    Battle_Metroid_Norfair,
    Battle_Metroid_Orpheon,
    Battle_Metroid_ZebesDx,
    Battle_MG_Shadowmoses,
    Battle_Mother_Fourside,
    Battle_Mother_Magicant,
    Battle_Mother_Newpork,
    Battle_Mother_Onett,
    Battle_Nintendogs,
    Battle_Pac_Land,
    Battle_Pickel_World,
    Battle_Pictochat2,
    Battle_Pikmin_Garden,
    Battle_Pikmin_Planet,
    Battle_Pilotwings,
    Battle_Plankton,
    Battle_Poke_Kalos,
    Battle_Poke_Stadium,
    Battle_Poke_Stadium2,
    Battle_Poke_Tengam,
    Battle_Poke_Tower,
    Battle_Poke_Unova,
    Battle_Poke_Yamabuki,
    Battle_PunchOutSB,
    Battle_PunchOutW,
    Battle_Rock_Wily,
    Battle_SF_Suzaku,
    Battle_Sonic_Greenhill,
    Battle_Sonic_Windyhill,
    Battle_Spla_Parking,
    Battle_StreetPass,
    Battle_Tantan_Spring,
    Battle_Tomodachi,
    Battle_Trail_Castle,
    Battle_Wario_Gamer,
    Battle_Wario_Madein,
    Battle_WiiFit,
    Battle_WreckingCrew,
    Battle_WufuIsland,
    Battle_Xeno_Alst,
    Battle_Xeno_Gaur,
    Battle_Yoshi_CartBoard,
    Battle_Yoshi_Island,
    Battle_Yoshi_Story,
    Battle_Yoshi_Yoster,
    Battle_Zelda_Gerudo,
    Battle_Zelda_Greatbay,
    Battle_Zelda_Hyrule,
    Battle_Zelda_Oldin,
    Battle_Zelda_Pirates,
    Battle_Zelda_Skyward,
    Battle_Zelda_Temple,
    Battle_Zelda_Tower,
    Battle_Zelda_Train,
    BattleField_L,
    BattleField_S,
    BattleField,
    Bayo_Clock,
    BonusGame,
    BossStage_Dracula,
    BossStage_Final1,
    BossStage_Final2,
    BossStage_Final3,
    BossStage_Galleom,
    BossStage_GanonBoss,
    BossStage_Marx,
    BossStage_Rathalos,
    Brave_Altar,
    Buddy_Spiral,
    CampaignMap,
    Demon_Dojo,
    DK_Jungle,
    DK_Lodge,
    DK_WaterFall,
    Dolly_Stadium,
    Dracula_Castle,
    DuckHunt,
    End_75m,
    End_Animal_City,
    End_Animal_Island,
    End_Animal_Village,
    End_BalloonFight,
    End_BattleField,
    End_Bayo_Clock,
    End_Brave_Altar,
    End_Buddy_Spiral,
    End_Demon_Dojo,
    End_DK_Jungle,
    End_DK_Lodge,
    End_DK_WaterFall,
    End_Dolly_Stadium,
    End_Dracula_Castle,
    End_DuckHunt,
    End_FE_Arena,
    End_FE_Colloseum,
    End_FE_Shrine,
    End_FE_Siege,
    End_FF_Cave,
    End_FF_Midgar,
    End_FlatZoneX,
    End_Fox_Corneria,
    End_Fox_LylatCruise,
    End_Fox_Venom,
    End_Fzero_Bigblue,
    End_Fzero_Mutecity3DS,
    End_Fzero_Porttown,
    End_Icarus_Angeland,
    End_Icarus_SkyWorld,
    End_Icarus_Uprising,
    End_Ice_Top,
    End_Jack_Mementoes,
    End_Kart_CircuitFor,
    End_Kart_CircuitX,
    End_Kirby_Cave,
    End_Kirby_Fountain,
    End_Kirby_Gameboy,
    End_Kirby_Greens,
    End_Kirby_Halberd,
    End_Kirby_Pupupu64,
    End_LuigiMansion,
    End_Mario_3DLand,
    End_Mario_Castle64,
    End_Mario_CastleDx,
    End_Mario_Dolpic,
    End_Mario_Galaxy,
    End_Mario_Maker,
    End_Mario_NewBros2,
    End_Mario_Odyssey,
    End_Mario_Paper,
    End_Mario_Past64,
    End_Mario_PastUsa,
    End_Mario_PastX,
    End_Mario_Rainbow,
    End_Mario_Uworld,
    End_MarioBros,
    End_Metroid_Kraid,
    End_Metroid_Norfair,
    End_Metroid_Orpheon,
    End_Metroid_ZebesDx,
    End_MG_Shadowmoses,
    End_Mother_Fourside,
    End_Mother_Magicant,
    End_Mother_Newpork,
    End_Mother_Onett,
    End_Nintendogs,
    End_Pac_Land,
    End_Pickel_World,
    End_Pictochat2,
    End_Pikmin_Garden,
    End_Pikmin_Planet,
    End_Pilotwings,
    End_Plankton,
    End_Poke_Kalos,
    End_Poke_Stadium,
    End_Poke_Stadium2,
    End_Poke_Tengam,
    End_Poke_Tower,
    End_Poke_Unova,
    End_Poke_Yamabuki,
    End_PunchOutSB,
    End_PunchOutW,
    End_Rock_Wily,
    End_SF_Suzaku,
    End_Sonic_Greenhill,
    End_Sonic_Windyhill,
    End_Spla_Parking,
    End_StreetPass,
    End_Tantan_Spring,
    End_Tomodachi,
    End_Trail_Castle,
    End_Wario_Gamer,
    End_Wario_Madein,
    End_WiiFit,
    End_WreckingCrew,
    End_WufuIsland,
    End_Xeno_Alst,
    End_Xeno_Gaur,
    End_Yoshi_CartBoard,
    End_Yoshi_Island,
    End_Yoshi_Story,
    End_Yoshi_Yoster,
    End_Zelda_Gerudo,
    End_Zelda_Greatbay,
    End_Zelda_Hyrule,
    End_Zelda_Oldin,
    End_Zelda_Pirates,
    End_Zelda_Skyward,
    End_Zelda_Temple,
    End_Zelda_Tower,
    End_Zelda_Train,
    End,
    FE_Arena,
    FE_Colloseum,
    FE_Shrine,
    FE_Siege,
    FF_Cave,
    FF_Midgar,
    FlatZoneX,
    Fox_Corneria,
    Fox_LylatCruise,
    Fox_Venom,
    Fzero_Bigblue,
    Fzero_Mutecity3DS,
    Fzero_Porttown,
    HomerunContest,
    Icarus_Angeland,
    Icarus_SkyWorld,
    Icarus_Uprising,
    Ice_Top,
    Invalid,
    Jack_Mementoes,
    Kart_CircuitFor,
    Kart_CircuitX,
    Kirby_Cave,
    Kirby_Fountain,
    Kirby_Gameboy,
    Kirby_Greens,
    Kirby_Halberd,
    Kirby_Pupupu64,
    LuigiMansion,
    Mario_3DLand,
    Mario_Castle64,
    Mario_CastleDx,
    Mario_Dolpic,
    Mario_Galaxy,
    Mario_Maker,
    Mario_NewBros2,
    Mario_Odyssey,
    Mario_Paper,
    Mario_Past64,
    Mario_PastUsa,
    Mario_PastX,
    Mario_Rainbow,
    Mario_Uworld,
    MarioBros,
    Metroid_Kraid,
    Metroid_Norfair,
    Metroid_Orpheon,
    Metroid_ZebesDx,
    MG_Shadowmoses,
    Mother_Fourside,
    Mother_Magicant,
    Mother_Newpork,
    Mother_Onett,
    Nintendogs,
    Pac_Land,
    PhotoStage,
    Pickel_World,
    Pictochat2,
    Pikmin_Garden,
    Pikmin_Planet,
    Pilotwings,
    Plankton,
    Poke_Kalos,
    Poke_Stadium,
    Poke_Stadium2,
    Poke_Tengam,
    Poke_Tower,
    Poke_Unova,
    Poke_Yamabuki,
    PunchOutSB,
    PunchOutW,
    ResultStage_Jack,
    ResultStage,
    Rock_Wily,
    SettingStage,
    SF_Suzaku,
    ShamFight,
    Sonic_Greenhill,
    Sonic_Windyhill,
    SP_Edit,
    SpiritsRoulette,
    Spla_Parking,
    Staffroll,
    StreetPass,
    Tantan_Spring,
    TestStage,
    Tomodachi,
    Trail_Castle,
    Training,
    Wario_Gamer,
    Wario_Madein,
    WiiFit,
    WreckingCrew,
    WufuIsland,
    Xeno_Alst,
    Xeno_Gaur,
    Yoshi_CartBoard,
    Yoshi_Island,
    Yoshi_Story,
    Yoshi_Yoster,
    Zelda_Gerudo,
    Zelda_Greatbay,
    Zelda_Hyrule,
    Zelda_Oldin,
    Zelda_Pirates,
    Zelda_Skyward,
    Zelda_Temple,
    Zelda_Tower,
    Zelda_Train,
    Max
}

impl Info {
    pub const fn new() -> Self {
        Self {
            arena_id: AtomicArenaId::new(None),
            remaining_frames: AtomicU32::new(u32::MAX),
            current_menu: AtomicU32::new(u32::MAX),
            is_match: AtomicBool::new(false),
            is_results_screen: AtomicBool::new(false),
            hid_hooks: AtomicU32::new(0),
            hid_npad_hits: AtomicU32::new(0),
            hid_elapsed_ms: AtomicU32::new(0),
            stage: AtomicU32::new(Stage::None as u32),
            players: [
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new()
            ]
        }
    }

    pub fn arena_id(&self) -> Option<String> {
        self.arena_id.load_string(Ordering::SeqCst)
    }

    pub fn remaining_frames(&self) -> u32 {
        self.remaining_frames.load(Ordering::SeqCst)
    }

    pub fn is_match(&self) -> bool {
        self.is_match.load(Ordering::SeqCst)
    }

    pub fn stage(&self) -> Stage {
        let s = self.stage.load(Ordering::SeqCst);
        if (0..Stage::Max as u32).contains(&s) {
            unsafe {
                core::mem::transmute(s)
            }
        } else {
            Stage::None
        }
    }
}

impl Player {
    pub const fn new() -> Self {
        Self {
            is_in_game: AtomicBool::new(false),
            name: AtomicName::new(None),
            character: AtomicU32::new(Character::None as u32),
            damage: AtomicF32::new(0.),
            stocks: AtomicU32::new(0),
            self_destructs: AtomicU32::new(0),
            is_cpu: AtomicBool::new(false),
            skin: AtomicU32::new(0),
            x: AtomicF32::new(0.),
            y: AtomicF32::new(0.),
            hero_menu_open: AtomicBool::new(false),
            hero_menu_selected: AtomicBool::new(false),
            hero_menu_selection: AtomicU32::new(0),
            team: AtomicI32::new(-1),
            neutral_wins: AtomicU32::new(0),
            neutral_losses: AtomicU32::new(0),
            non_killing_wins: AtomicU32::new(0),
            stage_control: AtomicU32::new(0),
            avg_damage_per_opening: AtomicF32::new(0.),
            top_opener: AtomicU64::new(0),
            top_opener_name: AtomicText::new(),
            avg_death: AtomicF32::new(0.),
            earliest_death: AtomicF32::new(0.),
            latest_death: AtomicF32::new(0.),
            damage_dealt: AtomicF32::new(0.),
            damage_taken: AtomicF32::new(0.),
            match_self_destructs: AtomicU32::new(0),
            stocks_taken: AtomicU32::new(0),
        }
    }

    pub fn clear_match_stats(&self) {
        let zero = FighterSummary::zero();
        self.store_match_stats(&zero, "");
    }

    pub fn store_match_stats(&self, summary: &FighterSummary, opener_name: &str) {
        self.neutral_wins.store(summary.neutral_wins, Ordering::SeqCst);
        self.neutral_losses.store(summary.neutral_losses, Ordering::SeqCst);
        self.non_killing_wins.store(summary.non_killing_wins, Ordering::SeqCst);
        self.stage_control.store(summary.stage_control_frames, Ordering::SeqCst);
        self.avg_damage_per_opening.store(summary.avg_damage_per_opening, Ordering::SeqCst);
        self.top_opener.store(summary.top_opener, Ordering::SeqCst);
        self.top_opener_name.store_str(opener_name, Ordering::SeqCst);
        self.avg_death.store(summary.avg_death, Ordering::SeqCst);
        self.earliest_death.store(summary.earliest_death, Ordering::SeqCst);
        self.latest_death.store(summary.latest_death, Ordering::SeqCst);
        self.damage_dealt.store(summary.damage_dealt, Ordering::SeqCst);
        self.damage_taken.store(summary.damage_taken, Ordering::SeqCst);
        self.match_self_destructs.store(summary.self_destructs, Ordering::SeqCst);
        self.stocks_taken.store(summary.stocks_taken, Ordering::SeqCst);
    }

    pub fn character(&self) -> Character {
        Character::from_u32(self.character.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    #[test]
    fn character_test() {
        // Test Character out of bounds
        let player = Player {
            character: AtomicU32::new(Character::Max as u32),
            ..Player::new()
        };

        // Invalid character
        assert_eq!(player.character(), Character::None);

        let player = Player {
            character: AtomicU32::new(u32::MAX),
            ..Player::new()
        };

        // Invalid character
        assert_eq!(player.character(), Character::None);

        let player = Player {
            character: AtomicU32::new(Character::Zenigame as u32),
            ..Player::new()
        };

        // Valid character
        assert_eq!(player.character(), Character::Zenigame);
    }

    #[test]
    fn player_stats_fields_default_when_missing_from_json() {
        let json = r#"{
            "is_in_game": false,
            "name": null,
            "character": 0,
            "stocks": 0,
            "self_destructs": 0,
            "damage": 0.0,
            "is_cpu": false,
            "skin": 0,
            "x": 0.0,
            "y": 0.0,
            "hero_menu_open": false,
            "hero_menu_selected": false,
            "hero_menu_selection": 0,
            "team": -1
        }"#;
        let player: Player = serde_json::from_str(json).unwrap();
        assert_eq!(player.neutral_wins.load(Ordering::SeqCst), 0);
        assert_eq!(player.stocks_taken.load(Ordering::SeqCst), 0);
        assert_eq!(player.top_opener_name.load_string(Ordering::SeqCst), "");
        assert_eq!(player.avg_damage_per_opening.load(Ordering::SeqCst), 0.0);
    }

    #[test]
    fn stage_test() {
        const TEST_INFO: Info = Info {
            arena_id: AtomicArenaId::new(Some([b'A', b'A', b'A', b'A', b'A'])),
            is_match: AtomicBool::new(true),
            remaining_frames: AtomicU32::new(3),
            current_menu: AtomicU32::new(3),
            is_results_screen: AtomicBool::new(false),
            hid_hooks: AtomicU32::new(0),
            hid_npad_hits: AtomicU32::new(0),
            hid_elapsed_ms: AtomicU32::new(0),
            stage: AtomicU32::new(Stage::Plankton as u32),
            players: [
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
                Player::new(),
            ]
        };

        assert_eq!(TEST_INFO.stage(), Stage::Plankton);
        assert_eq!(TEST_INFO.remaining_frames(), 3);
        assert!(TEST_INFO.is_match());

        let new_info = Info {
            stage: AtomicU32::new(Stage::Max as u32),
            ..TEST_INFO
        };

        // test invalid state
        assert_eq!(new_info.stage(), Stage::None);

        let new_info = Info {
            stage: AtomicU32::new(u32::MAX),
            ..TEST_INFO
        };

        // test invalid state
        assert_eq!(new_info.stage(), Stage::None);

        let new_info = Info {
            stage: AtomicU32::new(Stage::_75m as u32),
            ..TEST_INFO
        };

        assert_eq!(new_info.stage(), Stage::_75m);
    }
}
