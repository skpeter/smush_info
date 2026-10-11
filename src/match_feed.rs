use smash::app::{self, lua_bind::*};
use smash::lib::lua_const::*;
use smush_info_shared::{
    active_entry_pair, display_name, map_status, slot_for_entry, Character, FrameSample, Info,
    MatchStats, OpeningRecord, Phase,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::FIGHTER_MANAGER_ADDR;

static STATS_SAMPLING: AtomicBool = AtomicBool::new(false);
/// Temporary tick owner before both fighters are marked in-game.
static FALLBACK_TICK_OWNER: AtomicUsize = AtomicUsize::new(usize::MAX);
static mut STATS: MatchStats = MatchStats::new();

pub fn set_sampling(enabled: bool) {
    STATS_SAMPLING.store(enabled, Ordering::SeqCst);
}

fn in_game_flags(info: &Info) -> [bool; 8] {
    let mut flags = [false; 8];
    for i in 0..8 {
        flags[i] = info.players[i].is_in_game.load(Ordering::SeqCst);
    }
    flags
}

pub fn active_pair(info: &Info) -> Option<[usize; 2]> {
    active_entry_pair(in_game_flags(info))
}

pub fn is_tick_owner(entry: usize, info: &Info) -> bool {
    if let Some(pair) = active_entry_pair(in_game_flags(info)) {
        FALLBACK_TICK_OWNER.store(usize::MAX, Ordering::SeqCst);
        return entry == pair[0];
    }
    // No pair yet (is_in_game not set). First fighter hook claims tick duty so
    // entries other than 0 still arm eligibility / latched dumps.
    match FALLBACK_TICK_OWNER.compare_exchange(
        usize::MAX,
        entry,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => true,
        Err(existing) => entry == existing,
    }
}

pub fn reset(info: &Info) {
    FALLBACK_TICK_OWNER.store(usize::MAX, Ordering::SeqCst);
    unsafe {
        STATS.reset();
    }
    if let Some(pair) = active_pair(info) {
        info.players[pair[0]].clear_match_stats();
        info.players[pair[1]].clear_match_stats();
    } else {
        // Before both fighters are marked in-game, clear the common versus slots.
        info.players[0].clear_match_stats();
        info.players[1].clear_match_stats();
    }
}

pub fn openings() -> [Vec<OpeningRecord>; 2] {
    unsafe { STATS.openings() }
}

pub unsafe fn capture(
    module_accessor: *mut app::BattleObjectModuleAccessor,
    entry: usize,
) -> bool {
    if !STATS_SAMPLING.load(Ordering::SeqCst) || FIGHTER_MANAGER_ADDR == 0 {
        return false;
    }
    let info = crate::game_info();
    let Some(slot) = slot_for_entry(entry, in_game_flags(info)) else {
        return false;
    };
    let mgr = *(FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager);
    if mgr.is_null() {
        return false;
    }
    let fighter_information = FighterManager::get_fighter_information(
        mgr,
        app::FighterEntryID(entry as i32),
    ) as *mut app::FighterInformation;
    if fighter_information.is_null() {
        return false;
    }
    let hitstun = WorkModule::get_float(
        module_accessor,
        *FIGHTER_INSTANCE_WORK_ID_FLOAT_DAMAGE_REACTION_FRAME,
    );
    let mut phase = map_status(StatusModule::status_kind(module_accessor));
    if hitstun > 0.0 && matches!(phase, Phase::Other | Phase::OnGround) {
        phase = Phase::Hitstun;
    }
    let sample = FrameSample {
        damage: DamageModule::damage(module_accessor, 0),
        hitstun,
        phase,
        motion: MotionModule::motion_kind(module_accessor),
        world_x: PostureModule::pos_x(module_accessor),
        stocks: FighterInformation::stock_count(fighter_information) as u32,
        suicide_count: FighterInformation::suicide_count(fighter_information, 0) as u32,
        character: info.players[entry].character.load(Ordering::SeqCst),
    };
    // The sample keeps its own stocks. Do not write players[].stocks here.
    let stepped = STATS.push(slot, sample);
    if stepped {
        publish(info);
    }
    stepped
}

pub fn publish(info: &Info) {
    let summary = unsafe { STATS.summary() };
    let Some(pair) = active_pair(info) else {
        return;
    };
    for slot in 0..2 {
        let entry = pair[slot];
        let name = display_name(info.players[entry].character(), summary[slot].top_opener);
        info.players[entry].store_match_stats(&summary[slot], &name);
    }
}

pub fn openings_json() -> serde_json::Value {
    let openings = openings();
    let mut object = serde_json::Map::new();
    for slot in 0..2 {
        let rows: Vec<serde_json::Value> = openings[slot]
            .iter()
            .map(|opening| {
                let character = Character::from_u32(opening.character);
                serde_json::json!({
                    "character": opening.character,
                    "opener": opening.opener,
                    "name": display_name(character, opening.opener),
                    "damage_start": opening.damage_start,
                    "damage_end": opening.damage_end,
                    "killed": opening.killed,
                    "moves": opening.moves,
                })
            })
            .collect();
        object.insert(slot.to_string(), serde_json::Value::Array(rows));
    }
    serde_json::Value::Object(object)
}
