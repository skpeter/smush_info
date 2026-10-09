use smash::app::{self, lua_bind::*};
use smash::lib::lua_const::*;
use smush_info_shared::{
    display_name, map_status, Character, FrameSample, Info, MatchStats, OpeningRecord, Phase,
};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::FIGHTER_MANAGER_ADDR;

static STATS_SAMPLING: AtomicBool = AtomicBool::new(false);
static mut STATS: MatchStats = MatchStats::new();

pub fn set_sampling(enabled: bool) {
    STATS_SAMPLING.store(enabled, Ordering::SeqCst);
}

pub fn reset(info: &Info) {
    unsafe {
        STATS.reset();
    }
    info.players[0].clear_match_stats();
    info.players[1].clear_match_stats();
}

pub fn openings() -> [Vec<OpeningRecord>; 2] {
    unsafe { STATS.openings() }
}

pub unsafe fn capture(
    module_accessor: *mut app::BattleObjectModuleAccessor,
    player_num: usize,
) -> bool {
    if player_num >= 2 || !STATS_SAMPLING.load(Ordering::SeqCst) || FIGHTER_MANAGER_ADDR == 0 {
        return false;
    }
    let mgr = *(FIGHTER_MANAGER_ADDR as *mut *mut app::FighterManager);
    if mgr.is_null() {
        return false;
    }
    let fighter_information = FighterManager::get_fighter_information(
        mgr,
        app::FighterEntryID(player_num as i32),
    ) as *mut app::FighterInformation;
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
    };
    // The sample keeps its own stocks. Do not write players[].stocks here.
    let stepped = STATS.push(player_num, sample);
    if stepped {
        publish(crate::game_info());
    }
    stepped
}

pub fn publish(info: &Info) {
    let summary = unsafe { STATS.summary() };
    for slot in 0..2 {
        let name = display_name(info.players[slot].character(), summary[slot].top_opener);
        info.players[slot].store_match_stats(&summary[slot], &name);
    }
}

pub fn openings_json(characters: [Character; 2]) -> serde_json::Value {
    let openings = openings();
    let mut object = serde_json::Map::new();
    for slot in 0..2 {
        let rows: Vec<serde_json::Value> = openings[slot]
            .iter()
            .map(|opening| {
                serde_json::json!({
                    "opener": opening.opener,
                    "name": display_name(characters[slot], opening.opener),
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
