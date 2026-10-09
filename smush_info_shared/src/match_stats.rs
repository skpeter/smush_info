//! 1v1 match calculator ported from ReFramed's `StatsCalculator`.
//!
//! Neutral and strings follow that file. Stocks taken does not: it is
//! opponent stock losses since the first sample, minus opponent self-destructs
//! since that sample, clamped at 0.
//!
//! ```text
//! eligible rising --> reset, then sample
//! eligible match  --> step when both slots are fresh
//! results         --> freeze (caller stops stepping)
//! ineligible      --> caller publishes zeros and resets
//!
//! hitstun > 0 or shield-break fly --> leave neutral, counter = 30
//! hitstun == 0 and OnGround       --> decrement counter, then neutral
//! Rebirth                         --> neutral immediately
//! Dead during a string            --> that string killed
//! ```
//!
//! Move names on a stream overlay should credit Vye (Vye#0547) and
//! TheComet (TheComet#5387).

use std::collections::HashMap;

pub const NEUTRAL_RESET_FRAMES: u32 = 30;
pub const OPENING_HITSTUN_FRAMES: u32 = 45;
pub const CONTINUE_HITSTUN_FRAMES: u32 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    OnGround,
    Hitstun,
    Dead,
    Rebirth,
    ShieldBreakFly,
    Other,
}

/// Raw status ids live only in this function.
pub fn map_status(kind: i32) -> Phase {
    match kind {
        22 | 103 | 104 | 0 | 27 | 10 | 1 | 3 => Phase::OnGround,
        92 => Phase::ShieldBreakFly,
        181 => Phase::Dead,
        182 => Phase::Rebirth,
        _ => Phase::Other,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FrameSample {
    pub damage: f32,
    pub hitstun: f32,
    pub phase: Phase,
    pub motion: u64,
    pub world_x: f32,
    pub stocks: u32,
    pub suicide_count: u32,
}

impl FrameSample {
    pub fn neutral(slot_damage: f32) -> Self {
        Self {
            damage: slot_damage,
            hitstun: 0.0,
            phase: Phase::OnGround,
            motion: 0,
            world_x: 0.0,
            stocks: 3,
            suicide_count: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpeningRecord {
    pub opener: u64,
    pub damage_start: f32,
    pub damage_end: f32,
    pub killed: bool,
    pub moves: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FighterSummary {
    pub neutral_wins: u32,
    pub neutral_losses: u32,
    pub non_killing_wins: u32,
    pub stage_control_frames: u32,
    pub avg_damage_per_opening: f32,
    pub top_opener: u64,
    pub avg_death: f32,
    pub earliest_death: f32,
    pub latest_death: f32,
    pub damage_dealt: f32,
    pub damage_taken: f32,
    pub self_destructs: u32,
    pub stocks_taken: u32,
}

impl FighterSummary {
    pub const fn zero() -> Self {
        Self {
            neutral_wins: 0,
            neutral_losses: 0,
            non_killing_wins: 0,
            stage_control_frames: 0,
            avg_damage_per_opening: 0.0,
            top_opener: 0,
            avg_death: 0.0,
            earliest_death: 0.0,
            latest_death: 0.0,
            damage_dealt: 0.0,
            damage_taken: 0.0,
            self_destructs: 0,
            stocks_taken: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct ComboString {
    moves: Vec<u64>,
    damage_at_start: f32,
    damage_at_end: f32,
    killed: bool,
}

/// Eligible versus results ignore the two-minute cooldown and are written from
/// the game thread. Other modes keep the cooldown and may be written from the
/// UDP fallback when no fighter frame is running.
pub fn should_write_stats_snapshot(
    latched_eligible: bool,
    game_over_edge: bool,
    on_game_thread: bool,
    ticks_since_dump: u64,
    cooldown: u64,
) -> bool {
    if !game_over_edge {
        return false;
    }
    if latched_eligible {
        return on_game_thread;
    }
    ticks_since_dump >= cooldown
}

pub struct MatchStats {
    fresh: [bool; 2],
    slots: [FrameSample; 2],
    in_neutral: [bool; 2],
    neutral_counter: [u32; 2],
    old_damage_dealt: [f32; 2],
    string_old_damage: [f32; 2],
    damage_dealt: [f32; 2],
    damage_taken: [f32; 2],
    death_percents: [Vec<f32>; 2],
    old_stocks: [u32; 2],
    stocks_seen: [bool; 2],
    initial_stocks: [u32; 2],
    initial_sds: [u32; 2],
    last_stocks: [u32; 2],
    last_sds: [u32; 2],
    baseline_ready: [bool; 2],
    stage_control: [u32; 2],
    strings: [Vec<ComboString>; 2],
    being_comboed_by: [i8; 2],
    hitstun_counter: [u32; 2],
}

impl MatchStats {
    pub const fn new() -> Self {
        Self {
            fresh: [false, false],
            slots: [blank_sample(), blank_sample()],
            in_neutral: [true, true],
            neutral_counter: [0, 0],
            old_damage_dealt: [0.0, 0.0],
            string_old_damage: [0.0, 0.0],
            damage_dealt: [0.0, 0.0],
            damage_taken: [0.0, 0.0],
            death_percents: [Vec::new(), Vec::new()],
            old_stocks: [0, 0],
            stocks_seen: [false, false],
            initial_stocks: [0, 0],
            initial_sds: [0, 0],
            last_stocks: [0, 0],
            last_sds: [0, 0],
            baseline_ready: [false, false],
            stage_control: [0, 0],
            strings: [Vec::new(), Vec::new()],
            being_comboed_by: [-1, -1],
            hitstun_counter: [0, 0],
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Store one fighter's sample. Step once both slots are fresh since the last step.
    /// A lone sample is kept. Writing the same slot again replaces it and does not pair.
    pub fn push(&mut self, slot: usize, sample: FrameSample) -> bool {
        if slot >= 2 {
            return false;
        }
        self.slots[slot] = sample;
        self.fresh[slot] = true;
        if self.fresh[0] && self.fresh[1] {
            self.fresh = [false, false];
            self.update(&[self.slots[0], self.slots[1]]);
            true
        } else {
            false
        }
    }

    pub fn discard_fresh(&mut self) {
        self.fresh = [false, false];
    }

    pub fn is_neutral(&self, slot: usize) -> bool {
        self.in_neutral.get(slot).copied().unwrap_or(false)
    }

    pub fn update(&mut self, samples: &[FrameSample]) {
        if samples.len() != 2 {
            return;
        }
        self.update_neutral(samples);
        self.update_damage(samples);
        self.update_deaths(samples);
        self.update_stage_control(samples);
        self.update_strings(samples);
    }

    pub fn summary(&self) -> [FighterSummary; 2] {
        [self.fighter_summary(0), self.fighter_summary(1)]
    }

    pub fn openings(&self) -> [Vec<OpeningRecord>; 2] {
        [self.opening_records(0), self.opening_records(1)]
    }

    fn fighter_summary(&self, slot: usize) -> FighterSummary {
        let wins = self.strings[slot].len() as u32;
        let losses = self.strings[1 - slot].len() as u32;
        let non_killing = self.strings[slot].iter().filter(|s| !s.killed).count() as u32;
        let dealt = self.damage_dealt[slot];
        FighterSummary {
            neutral_wins: wins,
            neutral_losses: losses,
            non_killing_wins: non_killing,
            stage_control_frames: self.stage_control[slot],
            avg_damage_per_opening: if wins == 0 { 0.0 } else { dealt / wins as f32 },
            top_opener: most_common_opener(&self.strings[slot]),
            avg_death: avg(&self.death_percents[slot]),
            earliest_death: min_or_zero(&self.death_percents[slot]),
            latest_death: max_or_zero(&self.death_percents[slot]),
            damage_dealt: dealt,
            damage_taken: self.damage_taken[slot],
            self_destructs: self.last_sds[slot].saturating_sub(self.initial_sds[slot]),
            stocks_taken: self.stocks_taken(slot),
        }
    }

    fn stocks_taken(&self, slot: usize) -> u32 {
        let opp = 1 - slot;
        let losses = self.initial_stocks[opp].saturating_sub(self.last_stocks[opp]);
        let sds = self.last_sds[opp].saturating_sub(self.initial_sds[opp]);
        losses.saturating_sub(sds)
    }

    fn opening_records(&self, slot: usize) -> Vec<OpeningRecord> {
        self.strings[slot]
            .iter()
            .filter_map(|string| {
                let opener = *string.moves.first()?;
                Some(OpeningRecord {
                    opener,
                    damage_start: string.damage_at_start,
                    damage_end: string.damage_at_end,
                    killed: string.killed,
                    moves: string.moves.clone(),
                })
            })
            .collect()
    }

    fn update_neutral(&mut self, samples: &[FrameSample]) {
        for i in 0..2 {
            if samples[i].hitstun > 0.0 || samples[i].phase == Phase::ShieldBreakFly {
                self.in_neutral[i] = false;
                self.neutral_counter[i] = NEUTRAL_RESET_FRAMES;
            }
            if samples[i].hitstun == 0.0 && samples[i].phase == Phase::OnGround {
                if self.neutral_counter[i] > 0 {
                    self.neutral_counter[i] -= 1;
                } else {
                    self.in_neutral[i] = true;
                }
            }
            if samples[i].phase == Phase::Rebirth {
                self.in_neutral[i] = true;
            }
        }
    }

    fn update_damage(&mut self, samples: &[FrameSample]) {
        for i in 0..2 {
            let delta = samples[i].damage - self.old_damage_dealt[i];
            self.old_damage_dealt[i] = samples[i].damage;
            if delta > 0.0 {
                self.damage_taken[i] += delta;
                self.damage_dealt[1 - i] += delta;
            }
        }
    }

    fn update_deaths(&mut self, samples: &[FrameSample]) {
        for i in 0..2 {
            if !self.baseline_ready[i] {
                self.initial_stocks[i] = samples[i].stocks;
                self.initial_sds[i] = samples[i].suicide_count;
                self.baseline_ready[i] = true;
            }
            self.last_stocks[i] = samples[i].stocks;
            self.last_sds[i] = samples[i].suicide_count;

            if !self.stocks_seen[i] {
                self.old_stocks[i] = samples[i].stocks;
                self.stocks_seen[i] = true;
            } else if samples[i].stocks < self.old_stocks[i] {
                self.death_percents[i].push(samples[i].damage);
                self.old_stocks[i] = samples[i].stocks;
            } else if samples[i].stocks > self.old_stocks[i] {
                self.old_stocks[i] = samples[i].stocks;
            }
        }
    }

    fn update_stage_control(&mut self, samples: &[FrameSample]) {
        let mut owner: Option<usize> = None;
        let mut best = f32::MAX;
        for i in 0..2 {
            if self.in_neutral[i] {
                let distance = samples[i].world_x.abs();
                if distance < best {
                    best = distance;
                    owner = Some(i);
                }
            }
        }
        if let Some(i) = owner {
            self.stage_control[i] = self.stage_control[i].saturating_add(1);
        }
    }

    fn update_strings(&mut self, samples: &[FrameSample]) {
        for them in 0..2 {
            if self.hitstun_counter[them] == 0 && samples[them].hitstun > 0.0 {
                let me = 1 - them;
                self.being_comboed_by[them] = me as i8;
                self.hitstun_counter[them] = OPENING_HITSTUN_FRAMES;
                self.strings[me].push(ComboString {
                    moves: vec![samples[me].motion],
                    damage_at_start: self.string_old_damage[them],
                    damage_at_end: samples[them].damage,
                    killed: false,
                });
            } else if self.being_comboed_by[them] >= 0 {
                let me = self.being_comboed_by[them] as usize;
                if samples[them].hitstun > 0.0 {
                    self.hitstun_counter[them] = CONTINUE_HITSTUN_FRAMES;
                }
                if let Some(string) = self.strings[me].last_mut() {
                    if string.moves.last().copied() != Some(samples[me].motion) {
                        string.moves.push(samples[me].motion);
                    }
                    string.damage_at_end = samples[them].damage;
                }
            }
        }

        for i in 0..2 {
            if self.being_comboed_by[i] > -1 && samples[i].phase == Phase::Dead {
                let me = self.being_comboed_by[i] as usize;
                if let Some(string) = self.strings[me].last_mut() {
                    string.killed = true;
                }
                self.being_comboed_by[i] = -1;
            }
        }

        for i in 0..2 {
            if self.in_neutral[i] {
                self.being_comboed_by[i] = -1;
            }
        }

        for i in 0..2 {
            if samples[i].hitstun == 0.0 && self.hitstun_counter[i] > 0 {
                self.hitstun_counter[i] -= 1;
                if self.hitstun_counter[i] == 0 {
                    self.being_comboed_by[i] = -1;
                }
            }
        }

        for i in 0..2 {
            self.string_old_damage[i] = samples[i].damage;
        }
    }
}

impl Default for MatchStats {
    fn default() -> Self {
        Self::new()
    }
}

const fn blank_sample() -> FrameSample {
    FrameSample {
        damage: 0.0,
        hitstun: 0.0,
        phase: Phase::Other,
        motion: 0,
        world_x: 0.0,
        stocks: 0,
        suicide_count: 0,
    }
}

fn most_common_opener(strings: &[ComboString]) -> u64 {
    let mut counts: HashMap<u64, u32> = HashMap::new();
    let mut best = 0u64;
    let mut best_count = 0u32;
    for string in strings {
        let Some(opener) = string.moves.first().copied() else {
            continue;
        };
        let count = counts.entry(opener).or_insert(0);
        *count += 1;
        if *count > best_count {
            best_count = *count;
            best = opener;
        }
    }
    if best_count == 0 {
        0
    } else {
        best
    }
}

fn avg(values: &[f32]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    }
}

fn min_or_zero(values: &[f32]) -> f32 {
    values.iter().copied().reduce(f32::min).unwrap_or(0.0)
}

fn max_or_zero(values: &[f32]) -> f32 {
    values.iter().copied().reduce(f32::max).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(a: FrameSample, b: FrameSample) -> [FrameSample; 2] {
        [a, b]
    }

    fn step(stats: &mut MatchStats, a: FrameSample, b: FrameSample) {
        stats.update(&pair(a, b));
    }

    #[test]
    fn map_status_uses_only_the_eight_ground_ids() {
        for id in [22, 103, 104, 0, 27, 10, 1, 3] {
            assert_eq!(map_status(id), Phase::OnGround, "status {id}");
        }
        assert_eq!(map_status(92), Phase::ShieldBreakFly);
        assert_eq!(map_status(181), Phase::Dead);
        assert_eq!(map_status(182), Phase::Rebirth);
        assert_eq!(map_status(494), Phase::Other);
        assert_eq!(map_status(495), Phase::Other);
        assert_eq!(map_status(496), Phase::Other);
        assert_eq!(map_status(99), Phase::Other);
    }

    #[test]
    fn mailbox_pairs_fresh_samples_and_holds_a_lone_one() {
        let mut stats = MatchStats::new();
        let mut first = FrameSample::neutral(0.0);
        first.motion = 11;
        assert!(!stats.push(0, first));
        first.motion = 22;
        assert!(!stats.push(0, first));
        let mut second = FrameSample::neutral(0.0);
        second.world_x = 4.0;
        assert!(stats.push(1, second));
        assert_eq!(stats.slots[0].motion, 22);
        assert!(!stats.fresh[0]);
        assert!(!stats.fresh[1]);
    }

    #[test]
    fn update_rejects_a_single_sample() {
        let mut stats = MatchStats::new();
        stats.update(&[FrameSample::neutral(0.0)]);
        assert_eq!(stats.summary()[0], FighterSummary::zero());
    }

    #[test]
    fn hitstun_from_neutral_is_one_win_until_disadvantage_ends() {
        let mut stats = MatchStats::new();
        step(&mut stats, FrameSample::neutral(0.0), FrameSample::neutral(0.0));
        let mut attacker = FrameSample::neutral(0.0);
        attacker.motion = 0xabc;
        let mut defender = FrameSample::neutral(0.0);
        defender.hitstun = 8.0;
        defender.phase = Phase::Hitstun;
        defender.damage = 12.0;
        step(&mut stats, attacker, defender);
        let summary = stats.summary();
        assert_eq!(summary[0].neutral_wins, 1);
        assert_eq!(summary[0].neutral_losses, 0);
        assert_eq!(summary[1].neutral_losses, 1);
        assert_eq!(summary[0].damage_dealt, 12.0);
        assert_eq!(summary[1].damage_taken, 12.0);
        assert_eq!(summary[0].top_opener, 0xabc);
        assert!(!stats.is_neutral(1));

        defender.damage = 20.0;
        step(&mut stats, attacker, defender);
        assert_eq!(stats.summary()[0].neutral_wins, 1);
        assert_eq!(stats.summary()[0].damage_dealt, 20.0);
    }

    #[test]
    fn ground_counter_returns_to_neutral_after_thirty_frames() {
        let mut stats = MatchStats::new();
        let attacker = FrameSample::neutral(0.0);
        let mut defender = FrameSample::neutral(0.0);
        defender.hitstun = 5.0;
        defender.phase = Phase::Hitstun;
        defender.damage = 1.0;
        step(&mut stats, attacker, defender);

        let mut grounded = FrameSample::neutral(1.0);
        grounded.phase = Phase::OnGround;
        for _ in 0..NEUTRAL_RESET_FRAMES {
            step(&mut stats, attacker, grounded);
            assert!(!stats.is_neutral(1));
        }
        step(&mut stats, attacker, grounded);
        assert!(stats.is_neutral(1));
    }

    #[test]
    fn shield_break_leaves_neutral_and_rebirth_returns() {
        let mut stats = MatchStats::new();
        step(
            &mut stats,
            FrameSample::neutral(0.0),
            FrameSample::neutral(0.0),
        );
        let mut broken = FrameSample::neutral(0.0);
        broken.phase = Phase::ShieldBreakFly;
        step(&mut stats, FrameSample::neutral(0.0), broken);
        assert!(!stats.is_neutral(1));

        let mut rebirth = FrameSample::neutral(0.0);
        rebirth.phase = Phase::Rebirth;
        step(&mut stats, FrameSample::neutral(0.0), rebirth);
        assert!(stats.is_neutral(1));
    }

    #[test]
    fn heals_do_not_add_damage() {
        let mut stats = MatchStats::new();
        let mut hurt = FrameSample::neutral(30.0);
        step(&mut stats, FrameSample::neutral(0.0), hurt);
        assert_eq!(stats.summary()[0].damage_dealt, 30.0);
        hurt.damage = 10.0;
        step(&mut stats, FrameSample::neutral(0.0), hurt);
        assert_eq!(stats.summary()[0].damage_dealt, 30.0);
        assert_eq!(stats.summary()[1].damage_taken, 30.0);
    }

    #[test]
    fn stage_control_goes_to_the_closer_neutral_fighter() {
        let mut stats = MatchStats::new();
        let mut left = FrameSample::neutral(0.0);
        left.world_x = -2.0;
        let mut right = FrameSample::neutral(0.0);
        right.world_x = 9.0;
        step(&mut stats, left, right);
        let summary = stats.summary();
        assert_eq!(summary[0].stage_control_frames, 1);
        assert_eq!(summary[1].stage_control_frames, 0);

        left.hitstun = 3.0;
        left.phase = Phase::Hitstun;
        right.hitstun = 3.0;
        right.phase = Phase::Hitstun;
        step(&mut stats, left, right);
        let summary = stats.summary();
        assert_eq!(summary[0].stage_control_frames, 1);
        assert_eq!(summary[1].stage_control_frames, 0);
    }

    #[test]
    fn dead_during_a_string_marks_the_kill() {
        let mut stats = MatchStats::new();
        step(
            &mut stats,
            FrameSample::neutral(0.0),
            FrameSample::neutral(0.0),
        );
        let mut attacker = FrameSample::neutral(0.0);
        attacker.motion = 7;
        let mut defender = FrameSample::neutral(40.0);
        defender.hitstun = 4.0;
        defender.phase = Phase::Hitstun;
        step(&mut stats, attacker, defender);
        defender.hitstun = 4.0;
        defender.phase = Phase::Dead;
        defender.damage = 40.0;
        step(&mut stats, attacker, defender);
        let openings = stats.openings();
        assert!(openings[0][0].killed);
        assert!(!openings[0][0].killed || openings[0][0].opener == 7);
        assert_eq!(stats.summary()[0].non_killing_wins, 0);
    }

    #[test]
    fn death_percent_uses_damage_when_the_sample_stock_drops() {
        let mut stats = MatchStats::new();
        let mut live = FrameSample::neutral(0.0);
        live.stocks = 3;
        step(&mut stats, live, live);
        live.stocks = 2;
        live.damage = 80.0;
        step(&mut stats, live, FrameSample::neutral(0.0));
        let mut other = FrameSample::neutral(0.0);
        other.stocks = 2;
        other.damage = 40.0;
        let mut still = FrameSample::neutral(80.0);
        still.stocks = 2;
        step(&mut stats, still, other);
        let summary = stats.summary();
        assert_eq!(summary[0].earliest_death, 80.0);
        assert_eq!(summary[0].latest_death, 80.0);
        assert_eq!(summary[0].avg_death, 80.0);
        assert_eq!(summary[1].earliest_death, 40.0);
    }

    #[test]
    fn stocks_taken_subtracts_self_destructs_and_clamps_at_zero() {
        let mut stats = MatchStats::new();
        let mut a = FrameSample::neutral(0.0);
        let mut b = FrameSample::neutral(0.0);
        a.stocks = 3;
        b.stocks = 3;
        step(&mut stats, a, b);
        b.stocks = 2;
        step(&mut stats, a, b);
        assert_eq!(stats.summary()[0].stocks_taken, 1);

        b.suicide_count = 1;
        b.stocks = 1;
        step(&mut stats, a, b);
        assert_eq!(stats.summary()[0].stocks_taken, 1);
        assert_eq!(stats.summary()[1].self_destructs, 1);

        let mut stats = MatchStats::new();
        a.suicide_count = 0;
        b.suicide_count = 0;
        b.stocks = 3;
        step(&mut stats, a, b);
        b.suicide_count = 1;
        step(&mut stats, a, b);
        assert_eq!(stats.summary()[0].stocks_taken, 0);
    }

    #[test]
    fn reset_clears_counters() {
        let mut stats = MatchStats::new();
        let mut defender = FrameSample::neutral(15.0);
        defender.hitstun = 2.0;
        step(&mut stats, FrameSample::neutral(0.0), defender);
        stats.reset();
        assert_eq!(stats.summary()[0], FighterSummary::zero());
        assert!(stats.is_neutral(1));
        assert!(stats.openings()[0].is_empty());
    }

    #[test]
    fn equal_distance_stage_control_keeps_the_lower_slot() {
        let mut stats = MatchStats::new();
        let mut a = FrameSample::neutral(0.0);
        let mut b = FrameSample::neutral(0.0);
        a.world_x = 5.0;
        b.world_x = -5.0;
        step(&mut stats, a, b);
        assert_eq!(stats.summary()[0].stage_control_frames, 1);
        assert_eq!(stats.summary()[1].stage_control_frames, 0);
    }

    #[test]
    fn snapshot_write_bypasses_cooldown_only_for_a_latched_game_thread_edge() {
        assert!(should_write_stats_snapshot(true, true, true, 0, 7500));
        assert!(!should_write_stats_snapshot(true, true, false, 7500, 7500));
        assert!(!should_write_stats_snapshot(true, false, true, 7500, 7500));
        assert!(!should_write_stats_snapshot(false, true, true, 10, 7500));
        assert!(should_write_stats_snapshot(false, true, true, 7500, 7500));
        assert!(should_write_stats_snapshot(false, true, false, 7500, 7500));
    }
}
