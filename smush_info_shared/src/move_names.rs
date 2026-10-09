//! Move names from the community spreadsheet.
//!
//! The key is character plus hash40. 39 hashes in that sheet name different
//! moves on different fighters, and no (character, hash) pair disagrees with
//! itself. Fallback is English, then Specific, then General. A miss stays a hash.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::Character;

const SHEET: &str = include_str!("../data/move_names.csv");

pub fn pick_name<'a>(english: &'a str, specific: &'a str, general: &'a str) -> Option<&'a str> {
    if !english.is_empty() {
        Some(english)
    } else if !specific.is_empty() {
        Some(specific)
    } else if !general.is_empty() {
        Some(general)
    } else {
        None
    }
}

pub fn lookup(character: Character, hash: u64) -> Option<&'static str> {
    names()
        .get(&(character as u32, hash))
        .map(|stored| stored.as_str())
}

pub fn display_name(character: Character, hash: u64) -> String {
    if hash == 0 {
        return String::new();
    }
    lookup(character, hash).map(|name| name.to_string()).unwrap_or_else(|| format!("{hash:#x}"))
}

fn names() -> &'static HashMap<(u32, u64), String> {
    static NAMES: OnceLock<HashMap<(u32, u64), String>> = OnceLock::new();
    NAMES.get_or_init(load_names)
}

fn load_names() -> HashMap<(u32, u64), String> {
    let mut out = HashMap::new();
    for row in sheet_rows() {
        let Some(character) = sheet_character(&row[0]) else {
            continue;
        };
        let Ok(hash) = parse_hash(row[2].trim()) else {
            continue;
        };
        let Some(name) = pick_name(row[6].trim(), row[4].trim(), row[5].trim()) else {
            continue;
        };
        out.insert((character as u32, hash), name.to_string());
    }
    out
}

#[cfg(test)]
fn unmapped_sheet_characters() -> Vec<String> {
    let mut missing = Vec::new();
    for row in sheet_rows() {
        if sheet_character(&row[0]).is_none() && !missing.iter().any(|name: &String| name == &row[0]) {
            missing.push(row[0].clone());
        }
    }
    missing
}

fn sheet_rows() -> Vec<Vec<String>> {
    let mut lines = SHEET.lines();
    let _header = lines.next();
    lines.filter_map(|line| parse_csv_line(line)).filter(|row| row.len() >= 7).collect()
}

fn parse_hash(text: &str) -> Result<u64, std::num::ParseIntError> {
    let text = text.trim();
    let text = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    u64::from_str_radix(text, 16)
}

fn parse_csv_line(line: &str) -> Option<Vec<String>> {
    if line.is_empty() {
        return None;
    }
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                chars.next();
                current.push('"');
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    Some(fields)
}

fn sheet_character(name: &str) -> Option<Character> {
    Some(match name.trim() {
        "Banjo & Kazooie" => Character::Buddy,
        "Bayonetta" => Character::Bayonetta,
        "Bowser" => Character::Koopa,
        "Bowser Jr" => Character::Koopajr,
        "Byleth" => Character::Master,
        "Captain Falcon" => Character::Captain,
        "Chrom" => Character::Chrom,
        "Cloud" => Character::Cloud,
        "Corrin" => Character::Kamui,
        "Daisy" => Character::Daisy,
        "Dark Pit" => Character::Pitb,
        "Dark Samus" => Character::Samusd,
        "Diddy Kong" => Character::Diddy,
        "Doctor Mario" => Character::Mariod,
        "Donkey Kong" => Character::Donkey,
        "Duck Hunt Duo" => Character::Duckhunt,
        "Falco" => Character::Falco,
        "Fox" => Character::Fox,
        "Ganondorf" => Character::Ganon,
        "Greninja" => Character::Gekkouga,
        "Hero" => Character::Brave,
        "Ike" => Character::Ike,
        "Incineroar" => Character::Gaogaen,
        "Inkling" => Character::Inkling,
        "Isabelle" => Character::Shizue,
        "Jigglypuff" => Character::Purin,
        "Joker" => Character::Jack,
        "K. Rool" => Character::Krool,
        "Kazuya" => Character::Demon,
        "Ken" => Character::Ken,
        "King Dedede" => Character::Dedede,
        "Kirby" => Character::Kirby,
        "Link" => Character::Link,
        "Little Mac" => Character::Littlemac,
        "Lucario" => Character::Lucario,
        "Lucas" => Character::Lucas,
        "Lucina" => Character::Lucina,
        "Luigi" => Character::Luigi,
        "Mario" => Character::Mario,
        "Marth" => Character::Marth,
        "Mega Man" => Character::Rockman,
        "Meta Knight" => Character::Metaknight,
        "Mii Brawler" => Character::Miifighter,
        "Min Min" => Character::Tantan,
        "Mr. Game & Watch" => Character::Gamewatch,
        "Mythra" => Character::Elight,
        "Ness" => Character::Ness,
        "Pac-Man" => Character::Pacman,
        "Palutena" => Character::Palutena,
        "Peach" => Character::Peach,
        "Pichu" => Character::Pichu,
        "Pikachu" => Character::Pikachu,
        "Piranha Plant" => Character::Packun,
        "Pit" => Character::Pit,
        "Popo" => Character::Popo,
        "Pyra" => Character::Eflame,
        "R.O.B." => Character::Robot,
        "Richter" => Character::Richter,
        "Ridley" => Character::Ridley,
        "Robin" => Character::Reflet,
        "Rosalina" => Character::Rosetta,
        "Roy" => Character::Roy,
        "Ryu" => Character::Ryu,
        "Samus" => Character::Samus,
        "Sephiroth" => Character::Edge,
        "Sheik" => Character::Sheik,
        "Shulk" => Character::Shulk,
        "Simon" => Character::Simon,
        "Snake" => Character::Snake,
        "Sonic" => Character::Sonic,
        "Sora" => Character::Trail,
        "Squirtle" => Character::Zenigame,
        "Steve" => Character::Pickel,
        "Terry" => Character::Dolly,
        "Toon Link" => Character::Toonlink,
        "Villager" => Character::Murabito,
        "Wario" => Character::Wario,
        "Wii Fit Trainer" => Character::Wiifit,
        "Wolf" => Character::Wolf,
        "Yoshi" => Character::Yoshi,
        "Young Link" => Character::Younglink,
        "Zelda" => Character::Zelda,
        "Zero Suit Samus" => Character::Szerosuit,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_name_walks_english_then_specific_then_general() {
        assert_eq!(pick_name("Dash", "initial_dash", "dash"), Some("Dash"));
        assert_eq!(pick_name("", "initial_dash", "dash"), Some("initial_dash"));
        assert_eq!(pick_name("", "", "dash"), Some("dash"));
        assert_eq!(pick_name("", "", ""), None);
    }

    #[test]
    fn every_sheet_character_maps_onto_the_enum() {
        assert_eq!(unmapped_sheet_characters(), Vec::<String>::new());
    }

    #[test]
    fn pikachu_wait_is_idle_and_a_shared_hash_keeps_both_names() {
        assert_eq!(lookup(Character::Pikachu, 0x047dee83e5), Some("Idle"));
        assert_eq!(lookup(Character::Pikachu, 0x105c3c1e76), Some("Quick Attack"));
        let other = names()
            .iter()
            .find(|((character, hash), name)| {
                *hash == 0x105c3c1e76 && *character != Character::Pikachu as u32 && name.as_str() != "Quick Attack"
            });
        assert!(other.is_some());
    }

    #[test]
    fn missing_hash_falls_back_to_the_number() {
        assert_eq!(display_name(Character::Mario, 0), "");
        assert_eq!(display_name(Character::Mario, 0x1234), "0x1234");
    }
}
