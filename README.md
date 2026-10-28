# Smush Info (sharlot fork)

A Skyline plugin that hosts a TCP server for subscribing to information about the current Smash Ultimate match. Useful for statistics, game integration, and more.

I have tacked a whole bunch of stuff onto this for [ssbu-stream-automation](https://github.com/sticks-stuff/ssbu-stream-automation). Not my best code but it works.

Original Authors:
* jam1garner
* jugeeya

Seems jam1garner has left the scene so I don't feel particularly comfortable asking them licensing questions, but consider everything I've added to this project GPLv3

## What it does

Connect to the Switch on port **4242**. Each line is one JSON object about the match on screen. A browser overlay can use that same port.

For a normal versus 1v1 (CPUs are fine; training, free-for-alls, and doubles are not), each player also gets a few running totals: openings, stage control, damage, stocks, and death percents. Those update during the game and freeze on the results screen. Other modes just send zeros. If you want the field names, [example.json](example.json) is a finished 1v1. The live feed is that object. The results file also includes `game_version` and `openings`, which are in the sample.

If you show these numbers on a stream overlay, credit **Vye** (Vye#0547) and **TheComet** (TheComet#5387).

When that 1v1 ends, the same snapshot is written next to the replay, with the list of openings included.

After the results screen comes up, the plugin saves the replay for you, copies it to the SD card, and (unless you turn it off) taps A for a few seconds to leave the results screen. The file keeps the Vault name, under:

```
sd:/ultimate/smush_info/replays/{name}/
```

Copy that file into `save_data/replay/` if you want it back in the game, and keep the name. The results JSON sits in the same folder. Once the copy is on the SD card, the Vault copy is deleted so the console save does not fill up.

If the save never shows up, your controllers come back and it does not press A, so you can leave the screen yourself. Going Home pauses the wait. Watching a replay in the Vault does not trigger a save.

Do not also install [Auto-Save Replays](https://gamebanana.com/mods/394784) or another results-screen skip. They press buttons on the same screen and get in the way. Keep `libnn_hid_hook.nro` if your other mods need it.

# Requirements
smush_info requires you to have the following Skyline plugins downloaded and installed:
- [Arcropolis](https://github.com/Raytwo/ARCropolis/releases)
- [Smashline V2](https://github.com/HDR-Development/smashline/releases) (`libsmashline_plugin.nro`)
- [libnro_hook](https://github.com/ultimate-research/nro-hook-plugin/releases)

Do not install `libacmd_hook.nro` alongside Smashline. Both hook the same thing and the game will crash when a match loads.

# Settings

On boot, the plugin reads `sd:/ultimate/smush_info/overrides.toml` if it is there. Everything stays on unless you uncomment a line. If the file is missing, everything is on.

The release zip already includes this file. If you update the plugin later, copy the `.nro` only. Extracting the zip again puts the flags back to commented, which turns the features on again.

```toml
# auto (the default) turns emulator behavior on when this does not
# look like a real Atmosphère SD card. on always does. off never does.
emulator_mode = "auto"

[smush_info]
disable_list = [
    # "disable_results_log",
    # "disable_replay_save",
    # "disable_results_skip",
    # "disable_stats",
]
```

- `disable_results_log` — do not write the results JSON
- `disable_replay_save` — do not save the replay or copy it to the SD card
- `disable_results_skip` — leave the results screen up after a save
- `disable_stats` — leave the versus totals at zero and leave openings out of the results file. Percent, stocks, and screen position keep updating.
- `emulator_mode` — `auto`, `on`, or `off`. `auto` is meant for the Eden emulator: it turns on when `sd:/atmosphere/package3` is missing, and stays off on a real Switch SD. While it is on, live matches still work, Vault playback still sends match data, and replay save stays off. The ending stock count comes from deaths already seen, instead of asking the game again on the results screen. Screen position is not updated during Vault playback. A self-destruct on the last stock can show up as the opponent taking that stock.

# How to Build and Install
You must have Rust and Cargo installed. [Click here](https://www.rust-lang.org/tools/install) for instructions on how to install based on your system.

Once those are installed, open your command prompt or terminal and run the following commands
```sh
cargo install cargo-skyline
```

To compile your plugin use the following command in the root of the project (beside the `Cargo.toml` file):
```sh
cargo skyline build --release
```

Then pack the SD-card zip:
```sh
bash scripts/package-sd.sh
# Windows: powershell -File scripts/package-sd.ps1
```

The zip is `smush_info-sd.zip`. Extract it onto the root of the SD card. You should end up with:
```
atmosphere/contents/01006A800016E000/romfs/skyline/plugins/libsmush_info.nro
ultimate/smush_info/overrides.toml
```

The `.nro` by itself is at:
```
target/aarch64-skyline-switch/release/libsmush_info.nro
```
Install path, if you are copying it by hand:
```
sd:/atmosphere/contents/01006A800016E000/romfs/skyline/plugins
```

`cargo skyline` can also automate some of this process via FTP. If you have an FTP client on your Switch, you can run:
```sh
cargo skyline set-ip [Switch IP]
# install to the correct plugin folder on the Switch and listen for logs
cargo skyline run
```
